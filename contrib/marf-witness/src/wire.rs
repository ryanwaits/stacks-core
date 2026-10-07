// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Witness wire format (v3) and its storage-free verifier.
//!
//! A witness holds every node of one block's trie that lives in that block
//! (copy-on-write: the nodes on paths to keys written or carried in the block),
//! with children in older tries replaced by their ancestor block id, plus the
//! skip-list ancestor root hashes. That is everything the block's
//! `state_index_root` depends on, so a verifier recomputes the root from these
//! bytes alone and learns every leaf (path + value hash) of the block's trie.
//!
//! ```text
//! witness := u8 version=3 | u32 n_anc | [32]*n_anc ancestor roots
//!          | u32 n_tbl | [32]*n_tbl ancestor block ids | node
//! node    := u8 id | u8 path_len | path | u16 n_ptrs | ptr* | child*   (one child per local ptr, in order)
//! ptr     := u8 id | (id != 0: u8 chr) | (backptr: u32 table index)  (empty ptr = 0x00, chr 0)
//! leaf    := u8 1 | u8 path_len | path | [32] value hash
//! ```
//!
//! All integers are big-endian. Counts and table indexes are u32: a busy
//! mainnet block's trie points into more than 65,535 distinct ancestor tries
//! (v2 used u16 and could not encode them). `n_ptrs` (4/16/48/256) and
//! `path_len` (at most 32) stay small. A ptr costs 1 byte (empty), 2 (local)
//! or 6 (backptr), and each distinct ancestor block costs 32 bytes once.
//!
//! Node hashing follows stackslib exactly:
//! `sha512/256(id ‖ (ptr.id ‖ ptr.chr ‖ back_block)* ‖ path ‖ child_hash*)`, where an
//! empty child hashes to zeros and a backptr child contributes its ancestor block id.
//! The root is `sha512/256(node_root ‖ ancestor roots)` (or `node_root` alone).
//!
//! Witness bytes are malleable (e.g. a leaf's own path split is not bound to its
//! parent's chr), so never use them as identifiers: hash the parsed content.

use std::collections::HashMap;

use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stackslib::chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash};
use stackslib::chainstate::stacks::index::node::is_backptr;
use stackslib::chainstate::stacks::index::{MARFValue, ProofTrieNode, ProofTriePtr, TrieLeaf};

pub const VERSION: u8 = 3;

const EMPTY: u8 = 0;
const LEAF: u8 = 1;
const NODE4: u8 = 2;
const NODE16: u8 = 3;
const NODE48: u8 = 4;
const NODE256: u8 = 5;

/// A MARF key path / value hash is 32 bytes; a stored `MARFValue` is 40 with a zero tail.
const PATH_LEN: usize = 32;
const MARF_VALUE_LEN: usize = 40;

/// Number of child pointers a node of type `id` carries.
fn ptr_width(id: u8) -> Option<usize> {
    match id {
        NODE4 => Some(4),
        NODE16 => Some(16),
        NODE48 => Some(48),
        NODE256 => Some(256),
        _ => None,
    }
}

/// One child pointer of an interior node, as the emitter sees it.
pub enum Ptr {
    Empty,
    /// Child in this block's trie; its subtree follows in preorder.
    Local {
        id: u8,
        chr: u8,
    },
    /// Child in an ancestor trie, identified by that trie's block id.
    Back {
        id: u8,
        chr: u8,
        block: [u8; 32],
    },
}

/// Streaming v3 encoder. Feed nodes in preorder, then [`Encoder::finish`].
pub struct Encoder {
    ancestors: Vec<TrieHash>,
    table: Vec<[u8; 32]>,
    table_index: HashMap<[u8; 32], u32>,
    body: Vec<u8>,
}

impl Encoder {
    pub fn new(ancestors: Vec<TrieHash>) -> Self {
        Self {
            ancestors,
            table: vec![],
            table_index: HashMap::new(),
            body: vec![],
        }
    }

    fn path(&mut self, path: &[u8]) -> Result<(), String> {
        let len = u8::try_from(path.len()).map_err(|_| "node path longer than 255 bytes")?;
        self.body.push(len);
        self.body.extend_from_slice(path);
        Ok(())
    }

    pub fn leaf(&mut self, path: &[u8], value: &[u8]) -> Result<(), String> {
        if value.len() != MARF_VALUE_LEN || value[PATH_LEN..].iter().any(|b| *b != 0) {
            return Err("leaf value is not a 32-byte hash with a zero tail".into());
        }
        self.body.push(LEAF);
        self.path(path)?;
        self.body.extend_from_slice(&value[..PATH_LEN]);
        Ok(())
    }

    pub fn node(&mut self, id: u8, path: &[u8], ptrs: &[Ptr]) -> Result<(), String> {
        if ptr_width(id) != Some(ptrs.len()) {
            return Err(format!("node id {id} with {} ptrs", ptrs.len()));
        }
        self.body.push(id);
        self.path(path)?;
        self.body
            .extend_from_slice(&(ptrs.len() as u16).to_be_bytes());
        for p in ptrs {
            match p {
                Ptr::Empty => self.body.push(EMPTY),
                Ptr::Local { id, chr } => self.body.extend_from_slice(&[*id, *chr]),
                Ptr::Back { id, chr, block } => {
                    let idx = match self.table_index.get(block) {
                        Some(i) => *i,
                        None => {
                            let i = u32::try_from(self.table.len())
                                .map_err(|_| "more than 2^32-1 ancestor blocks")?;
                            self.table.push(*block);
                            self.table_index.insert(*block, i);
                            i
                        }
                    };
                    self.body.extend_from_slice(&[*id, *chr]);
                    self.body.extend_from_slice(&idx.to_be_bytes());
                }
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, String> {
        let n_anc = u32::try_from(self.ancestors.len()).map_err(|_| "too many ancestor roots")?;
        let n_tbl = u32::try_from(self.table.len()).map_err(|_| "too many ancestor blocks")?;
        let mut out = Vec::with_capacity(
            9 + 32 * (self.ancestors.len() + self.table.len()) + self.body.len(),
        );
        out.push(VERSION);
        out.extend_from_slice(&n_anc.to_be_bytes());
        for a in &self.ancestors {
            out.extend_from_slice(a.as_bytes());
        }
        out.extend_from_slice(&n_tbl.to_be_bytes());
        for b in &self.table {
            out.extend_from_slice(b);
        }
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

/// A leaf of the block's trie: full key path and value hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub path: [u8; 32],
    pub value_hash: [u8; 32],
}

/// The result of verifying a witness.
#[derive(Debug)]
pub struct Verified {
    pub root: TrieHash,
    pub leaves: Vec<Leaf>,
    pub nodes: usize,
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .i
            .checked_add(n)
            .filter(|e| *e <= self.b.len())
            .ok_or_else(|| format!("truncated witness at byte {}", self.i))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn hash(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }
}

struct Verifier<'a> {
    r: Reader<'a>,
    table: Vec<[u8; 32]>,
    leaves: Vec<Leaf>,
    nodes: usize,
}

impl Verifier<'_> {
    /// Parse one node (and its local subtree) at key prefix `prefix`; return (id, hash).
    fn node(&mut self, prefix: &mut Vec<u8>) -> Result<(u8, TrieHash), String> {
        self.nodes += 1;
        let at = self.r.i;
        let id = self.r.u8()?;
        let plen = self.r.u8()? as usize;
        let path = self.r.take(plen)?.to_vec();
        let depth = prefix.len() + plen;

        if id == LEAF {
            if depth != PATH_LEN {
                return Err(format!("leaf at byte {at} has a {depth}-byte key path"));
            }
            let mut value = [0u8; MARF_VALUE_LEN];
            value[..PATH_LEN].copy_from_slice(self.r.take(PATH_LEN)?);
            let mut full = [0u8; PATH_LEN];
            full[..prefix.len()].copy_from_slice(prefix);
            full[prefix.len()..].copy_from_slice(&path);
            self.leaves.push(Leaf {
                path: full,
                value_hash: value[..PATH_LEN].try_into().expect("32 bytes"),
            });
            let hash = get_leaf_hash(&TrieLeaf {
                path,
                data: MARFValue(value),
            });
            return Ok((LEAF, hash));
        }

        let width = ptr_width(id).ok_or_else(|| format!("bad node id {id} at byte {at}"))?;
        if depth >= PATH_LEN {
            return Err(format!(
                "interior node at byte {at} has no room for children"
            ));
        }
        if self.r.u16()? as usize != width {
            return Err(format!(
                "node at byte {at}: ptr count does not match id {id}"
            ));
        }

        let mut ptrs = Vec::with_capacity(width);
        for _ in 0..width {
            let pid = self.r.u8()?;
            if pid == EMPTY {
                ptrs.push(ProofTriePtr {
                    id: EMPTY,
                    chr: 0,
                    back_block: StacksBlockId([0u8; 32]),
                });
                continue;
            }
            let base = pid & 0x7f;
            if !(LEAF..=NODE256).contains(&base) {
                return Err(format!("bad ptr id {pid} in node at byte {at}"));
            }
            let chr = self.r.u8()?;
            let back_block = if is_backptr(pid) {
                let idx = self.r.u32()? as usize;
                *self
                    .table
                    .get(idx)
                    .ok_or_else(|| format!("block table index {idx} out of range"))?
            } else {
                [0u8; 32]
            };
            ptrs.push(ProofTriePtr {
                id: pid,
                chr,
                back_block: StacksBlockId(back_block),
            });
        }

        let mut child_hashes = Vec::with_capacity(width);
        for p in &ptrs {
            child_hashes.push(if p.id == EMPTY {
                TrieHash::EMPTY
            } else if is_backptr(p.id) {
                TrieHash(p.back_block.0)
            } else {
                prefix.extend_from_slice(&path);
                prefix.push(p.chr);
                let (child_id, h) = self.node(prefix)?;
                prefix.truncate(depth - plen);
                if child_id != p.id {
                    return Err(format!(
                        "node at byte {at}: ptr id {} but child id {child_id}",
                        p.id
                    ));
                }
                h
            });
        }
        let hash = get_node_hash(&ProofTrieNode { id, path, ptrs }, &child_hashes, &mut ());
        Ok((id, hash))
    }
}

/// Recompute the trie root from witness bytes alone and enumerate its leaves.
pub fn verify(witness: &[u8]) -> Result<Verified, String> {
    let mut r = Reader { b: witness, i: 0 };
    let version = r.u8()?;
    if version != VERSION {
        return Err(format!("unsupported witness version {version}"));
    }
    let n_anc = r.u32()? as usize;
    let ancestors = (0..n_anc)
        .map(|_| r.hash().map(TrieHash))
        .collect::<Result<Vec<_>, _>>()?;
    let n_tbl = r.u32()? as usize;
    let table = (0..n_tbl)
        .map(|_| r.hash())
        .collect::<Result<Vec<_>, _>>()?;

    let mut v = Verifier {
        r,
        table,
        leaves: vec![],
        nodes: 0,
    };
    let (root_id, node_root) = v.node(&mut vec![])?;
    if root_id != NODE256 {
        return Err(format!("trie root is node id {root_id}, expected Node256"));
    }
    if v.r.i != witness.len() {
        return Err(format!("{} trailing bytes", witness.len() - v.r.i));
    }

    let root = if ancestors.is_empty() {
        node_root
    } else {
        let mut all = Vec::with_capacity(ancestors.len() + 1);
        all.push(node_root);
        all.extend(ancestors);
        TrieHash::from_data_array(&all)
    };
    Ok(Verified {
        root,
        leaves: v.leaves,
        nodes: v.nodes,
    })
}
