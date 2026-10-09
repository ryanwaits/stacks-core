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

//! Shared MARF proofs: one proof for many key reads, at many roots.
//!
//! A MARF read walks the key's path from a block's trie root. At a
//! back-pointer it restarts at the root of the ancestor trie the pointer
//! names, and it ends at a leaf (present: the leaf's value) or where the path
//! cannot continue (absent): an interior node with no child at the next path
//! byte, or a node or leaf whose compressed path differs from the key's.
//!
//! A shared proof is the union of every node all those walks touched, per
//! trie, with each child the walks did not enter replaced by its hash. Each
//! trie also carries its skip-list (the root hashes of its ancestors at
//! distances 1, 2, 4, ...), so its full root hash
//! `sha512/256(root node hash ‖ ancestor roots)` can be recomputed. The
//! verifier recomputes every trie's root from the proof bytes alone and
//! requires it to equal the `state_index_root` of that trie's block header,
//! then answers each read by walking the proof exactly as the MARF walks.
//!
//! A back-pointer child hashes as the id of the block it points into, so a
//! node pins which trie the walk continues in, and that trie's content is
//! pinned by the block's header. Unlike per-read proofs, no shunt proofs
//! (skip-list hash chains from a trie back to each ancestor it points into)
//! are needed: the client authenticates every crossed trie's root by its
//! header instead. Size and proving work scale with the distinct nodes and
//! tries the reads touch, not with reads times path length.
//!
//! Wire format (big-endian):
//!
//! ```text
//! proof := u8 version=1
//!        | u32 n_blocks | [32]*n_blocks   block ids (tries, back-pointer targets)
//!        | u32 n_hashes | [32]*n_hashes   ancestor root hashes, deduplicated
//!        | u32 n_tries  | trie*
//! trie  := u32 block index | u8 n_anc | u32*n_anc hash index | node   (root: Node256)
//! node  := u8 id | u8 path_len | path
//!          | leaf (id 1): [40] value
//!          | interior (id 2/3/4/5): ptr*(4/16/48/256) | child*   (one per expanded ptr, in order)
//! ptr   := u8 tag | (tag != 0: u8 chr) | (back-pointer: u32 block index) | (pruned: [32] hash)
//! ```
//!
//! A ptr tag is 0 (empty), or a node id (1..=5) plus at most one flag: 0x80
//! back-pointer, 0x40 pruned (a local child no walk entered, given by its
//! hash). Without a flag, the child is expanded and follows in preorder.
//!
//! The verifier is strict: the bytes must parse exactly, every block and
//! ancestor hash in the tables must be used, every trie must hash to its
//! header's root, and after all reads [`Multiproof::unvisited`] must be zero
//! (a node no read reaches is an extra node). A read that needs a pruned or
//! missing node fails.
//!
//! The MARF has no deletions (a Clarity `map-delete` writes a value that
//! decodes to none), so "absent" means "never written on this fork".

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    Error, MARFValue, MarfTrieId, ProofTrieNode, ProofTriePtr, TrieLeaf,
};

pub const MULTIPROOF_VERSION: u8 = 1;

const EMPTY: u8 = TrieNodeID::Empty as u8;
const LEAF: u8 = TrieNodeID::Leaf as u8;
const NODE256: u8 = TrieNodeID::Node256 as u8;
const BACKPTR: u8 = 0x80;
const PRUNED: u8 = 0x40;
/// A MARF key path is 32 bytes; a leaf value is a 40-byte `MARFValue`.
const PATH_LEN: usize = 32;
const VALUE_LEN: usize = 40;
/// A walk restarts at an ancestor's root at most once per path byte.
const MAX_HOPS: usize = PATH_LEN + 1;

fn ptr_count(id: u8) -> Option<usize> {
    match TrieNodeID::from_u8(id)? {
        TrieNodeID::Node4 => Some(4),
        TrieNodeID::Node16 => Some(16),
        TrieNodeID::Node48 => Some(48),
        TrieNodeID::Node256 => Some(256),
        _ => None,
    }
}

/// Where a key's walk ended.
#[derive(Debug, Clone, PartialEq)]
pub struct WalkEnd<T> {
    /// The leaf's value, or `None`: the key is absent.
    pub value: Option<MARFValue>,
    /// The trie the walk ended in (for a present key, the block that last
    /// wrote it, or a block that carried its leaf).
    pub trie: T,
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Collects the walks of many reads, then encodes them as one proof.
pub struct MultiproofBuilder<T: MarfTrieId> {
    /// Tries in the order walks first reached them, with the storage offsets
    /// of their nodes the walks touched.
    tries: Vec<(T, HashSet<u64>)>,
    index: HashMap<T, usize>,
}

impl<T: MarfTrieId> Default for MultiproofBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: MarfTrieId> MultiproofBuilder<T> {
    pub fn new() -> Self {
        MultiproofBuilder {
            tries: vec![],
            index: HashMap::new(),
        }
    }

    /// Blocks whose tries the proof holds: the client needs their headers.
    pub fn tries(&self) -> impl Iterator<Item = &T> {
        self.tries.iter().map(|(block, _)| block)
    }

    pub fn is_empty(&self) -> bool {
        self.tries.is_empty()
    }

    fn touch(&mut self, block: &T, ptr: u64) {
        let i = match self.index.get(block) {
            Some(i) => *i,
            None => {
                self.tries.push((block.clone(), HashSet::new()));
                self.index.insert(block.clone(), self.tries.len() - 1);
                self.tries.len() - 1
            }
        };
        self.tries[i].1.insert(ptr);
    }

    /// Walk `path` from `root`'s trie as the MARF does, recording every node
    /// touched, and return where the walk ended.
    pub fn walk(
        &mut self,
        storage: &mut TrieStorageConnection<T>,
        root: &T,
        path: &TrieHash,
    ) -> Result<WalkEnd<T>, Error> {
        if storage.is_squashed() {
            return Err(Error::UnsupportedOnSquashedMarf("MultiproofBuilder::walk"));
        }
        let path = path.as_bytes();
        let mut block = root.clone();
        'tries: for _ in 0..MAX_HOPS {
            storage.open_block(&block)?;
            let mut ptr = storage.root_trieptr();
            let (mut node, _) = storage.read_nodetype(&ptr)?;
            let mut depth = 0;
            loop {
                self.touch(&block, ptr.ptr());
                let rest = path.get(depth..).unwrap_or_default();
                if let TrieNodeType::Leaf(leaf) = &node {
                    let value = (leaf.path.as_slice() == rest).then(|| leaf.data.clone());
                    return Ok(WalkEnd { value, trie: block });
                }
                let node_path = node.path_bytes();
                if !rest.starts_with(node_path) {
                    return Ok(WalkEnd {
                        value: None,
                        trie: block,
                    });
                }
                depth += node_path.len();
                let chr = *path.get(depth).ok_or_else(|| {
                    Error::CorruptionError(format!("interior node at depth {depth} in {block}"))
                })?;
                let Some(child) = node.walk(chr) else {
                    return Ok(WalkEnd {
                        value: None,
                        trie: block,
                    });
                };
                if is_backptr(child.id()) {
                    block = storage.get_block_from_local_id(child.back_block())?.clone();
                    continue 'tries;
                }
                depth += 1;
                let (next, _) = storage.read_nodetype(&child)?;
                node = next;
                ptr = child;
            }
        }
        Err(Error::CorruptionError(format!(
            "walk of {} crossed more than {MAX_HOPS} tries",
            TrieHash(*path)
        )))
    }

    /// Encode every walk so far as one proof.
    pub fn encode(&self, storage: &mut TrieStorageConnection<T>) -> Result<Vec<u8>, Error> {
        let mut enc = Encoder::default();
        for (block, touched) in self.tries.iter() {
            storage.open_block(block)?;
            let ancestors = Trie::get_trie_ancestor_hashes_bytes(storage)?;
            let block_index = enc.block(block.as_bytes());
            enc.u32(block_index);
            let n_anc = u8::try_from(ancestors.len())
                .map_err(|_| Error::CorruptionError("more than 255 ancestor roots".into()))?;
            enc.body.push(n_anc);
            for hash in ancestors.iter() {
                let i = enc.hash(hash);
                enc.u32(i);
            }
            let root = storage.root_trieptr();
            enc.node(storage, &root, touched)?;
        }
        enc.finish(self.tries.len())
    }
}

#[derive(Default)]
struct Encoder {
    blocks: Vec<[u8; 32]>,
    block_index: HashMap<[u8; 32], u32>,
    hashes: Vec<TrieHash>,
    hash_index: HashMap<TrieHash, u32>,
    body: Vec<u8>,
}

impl Encoder {
    fn u32(&mut self, n: u32) {
        self.body.extend_from_slice(&n.to_be_bytes());
    }

    fn block(&mut self, id: &[u8]) -> u32 {
        let id: [u8; 32] = id.try_into().expect("block ids are 32 bytes");
        if let Some(i) = self.block_index.get(&id) {
            return *i;
        }
        let i = self.blocks.len() as u32;
        self.blocks.push(id);
        self.block_index.insert(id, i);
        i
    }

    fn hash(&mut self, hash: &TrieHash) -> u32 {
        if let Some(i) = self.hash_index.get(hash) {
            return *i;
        }
        let i = self.hashes.len() as u32;
        self.hashes.push(*hash);
        self.hash_index.insert(*hash, i);
        i
    }

    fn node<T: MarfTrieId>(
        &mut self,
        storage: &mut TrieStorageConnection<T>,
        ptr: &TriePtr,
        touched: &HashSet<u64>,
    ) -> Result<(), Error> {
        let (node, _) = storage.read_nodetype(ptr)?;
        self.body.push(clear_backptr(node.id()));
        let path = node.path_bytes();
        let path_len = u8::try_from(path.len())
            .map_err(|_| Error::CorruptionError("node path longer than 255 bytes".into()))?;
        self.body.push(path_len);
        self.body.extend_from_slice(path);
        if let TrieNodeType::Leaf(leaf) = &node {
            self.body.extend_from_slice(&leaf.data.0);
            return Ok(());
        }
        let mut expanded = vec![];
        for child in node.ptrs() {
            if child.id() == EMPTY {
                if child.chr() != 0 {
                    return Err(Error::CorruptionError("empty pointer with a chr".into()));
                }
                self.body.push(EMPTY);
                continue;
            }
            let base = clear_backptr(child.id());
            if !(LEAF..=NODE256).contains(&base) {
                return Err(Error::CorruptionError(format!(
                    "bad pointer id {}",
                    child.id()
                )));
            }
            if is_backptr(child.id()) {
                let back = storage.get_block_from_local_id(child.back_block())?.clone();
                let i = self.block(back.as_bytes());
                self.body.extend_from_slice(&[base | BACKPTR, child.chr()]);
                self.u32(i);
            } else if touched.contains(&child.ptr()) {
                self.body.extend_from_slice(&[base, child.chr()]);
                expanded.push(*child);
            } else {
                let hash = storage.read_node_hash_bytes(child)?;
                self.body.extend_from_slice(&[base | PRUNED, child.chr()]);
                self.body.extend_from_slice(hash.as_bytes());
            }
        }
        for child in expanded.iter() {
            self.node(storage, child, touched)?;
        }
        Ok(())
    }

    fn finish(self, n_tries: usize) -> Result<Vec<u8>, Error> {
        let count = |n: usize| {
            u32::try_from(n).map_err(|_| Error::CorruptionError("table too large".into()))
        };
        let mut out =
            Vec::with_capacity(13 + 32 * (self.blocks.len() + self.hashes.len()) + self.body.len());
        out.push(MULTIPROOF_VERSION);
        out.extend_from_slice(&count(self.blocks.len())?.to_be_bytes());
        for block in self.blocks.iter() {
            out.extend_from_slice(block);
        }
        out.extend_from_slice(&count(self.hashes.len())?.to_be_bytes());
        for hash in self.hashes.iter() {
            out.extend_from_slice(hash.as_bytes());
        }
        out.extend_from_slice(&count(n_tries)?.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

enum Child<T> {
    Local(usize),
    Pruned,
    Back(T),
}

struct Node<T> {
    /// Set for a leaf.
    value: Option<MARFValue>,
    path: Vec<u8>,
    /// Non-empty children by path byte.
    children: Vec<(u8, Child<T>)>,
}

struct TrieEntry {
    root: usize,
    /// `sha512/256(root node hash ‖ ancestor roots)`, recomputed.
    hash: TrieHash,
    /// Why reads may not use this trie (it does not hash to its header root).
    rejected: Option<String>,
}

/// A decoded shared proof. Every trie's root hash is recomputed from the
/// bytes; [`Multiproof::check_roots`] pins them to block headers.
pub struct Multiproof<T: MarfTrieId> {
    nodes: Vec<Node<T>>,
    visited: Vec<Cell<bool>>,
    tries: HashMap<T, TrieEntry>,
    bytes: usize,
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
            .filter(|end| *end <= self.b.len())
            .ok_or_else(|| format!("truncated at byte {}", self.i))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// A count whose entries take at least `min_size` bytes each.
    fn count(&mut self, min_size: usize) -> Result<usize, String> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_size) > self.b.len() - self.i {
            return Err(format!(
                "count {n} at byte {} overruns the proof",
                self.i - 4
            ));
        }
        Ok(n)
    }
}

struct Decoder<'a, T> {
    r: Reader<'a>,
    blocks: Vec<T>,
    blocks_used: Vec<bool>,
    nodes: Vec<Node<T>>,
}

impl<T: MarfTrieId> Decoder<'_, T> {
    fn block(&mut self, index: u32) -> Result<T, String> {
        let i = index as usize;
        let block = self
            .blocks
            .get(i)
            .ok_or_else(|| format!("block index {i} out of range"))?
            .clone();
        self.blocks_used[i] = true;
        Ok(block)
    }

    /// Parse one node and its expanded subtree at key depth `depth`; return
    /// its node index, id and hash.
    fn node(&mut self, depth: usize) -> Result<(usize, u8, TrieHash), String> {
        let at = self.r.i;
        let id = self.r.u8()?;
        let path_len = self.r.u8()? as usize;
        let path = self.r.take(path_len)?.to_vec();
        let end = depth + path_len;

        if id == LEAF {
            if end != PATH_LEN {
                return Err(format!("leaf at byte {at} ends at key byte {end}"));
            }
            let value = MARFValue(self.r.take(VALUE_LEN)?.try_into().expect("40 bytes"));
            let hash = get_leaf_hash(&TrieLeaf {
                path: path.clone(),
                data: value.clone(),
            });
            self.nodes.push(Node {
                value: Some(value),
                path,
                children: vec![],
            });
            return Ok((self.nodes.len() - 1, id, hash));
        }

        let width = ptr_count(id).ok_or_else(|| format!("bad node id {id} at byte {at}"))?;
        if end >= PATH_LEN {
            return Err(format!(
                "interior node at byte {at} has no room for children"
            ));
        }
        let mut ptrs = Vec::with_capacity(width);
        let mut kinds = Vec::with_capacity(width);
        for _ in 0..width {
            let tag = self.r.u8()?;
            if tag == EMPTY {
                ptrs.push(ProofTriePtr {
                    id: EMPTY,
                    chr: 0,
                    back_block: T::from_bytes([0; 32]),
                });
                kinds.push(None);
                continue;
            }
            let base = tag & !(BACKPTR | PRUNED);
            if !(LEAF..=NODE256).contains(&base) || tag & BACKPTR != 0 && tag & PRUNED != 0 {
                return Err(format!("bad pointer tag {tag:#04x} in node at byte {at}"));
            }
            let chr = self.r.u8()?;
            let (ptr_id, back_block, kind) = if tag & BACKPTR != 0 {
                let index = self.r.u32()?;
                let block = self.block(index)?;
                (base | BACKPTR, block.clone(), Some(Kind::Back(block)))
            } else if tag & PRUNED != 0 {
                let hash = TrieHash(self.r.bytes32()?);
                (base, T::from_bytes([0; 32]), Some(Kind::Pruned(hash)))
            } else {
                (base, T::from_bytes([0; 32]), Some(Kind::Local))
            };
            ptrs.push(ProofTriePtr {
                id: ptr_id,
                chr,
                back_block,
            });
            kinds.push(kind);
        }

        let mut child_hashes = Vec::with_capacity(width);
        let mut children: Vec<(u8, Child<T>)> = vec![];
        for (ptr, kind) in ptrs.iter().zip(kinds.into_iter()) {
            let hash = match kind {
                None => TrieHash::EMPTY,
                Some(Kind::Back(block)) => {
                    let hash = TrieHash(block.clone().to_bytes());
                    children.push((ptr.chr, Child::Back(block)));
                    hash
                }
                Some(Kind::Pruned(hash)) => {
                    children.push((ptr.chr, Child::Pruned));
                    hash
                }
                Some(Kind::Local) => {
                    let (index, child_id, hash) = self.node(end + 1)?;
                    if child_id != ptr.id {
                        return Err(format!(
                            "node at byte {at}: pointer id {} but child id {child_id}",
                            ptr.id
                        ));
                    }
                    children.push((ptr.chr, Child::Local(index)));
                    hash
                }
            };
            child_hashes.push(hash);
        }
        let mut chrs: Vec<u8> = children.iter().map(|(chr, _)| *chr).collect();
        chrs.sort_unstable();
        if chrs.windows(2).any(|w| w[0] == w[1]) {
            return Err(format!(
                "node at byte {at} has two children at one path byte"
            ));
        }
        let hash = get_node_hash(
            &ProofTrieNode {
                id,
                path: path.clone(),
                ptrs,
            },
            &child_hashes,
            &mut (),
        );
        self.nodes.push(Node {
            value: None,
            path,
            children,
        });
        Ok((self.nodes.len() - 1, id, hash))
    }
}

enum Kind<T> {
    Local,
    Pruned(TrieHash),
    Back(T),
}

impl<T: MarfTrieId> Multiproof<T> {
    /// Parse `bytes` and recompute every trie's root hash. Structural errors
    /// (bad encoding, unused table entries, trailing bytes) fail the whole
    /// proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader { b: bytes, i: 0 };
        let version = r.u8()?;
        if version != MULTIPROOF_VERSION {
            return Err(format!("multiproof version {version}"));
        }
        let n_blocks = r.count(32)?;
        let blocks = (0..n_blocks)
            .map(|_| r.bytes32().map(T::from_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let n_hashes = r.count(32)?;
        let hashes = (0..n_hashes)
            .map(|_| r.bytes32().map(TrieHash))
            .collect::<Result<Vec<_>, _>>()?;
        let mut hashes_used = vec![false; hashes.len()];
        let n_tries = r.count(5)?;

        let mut d = Decoder {
            r,
            blocks_used: vec![false; blocks.len()],
            blocks,
            nodes: vec![],
        };
        let mut tries = HashMap::new();
        for _ in 0..n_tries {
            let index = d.r.u32()?;
            let block = d.block(index)?;
            let n_anc = d.r.u8()? as usize;
            let mut ancestors = Vec::with_capacity(n_anc);
            for _ in 0..n_anc {
                let i = d.r.u32()? as usize;
                let hash = hashes
                    .get(i)
                    .ok_or_else(|| format!("hash index {i} out of range"))?;
                hashes_used[i] = true;
                ancestors.push(*hash);
            }
            let (root, id, node_hash) = d.node(0)?;
            if id != NODE256 {
                return Err(format!("trie of {block} has root node id {id}"));
            }
            let hash = if ancestors.is_empty() {
                node_hash
            } else {
                let mut all = Vec::with_capacity(ancestors.len() + 1);
                all.push(node_hash);
                all.extend(ancestors);
                TrieHash::from_data_array(&all)
            };
            let entry = TrieEntry {
                root,
                hash,
                rejected: None,
            };
            if tries.insert(block.clone(), entry).is_some() {
                return Err(format!("two tries for {block}"));
            }
        }
        if d.r.i != bytes.len() {
            return Err(format!("{} trailing bytes", bytes.len() - d.r.i));
        }
        if let Some(i) = d.blocks_used.iter().position(|used| !used) {
            return Err(format!("block {} is never used", d.blocks[i]));
        }
        if let Some(i) = hashes_used.iter().position(|used| !used) {
            return Err(format!("ancestor hash {} is never used", hashes[i]));
        }
        let visited = (0..d.nodes.len()).map(|_| Cell::new(false)).collect();
        Ok(Multiproof {
            nodes: d.nodes,
            visited,
            tries,
            bytes: bytes.len(),
        })
    }

    /// Pin every trie to its block's root (`root_of`, from authenticated
    /// headers). A trie that does not match is kept, but every read that
    /// reaches it fails with the reason.
    pub fn check_roots(&mut self, root_of: impl Fn(&T) -> Option<TrieHash>) {
        for (block, entry) in self.tries.iter_mut() {
            entry.rejected = match root_of(block) {
                None => Some(format!("no header for block {block}")),
                Some(root) if root != entry.hash => Some(format!(
                    "the trie of block {block} does not hash to its header's root"
                )),
                Some(_) => None,
            };
        }
    }

    /// [`Multiproof::decode`] then [`Multiproof::check_roots`].
    pub fn open(bytes: &[u8], root_of: impl Fn(&T) -> Option<TrieHash>) -> Result<Self, String> {
        let mut proof = Self::decode(bytes)?;
        proof.check_roots(root_of);
        Ok(proof)
    }

    /// The value of `path` at `root`'s trie (`None`: absent), read by walking
    /// the proof. Fails if the walk needs a node the proof left out, or a
    /// trie that does not hash to its header's root.
    pub fn get(&self, root: &T, path: &TrieHash) -> Result<WalkEnd<T>, String> {
        let path = path.as_bytes();
        let mut block = root.clone();
        'tries: for _ in 0..MAX_HOPS {
            let entry = self
                .tries
                .get(&block)
                .ok_or_else(|| format!("the proof has no trie for block {block}"))?;
            if let Some(reason) = &entry.rejected {
                return Err(reason.clone());
            }
            let mut index = entry.root;
            let mut depth = 0;
            loop {
                self.visited[index].set(true);
                let node = &self.nodes[index];
                let rest = path.get(depth..).unwrap_or_default();
                if let Some(value) = &node.value {
                    let value = (node.path.as_slice() == rest).then(|| value.clone());
                    return Ok(WalkEnd { value, trie: block });
                }
                if !rest.starts_with(&node.path) {
                    return Ok(WalkEnd {
                        value: None,
                        trie: block,
                    });
                }
                depth += node.path.len();
                let chr = path[depth];
                match node.children.iter().find(|(c, _)| *c == chr) {
                    None => {
                        return Ok(WalkEnd {
                            value: None,
                            trie: block,
                        })
                    }
                    Some((_, Child::Local(child))) => {
                        index = *child;
                        depth += 1;
                    }
                    Some((_, Child::Pruned)) => {
                        return Err(format!(
                            "the proof does not cover {} in the trie of block {block}",
                            TrieHash(*path)
                        ))
                    }
                    Some((_, Child::Back(ancestor))) => {
                        block = ancestor.clone();
                        continue 'tries;
                    }
                }
            }
        }
        Err(format!("walk crossed more than {MAX_HOPS} tries"))
    }

    /// Nodes no read has reached so far. After every read the proof is for,
    /// a strict verifier requires zero.
    pub fn unvisited(&self) -> usize {
        self.visited.iter().filter(|v| !v.get()).count()
    }

    pub fn tries(&self) -> usize {
        self.tries.len()
    }

    pub fn nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn byte_len(&self) -> usize {
        self.bytes
    }
}
