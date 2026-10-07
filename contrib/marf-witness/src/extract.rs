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

//! Read-only MARF access and per-block witness extraction.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::to_hex;
use stackslib::chainstate::stacks::index::BlockMap;
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts, MarfConnection};
use stackslib::chainstate::stacks::index::node::{TrieNodeType, TriePtr, is_backptr};
use stackslib::chainstate::stacks::index::storage::{TrieFileStorage, TrieStorageConnection};
use stackslib::chainstate::stacks::index::trie::Trie;

use crate::wire::{self, Encoder, Ptr};

/// A MARF opened strictly read-only.
///
/// * sqlite: `SQLITE_OPEN_READ_ONLY` (via `TrieFileStorage::open_readonly`), which
///   never creates or migrates tables; plus `PRAGMA query_only` so any write
///   statement on the connection fails.
/// * `.blobs` sidecar: opened with `write(false).create(false)`.
pub struct ReadOnlyMarf {
    marf: MARF<StacksBlockId>,
}

impl ReadOnlyMarf {
    pub fn open(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("MARF database not found: {}", path.display()));
        }
        let path_str = path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?;
        let mut opts = MARFOpenOpts::default();
        opts.external_blobs = PathBuf::from(format!("{path_str}.blobs")).exists();

        let storage = TrieFileStorage::<StacksBlockId>::open_readonly(path_str, opts)
            .map_err(|e| format!("open {} read-only: {e:?}", path.display()))?;
        if let Some(info) = storage.squash_info() {
            return Err(format!(
                "{} is a squashed MARF (squash height {}): tries below the squash \
                 height no longer exist per block, so their witnesses cannot be \
                 extracted. Use an unsquashed (archival) chainstate.",
                path.display(),
                info.squash_height
            ));
        }
        storage
            .sqlite_conn()
            .pragma_update(None, "query_only", true)
            .map_err(|e| format!("set query_only: {e}"))?;
        Ok(Self {
            marf: MARF::from_storage(storage),
        })
    }

    pub fn height_of(&mut self, block: &StacksBlockId) -> Result<u32, String> {
        self.marf
            .with_conn(|conn| MARF::get_block_height(conn, block, block))
            .map_err(|e| format!("height of {block}: {e:?}"))?
            .ok_or_else(|| format!("block {block} is not in this MARF"))
    }

    /// The block at `height` on the fork ending at `tip`.
    pub fn block_at(&mut self, height: u32, tip: &StacksBlockId) -> Result<StacksBlockId, String> {
        self.marf
            .with_conn(|conn| MARF::get_block_at_height(conn, height, tip))
            .map_err(|e| format!("block at height {height} from {tip}: {e:?}"))?
            .ok_or_else(|| format!("no block at height {height} on the fork of {tip}"))
    }

    pub fn root_hash_at(&mut self, block: &StacksBlockId) -> Result<TrieHash, String> {
        self.marf
            .get_root_hash_at(block)
            .map_err(|e| format!("root hash of {block}: {e:?}"))
    }

    /// Emit the v2 witness of `block`'s trie.
    pub fn witness(&mut self, block: &StacksBlockId) -> Result<Vec<u8>, String> {
        self.marf.with_conn(|conn| {
            conn.open_block(block)
                .map_err(|e| format!("open trie of {block}: {e:?}"))?;
            let ancestors = Trie::get_trie_ancestor_hashes_bytes(conn)
                .map_err(|e| format!("ancestor roots of {block}: {e:?}"))?;
            let mut enc = Encoder::new(ancestors);
            let root = conn.root_trieptr();
            emit_node(conn, &root, &mut enc)?;
            enc.finish()
        })
    }
}

/// Walk the block-local subtree at `ptr` in preorder.
fn emit_node(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    ptr: &TriePtr,
    enc: &mut Encoder,
) -> Result<(), String> {
    let (node, _) = conn
        .read_nodetype(ptr)
        .map_err(|e| format!("read node {ptr:?}: {e:?}"))?;
    if let TrieNodeType::Leaf(leaf) = &node {
        return enc.leaf(&leaf.path, leaf.data.as_bytes());
    }
    let mut ptrs = Vec::with_capacity(node.ptrs().len());
    for p in node.ptrs() {
        ptrs.push(if p.id() == 0 {
            if p.chr() != 0 {
                return Err(format!("empty ptr with chr {} in {ptr:?}", p.chr()));
            }
            Ptr::Empty
        } else if is_backptr(p.id()) {
            let block = conn
                .get_block_hash_caching(p.back_block())
                .map_err(|e| format!("block id {}: {e:?}", p.back_block()))?;
            Ptr::Back {
                id: p.id(),
                chr: p.chr(),
                block: block.0,
            }
        } else {
            Ptr::Local {
                id: p.id(),
                chr: p.chr(),
            }
        });
    }
    enc.node(node.id(), node.path_bytes(), &ptrs)?;
    for p in node.ptrs() {
        if p.id() != 0 && !is_backptr(p.id()) {
            emit_node(conn, p, enc)?;
        }
    }
    Ok(())
}

/// Sidecar metadata written next to each `<block>.witness`.
#[derive(Debug, Serialize, Deserialize)]
pub struct WitnessMeta {
    pub block: String,
    pub height: u32,
    pub root_hex: String,
    pub leaves: usize,
    pub nodes: usize,
    pub bytes: usize,
}

/// Extract, self-check and write the witness for each block. The recomputed
/// root must equal the MARF's root for that block, or nothing is written for it
/// and extraction stops.
pub fn extract_blocks(
    marf: &mut ReadOnlyMarf,
    blocks: &[StacksBlockId],
    out_dir: &Path,
) -> Result<Vec<WitnessMeta>, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;
    let mut metas = Vec::with_capacity(blocks.len());
    for block in blocks {
        let height = marf.height_of(block)?;
        let expected = marf.root_hash_at(block)?;
        let bytes = marf.witness(block)?;
        let v = wire::verify(&bytes).map_err(|e| format!("witness of {block}: {e}"))?;
        if v.root != expected {
            return Err(format!(
                "witness of {block} recomputes root {} but the MARF root is {expected}",
                v.root
            ));
        }
        let meta = WitnessMeta {
            block: block.to_string(),
            height,
            root_hex: to_hex(expected.as_bytes()),
            leaves: v.leaves.len(),
            nodes: v.nodes,
            bytes: bytes.len(),
        };
        let base = out_dir.join(block.to_string());
        let json = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
        std::fs::write(base.with_extension("witness"), &bytes)
            .and_then(|_| std::fs::write(base.with_extension("json"), json))
            .map_err(|e| format!("write {}: {e}", base.display()))?;
        metas.push(meta);
    }
    Ok(metas)
}

/// `tip` and its ancestors, newest first, at most `count` blocks.
pub fn walk_parents(
    marf: &mut ReadOnlyMarf,
    tip: &StacksBlockId,
    count: u32,
) -> Result<Vec<StacksBlockId>, String> {
    let tip_height = marf.height_of(tip)?;
    (0..count.min(tip_height.saturating_add(1)))
        .map(|k| marf.block_at(tip_height - k, tip))
        .collect()
}
