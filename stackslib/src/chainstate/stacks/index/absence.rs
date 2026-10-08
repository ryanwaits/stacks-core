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

//! Non-membership (absence) proofs for the MARF.
//!
//! A MARF read walks the key's path from the tip trie's root, following
//! back-pointers into ancestor tries, until it reaches a leaf. The key is
//! absent when the walk stops early:
//!
//! * an intermediate node has no child (not even a back-pointer) at the next
//!   path byte, or
//! * a node's compressed path, or a leaf's remaining path, differs from the
//!   key's.
//!
//! An absence proof is that walk. It has the same shape as an inclusion proof
//! ([`TrieMerkleProof`]): one segment proof per trie visited, oldest first,
//! each followed by the shunt proof that links that trie's root into the next
//! (newer) trie's skip-list, ending at the tip root. The difference is the
//! deepest node: instead of the leaf holding the value, the proof carries the
//! node where the walk ends, whole, with every child hash, so the verifier can
//! see the missing child or the diverging path for itself.
//!
//! Hashing is the MARF's own: an empty child hashes as `TrieHash::EMPTY`, a
//! back-pointer child as the ancestor block's id, and a trie root as the hash
//! of its root node plus its ancestors' roots (the skip-list).
//!
//! The MARF has no deletions (a Clarity `map-delete` writes a value that
//! decodes to none), so "absent" means "never written on this fork".

use std::collections::HashMap;

use stacks_common::types::chainstate::TrieHash;

use crate::chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash};
use crate::chainstate::stacks::index::node::{
    is_backptr, CursorError, TrieCursor, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    Error, MarfTrieId, ProofTrieNode, TrieLeaf, TrieMerkleProof, TrieMerkleProofType,
};

/// The node where a key's walk ends, in the oldest trie the walk reaches.
#[derive(Clone, Debug, PartialEq)]
pub enum AbsenceEnd<T: MarfTrieId> {
    /// A leaf whose remaining path differs from the key's.
    Leaf(TrieLeaf),
    /// An intermediate node whose compressed path differs from the key's, or
    /// which has no child at the key's next byte. `hashes` has one entry per
    /// child pointer.
    Node {
        node: ProofTrieNode<T>,
        hashes: Vec<TrieHash>,
    },
}

/// Proof that a path has no leaf in the MARF as seen from one block.
#[derive(Clone, Debug, PartialEq)]
pub struct TrieAbsenceProof<T: MarfTrieId> {
    pub end: AbsenceEnd<T>,
    /// The rest of the walk, in inclusion-proof order: the end node's
    /// ancestors in its trie (deepest first), a shunt proof, then each newer
    /// trie's segment and shunt proof, ending at the tip.
    pub proof: Vec<TrieMerkleProofType<T>>,
}

/// Where a walk within one trie stopped.
enum TrieWalk<T: MarfTrieId> {
    /// Reached a leaf holding the path: the key is present.
    Found,
    /// Stopped at the cursor's last node: the key is absent.
    Ended(TrieCursor<T>),
    /// Reached a back-pointer: the walk continues in an ancestor trie.
    Backptr(TrieCursor<T>, TriePtr),
}

fn walk_trie<T: MarfTrieId>(
    storage: &mut TrieStorageConnection<T>,
    path: &TrieHash,
) -> Result<TrieWalk<T>, Error> {
    let (mut node, _) = Trie::read_root(storage)?;
    let mut cursor = TrieCursor::new(path, storage.root_trieptr());
    for _ in 0..(cursor.path.len() + 1) {
        match Trie::walk_from(storage, &node, &mut cursor) {
            Ok(Some((_, next_node, _))) => node = next_node,
            Ok(None) => return Ok(TrieWalk::Found),
            Err(Error::CursorError(CursorError::PathDiverged))
            | Err(Error::CursorError(CursorError::ChrNotFound)) => {
                return Ok(TrieWalk::Ended(cursor))
            }
            Err(Error::CursorError(CursorError::BackptrEncountered(ptr))) => {
                if !is_backptr(ptr.id()) {
                    return Err(Error::CorruptionError(format!(
                        "Failed to walk 0x{:02x} -- got non-backptr",
                        ptr.chr()
                    )));
                }
                return Ok(TrieWalk::Backptr(cursor, ptr));
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::CorruptionError("Trie has a cycle".to_string()))
}

fn child_count(id: u8) -> Option<usize> {
    match TrieNodeID::from_u8(id)? {
        TrieNodeID::Node4 => Some(4),
        TrieNodeID::Node16 => Some(16),
        TrieNodeID::Node48 => Some(48),
        TrieNodeID::Node256 => Some(256),
        _ => None,
    }
}

impl<T: MarfTrieId> TrieAbsenceProof<T> {
    /// Prove that `path` has no leaf in the MARF at `root_block`. Errors with
    /// `NotFoundError` if it has one.
    pub fn from_path(
        storage: &mut TrieStorageConnection<T>,
        path: &TrieHash,
        root_block: &T,
    ) -> Result<TrieAbsenceProof<T>, Error> {
        if storage.is_squashed() {
            return Err(Error::UnsupportedOnSquashedMarf(
                "TrieAbsenceProof::from_path",
            ));
        }

        // newest trie first; reversed at the end
        let mut segments = vec![];
        let mut shunts = vec![];
        let mut block = root_block.clone();
        let end = loop {
            storage.open_block(&block)?;
            match walk_trie(storage, path)? {
                TrieWalk::Found => return Err(Error::NotFoundError),
                TrieWalk::Backptr(cursor, backptr) => {
                    let chr = cursor.chr().ok_or(Error::NotFoundError)?;
                    segments.push(TrieMerkleProof::make_segment_proof(
                        storage,
                        &cursor.node_ptrs,
                        chr,
                    )?);
                    shunts.push(TrieMerkleProof::make_backptr_shunt_proof(
                        storage, &backptr,
                    )?);
                    storage.open_block(&block)?;
                    block = storage
                        .get_block_from_local_id(backptr.back_block())?
                        .clone();
                }
                TrieWalk::Ended(cursor) => {
                    let end_ptr = cursor.ptr();
                    let (node, _) = storage.read_nodetype(&end_ptr)?;
                    let end = match node {
                        TrieNodeType::Leaf(leaf) => AbsenceEnd::Leaf(leaf),
                        ref node => AbsenceEnd::Node {
                            hashes: Trie::get_children_hashes(storage, node)?,
                            node: match node {
                                TrieNodeType::Node4(n) => {
                                    ProofTrieNode::try_from_trie_node(n, storage)?
                                }
                                TrieNodeType::Node16(n) => {
                                    ProofTrieNode::try_from_trie_node(n, storage)?
                                }
                                TrieNodeType::Node48(n) => {
                                    ProofTrieNode::try_from_trie_node(n.as_ref(), storage)?
                                }
                                TrieNodeType::Node256(n) => {
                                    ProofTrieNode::try_from_trie_node(n.as_ref(), storage)?
                                }
                                TrieNodeType::Leaf(_) => unreachable!(),
                            },
                        },
                    };
                    let above = &cursor.node_ptrs[..cursor.node_ptrs.len() - 1];
                    segments.push(if above.is_empty() {
                        vec![]
                    } else {
                        TrieMerkleProof::make_segment_proof(storage, above, end_ptr.chr())?
                    });
                    shunts.push(TrieMerkleProof::make_initial_shunt_proof(storage)?);
                    break end;
                }
            }
        };

        let mut proof = vec![];
        for (segment, shunt) in segments.into_iter().rev().zip(shunts.into_iter().rev()) {
            proof.extend(segment);
            proof.extend(shunt);
        }
        Ok(TrieAbsenceProof { end, proof })
    }

    /// Accept iff the proof is a walk of `path` from the trie whose root is
    /// `root_hash` that ends without a leaf for `path`, every node of it
    /// hashed into that root. `root_to_block` resolves the root hash of every
    /// trie the walk visits to its block id (the hash a back-pointer child
    /// contributes).
    pub fn verify(
        &self,
        path: &TrieHash,
        root_hash: &TrieHash,
        root_to_block: &HashMap<TrieHash, T>,
    ) -> bool {
        let path = path.as_bytes();
        if self
            .proof
            .iter()
            .any(|step| matches!(step, TrieMerkleProofType::Leaf(_)))
        {
            return false;
        }
        let Some(first_shunt) = self
            .proof
            .iter()
            .position(|step| matches!(step, TrieMerkleProofType::Shunt(_)))
        else {
            return false;
        };

        // the bytes the walk consumed above the end node, in its trie
        let Some(walked) =
            TrieMerkleProof::get_segment_proof_path_prefix(&self.proof[..first_shunt])
        else {
            return false;
        };
        if !path.starts_with(&walked) {
            return false;
        }
        let rest = &path[walked.len()..];

        // the end node must show the key cannot continue
        let end_hash = match &self.end {
            AbsenceEnd::Leaf(leaf) => {
                if leaf.path.as_slice() == rest {
                    return false;
                }
                get_leaf_hash(leaf)
            }
            AbsenceEnd::Node { node, hashes } => {
                if child_count(node.id) != Some(node.ptrs.len()) || hashes.len() != node.ptrs.len()
                {
                    return false;
                }
                if rest.starts_with(&node.path) {
                    let Some(next) = rest.get(node.path.len()) else {
                        return false;
                    };
                    if node
                        .ptrs
                        .iter()
                        .any(|ptr| ptr.id != TrieNodeID::Empty as u8 && ptr.chr == *next)
                    {
                        return false;
                    }
                }
                get_node_hash(node, hashes, &mut ())
            }
        };

        // every newer trie's segment must walk the same path, no deeper than
        // the oldest one did
        let mut i = first_shunt;
        while i < self.proof.len() {
            let segment_start = match self.proof[i..]
                .iter()
                .position(|step| !matches!(step, TrieMerkleProofType::Shunt(_)))
            {
                Some(offset) => i + offset,
                None => break,
            };
            let segment_end = self.proof[segment_start..]
                .iter()
                .position(|step| matches!(step, TrieMerkleProofType::Shunt(_)))
                .map_or(self.proof.len(), |offset| segment_start + offset);
            let Some(prefix) = TrieMerkleProof::get_segment_proof_path_prefix(
                &self.proof[segment_start..segment_end],
            ) else {
                return false;
            };
            if !walked.starts_with(&prefix) {
                return false;
            }
            i = segment_end;
        }

        TrieMerkleProof::verify_proof_chain(&self.proof, end_hash, root_hash, root_to_block)
    }

    /// Encoded size in bytes (consensus encoding of every step).
    pub fn byte_len(&self) -> usize {
        use stacks_common::codec::StacksMessageCodec;
        let mut bytes = vec![];
        for step in self.proof.iter() {
            step.consensus_serialize(&mut bytes)
                .expect("write to memory");
        }
        let end = match &self.end {
            AbsenceEnd::Leaf(leaf) => {
                leaf.consensus_serialize(&mut bytes)
                    .expect("write to memory");
                0
            }
            AbsenceEnd::Node { node, hashes } => {
                node.consensus_serialize(&mut bytes)
                    .expect("write to memory");
                hashes.len() * 32
            }
        };
        bytes.len() + end
    }
}
