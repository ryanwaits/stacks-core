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

//! Absence (non-membership) proofs against real MARFs.

use std::collections::HashMap;

use crate::chainstate::stacks::index::absence::{AbsenceEnd, TrieAbsenceProof};
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::{
    ClarityMarfTrieId, Error, MARFValue, TrieMerkleProof, TrieMerkleProofType,
};
use crate::chainstate::stacks::{BlockHeaderHash, TrieHash};

const BLOCKS: u8 = 8;
const KEYS_PER_BLOCK: usize = 40;

fn block(i: u8) -> BlockHeaderHash {
    BlockHeaderHash([i + 1; 32])
}

fn written_key(block: u8, i: usize) -> String {
    format!("written-{block}-{i}")
}

/// A MARF of `BLOCKS` blocks, each writing `KEYS_PER_BLOCK` fresh keys, so
/// later tries reach most paths through back-pointers. [`late_key`] is
/// written only in block `LATE_BLOCK`.
struct Chain {
    marf: MARF<BlockHeaderHash>,
    roots: Vec<TrieHash>,
    root_to_block: HashMap<TrieHash, BlockHeaderHash>,
}

const LATE_BLOCK: u8 = 5;

/// A key whose first path byte block 0 wrote and blocks 1 to `LATE_BLOCK - 1`
/// did not, so before `LATE_BLOCK` its walk leaves the tip trie through a
/// root back-pointer into block 0.
fn late_key() -> String {
    let first_byte = |key: &str| TrieHash::from_key(key).0[0];
    let in_block =
        |b: u8, byte: u8| (0..KEYS_PER_BLOCK).any(|i| first_byte(&written_key(b, i)) == byte);
    (0..)
        .map(|i| format!("written-late-{i}"))
        .find(|key| {
            let byte = first_byte(key);
            in_block(0, byte) && !(1..LATE_BLOCK).any(|b| in_block(b, byte))
        })
        .unwrap()
}

impl Chain {
    fn new() -> Self {
        let mut marf = MARF::from_path(":memory:", MARFOpenOpts::default()).unwrap();
        let mut parent = BlockHeaderHash::sentinel();
        let mut roots = vec![];
        for b in 0..BLOCKS {
            marf.begin(&parent, &block(b)).unwrap();
            for i in 0..KEYS_PER_BLOCK {
                marf.insert(
                    &written_key(b, i),
                    MARFValue::from_value(&format!("v{b}-{i}")),
                )
                .unwrap();
            }
            if b == LATE_BLOCK {
                marf.insert(&late_key(), MARFValue::from_value("late"))
                    .unwrap();
            }
            marf.commit().unwrap();
            roots.push(marf.get_root_hash_at(&block(b)).unwrap());
            parent = block(b);
        }
        let root_to_block = marf
            .borrow_storage_backend()
            .read_root_to_block_table()
            .unwrap();
        Chain {
            marf,
            roots,
            root_to_block,
        }
    }

    fn tip(&self) -> u8 {
        BLOCKS - 1
    }

    fn prove_absent(
        &mut self,
        path: &TrieHash,
        at: u8,
    ) -> Result<TrieAbsenceProof<BlockHeaderHash>, Error> {
        TrieAbsenceProof::from_path(&mut self.marf.borrow_storage_backend(), path, &block(at))
    }

    fn verifies(&self, proof: &TrieAbsenceProof<BlockHeaderHash>, path: &TrieHash, at: u8) -> bool {
        proof.verify(path, &self.roots[at as usize], &self.root_to_block)
    }
}

/// How many tries the proof's walk visited (one segment each).
fn tries_visited(proof: &TrieAbsenceProof<BlockHeaderHash>) -> usize {
    1 + proof
        .proof
        .windows(2)
        .filter(|w| {
            matches!(w[0], TrieMerkleProofType::Shunt(_))
                && !matches!(w[1], TrieMerkleProofType::Shunt(_))
        })
        .count()
}

/// The path of a written key with one byte changed.
fn near_miss(key: &str, byte: usize) -> TrieHash {
    let mut path = TrieHash::from_key(key);
    path.0[byte] ^= 0x01;
    path
}

#[test]
fn absent_paths_verify_and_present_paths_cannot_be_proven_absent() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let (mut leaf_ends, mut node_ends, mut across_backptrs) = (0, 0, 0);
    for i in 0..300 {
        let path = TrieHash::from_key(&format!("never-written-{i}"));
        let proof = chain
            .prove_absent(&path, tip)
            .expect("absent key has a proof");
        assert!(
            chain.verifies(&proof, &path, tip),
            "absence of never-written-{i}"
        );
        match proof.end {
            AbsenceEnd::Leaf(_) => leaf_ends += 1,
            AbsenceEnd::Node { .. } => node_ends += 1,
        }
        if tries_visited(&proof) > 1 {
            across_backptrs += 1;
        }
    }
    assert!(
        leaf_ends > 0 && node_ends > 0,
        "{leaf_ends} leaf / {node_ends} node ends"
    );
    assert!(across_backptrs > 0);

    for b in 0..BLOCKS {
        for i in 0..KEYS_PER_BLOCK {
            let path = TrieHash::from_key(&written_key(b, i));
            assert!(matches!(
                chain.prove_absent(&path, tip),
                Err(Error::NotFoundError)
            ));
        }
    }
}

/// A path that shares all but its last byte with a written key ends at that
/// key's leaf. That proof must not pass as the written key's absence, and
/// neither may the written key's own inclusion proof dressed as one.
#[test]
fn near_miss_of_a_written_leaf_is_absent_but_the_leaf_is_not() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let key = written_key(2, 7);
    let present = TrieHash::from_key(&key);

    for byte in [31, 20, 5, 1] {
        let path = near_miss(&key, byte);
        let proof = chain.prove_absent(&path, tip).expect("near miss is absent");
        assert!(
            chain.verifies(&proof, &path, tip),
            "near miss at byte {byte}"
        );
        assert!(!chain.verifies(&proof, &present, tip));
        if byte == 31 {
            let AbsenceEnd::Leaf(ref leaf) = proof.end else {
                panic!("a last-byte near miss ends at the written leaf");
            };
            assert_eq!(leaf.data, MARFValue::from_value("v2-7"));
        }
    }

    let value = MARFValue::from_value("v2-7");
    let inclusion = TrieMerkleProof::from_path(
        &mut chain.marf.borrow_storage_backend(),
        &present,
        &value,
        &block(tip),
    )
    .unwrap();
    assert!(inclusion.verify(
        &present,
        &value,
        &chain.roots[tip as usize],
        &chain.root_to_block
    ));
    let TrieMerkleProofType::Leaf((_, ref leaf)) = inclusion.0[0] else {
        panic!("inclusion proofs start at the leaf");
    };
    let disguised = TrieAbsenceProof {
        end: AbsenceEnd::Leaf(leaf.clone()),
        proof: inclusion.0[1..].to_vec(),
    };
    assert!(!chain.verifies(&disguised, &present, tip));
}

#[test]
fn tampering_with_any_part_of_an_absence_proof_breaks_it() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let path = (0..)
        .map(|i| TrieHash::from_key(&format!("never-written-{i}")))
        .find(|path| {
            let proof = chain.prove_absent(path, tip).unwrap();
            matches!(proof.end, AbsenceEnd::Node { .. }) && tries_visited(&proof) > 1
        })
        .unwrap();
    let honest = chain.prove_absent(&path, tip).unwrap();
    assert!(chain.verifies(&honest, &path, tip));

    // a sibling hash of the end node
    let mut forged = honest.clone();
    let AbsenceEnd::Node { ref mut hashes, .. } = forged.end else {
        unreachable!()
    };
    let occupied = hashes.iter().position(|h| *h != TrieHash::EMPTY).unwrap();
    hashes[occupied].0[0] ^= 1;
    assert!(!chain.verifies(&forged, &path, tip));

    // the end node's child pointers: drop a child (claim a slot is empty)
    let mut forged = honest.clone();
    let AbsenceEnd::Node { ref mut node, .. } = forged.end else {
        unreachable!()
    };
    let occupied = node.ptrs.iter().position(|p| p.id != 0).unwrap();
    node.ptrs[occupied].id = 0;
    assert!(!chain.verifies(&forged, &path, tip));

    // every segment node and shunt hash along the way
    for step in 0..honest.proof.len() {
        let mut forged = honest.clone();
        match forged.proof[step] {
            TrieMerkleProofType::Node4((_, ref mut n, ref mut h)) => {
                n.path.push(0);
                h[0].0[0] ^= 1;
            }
            TrieMerkleProofType::Node16((_, ref mut n, ref mut h)) => {
                n.path.push(0);
                h[0].0[0] ^= 1;
            }
            TrieMerkleProofType::Node48((_, ref mut n, ref mut h)) => {
                n.path.push(0);
                h[0].0[0] ^= 1;
            }
            TrieMerkleProofType::Node256((_, ref mut n, ref mut h)) => {
                n.path.push(0);
                h[0].0[0] ^= 1;
            }
            TrieMerkleProofType::Shunt((_, ref mut hashes)) => match hashes.first_mut() {
                Some(h) => h.0[0] ^= 1,
                None => continue,
            },
            TrieMerkleProofType::Leaf(_) => unreachable!(),
        }
        assert!(!chain.verifies(&forged, &path, tip), "tampered step {step}");
    }

    // a different root
    assert!(!chain.verifies(&honest, &path, tip - 1));
}

/// "Absent" means never written on this fork: a key written in block 5 is
/// provably absent at block 4 and provably present (not absent) from block 5
/// on, through back-pointers.
#[test]
fn absence_holds_until_the_block_that_writes_the_key() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let path = TrieHash::from_key(&late_key());

    let before = chain.prove_absent(&path, LATE_BLOCK - 1).unwrap();
    assert!(chain.verifies(&before, &path, LATE_BLOCK - 1));
    assert!(tries_visited(&before) > 1, "walk crosses back-pointers");
    // the old absence proof does not hold at a block that has the key
    assert!(!chain.verifies(&before, &path, LATE_BLOCK));
    assert!(!chain.verifies(&before, &path, tip));

    for at in LATE_BLOCK..BLOCKS {
        assert!(matches!(
            chain.prove_absent(&path, at),
            Err(Error::NotFoundError)
        ));
    }
    let value = MARFValue::from_value("late");
    let inclusion = TrieMerkleProof::from_path(
        &mut chain.marf.borrow_storage_backend(),
        &path,
        &value,
        &block(tip),
    )
    .unwrap();
    assert!(inclusion.verify(
        &path,
        &value,
        &chain.roots[tip as usize],
        &chain.root_to_block
    ));
}
