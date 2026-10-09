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

//! Shared MARF proofs (inclusion and absence for many reads) against real
//! MARFs.

use std::collections::HashMap;

use stacks_common::codec::StacksMessageCodec;

use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::multiproof::{Multiproof, MultiproofBuilder};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue, TrieMerkleProof};
use crate::chainstate::stacks::{BlockHeaderHash, TrieHash};

const BLOCKS: u8 = 8;
const KEYS_PER_BLOCK: usize = 40;

fn block(i: u8) -> BlockHeaderHash {
    BlockHeaderHash([i + 1; 32])
}

fn written_key(block: u8, i: usize) -> String {
    format!("written-{block}-{i}")
}

fn written_value(block: u8, i: usize) -> MARFValue {
    MARFValue::from_value(&format!("v{block}-{i}"))
}

/// A MARF of `BLOCKS` blocks, each writing `KEYS_PER_BLOCK` fresh keys, so
/// later tries reach most paths through back-pointers. [`late_key`] is
/// written only in block `LATE_BLOCK`.
struct Chain {
    marf: MARF<BlockHeaderHash>,
    roots: HashMap<BlockHeaderHash, TrieHash>,
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

/// What a read expects: `path` at `at` holds `value` (`None`: absent).
type Read = (u8, TrieHash, Option<MARFValue>);

impl Chain {
    fn new() -> Self {
        let mut marf = MARF::from_path(":memory:", MARFOpenOpts::default()).unwrap();
        let mut parent = BlockHeaderHash::sentinel();
        let mut roots = HashMap::new();
        for b in 0..BLOCKS {
            marf.begin(&parent, &block(b)).unwrap();
            for i in 0..KEYS_PER_BLOCK {
                marf.insert(&written_key(b, i), written_value(b, i))
                    .unwrap();
            }
            if b == LATE_BLOCK {
                marf.insert(&late_key(), MARFValue::from_value("late"))
                    .unwrap();
            }
            marf.commit().unwrap();
            roots.insert(block(b), marf.get_root_hash_at(&block(b)).unwrap());
            parent = block(b);
        }
        Chain { marf, roots }
    }

    fn tip(&self) -> u8 {
        BLOCKS - 1
    }

    /// One shared proof for `reads`, each walk checked against the MARF.
    fn prove(&mut self, reads: &[Read]) -> Vec<u8> {
        let mut conn = self.marf.borrow_storage_backend();
        let mut builder = MultiproofBuilder::new();
        for (at, path, value) in reads.iter() {
            let end = builder.walk(&mut conn, &block(*at), path).unwrap();
            assert_eq!(&end.value, value, "the MARF disagrees with {path} at {at}");
        }
        builder.encode(&mut conn).unwrap()
    }

    fn open(&self, bytes: &[u8]) -> Result<Multiproof<BlockHeaderHash>, String> {
        Multiproof::open(bytes, |id| self.roots.get(id).copied())
    }

    /// The proof decodes, every trie hashes to its root, every read holds,
    /// and no node is left over.
    fn verifies(&self, bytes: &[u8], reads: &[Read]) -> bool {
        let Ok(proof) = self.open(bytes) else {
            return false;
        };
        reads.iter().all(|(at, path, value)| {
            proof
                .get(&block(*at), path)
                .is_ok_and(|end| &end.value == value)
        }) && proof.unvisited() == 0
    }
}

fn never_written(i: usize) -> TrieHash {
    TrieHash::from_key(&format!("never-written-{i}"))
}

/// The path of a written key with one byte changed.
fn near_miss(key: &str, byte: usize) -> TrieHash {
    let mut path = TrieHash::from_key(key);
    path.0[byte] ^= 0x01;
    path
}

/// 300 absent and 320 present keys at the tip, from one proof. Absent walks
/// end in the tip trie and, through back-pointers, in older ones. The proof
/// is a fraction of the per-read inclusion proofs for the same present keys.
#[test]
fn absent_and_present_reads_verify_from_one_shared_proof() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let mut reads: Vec<Read> = (0..300).map(|i| (tip, never_written(i), None)).collect();
    for b in 0..BLOCKS {
        for i in 0..KEYS_PER_BLOCK {
            let path = TrieHash::from_key(&written_key(b, i));
            reads.push((tip, path, Some(written_value(b, i))));
        }
    }
    let bytes = chain.prove(&reads);
    assert!(chain.verifies(&bytes, &reads));

    let proof = chain.open(&bytes).unwrap();
    let (mut in_tip, mut in_older) = (0, 0);
    for (at, path, _) in reads.iter().take(300) {
        let end = proof.get(&block(*at), path).unwrap();
        if end.trie == block(tip) {
            in_tip += 1;
        } else {
            in_older += 1;
        }
    }
    assert!(in_tip > 0 && in_older > 0, "{in_tip} / {in_older}");

    // a present key is never absent, an absent key never present
    let (present, absent) = (&reads[300], &reads[0]);
    assert!(!chain.verifies(&bytes, &[(tip, present.1, None)]));
    assert!(!chain.verifies(&bytes, &[(tip, absent.1, Some(MARFValue::from_value("x")))]));

    let mut per_read = 0;
    let mut conn = chain.marf.borrow_storage_backend();
    for (_, path, value) in reads.iter().skip(300) {
        let proof =
            TrieMerkleProof::from_path(&mut conn, path, value.as_ref().unwrap(), &block(tip))
                .unwrap();
        per_read += proof.serialize_to_vec().len();
    }
    eprintln!(
        "{} reads ({} present) in one proof: {} bytes, {} tries, {} nodes; \
         per-read inclusion proofs for the present keys alone: {per_read} bytes",
        reads.len(),
        reads.len() - 300,
        bytes.len(),
        proof.tries(),
        proof.nodes()
    );
    assert!(bytes.len() * 10 < per_read);
}

/// A path that shares all but one byte with a written key is absent; the
/// written key itself is present, from the same proof.
#[test]
fn near_miss_of_a_written_leaf_is_absent_but_the_leaf_is_not() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let key = written_key(2, 7);
    let present = TrieHash::from_key(&key);
    let mut reads: Vec<Read> = [31, 20, 5, 1]
        .iter()
        .map(|byte| (tip, near_miss(&key, *byte), None))
        .collect();
    reads.push((tip, present, Some(written_value(2, 7))));
    let bytes = chain.prove(&reads);
    assert!(chain.verifies(&bytes, &reads));
    assert!(!chain.verifies(&bytes, &[(tip, present, None)]));
}

/// Flipping any bit of any byte of a proof breaks it: it no longer decodes,
/// a trie no longer hashes to its root, a read changes, or a node is left
/// over.
#[test]
fn tampering_with_any_byte_of_a_shared_proof_breaks_it() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let reads: Vec<Read> = vec![
        (tip, never_written(0), None),
        (tip, never_written(1), None),
        (
            tip,
            TrieHash::from_key(&written_key(1, 3)),
            Some(written_value(1, 3)),
        ),
        (
            tip,
            TrieHash::from_key(&written_key(6, 9)),
            Some(written_value(6, 9)),
        ),
        (
            3,
            TrieHash::from_key(&written_key(0, 5)),
            Some(written_value(0, 5)),
        ),
    ];
    let honest = chain.prove(&reads);
    assert!(chain.verifies(&honest, &reads));
    let proof = chain.open(&honest).unwrap();
    assert!(proof.tries() > 2, "walks cross into older tries");

    for i in 0..honest.len() {
        for bit in [0x01, 0x80] {
            let mut forged = honest.clone();
            forged[i] ^= bit;
            assert!(
                !chain.verifies(&forged, &reads),
                "flipping bit {bit:#04x} of byte {i} of {} went unnoticed",
                honest.len()
            );
        }
    }
    // truncated, or with a trailing byte
    assert!(!chain.verifies(&honest[..honest.len() - 1], &reads));
    let mut longer = honest.clone();
    longer.push(0);
    assert!(!chain.verifies(&longer, &reads));
}

/// A proof is exact: verifying fewer reads than it was made for leaves nodes
/// over, and a read it was not made for needs a node it left out.
#[test]
fn a_shared_proof_holds_its_reads_and_no_others() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let reads: Vec<Read> = (0..20)
        .map(|i| {
            let path = TrieHash::from_key(&written_key(i % BLOCKS, i as usize));
            (tip, path, Some(written_value(i % BLOCKS, i as usize)))
        })
        .collect();
    let bytes = chain.prove(&reads);
    assert!(chain.verifies(&bytes, &reads));
    assert!(
        !chain.verifies(&bytes, &reads[..10]),
        "extra nodes are rejected"
    );

    let proof = chain.open(&bytes).unwrap();
    let uncovered = (0..KEYS_PER_BLOCK)
        .map(|i| TrieHash::from_key(&written_key(3, i)))
        .find(|path| proof.get(&block(tip), path).is_err());
    assert!(uncovered.is_some(), "some read needs a pruned node");
}

/// "Absent" means never written on this fork: a key written in block 5 is
/// absent at block 4, through a back-pointer, and present from block 5 on.
/// A proof made at block 4 does not hold against block 5's root.
#[test]
fn absence_holds_until_the_block_that_writes_the_key() {
    let mut chain = Chain::new();
    let tip = chain.tip();
    let path = TrieHash::from_key(&late_key());
    let before: Vec<Read> = vec![(LATE_BLOCK - 1, path, None)];
    let bytes = chain.prove(&before);
    assert!(chain.verifies(&bytes, &before));
    let proof = chain.open(&bytes).unwrap();
    let end = proof.get(&block(LATE_BLOCK - 1), &path).unwrap();
    assert_ne!(
        end.trie,
        block(LATE_BLOCK - 1),
        "walk crosses back-pointers"
    );

    // the same bytes, pinned to block 5's root
    let shifted = Multiproof::open(&bytes, |id| {
        if *id == block(LATE_BLOCK - 1) {
            chain.roots.get(&block(LATE_BLOCK)).copied()
        } else {
            chain.roots.get(id).copied()
        }
    })
    .unwrap();
    assert!(shifted.get(&block(LATE_BLOCK - 1), &path).is_err());

    let late = MARFValue::from_value("late");
    let after: Vec<Read> = (LATE_BLOCK..BLOCKS)
        .map(|at| (at, path, Some(late.clone())))
        .collect();
    let bytes = chain.prove(&after);
    assert!(chain.verifies(&bytes, &after));
    let proof = chain.open(&bytes).unwrap();
    assert_eq!(
        proof.get(&block(tip), &path).unwrap().trie,
        block(LATE_BLOCK),
        "a present key's walk ends in the trie that wrote it"
    );
}
