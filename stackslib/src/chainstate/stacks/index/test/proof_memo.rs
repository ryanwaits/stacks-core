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

//! The opt-in lookup memo changes how much proving reads, never what it proves.

use std::time::{Duration, Instant};

use stacks_common::codec::StacksMessageCodec;

use crate::chainstate::stacks::index::absence::TrieAbsenceProof;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue, TrieMerkleProof};
use crate::chainstate::stacks::{BlockHeaderHash, TrieHash};

fn block(i: u32) -> BlockHeaderHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&(i + 1).to_be_bytes());
    BlockHeaderHash(bytes)
}

/// Deterministic pseudo-random sequence (splitmix64).
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        (z ^ (z >> 31)) % n
    }
}

/// A chain of `blocks` blocks, each writing `fresh` new keys and rewriting
/// `rewrites` random older ones, so keys are last written all along the
/// chain and walks cross back-pointers at every depth. Returns the MARF and
/// each key's latest value.
fn chain(
    path: &str,
    blocks: u32,
    fresh: u32,
    rewrites: u32,
) -> (MARF<BlockHeaderHash>, Vec<String>) {
    let opts = MARFOpenOpts {
        external_blobs: path != ":memory:",
        ..MARFOpenOpts::default()
    };
    let mut marf = MARF::from_path(path, opts).unwrap();
    let mut rng = Rng(7);
    let mut values: Vec<String> = vec![];
    let mut parent = BlockHeaderHash::sentinel();
    for b in 0..blocks {
        marf.begin(&parent, &block(b)).unwrap();
        let mut keys = vec![];
        let mut vals = vec![];
        for _ in 0..fresh {
            values.push(format!("v{b}"));
            keys.push(format!("key-{}", values.len() - 1));
            vals.push(MARFValue::from_value(values.last().unwrap()));
        }
        for _ in 0..rewrites.min(values.len() as u32) {
            let k = rng.below(values.len() as u64) as usize;
            values[k] = format!("v{b}-{k}");
            keys.push(format!("key-{k}"));
            vals.push(MARFValue::from_value(&values[k]));
        }
        marf.insert_batch(&keys, vals).unwrap();
        marf.commit().unwrap();
        parent = block(b);
    }
    (marf, values)
}

/// Proof bytes for `present` written keys and `absent` unwritten ones at
/// `tip`, plus node reads and time spent.
fn prove_all(
    marf: &mut MARF<BlockHeaderHash>,
    values: &[String],
    tip: u32,
    present: u32,
    absent: u32,
    memo: Option<Option<u32>>,
) -> (Vec<Vec<u8>>, u64, Duration) {
    let mut rng = Rng(11);
    let mut conn = marf.borrow_storage_backend();
    if let Some(anchor) = memo {
        conn.enable_lookup_memo(anchor.map(block));
    }
    conn.stats();
    let started = Instant::now();
    let mut proofs = vec![];
    for _ in 0..present {
        let k = rng.below(values.len() as u64) as usize;
        let proof =
            TrieMerkleProof::from_entry(&mut conn, &format!("key-{k}"), &values[k], &block(tip))
                .unwrap();
        proofs.push(proof.serialize_to_vec());
    }
    for i in 0..absent {
        let path = TrieHash::from_key(&format!("absent-{i}"));
        let proof = TrieAbsenceProof::from_path(&mut conn, &path, &block(tip)).unwrap();
        proofs.push(proof.serialize_to_vec());
    }
    let elapsed = started.elapsed();
    let (reads, _) = conn.stats();
    if let Some((tries, heights, blocks)) = conn.lookup_memo_len() {
        eprintln!(
            "memo: {tries} tries' ancestor hashes, {heights} heights, {blocks} blocks at a height"
        );
    }
    conn.disable_lookup_memo();
    (proofs, reads, elapsed)
}

fn compare(path: &str, blocks: u32, fresh: u32, rewrites: u32, present: u32, absent: u32) {
    let (mut marf, values) = chain(path, blocks, fresh, rewrites);
    let tip = blocks - 1;
    let (plain, plain_reads, plain_time) =
        prove_all(&mut marf, &values, tip, present, absent, None);
    let (memo, memo_reads, memo_time) =
        prove_all(&mut marf, &values, tip, present, absent, Some(None));
    let (anchored, anchored_reads, anchored_time) =
        prove_all(&mut marf, &values, tip, present, absent, Some(Some(tip)));
    eprintln!(
        "{blocks} blocks, {} keys, {present} inclusion + {absent} absence proofs ({} bytes): \
         {plain_reads} node reads in {plain_time:?} without the memo, \
         {memo_reads} in {memo_time:?} with it, \
         {anchored_reads} in {anchored_time:?} anchored at the tip",
        values.len(),
        plain.iter().map(Vec::len).sum::<usize>(),
    );
    for (i, a) in plain.iter().enumerate() {
        assert_eq!(a, &memo[i], "proof {i} differs with the memo on");
        assert_eq!(a, &anchored[i], "proof {i} differs with the anchored memo");
    }
    assert_eq!(plain.len(), memo.len());
    assert_eq!(plain.len(), anchored.len());
    assert!(memo_reads < plain_reads);
    assert!(anchored_reads < memo_reads);

    // turning it off drops it, and proving without it still matches
    assert_eq!(marf.borrow_storage_backend().lookup_memo_len(), None);
    let (again, _, _) = prove_all(&mut marf, &values, tip, present, absent, None);
    assert_eq!(plain, again);
}

#[test]
fn memoized_lookups_produce_byte_identical_proofs_with_fewer_reads() {
    compare(":memory:", 300, 4, 12, 400, 100);
}

/// Larger chain for measuring (`--ignored`); keeps its MARF in a temp file so
/// reads go through the blob file as on a node.
#[test]
#[ignore]
fn memoized_lookups_measure_a_long_chain() {
    let dir = std::env::temp_dir().join(format!("proof-memo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("marf.sqlite");
    compare(&path.to_string_lossy(), 32768, 2, 6, 3000, 500);
    std::fs::remove_dir_all(&dir).unwrap();
}
