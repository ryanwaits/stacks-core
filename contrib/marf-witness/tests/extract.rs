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

//! End-to-end extraction against local MARFs, through the CLI binary.

mod common;

use std::collections::HashMap;
use std::path::Path;

use common::*;
use marf_witness::extract::{ReadOnlyMarf, WitnessMeta};
use marf_witness::wire::{self, Encoder, Ptr};
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::to_hex;
use stackslib::chainstate::stacks::index::MARFValue;
use stackslib::chainstate::stacks::index::marf::MARF;

/// Main-chain heights committed as cross-language fixtures (small, typical, large).
const FIXTURE_HEIGHTS: [usize; 3] = [1, 157, 160];

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/witness")
}

fn read_meta(dir: &Path, block: &StacksBlockId) -> WitnessMeta {
    serde_json::from_slice(&std::fs::read(dir.join(format!("{block}.json"))).unwrap()).unwrap()
}

fn extract(marf: &Path, out: &Path, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "extract",
        "--marf",
        marf.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run(&args)
}

#[test]
fn extract_leaves_marf_files_byte_identical_and_every_root_matches() {
    let tmp = tempdir();
    let chain = tmp.path().join("chain");
    let out = tmp.path().join("out");
    let local = build_marf(&chain, 300, 3, false);
    let tip = local.blocks.last().unwrap().to_string();

    let before = digests(&chain);
    assert!(before.contains_key("marf.sqlite") && before.contains_key("marf.sqlite.blobs"));
    let o = extract(&local.path, &out, &["--tip", &tip, "--count", "300"]);
    assert!(o.status.success(), "extract failed: {}", stderr(&o));
    assert_untouched(&chain, &before);

    let mut marf = ReadOnlyMarf::open(&local.path).unwrap();
    for (height, block) in local.blocks.iter().enumerate() {
        let meta = read_meta(&out, block);
        assert_eq!(meta.height as usize, height);
        let expected = to_hex(marf.root_hash_at(block).unwrap().as_bytes());
        assert_eq!(meta.root_hex, expected, "json root of block {height}");

        let bytes = std::fs::read(out.join(format!("{block}.witness"))).unwrap();
        assert_eq!(bytes.len(), meta.bytes);
        let v = wire::verify(&bytes).unwrap();
        assert_eq!(
            to_hex(v.root.as_bytes()),
            expected,
            "recomputed root of block {height}"
        );
        assert_eq!(v.leaves.len(), meta.leaves);

        // Every write of the block is a leaf of its trie with the written value.
        let leaves: HashMap<[u8; 32], [u8; 32]> =
            v.leaves.iter().map(|l| (l.path, l.value_hash)).collect();
        for (k, val) in &local.writes[height] {
            let want: [u8; 32] = MARFValue::from_value(val).0[..32].try_into().unwrap();
            assert_eq!(
                leaves.get(TrieHash::from_key(k).as_bytes()),
                Some(&want),
                "write {k} of block {height} missing from its witness"
            );
        }
    }
    drop(marf);

    let o = run(&["stats", out.to_str().unwrap()]);
    assert!(o.status.success(), "stats failed: {}", stderr(&o));
    assert!(stdout(&o).starts_with("blocks 300\n"));
    eprintln!("{}", stdout(&o));

    // Cross-language fixtures for the TypeScript verifier must match a fresh extract.
    let fixtures = fixture_dir();
    let regenerate = std::env::var_os("MARF_WITNESS_WRITE_FIXTURES").is_some();
    if regenerate {
        std::fs::create_dir_all(&fixtures).unwrap();
    }
    for h in FIXTURE_HEIGHTS {
        for ext in ["witness", "json"] {
            let name = format!("{}.{ext}", local.blocks[h]);
            let fresh = std::fs::read(out.join(&name)).unwrap();
            if regenerate {
                std::fs::write(fixtures.join(&name), &fresh).unwrap();
            } else {
                let committed = std::fs::read(fixtures.join(&name)).unwrap_or_else(|e| {
                    panic!("fixture {name}: {e}; set MARF_WITNESS_WRITE_FIXTURES=1")
                });
                assert!(committed == fresh, "fixture {name} is stale");
            }
        }
    }
}

#[test]
fn tip_walk_follows_the_tip_fork_and_stops_at_genesis() {
    let tmp = tempdir();
    let local = build_marf(&tmp.path().join("chain"), 40, 3, false);
    let out = tmp.path().join("out");
    let fork_tip = local.fork.last().unwrap().to_string();

    let o = extract(&local.path, &out, &["--tip", &fork_tip, "--count", "5"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let mut want: Vec<StacksBlockId> = local.fork.iter().rev().cloned().collect();
    want.extend([local.blocks[36].clone(), local.blocks[35].clone()]);
    for (k, b) in want.iter().enumerate() {
        assert_eq!(read_meta(&out, b).height as usize, 39 - k);
    }
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 10);

    // --count beyond genesis extracts the whole chain, block 0 included.
    let all = tmp.path().join("all");
    let tip = local.blocks[39].to_string();
    let o = extract(&local.path, &all, &["--tip", &tip, "--count", "1000"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(read_meta(&all, &local.blocks[0]).height, 0);
    assert_eq!(std::fs::read_dir(&all).unwrap().count(), 80);

    // Explicit --block list, and an unknown block is a clear error.
    let some = tmp.path().join("some");
    let (a, b) = (local.blocks[3].to_string(), local.fork[0].to_string());
    let o = extract(&local.path, &some, &["--block", &a, &b]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(read_meta(&some, &local.fork[0]).height, 37);

    // An unknown block is reported with its id; the blocks after it still extract.
    let rest = tmp.path().join("rest");
    let (bad, good) = (block(9999).to_string(), local.blocks[5].to_string());
    let o = extract(&local.path, &rest, &["--block", &bad, &good]);
    assert!(!o.status.success());
    let err = stderr(&o);
    assert!(
        err.contains(&format!("block {bad}")) && err.contains("not in this MARF"),
        "{err}"
    );
    assert!(err.contains("1 of 2 blocks failed"), "{err}");
    assert_eq!(read_meta(&rest, &local.blocks[5]).height, 5);
}

#[test]
fn compressed_marf_witnesses_recompute_their_roots() {
    let tmp = tempdir();
    let chain = tmp.path().join("chain");
    let local = build_marf(&chain, 80, 0, true);
    let before = digests(&chain);
    let mut marf = ReadOnlyMarf::open(&local.path).unwrap();
    for block in &local.blocks {
        let v = wire::verify(&marf.witness(block).unwrap()).unwrap();
        assert_eq!(v.root, marf.root_hash_at(block).unwrap());
    }
    drop(marf);
    assert_untouched(&chain, &before);
}

#[test]
fn single_byte_flips_are_detected() {
    let fixtures = fixture_dir();
    let mut checked = 0;
    for entry in std::fs::read_dir(&fixtures).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|x| x != "witness") {
            continue;
        }
        let meta: WitnessMeta =
            serde_json::from_slice(&std::fs::read(path.with_extension("json")).unwrap()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            to_hex(wire::verify(&bytes).unwrap().root.as_bytes()),
            meta.root_hex
        );
        // Exhaustive for small witnesses; every 31st byte of large ones keeps this fast.
        let step = if bytes.len() <= 20_000 { 1 } else { 31 };
        for i in (0..bytes.len()).step_by(step) {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            if let Ok(v) = wire::verify(&t) {
                assert_ne!(
                    to_hex(v.root.as_bytes()),
                    meta.root_hex,
                    "flip at byte {i} undetected"
                );
            }
        }
        checked += 1;

        // CLI: intact passes, tampered exits nonzero.
        let p = path.to_str().unwrap();
        let o = run(&["verify", p, "--root", &meta.root_hex]);
        assert!(o.status.success(), "{}", stderr(&o));
        assert!(stdout(&o).contains(&format!("leaves={}", meta.leaves)));
        let tmp = tempdir();
        let tampered = tmp.path().join("tampered.witness");
        let mut t = bytes.clone();
        let n = t.len();
        t[n - 5] ^= 0x01; // inside the last leaf's value hash
        std::fs::write(&tampered, &t).unwrap();
        let o = run(&[
            "verify",
            tampered.to_str().unwrap(),
            "--root",
            &meta.root_hex,
        ]);
        assert!(!o.status.success());
        assert!(stderr(&o).contains("root mismatch"), "{}", stderr(&o));
    }
    assert_eq!(checked, FIXTURE_HEIGHTS.len());
}

#[test]
fn squashed_marf_is_refused_without_touching_it() {
    let tmp = tempdir();
    let local = build_marf(&tmp.path().join("chain"), 20, 0, false);
    let squashed_dir = tmp.path().join("squashed");
    std::fs::create_dir_all(&squashed_dir).unwrap();
    let squashed = squashed_dir.join("marf.sqlite");
    MARF::<StacksBlockId>::squash_to_path(
        local.path.to_str().unwrap(),
        squashed.to_str().unwrap(),
        node_opts(false),
        local.blocks.last().unwrap(),
        10,
        "test",
    )
    .unwrap();

    let before = digests(&squashed_dir);
    let tip = local.blocks[19].to_string();
    let o = extract(
        &squashed,
        &tmp.path().join("out"),
        &["--tip", &tip, "--count", "2"],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("is a squashed MARF"), "{}", stderr(&o));
    assert_untouched(&squashed_dir, &before);
}

#[test]
fn missing_marf_is_not_created() {
    let tmp = tempdir();
    let missing = tmp.path().join("nope.sqlite");
    let o = extract(
        &missing,
        &tmp.path().join("out"),
        &["--block", &block(0).to_string()],
    );
    assert!(!o.status.success());
    assert!(stderr(&o).contains("not found"));
    assert!(!missing.exists());
}

#[test]
fn witness_with_more_than_65535_ancestor_blocks_round_trips() {
    // Root Node256 -> 256 local Node256s, each with 255 backptrs and one local
    // Node4 of 4 backptrs: 256 * 259 = 66,304 distinct ancestor blocks.
    const NODE4: u8 = 2;
    const NODE256: u8 = 5;
    const BACK: u8 = 0x80;
    let mut next = 0u32;
    let mut back = |chr: u8| {
        let mut block = [0u8; 32];
        block[..4].copy_from_slice(&next.to_be_bytes());
        block[31] = 0xab;
        next += 1;
        Ptr::Back {
            id: BACK | NODE256,
            chr,
            block,
        }
    };
    let ancestors = vec![TrieHash([7u8; 32]), TrieHash([8u8; 32])];
    let mut enc = Encoder::new(ancestors.clone());
    let root: Vec<Ptr> = (0..=255u8)
        .map(|chr| Ptr::Local { id: NODE256, chr })
        .collect();
    enc.node(NODE256, &[], &root).unwrap();
    for _ in 0..256 {
        let mut ptrs: Vec<Ptr> = (0..255u8).map(&mut back).collect();
        ptrs.push(Ptr::Local {
            id: NODE4,
            chr: 255,
        });
        enc.node(NODE256, &[], &ptrs).unwrap();
        let ptrs: Vec<Ptr> = (0..4u8).map(&mut back).collect();
        enc.node(NODE4, &[], &ptrs).unwrap();
    }
    let bytes = enc.finish().unwrap();
    assert_eq!(next, 66_304);

    let v = wire::verify(&bytes).unwrap();
    assert_eq!((v.nodes, v.leaves.len()), (513, 0));
    let tbl_at = 1 + 4 + 32 * ancestors.len();
    let n_tbl = u32::from_be_bytes(bytes[tbl_at..tbl_at + 4].try_into().unwrap());
    assert_eq!(n_tbl, 66_304);
    eprintln!(
        "synthetic witness: {} table entries, {} bytes",
        n_tbl,
        bytes.len()
    );

    // The last table entry (index 66,303) is hashed into the root.
    let mut t = bytes.clone();
    t[tbl_at + 4 + 32 * (n_tbl as usize - 1)] ^= 1;
    assert_ne!(wire::verify(&t).unwrap().root, v.root);
    // A table index past the end is rejected.
    let mut t = bytes.clone();
    let n = t.len();
    t[n - 4..].copy_from_slice(&n_tbl.to_be_bytes());
    assert!(wire::verify(&t).unwrap_err().contains("out of range"));
}
