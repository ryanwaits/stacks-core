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

//! Consensus-hash preimage reconstruction from sortition-DB fixtures.

mod common;

use common::*;
use marf_witness::burn::{self, MAINNET_FIRST_BURN_HEIGHT};
use serde_json::Value;
use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash, PoxId, SortitionId};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum, hex_bytes, to_hex};
use stackslib::chainstate::burn::{ConsensusHashExtensions, OpsHash};

#[test]
fn mainnet_consensus_hash_reproduces_from_a_read_only_db() {
    let tmp = tempdir();
    let path = mainnet_sortition_db(tmp.path());
    let want = burn_fixture("preimage-970269.json");
    let ch = want["consensus_hash"].as_str().unwrap();
    let before = digests(tmp.path());

    let conn = burn::open_readonly(&path).unwrap();
    let p = burn::burn_preimage(&conn, ch, MAINNET_FIRST_BURN_HEIGHT)
        .unwrap()
        .unwrap();
    drop(conn);
    assert_eq!(p.preimage, want["preimage"].as_str().unwrap());
    assert_eq!(p.burn_height, 970269);
    let pre = hex_bytes(&p.preimage).unwrap();
    assert_eq!(pre.len(), 602);
    assert_eq!(to_hex(&Hash160::from_data(&pre).0), ch);
    // bytes 4..36 are the bitcoin block hash in display order, no reversal
    assert_eq!(
        to_hex(&pre[4..36]),
        want["bitcoin_block_hash"].as_str().unwrap()
    );
    assert_eq!(
        p.bitcoin_block_hash,
        want["bitcoin_block_hash"].as_str().unwrap()
    );
    // pox_id: 146 cycles, all valid
    assert_eq!(&pre[76..76 + 146], "1".repeat(146).as_bytes());

    let o = run(&[
        "burn",
        "--sortition-db",
        path.to_str().unwrap(),
        "--consensus-hash",
        ch,
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out: Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(out["preimage"], want["preimage"]);
    assert_eq!(out["burn_height"], 970269);
    assert_eq!(out["consensus_hash"], ch);
    assert_eq!(out["bitcoin_block_hash"], want["bitcoin_block_hash"]);

    assert_untouched(tmp.path(), &before);
}

#[test]
fn wrong_first_burn_height_or_unknown_hash_fail_cleanly() {
    let tmp = tempdir();
    let path = mainnet_sortition_db(tmp.path());
    let ch = "e55512fc4410f497503e39d10ce1d1a3e894060c";
    let o = run(&[
        "burn",
        "--sortition-db",
        path.to_str().unwrap(),
        "--consensus-hash",
        ch,
        "--first-burn-height",
        "800000",
    ]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("does not hash to consensus hash"),
        "{}",
        stderr(&o)
    );

    let o = run(&[
        "burn",
        "--sortition-db",
        path.to_str().unwrap(),
        "--consensus-hash",
        &"ab".repeat(20),
    ]);
    assert!(!o.status.success());
    assert!(
        stderr(&o).contains("no snapshot with consensus hash"),
        "{}",
        stderr(&o)
    );

    let missing = tmp.path().join("missing.sqlite");
    let o = run(&[
        "burn",
        "--sortition-db",
        missing.to_str().unwrap(),
        "--consensus-hash",
        ch,
    ]);
    assert!(!o.status.success());
    assert!(!missing.exists());
}

fn h32(tag: &str, h: u64) -> [u8; 32] {
    Sha512Trunc256Sum::from_data(format!("{tag}-{h}").as_bytes()).0
}

fn ch_of(tag: &str, h: u64) -> String {
    to_hex(&Hash160::from_data(format!("{tag}-{h}").as_bytes()).0)
}

/// stackslib's own consensus-hash function over the canonical fork, so the tool
/// is checked against an independent implementation, not against itself.
fn expected_ch(
    canonical: &dyn Fn(u64) -> String,
    height: u64,
    first: u64,
    bhh: &[u8; 32],
    ops: &[u8; 32],
    total_burn: u64,
    pox: &PoxId,
) -> String {
    let parent = height - 1;
    let prev: Vec<ConsensusHash> = (0..64)
        .map(|i| parent as i64 - ((1i64 << i) - 1))
        .take_while(|h| *h >= first as i64)
        .map(|h| ConsensusHash::from_hex(&canonical(h as u64)).unwrap())
        .collect();
    to_hex(
        &ConsensusHash::from_ops(
            &BurnchainHeaderHash(*bhh),
            &OpsHash(*ops),
            total_burn,
            &prev,
            pox,
        )
        .0,
    )
}

#[test]
fn forked_heights_resolve_through_parent_links() {
    let tmp = tempdir();
    let path = tmp.path().join("sortition.sqlite");
    let conn = create_snapshots(&path);
    let first = 100;
    let zeros = "00".repeat(32);

    // Canonical fork 100..=159; a decoy fork at 150..=159 (same heights, other rows).
    let sort = |tag: &str, h: u64| to_hex(&h32(&format!("sort-{tag}"), h));
    for h in first..160 {
        let parent = if h == first {
            zeros.clone()
        } else {
            sort("main", h - 1)
        };
        insert_snapshot(
            &conn,
            h,
            &to_hex(&h32("bhh", h)),
            &sort("main", h),
            &parent,
            &ch_of("main", h),
            &zeros,
            "0",
        );
    }
    for h in 150..160 {
        let parent = if h == 150 {
            sort("main", 149)
        } else {
            sort("decoy", h - 1)
        };
        insert_snapshot(
            &conn,
            h,
            &to_hex(&h32("bhh-decoy", h)),
            &sort("decoy", h),
            &parent,
            &ch_of("decoy", h),
            &zeros,
            "0",
        );
    }
    let canonical = |h: u64| ch_of("main", h);

    // Tenure at 160: a PoX id with one invalidated cycle.
    let (bhh, ops) = (h32("bhh", 160), h32("ops", 160));
    let pox = PoxId::new("1111011111".chars().map(|c| c == '1').collect());
    let ch160 = expected_ch(&canonical, 160, first, &bhh, &ops, 4242, &pox);
    insert_snapshot(
        &conn,
        160,
        &to_hex(&bhh),
        &to_hex(&SortitionId::new(&BurnchainHeaderHash(bhh), &pox).0),
        &sort("main", 159),
        &ch160,
        &to_hex(&ops),
        "4242",
    );

    // Tenure at 161 with the stubbed (empty) PoX id: sortition id == burn header hash.
    let (bhh2, ops2) = (h32("bhh", 161), h32("ops", 161));
    let canonical2 = |h: u64| {
        if h == 160 {
            ch160.clone()
        } else {
            ch_of("main", h)
        }
    };
    let ch161 = expected_ch(
        &canonical2,
        161,
        first,
        &bhh2,
        &ops2,
        5000,
        &PoxId::stubbed(),
    );
    insert_snapshot(
        &conn,
        161,
        &to_hex(&bhh2),
        &to_hex(&bhh2),
        &to_hex(&SortitionId::new(&BurnchainHeaderHash(bhh), &pox).0),
        &ch161,
        &to_hex(&ops2),
        "5000",
    );
    drop(conn);

    let conn = burn::open_readonly(&path).unwrap();
    for (ch, height, bhh) in [(&ch160, 160, bhh), (&ch161, 161, bhh2)] {
        let p = burn::burn_preimage(&conn, ch, first).unwrap().unwrap();
        assert_eq!(p.burn_height, height);
        assert_eq!(p.bitcoin_block_hash, to_hex(&bhh));
        assert_eq!(
            to_hex(&Hash160::from_data(&hex_bytes(&p.preimage).unwrap()).0),
            *ch
        );
    }
}
