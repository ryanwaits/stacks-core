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

//! `check` against local MARFs built from a known write log, and against a
//! mainnet witness with rows from the buggy collector.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use serde_json::{Value as Json, json};
use stacks_common::types::chainstate::TrieHash;
use stacks_common::util::hash::to_hex;
use stackslib::clarity::vm::Value;

const CONTRACT: &str = "SP000000000000000000002Q6VF78.amm";
const BLOCKS: usize = 40;
/// Key every block writes three times; only the last value lands.
const HOT_KEY: u128 = 9999;

fn uint(n: u128) -> String {
    Value::UInt(n).serialize_to_hex().unwrap()
}

/// A block's log: vm_events rows plus every storage write, both in execution order.
#[derive(Default)]
struct Log {
    height: usize,
    rows: Vec<Json>,
    writes: Vec<Json>,
    /// (key, value string) applied to the MARF.
    applied: Vec<(String, String)>,
    ordinal: usize,
}

impl Log {
    fn row(&mut self, kind: &str, data: Json) {
        self.rows.push(json!({
            "block_height": self.height, "ordinal": self.ordinal, "type": kind,
            "tx_id": format!("0x{:064x}", self.height), "data": data,
        }));
        self.ordinal += 1;
    }

    /// A storage write, logged as a row too when `row` is given.
    fn write(&mut self, row: Option<(&str, Json)>, key: String, value: String) {
        if let Some((kind, data)) = row {
            self.row(kind, data);
        }
        self.writes.push(json!({
            "block_height": self.height, "tx_index": 0, "ordinal": self.writes.len(),
            "key": key, "value_hex": to_hex(value.as_bytes()),
        }));
        self.applied.push((key, value));
    }
}

fn map_key(raw_key: &str) -> String {
    format!("vm::{CONTRACT}::0::reserve::{raw_key}")
}

fn map_row(raw_key: &str, raw_value: Option<&str>) -> Json {
    let mut data = json!({"contract_identifier": CONTRACT, "map_name": "reserve", "raw_key": format!("0x{raw_key}")});
    if let Some(v) = raw_value {
        data["raw_value"] = json!(format!("0x{v}"));
    }
    data
}

/// One block of map sets/inserts/deletes, a var-set, the hot key three times,
/// and account writes that only a storage-layer log names.
fn block_log(height: usize, rng: &mut Rng) -> Log {
    let mut log = Log {
        height,
        ..Default::default()
    };
    for _ in 0..20 + rng.below(100) {
        let k = uint(rng.below(400).into());
        let v = uint(rng.below(1 << 40).into());
        let (row, value) = match rng.below(6) {
            0 => (("map_delete", map_row(&k, None)), "09".to_string()),
            1 => (("map_insert", map_row(&k, Some(&v))), format!("0a{v}")),
            _ => (("map_set", map_row(&k, Some(&v))), format!("0a{v}")),
        };
        log.write(Some(row), map_key(&k), value);
    }
    let k = uint(HOT_KEY);
    for i in 0..3u128 {
        let v = uint(height as u128 * 10 + i);
        log.write(
            Some(("map_set", map_row(&k, Some(&v)))),
            map_key(&k),
            format!("0a{v}"),
        );
    }
    let v = uint(height as u128);
    let data =
        json!({"contract_identifier": CONTRACT, "var_name": "n", "raw_value": format!("0x{v}")});
    log.write(Some(("var_set", data)), format!("vm::{CONTRACT}::1::n"), v);
    log.row(
        "nested_contract_call",
        json!({"contract_identifier": CONTRACT, "function_name": "f"}),
    );
    for _ in 0..5 {
        let key = format!("vm-account::SP{:04}::stx", rng.below(300));
        log.write(None, key, format!("{:x}", rng.below(1 << 40)));
    }
    log
}

struct Chain {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    marf: PathBuf,
    logs: Vec<Log>,
}

fn chain() -> Chain {
    let tmp = tempdir();
    let dir = tmp.path().join("chain");
    let mut rng = Rng::new();
    let logs: Vec<Log> = (0..BLOCKS).map(|h| block_log(h, &mut rng)).collect();
    let applied: Vec<_> = logs.iter().map(|l| l.applied.clone()).collect();
    let local = build_marf_with(&dir, &applied);
    Chain {
        dir,
        marf: local.path,
        logs,
        _tmp: tmp,
    }
}

fn write_jsonl(dir: &Path, name: &str, lines: impl IntoIterator<Item = Json>) -> PathBuf {
    let p = dir.join(name);
    let body: Vec<String> = lines.into_iter().map(|l| l.to_string()).collect();
    std::fs::write(&p, body.join("\n")).unwrap();
    p
}

impl Chain {
    fn rows(&self) -> Vec<Json> {
        self.logs.iter().flat_map(|l| l.rows.clone()).collect()
    }
    fn writes(&self) -> Vec<Json> {
        self.logs.iter().flat_map(|l| l.writes.clone()).collect()
    }
    /// Run `check` with the given logs and block selection.
    fn check(&self, rows: Vec<Json>, writes: Option<Vec<Json>>, select: &[&str]) -> (bool, Json) {
        let tmp = tempdir();
        let rows = write_jsonl(tmp.path(), "rows.jsonl", rows);
        let mut args = vec![
            "check",
            "--marf",
            self.marf.to_str().unwrap(),
            "--rows",
            rows.to_str().unwrap(),
        ];
        let writes = writes.map(|w| write_jsonl(tmp.path(), "writes.jsonl", w));
        if let Some(w) = &writes {
            args.extend(["--writes", w.to_str().unwrap()]);
        }
        args.extend_from_slice(select);
        let o = run(&args);
        let report: Json = serde_json::from_str(&stdout(&o))
            .unwrap_or_else(|e| panic!("{e}: {}\n{}", stdout(&o), stderr(&o)));
        (o.status.success(), report)
    }
}

fn all_blocks() -> [&'static str; 4] {
    ["--from", "0", "--to", "39"]
}

fn failures(report: &Json) -> Vec<&Json> {
    report["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|b| b["row_failures"].as_array().unwrap())
        .collect()
}

#[test]
fn correct_rows_and_writes_pass_with_carried_and_internal_leaves_unflagged() {
    let c = chain();
    let before = digests(&c.dir);
    let (ok, report) = c.check(c.rows(), Some(c.writes()), &all_blocks());
    assert_untouched(&c.dir, &before);
    let s = &report["summary"];
    assert!(ok, "{report:#}");
    assert_eq!(s["ok"], true);
    assert_eq!(s["blocks"], BLOCKS);
    assert_eq!(
        (s["row_failures"].as_u64(), s["unnamed"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(s["rows_unmatched"], 0);
    assert_eq!(s["tip"], block(BLOCKS as u64 - 1).to_string());

    let blocks = report["blocks"].as_array().unwrap();
    let mut carried = 0;
    for (h, b) in blocks.iter().enumerate() {
        assert_eq!(b["height"], h);
        assert_eq!(b["id"], block(h as u64).to_string());
        assert_eq!(b["root_ok"], true);
        // Genesis has no parent, so no `HEIGHT_TO_HASH::{h-1}` / `HASH_TO_HEIGHT::{parent}`.
        assert_eq!(b["leaves"]["internal"], if h == 0 { 3 } else { 5 });
        let rows = c.logs[h]
            .rows
            .iter()
            .filter(|r| r["type"] != "nested_contract_call");
        assert_eq!(b["rows_checked"], rows.count());
        carried += b["leaves"]["carried"].as_u64().unwrap();
    }
    assert!(
        carried > 0,
        "no block carried a leaf; the test proves nothing"
    );

    // Rows alone never name account keys: reported, but not a failure.
    let (ok, report) = c.check(c.rows(), None, &all_blocks());
    assert!(ok, "{report:#}");
    assert!(report["summary"]["unnamed"].as_u64().unwrap() > 0);
    assert!(report["summary"].get("writes_checked").is_none());

    // --height and --block select the same blocks.
    let (h, id) = ("7".to_string(), block(7).to_string());
    let (ok, by_height) = c.check(c.rows(), Some(c.writes()), &["--height", &h]);
    assert!(ok);
    let (ok, by_block) = c.check(c.rows(), Some(c.writes()), &["--block", &id]);
    assert!(ok);
    assert_eq!(by_height["blocks"], by_block["blocks"]);
    // Rows and writes of the 39 other heights matched no checked block.
    let others = c.rows().len() + c.writes().len() - c.logs[7].rows.len() - c.logs[7].writes.len();
    assert_eq!(by_block["summary"]["rows_unmatched"], others);
}

#[test]
fn row_keyed_by_the_previous_value_is_key_not_written() {
    let c = chain();
    let mut rows = c.rows();
    // The collector bug: a map-set row whose key slot holds the previous value.
    let i = rows
        .iter()
        .position(|r| r["type"] == "map_set" && r["block_height"] == 12)
        .unwrap();
    rows[i]["data"]["raw_key"] = json!(format!("0x{}", uint(1 << 50)));
    let (ok, report) = c.check(rows.clone(), None, &all_blocks());
    assert!(!ok);
    let f = failures(&report);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0]["reason"], "key_not_written");
    assert_eq!(f[0]["ordinal"], rows[i]["ordinal"]);
    assert_eq!(f[0]["type"], "map_set");
    assert_eq!(f[0]["key"], map_key(&uint(1 << 50)));
    assert_eq!(report["blocks"][12]["root_ok"], true);
    assert_eq!(report["summary"]["blocks_failed"], 1);
}

#[test]
fn wrong_final_value_is_value_mismatch() {
    let c = chain();
    let mut rows = c.rows();
    let i = rows
        .iter()
        .rposition(|r| r["type"] == "var_set" && r["block_height"] == 20)
        .unwrap();
    rows[i]["data"]["raw_value"] = json!(format!("0x{}", uint(424242)));
    let (ok, report) = c.check(rows, None, &all_blocks());
    assert!(!ok);
    let f = failures(&report);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0]["reason"], "value_mismatch");
    assert_eq!(f[0]["key"], format!("vm::{CONTRACT}::1::n"));
    let want = TrieHash::from_data(uint(424242).as_bytes());
    assert_eq!(f[0]["expected"], to_hex(want.as_bytes()));
    assert_ne!(f[0]["leaf"], f[0]["expected"]);

    // The same mismatch in the storage-layer log.
    let mut writes = c.writes();
    let i = writes
        .iter()
        .position(|w| {
            w["block_height"] == 20 && w["key"].as_str().unwrap().starts_with("vm-account")
        })
        .unwrap();
    writes[i]["value_hex"] = json!(to_hex(b"ffff"));
    let (ok, report) = c.check(c.rows(), Some(writes), &all_blocks());
    assert!(!ok);
    let f = failures(&report);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(
        (f[0]["source"].as_str(), f[0]["reason"].as_str()),
        (Some("write"), Some("value_mismatch"))
    );
}

#[test]
fn changed_leaf_missing_from_writes_is_unnamed_and_fails() {
    let c = chain();
    let mut writes = c.writes();
    let i = writes
        .iter()
        .position(|w| {
            w["block_height"] == 30 && w["key"].as_str().unwrap().starts_with("vm-account")
        })
        .unwrap();
    let dropped = writes.remove(i);
    let (ok, report) = c.check(c.rows(), Some(writes), &all_blocks());
    assert!(!ok);
    assert!(failures(&report).is_empty());
    assert_eq!(report["summary"]["unnamed"], 1);
    let b = &report["blocks"][30];
    let path = TrieHash::from_key(dropped["key"].as_str().unwrap());
    assert_eq!(b["unnamed_paths"], json!([to_hex(path.as_bytes())]));
    assert_eq!(report["summary"]["blocks_failed"], 1);
}

#[test]
fn only_the_last_write_to_a_key_must_match() {
    let c = chain();
    let hot = |rows: &[Json], h: u64| -> Vec<usize> {
        rows.iter()
            .enumerate()
            .filter(|(_, r)| {
                r["block_height"] == h && r["data"]["raw_key"] == format!("0x{}", uint(HOT_KEY))
            })
            .map(|(i, _)| i)
            .collect()
    };
    // Earlier writes to the hot key may carry any value: only the path must exist.
    let mut rows = c.rows();
    let idx = hot(&rows, 5);
    assert_eq!(idx.len(), 3);
    rows[idx[0]]["data"]["raw_value"] = json!(format!("0x{}", uint(1)));
    rows[idx[1]]["data"]["raw_value"] = json!(format!("0x{}", uint(2)));
    let (ok, report) = c.check(rows, None, &["--height", "5"]);
    assert!(ok, "{report:#}");

    // Moving an earlier write last (by ordinal) makes its value the one checked.
    let mut rows = c.rows();
    let idx = hot(&rows, 5);
    let (o0, o2) = (
        rows[idx[0]]["ordinal"].clone(),
        rows[idx[2]]["ordinal"].clone(),
    );
    rows[idx[0]]["ordinal"] = o2;
    rows[idx[2]]["ordinal"] = o0;
    let (ok, report) = c.check(rows, None, &["--height", "5"]);
    assert!(!ok);
    let f = failures(&report);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(f[0]["reason"], "value_mismatch");
    assert_eq!(f[0]["key"], map_key(&uint(HOT_KEY)));
}

#[test]
fn unknown_block_is_reported_and_the_rest_still_checked() {
    let c = chain();
    let (good, bad) = (block(3).to_string(), block(9999).to_string());
    let (ok, report) = c.check(c.rows(), None, &["--block", &bad, &good, "nothex"]);
    assert!(!ok);
    let blocks = report["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 3);
    assert!(
        blocks[0]["error"]
            .as_str()
            .unwrap()
            .contains("not in this MARF")
    );
    assert!(blocks[1].get("error").is_none());
    assert_eq!(blocks[1]["root_ok"], true);
    assert!(
        blocks[2]["error"]
            .as_str()
            .unwrap()
            .contains("not a 32-byte")
    );
    assert_eq!(report["summary"]["errors"], 2);
}

fn mainnet_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mainnet")
        .join(name)
}

const MAINNET_BLOCK: &str = "68df6083cbf08375d57a27aed303e9bb95c101ce9b08813aa519ba6887a730f2";
/// `reserve[SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.token-wkiki]` of amm-vault-v2-01.
const RESERVE_LEAF: &str = "8b37d712c09450c011f6ce9bfc67fb0dd3bf3743a4ae69534283519ae4f55459";

fn check_mainnet(rows: &Path) -> (bool, Json) {
    let witness = mainnet_fixture(&format!("{MAINNET_BLOCK}.witness"));
    let o = run(&[
        "check",
        "--witness",
        witness.to_str().unwrap(),
        "--rows",
        rows.to_str().unwrap(),
    ]);
    (
        o.status.success(),
        serde_json::from_str(&stdout(&o)).unwrap(),
    )
}

#[test]
fn mainnet_1230200_buggy_reserve_row_is_key_not_written() {
    let witness = std::fs::read(mainnet_fixture(&format!("{MAINNET_BLOCK}.witness"))).unwrap();
    let v = marf_witness::wire::verify(&witness).unwrap();
    assert_eq!(
        to_hex(v.root.as_bytes()),
        "d7947b1bfd2badf58aea19d966ec7615da26520ab9358c65220f1d21593bb2a9"
    );

    let (ok, report) = check_mainnet(&mainnet_fixture("vm-1230200-rows.jsonl"));
    assert!(!ok);
    let b = &report["blocks"][0];
    assert_eq!(
        (b["height"].as_u64(), b["id"].as_str()),
        (Some(1_230_200), Some(MAINNET_BLOCK))
    );
    assert_eq!(b["rows_checked"], 2);
    // Ordinal 19 (key = previous value) fails; ordinal 22 names its leaf with the right value.
    let f = failures(&report);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!(
        (f[0]["ordinal"].as_u64(), f[0]["reason"].as_str()),
        (Some(19), Some("key_not_written"))
    );
    assert_eq!(b["leaves"]["written_named"], 1);
    assert_eq!(b["leaves"]["internal"], 5);
    let unnamed = b["unnamed_paths"].as_array().unwrap();
    assert!(unnamed.contains(&json!(RESERVE_LEAF)), "{unnamed:?}");

    // The row as the fixed collector emits it (key = the token principal) names that leaf.
    let tmp = tempdir();
    let mut fixed: Json = serde_json::from_str(
        std::fs::read_to_string(mainnet_fixture("vm-1230200-rows.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    fixed["data"]["raw_key"] =
        json!("0x0616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0b746f6b656e2d776b696b69");
    let rows = write_jsonl(tmp.path(), "fixed.jsonl", [fixed]);
    let (ok, report) = check_mainnet(&rows);
    assert!(ok, "{report:#}");
    let b = &report["blocks"][0];
    assert!(
        !b["unnamed_paths"]
            .as_array()
            .unwrap()
            .contains(&json!(RESERVE_LEAF))
    );
}
