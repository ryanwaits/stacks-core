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

//! `check`: verify a write log against each block's state witness.
//!
//! It verifies, never re-executes. A block's trie holds a leaf for every key
//! the block wrote, so for each block:
//!
//! 1. the witness root must equal the MARF root (and the header root, given an RPC);
//! 2. every logged write must name a leaf of the block, and the last write to
//!    each key must match that leaf's value hash;
//! 3. every leaf is classified: named by the log, MARF-internal
//!    (`__MARF_BLOCK_*`), carried (copy-on-write, same value at the parent),
//!    or unnamed. With a storage-layer write log, an unnamed leaf is a gap.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::{Sha512Trunc256Sum, hex_bytes, to_hex};
use stackslib::chainstate::stacks::index::MARFValue;
use stackslib::chainstate::stacks::index::marf::{
    BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, OWN_BLOCK_HEIGHT_KEY,
};
use stackslib::clarity::vm::database::{ClarityDatabase, StoreType};
use stackslib::clarity::vm::types::QualifiedContractIdentifier;
use stackslib::net::httpcore::{StacksHttpRequest, send_http_request};

use crate::extract::ReadOnlyMarf;
use crate::wire::{self, Leaf};

/// Serialized `(some …)` prefix and `none`, as `put_value` stores map entries.
pub const SOME_PREFIX: &str = "0a";
pub const NONE: &str = "09";

/// One `vm_events` row.
#[derive(Debug, Clone, Deserialize)]
pub struct Row {
    pub block_height: u64,
    pub ordinal: i64,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub tx_id: Option<String>,
    #[serde(default)]
    pub data: Json,
}

/// One storage-layer write: the full MARF key and the hex of the side-store
/// value string's bytes.
#[derive(Debug, Clone, Deserialize)]
pub struct Write {
    pub block_height: u64,
    pub tx_index: Option<u32>,
    pub ordinal: i64,
    pub key: String,
    pub value_hex: String,
}

/// Parse JSON lines; blank lines are skipped.
pub fn read_jsonl<T: DeserializeOwned>(r: impl BufRead, what: &str) -> Result<Vec<T>, String> {
    let mut out = vec![];
    for (i, line) in r.lines().enumerate() {
        let line = line.map_err(|e| format!("read {what}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line).map_err(|e| format!("{what} line {}: {e}", i + 1))?);
    }
    Ok(out)
}

fn hex_field(data: &Json, name: &str) -> Result<String, String> {
    let v = str_field(data, name)?;
    let h = v.strip_prefix("0x").unwrap_or(v).to_ascii_lowercase();
    if h.is_empty() || h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("data.{name} is not hex: {v}"));
    }
    Ok(h)
}

fn str_field<'a>(data: &'a Json, name: &str) -> Result<&'a str, String> {
    data.get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("data.{name} missing"))
}

/// The MARF key a row writes and the side-store string it leaves there, or
/// `None` for rows that write nothing (`nested_contract_call`).
pub fn row_write(row: &Row) -> Result<Option<(String, String)>, String> {
    let d = &row.data;
    let contract = || {
        let c = str_field(d, "contract_identifier")?;
        QualifiedContractIdentifier::parse(c).map_err(|e| format!("contract {c}: {e:?}"))
    };
    let map_key = || -> Result<String, String> {
        Ok(ClarityDatabase::make_key_for_quad(
            &contract()?,
            StoreType::DataMap,
            str_field(d, "map_name")?,
            &hex_field(d, "raw_key")?,
        ))
    };
    Ok(Some(match row.kind.as_str() {
        "nested_contract_call" => return Ok(None),
        "var_set" => (
            ClarityDatabase::make_key_for_trip(
                &contract()?,
                StoreType::Variable,
                str_field(d, "var_name")?,
            ),
            hex_field(d, "raw_value")?,
        ),
        "map_set" | "map_insert" => (
            map_key()?,
            format!("{SOME_PREFIX}{}", hex_field(d, "raw_value")?),
        ),
        "map_delete" => (map_key()?, NONE.to_string()),
        other => return Err(format!("unknown type {other}")),
    }))
}

/// Leaf value hash of a side-store value string.
pub fn value_hash(value: &[u8]) -> [u8; 32] {
    Sha512Trunc256Sum::from_data(value).0
}

fn path_of(key: &str) -> [u8; 32] {
    TrieHash::from_key(key).0
}

fn height_value(h: u32) -> [u8; 32] {
    MARFValue::from(h).0[..32].try_into().expect("32 bytes")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Row,
    Write,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The write's key is not a leaf of the block's trie.
    KeyNotWritten,
    /// The last write to a key differs from the leaf's value.
    ValueMismatch,
    /// The row or write could not be turned into a MARF key and value.
    BadRow,
    /// A `__MARF_BLOCK_*` leaf is missing or has the wrong value.
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Failure {
    pub source: Source,
    pub reason: Reason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<i64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub row_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Value hash the log implies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// Value hash in the block's trie.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Failure {
    fn new(source: Source, reason: Reason) -> Self {
        Failure {
            source,
            reason,
            ordinal: None,
            row_type: None,
            tx_id: None,
            tx_index: None,
            key: None,
            path: None,
            expected: None,
            leaf: None,
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LeafCounts {
    pub written_named: usize,
    pub internal: usize,
    pub carried: usize,
    pub unnamed: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BlockReport {
    pub height: Option<u32>,
    pub id: Option<String>,
    /// Root recomputed from the witness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Witness root == MARF root (and == header root when checked). `null`
    /// offline, where there is nothing to compare against.
    pub root_ok: Option<bool>,
    pub rows_checked: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writes_checked: Option<usize>,
    pub row_failures: Vec<Failure>,
    pub leaves: LeafCounts,
    pub unnamed_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The block could not be checked at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BlockReport {
    /// Whether this block fails the gate. Unnamed leaves fail only when a
    /// storage-layer write log was given (rows alone never name every leaf).
    pub fn failed(&self) -> bool {
        self.error.is_some()
            || self.root_ok == Some(false)
            || !self.row_failures.is_empty()
            || (self.writes_checked.is_some() && self.leaves.unnamed > 0)
    }
}

/// The write log for one block.
pub struct BlockLog<'a> {
    pub rows: Vec<&'a Row>,
    /// `None` when no storage-layer log was given.
    pub writes: Option<Vec<&'a Write>>,
}

/// Result of checking one block's leaves against its log.
#[derive(Debug, Default)]
pub struct LeafCheck {
    pub rows_checked: usize,
    pub writes_checked: Option<usize>,
    pub failures: Vec<Failure>,
    pub leaves: LeafCounts,
    pub unnamed_paths: Vec<String>,
}

/// A logged write reduced to its leaf path and expected value hash.
struct Named<F> {
    path: [u8; 32],
    key: String,
    hash: [u8; 32],
    describe: F,
}

/// Path presence for every write, value match for the last write per path.
/// `named` must be in execution order.
fn match_writes<F: Fn() -> Failure>(
    named: &[Named<F>],
    leaves: &HashMap<[u8; 32], [u8; 32]>,
    failures: &mut Vec<Failure>,
) {
    let last: HashMap<[u8; 32], usize> =
        named.iter().enumerate().map(|(i, n)| (n.path, i)).collect();
    for (i, n) in named.iter().enumerate() {
        let fail = |reason, leaf: Option<&[u8; 32]>| {
            let mut f = (n.describe)();
            f.reason = reason;
            f.key = Some(n.key.clone());
            f.path = Some(to_hex(&n.path));
            f.expected = Some(to_hex(&n.hash));
            f.leaf = leaf.map(|l| to_hex(l));
            f
        };
        match leaves.get(&n.path) {
            None => failures.push(fail(Reason::KeyNotWritten, None)),
            Some(leaf) if last[&n.path] == i && *leaf != n.hash => {
                failures.push(fail(Reason::ValueMismatch, Some(leaf)))
            }
            Some(_) => {}
        }
    }
}

/// The `__MARF_BLOCK_*` leaves every block writes, checked for value. Returns
/// their paths and the parent block id (from `HEIGHT_TO_HASH::{h-1}`).
///
/// The MARF names a block's own trie by a temporary hash while it is built, so
/// `HEIGHT_TO_HASH::{h}` holds that hash and the next block writes the real id
/// at `HEIGHT_TO_HASH::{h-1}`.
fn internal_leaves(
    height: u32,
    leaves: &HashMap<[u8; 32], [u8; 32]>,
    failures: &mut Vec<Failure>,
) -> (HashSet<[u8; 32]>, Option<StacksBlockId>) {
    let mut paths = HashSet::new();
    let mut expect = |key: String, want: Option<[u8; 32]>| -> Option<[u8; 32]> {
        let path = path_of(&key);
        let got = leaves.get(&path).copied();
        if got.is_none() || (want.is_some() && got != want) {
            let mut f = Failure::new(Source::Internal, Reason::Internal);
            f.path = Some(to_hex(&path));
            f.expected = want.map(|w| to_hex(&w));
            f.leaf = got.map(|g| to_hex(&g));
            f.key = Some(key);
            failures.push(f);
        }
        paths.insert(path);
        got
    };
    expect(OWN_BLOCK_HEIGHT_KEY.into(), Some(height_value(height)));
    let own = expect(
        format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}"),
        None,
    );
    if let Some(own) = own {
        expect(
            format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{}", StacksBlockId(own)),
            Some(height_value(height)),
        );
    }
    let mut parent = None;
    if height > 0 {
        parent = expect(
            format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{}", height - 1),
            None,
        )
        .map(StacksBlockId);
        if let Some(p) = &parent {
            expect(
                format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{p}"),
                Some(height_value(height - 1)),
            );
        }
    }
    (paths, parent)
}

/// Reads a leaf's value hash at the parent block, by path.
pub type ParentValue<'a> =
    &'a mut dyn FnMut(&StacksBlockId, &[u8; 32]) -> Result<Option<[u8; 32]>, String>;

/// Check a block's leaves against its write log. `parent_value(parent, path)`
/// reads a leaf's value hash at the parent block; `None` disables carried-leaf
/// detection (offline), so carried leaves count as unnamed.
pub fn check_leaves(
    height: u32,
    leaves: &[Leaf],
    log: &BlockLog,
    parent_value: Option<ParentValue>,
) -> Result<LeafCheck, String> {
    let by_path: HashMap<[u8; 32], [u8; 32]> =
        leaves.iter().map(|l| (l.path, l.value_hash)).collect();
    let mut out = LeafCheck::default();
    let mut named_paths = HashSet::new();

    let mut rows = log.rows.clone();
    rows.sort_by_key(|r| r.ordinal);
    let mut named = vec![];
    for row in rows {
        let describe = move || {
            let mut f = Failure::new(Source::Row, Reason::BadRow);
            f.ordinal = Some(row.ordinal);
            f.row_type = Some(row.kind.clone());
            f.tx_id = row.tx_id.clone();
            f
        };
        match row_write(row) {
            Ok(None) => {}
            Ok(Some((key, value))) => named.push(Named {
                path: path_of(&key),
                key,
                hash: value_hash(value.as_bytes()),
                describe,
            }),
            Err(e) => {
                let mut f = describe();
                f.detail = Some(e);
                out.failures.push(f);
            }
        }
    }
    out.rows_checked = named.len();
    match_writes(&named, &by_path, &mut out.failures);
    named_paths.extend(named.iter().map(|n| n.path));

    if let Some(writes) = &log.writes {
        // Block-level writes (no tx) run before the block's transactions.
        let mut writes = writes.clone();
        writes.sort_by_key(|w| (w.tx_index.is_some(), w.tx_index, w.ordinal));
        let mut named = vec![];
        for w in writes {
            let describe = move || {
                let mut f = Failure::new(Source::Write, Reason::BadRow);
                f.ordinal = Some(w.ordinal);
                f.tx_index = w.tx_index;
                f
            };
            match hex_bytes(w.value_hex.trim_start_matches("0x")) {
                Ok(bytes) => named.push(Named {
                    path: path_of(&w.key),
                    key: w.key.clone(),
                    hash: value_hash(&bytes),
                    describe,
                }),
                Err(_) => {
                    let mut f = describe();
                    f.key = Some(w.key.clone());
                    f.detail = Some(format!("value_hex is not hex: {}", w.value_hex));
                    out.failures.push(f);
                }
            }
        }
        out.writes_checked = Some(named.len());
        match_writes(&named, &by_path, &mut out.failures);
        named_paths.extend(named.iter().map(|n| n.path));
    }

    let (internal, parent) = internal_leaves(height, &by_path, &mut out.failures);
    let mut parent_value = parent_value;
    for leaf in leaves {
        let counts = &mut out.leaves;
        if named_paths.contains(&leaf.path) {
            counts.written_named += 1;
        } else if internal.contains(&leaf.path) {
            counts.internal += 1;
        } else if let (Some(read), Some(parent)) = (parent_value.as_mut(), &parent)
            && read(parent, &leaf.path)? == Some(leaf.value_hash)
        {
            counts.carried += 1;
        } else {
            counts.unnamed += 1;
            out.unnamed_paths.push(to_hex(&leaf.path));
        }
    }
    Ok(out)
}

/// A Stacks node RPC endpoint for header roots (`http://host:port`).
pub struct Rpc {
    host: String,
    port: u16,
}

impl Rpc {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("--rpc must be http://host[:port], got {url}"))?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| format!("bad port in {url}"))?),
            None => (authority, 80),
        };
        if host.is_empty() {
            return Err(format!("no host in {url}"));
        }
        Ok(Rpc {
            host: host.to_string(),
            port,
        })
    }

    /// `state_index_root` from `/v3/blocks/<id>`, or `None` when the node has
    /// no Nakamoto block by that id (epoch 2.x blocks are not served there).
    pub fn header_root(&self, block: &StacksBlockId) -> Result<Option<TrieHash>, String> {
        let req = StacksHttpRequest::new_get_nakamoto_block(
            PeerHost::DNS(self.host.clone(), self.port),
            block.clone(),
        )
        .with_header("Connection".into(), "close".into());
        match send_http_request(&self.host, self.port, req, Duration::from_secs(60)) {
            Ok(resp) => {
                let b = resp
                    .decode_nakamoto_block()
                    .map_err(|e| format!("decode /v3/blocks/{block}: {e:?}"))?;
                if b.header.block_id() != *block {
                    return Err(format!(
                        "/v3/blocks/{block} returned block {}",
                        b.header.block_id()
                    ));
                }
                Ok(Some(b.header.state_index_root))
            }
            Err(e) if e.to_string().contains("(404 != 200)") => Ok(None),
            Err(e) => Err(format!("GET /v3/blocks/{block}: {e}")),
        }
    }
}

/// Check one block of a MARF: extract its witness in-process, compare roots,
/// then check its leaves. Errors land in the report, never abort the run.
pub fn check_marf_block<'a>(
    marf: &mut ReadOnlyMarf,
    block: &StacksBlockId,
    log: &dyn Fn(u32) -> BlockLog<'a>,
    rpc: Option<&Rpc>,
) -> BlockReport {
    let mut report = BlockReport {
        id: Some(block.to_string()),
        ..Default::default()
    };
    if let Err(e) = check_marf_block_inner(marf, block, log, rpc, &mut report) {
        report.error = Some(e);
    }
    report
}

fn check_marf_block_inner<'a>(
    marf: &mut ReadOnlyMarf,
    block: &StacksBlockId,
    log: &dyn Fn(u32) -> BlockLog<'a>,
    rpc: Option<&Rpc>,
    report: &mut BlockReport,
) -> Result<(), String> {
    let height = marf.height_of(block)?;
    report.height = Some(height);
    let expected = marf.root_hash_at(block)?;
    let v = wire::verify(&marf.witness(block)?)?;
    report.root = Some(to_hex(v.root.as_bytes()));
    let mut root_ok = v.root == expected;
    if !root_ok {
        report.notes.push(format!("MARF root is {expected}"));
    }
    if let Some(rpc) = rpc {
        match rpc.header_root(block)? {
            Some(h) if h == expected => {}
            Some(h) => {
                root_ok = false;
                report.notes.push(format!("header state_index_root is {h}"));
            }
            None => report
                .notes
                .push("header root not checked: /v3/blocks has no such block (epoch 2.x)".into()),
        }
    }
    report.root_ok = Some(root_ok);

    let mut read = |parent: &StacksBlockId, path: &[u8; 32]| marf.value_at(parent, path);
    let c = check_leaves(height, &v.leaves, &log(height), Some(&mut read))?;
    fill(report, c);
    Ok(())
}

/// Check one witness file with no MARF: the height comes from its
/// `__MARF_BLOCK_HEIGHT_SELF` leaf, the root is not compared, and carried
/// leaves cannot be told apart from unnamed ones.
pub fn check_witness<'a>(
    bytes: &[u8],
    id: Option<String>,
    log: &dyn Fn(u32) -> BlockLog<'a>,
) -> BlockReport {
    let mut report = BlockReport {
        id,
        ..Default::default()
    };
    let res = (|| {
        let v = wire::verify(bytes)?;
        report.root = Some(to_hex(v.root.as_bytes()));
        let own = path_of(OWN_BLOCK_HEIGHT_KEY);
        let h = v
            .leaves
            .iter()
            .find(|l| l.path == own)
            .ok_or("witness has no __MARF_BLOCK_HEIGHT_SELF leaf")?
            .value_hash;
        let height = u32::from_le_bytes(h[..4].try_into().expect("4 bytes"));
        report.height = Some(height);
        report
            .notes
            .push("offline: root not compared; carried leaves count as unnamed".into());
        check_leaves(height, &v.leaves, &log(height), None)
    })();
    match res {
        Ok(c) => fill(&mut report, c),
        Err(e) => report.error = Some(e),
    }
    report
}

fn fill(report: &mut BlockReport, c: LeafCheck) {
    report.rows_checked = c.rows_checked;
    report.writes_checked = c.writes_checked;
    report.row_failures = c.failures;
    report.leaves = c.leaves;
    report.unnamed_paths = c.unnamed_paths;
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub ok: bool,
    pub blocks: usize,
    pub blocks_failed: usize,
    pub errors: usize,
    pub root_mismatches: usize,
    pub rows_checked: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writes_checked: Option<usize>,
    pub row_failures: usize,
    pub unnamed: usize,
    /// Rows (and writes) whose height matched no checked block.
    pub rows_unmatched: usize,
    /// Block that `--height`/`--from`/`--to` resolved heights against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub blocks: Vec<BlockReport>,
    pub summary: Summary,
}

pub fn summarize(
    blocks: Vec<BlockReport>,
    writes_given: bool,
    rows_unmatched: usize,
    tip: Option<String>,
) -> Report {
    let sum = |f: fn(&BlockReport) -> usize| blocks.iter().map(f).sum::<usize>();
    let summary = Summary {
        ok: !blocks.iter().any(BlockReport::failed),
        blocks: blocks.len(),
        blocks_failed: blocks.iter().filter(|b| b.failed()).count(),
        errors: sum(|b| b.error.is_some() as usize),
        root_mismatches: sum(|b| (b.root_ok == Some(false)) as usize),
        rows_checked: sum(|b| b.rows_checked),
        writes_checked: writes_given.then(|| sum(|b| b.writes_checked.unwrap_or(0))),
        row_failures: sum(|b| b.row_failures.len()),
        unnamed: sum(|b| b.leaves.unnamed),
        rows_unmatched,
        tip,
    };
    Report { blocks, summary }
}

#[cfg(test)]
mod tests {
    use stackslib::clarity::vm::Value;

    use super::*;

    #[test]
    fn stored_forms_match_clarity_serialization() {
        let v = Value::UInt(42);
        let raw = v.serialize_to_hex().unwrap();
        let some = Value::some(v).unwrap().serialize_to_hex().unwrap();
        assert_eq!(some, format!("{SOME_PREFIX}{raw}"));
        assert_eq!(Value::none().serialize_to_hex().unwrap(), NONE);
    }

    #[test]
    fn row_keys_follow_clarity_db() {
        let row = |kind: &str, data: Json| Row {
            block_height: 1,
            ordinal: 0,
            kind: kind.into(),
            tx_id: None,
            data,
        };
        let c = "SP000000000000000000002Q6VF78.pox";
        let (k, v) = row_write(&row(
            "var_set",
            serde_json::json!({"contract_identifier": c, "var_name": "n", "raw_value": "0x0100000000000000000000000000000001"}),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(k, format!("vm::{c}::1::n"));
        assert_eq!(v, "0100000000000000000000000000000001");
        let (k, v) = row_write(&row(
            "map_insert",
            serde_json::json!({"contract_identifier": c, "map_name": "m", "raw_key": "0x0D0000000161", "raw_value": "0x03"}),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(k, format!("vm::{c}::0::m::0d0000000161"));
        assert_eq!(v, "0a03");
        let (_, v) = row_write(&row(
            "map_delete",
            serde_json::json!({"contract_identifier": c, "map_name": "m", "raw_key": "0x03"}),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(v, "09");
        assert!(
            row_write(&row("nested_contract_call", Json::Null))
                .unwrap()
                .is_none()
        );
        assert!(row_write(&row("map_set", serde_json::json!({}))).is_err());
        assert!(row_write(&row("stx_transfer", Json::Null)).is_err());
    }

    #[test]
    fn rpc_url_parsing() {
        let r = Rpc::parse("http://localhost:20443/").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("localhost", 20443));
        assert_eq!(Rpc::parse("http://node").unwrap().port, 80);
        assert!(Rpc::parse("https://node").is_err());
    }
}
