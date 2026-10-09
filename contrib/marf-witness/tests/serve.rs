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

//! The `serve` sidecar over a node-shaped working dir: local MARF, mainnet
//! sortition rows, and a small SPV headers DB.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use marf_witness::extract::ReadOnlyMarf;
use marf_witness::serve::{Config, Server, Slots};
use marf_witness::wire;
use rusqlite::{Connection, params};
use serde_json::Value;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::deps_common::bitcoin::blockdata::block::BlockHeader;
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId, TrieHash};
use stacks_common::util::hash::{hex_bytes, to_hex};
use stackslib::chainstate::stacks::index::marf::MARF;
use stackslib::chainstate::stacks::index::{MARFValue, TrieMerkleProof};

const MAINNET_GENESIS_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
const MAINNET_GENESIS_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
/// Headers stored in the fixture: mainnet genesis plus chained synthetic ones.
const HEADERS: u64 = 10;
const MARF_BLOCKS: u64 = 40;

/// A node working dir (`…/mainnet`) laid out as stacks-node lays it out.
struct NodeDir {
    _tmp: tempfile::TempDir,
    wd: PathBuf,
    local: LocalMarf,
}

impl NodeDir {
    fn new() -> Self {
        let tmp = tempdir();
        let wd = tmp.path().join("mainnet");
        let local = build_marf(&wd.join("chainstate/vm/clarity"), MARF_BLOCKS, 0, false);
        let sortition = wd.join("burnchain/sortition");
        std::fs::create_dir_all(&sortition).unwrap();
        let db = mainnet_sortition_db(&sortition);
        std::fs::rename(db, sortition.join("marf.sqlite")).unwrap();
        write_headers_db(&wd.join("headers.sqlite"));
        Self {
            _tmp: tmp,
            wd,
            local,
        }
    }

    fn sortition_db(&self) -> PathBuf {
        self.wd.join("burnchain/sortition/marf.sqlite")
    }

    fn headers_db(&self) -> PathBuf {
        self.wd.join("headers.sqlite")
    }

    /// Directories holding database files, for before/after digests.
    fn db_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.wd.clone(),
            self.wd.join("chainstate/vm/clarity"),
            self.wd.join("burnchain/sortition"),
        ]
    }

    fn snapshot(&self) -> Vec<BTreeMap<String, String>> {
        self.db_dirs().iter().map(|d| digests(d)).collect()
    }

    fn assert_untouched(&self, before: &[BTreeMap<String, String>]) {
        for (dir, before) in self.db_dirs().iter().zip(before) {
            assert_untouched(dir, before);
        }
    }

    /// Run an in-process server; returns its address and extraction slots.
    fn serve(&self, slots: usize) -> (SocketAddr, Arc<Slots>) {
        let server = Server::bind(Config {
            marf: self.local.path.clone(),
            sortition_db: self.sortition_db(),
            headers_db: self.headers_db(),
            listen: "127.0.0.1:0".parse().unwrap(),
            max_concurrent_extractions: slots,
            cache_bytes: 1 << 20,
            request_timeout: Duration::from_secs(10),
        })
        .unwrap();
        let addr = server.local_addr().unwrap();
        let slots = server.extraction_slots();
        std::thread::spawn(move || server.run());
        (addr, slots)
    }
}

/// stackslib's SPV schema v3: mainnet genesis, then headers chained by prev hash.
fn write_headers_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE headers(
            version INTEGER NOT NULL,
            prev_blockhash TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            time INTEGER NOT NULL,
            bits INTEGER NOT NULL,
            nonce INTEGER NOT NULL,
            height INTEGER PRIMARY KEY NOT NULL,
            hash TEXT NOT NULL);
         CREATE INDEX index_headers_by_hash ON headers(hash);
         CREATE TABLE chain_work(interval INTEGER PRIMARY KEY, work TEXT NOT NULL);
         CREATE TABLE db_config(version TEXT NOT NULL);
         INSERT INTO db_config (version) VALUES ('3');",
    )
    .unwrap();
    let mut headers = vec![BlockHeader {
        version: 1,
        prev_blockhash: Sha256dHash([0; 32]),
        merkle_root: Sha256dHash::from_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .unwrap(),
        time: 1231006505,
        bits: 0x1d00ffff,
        nonce: 2083236893,
    }];
    for i in 1..HEADERS {
        let prev = headers.last().unwrap().bitcoin_hash();
        headers.push(BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: prev,
            merkle_root: Sha256dHash::from_data(format!("merkle-{i}").as_bytes()),
            time: 1231006505 + 600 * i as u32,
            bits: 0x1d00ffff,
            nonce: u32::MAX - i as u32,
        });
    }
    for (height, h) in headers.iter().enumerate() {
        conn.execute(
            "INSERT INTO headers (version, prev_blockhash, merkle_root, time, bits, nonce, height, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                h.version,
                h.prev_blockhash,
                h.merkle_root,
                h.time,
                h.bits,
                h.nonce,
                height as i64,
                BurnchainHeaderHash::from_bitcoin_hash(&h.bitcoin_hash()),
            ],
        )
        .unwrap();
    }
}

struct Reply {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("no {name} header in {:?}", self.headers))
    }
}

fn request(addr: SocketAddr, method: &str, target: &str) -> Reply {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "{method} {target} HTTP/1.1\r\nhost: test\r\n\r\n").unwrap();
    let mut raw = vec![];
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(": ").unwrap();
            (k.to_ascii_lowercase(), v.to_string())
        })
        .collect::<HashMap<_, _>>();
    let body = raw[split + 4..].to_vec();
    assert_eq!(headers["content-length"], body.len().to_string());
    Reply {
        status,
        headers,
        body,
    }
}

fn get(addr: SocketAddr, target: &str) -> Reply {
    request(addr, "GET", target)
}

#[test]
fn served_witness_equals_extract_output_and_recomputes_the_marf_root() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let out = node.wd.parent().unwrap().join("out");
    let mut marf = ReadOnlyMarf::open(&node.local.path).unwrap();

    for height in [1, 20, MARF_BLOCKS as usize - 1] {
        let block = &node.local.blocks[height];
        let r = get(addr, &format!("/witness/{block}"));
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), "application/octet-stream");
        assert_eq!(
            r.header("cache-control"),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(r.header("x-block-height"), height.to_string());
        assert_eq!(r.header("x-cache"), "miss");

        let o = run(&[
            "extract",
            "--marf",
            node.local.path.to_str().unwrap(),
            "--block",
            &block.to_string(),
            "--out",
            out.to_str().unwrap(),
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        let extracted = std::fs::read(out.join(format!("{block}.witness"))).unwrap();
        assert!(r.body == extracted, "served witness of {height} != extract");

        let root = to_hex(marf.root_hash_at(block).unwrap().as_bytes());
        assert_eq!(r.header("x-state-root"), root);
        let v = wire::verify(&r.body).unwrap();
        assert_eq!(to_hex(v.root.as_bytes()), root);

        let again = get(addr, &format!("/witness/0x{block}"));
        assert_eq!(again.header("x-cache"), "hit");
        assert!(again.body == r.body);
    }

    // The CLI verifier accepts the served bytes against the header root.
    let block = &node.local.blocks[20];
    let r = get(addr, &format!("/witness/{block}"));
    let file = out.join("served.witness");
    std::fs::write(&file, &r.body).unwrap();
    let o = run(&[
        "verify",
        file.to_str().unwrap(),
        "--root",
        r.header("x-state-root"),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
}

#[test]
fn unknown_block_is_404_and_malformed_requests_are_rejected() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let r = get(addr, &format!("/witness/{}", "ab".repeat(32)));
    assert_eq!(r.status, 404);
    assert!(r.json()["error"].is_string());
    assert_eq!(get(addr, "/witness/not-a-hash").status, 400);
    assert_eq!(
        get(addr, &format!("/witness/{}", "ab".repeat(31))).status,
        400
    );
    assert_eq!(get(addr, "/nowhere").status, 404);
    let r = request(addr, "POST", "/health");
    assert_eq!((r.status, r.header("allow")), (405, "GET"));
}

#[test]
fn burn_route_returns_the_mainnet_preimage_and_404_for_unknown_hashes() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let want = burn_fixture("preimage-970269.json");
    let ch = want["consensus_hash"].as_str().unwrap();

    let r = get(addr, &format!("/burn/{ch}"));
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), "application/json");
    let got = r.json();
    let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "bitcoin_block_hash",
            "burn_height",
            "consensus_hash",
            "preimage"
        ]
    );
    assert_eq!(got["consensus_hash"], ch);
    assert_eq!(got["burn_height"], 970269);
    assert_eq!(got["bitcoin_block_hash"], want["bitcoin_block_hash"]);
    assert_eq!(got["preimage"], want["preimage"]);
    // preimage[4..36] is the Bitcoin block hash as displayed, no reversal
    let pre = hex_bytes(got["preimage"].as_str().unwrap()).unwrap();
    assert_eq!(to_hex(&pre[4..36]), want["bitcoin_block_hash"]);

    assert_eq!(get(addr, &format!("/burn/{}", "ab".repeat(20))).status, 404);
    assert_eq!(get(addr, "/burn/abcd").status, 400);
}

#[test]
fn headers_route_returns_80_byte_wire_headers_in_height_order() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);

    let r = get(addr, &format!("/bitcoin/headers?from=0&count={HEADERS}"));
    assert_eq!(r.status, 200);
    let body = r.json();
    assert_eq!(body["from"], 0);
    let hs: Vec<Vec<u8>> = body["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hex_bytes(h.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(hs.len() as u64, HEADERS);
    assert_eq!(to_hex(&hs[0]), MAINNET_GENESIS_HEADER);
    assert_eq!(
        Sha256dHash::from_data(&hs[0]).be_hex_string(),
        MAINNET_GENESIS_HASH
    );
    for pair in hs.windows(2) {
        assert_eq!(pair[1].len(), 80);
        // Each header's prev-hash field is the previous header's sha256d.
        assert_eq!(pair[1][4..36], Sha256dHash::from_data(&pair[0]).0);
    }

    // Past the tip: truncated, then empty.
    let r = get(addr, "/bitcoin/headers?count=2016&from=5");
    assert_eq!(
        r.json()["headers"].as_array().unwrap().len() as u64,
        HEADERS - 5
    );
    assert_eq!(r.json()["headers"][0].as_str().unwrap(), to_hex(&hs[5]));
    let r = get(addr, "/bitcoin/headers?from=1000&count=5");
    assert_eq!(
        (r.status, r.json()["headers"].as_array().unwrap().len()),
        (200, 0)
    );

    for bad in [
        "count=2017&from=0",
        "from=0&count=0",
        "from=0",
        "from=-1&count=1",
        "from=x&count=1",
    ] {
        assert_eq!(
            get(addr, &format!("/bitcoin/headers?{bad}")).status,
            400,
            "{bad}"
        );
    }

    let h = get(addr, "/health");
    assert_eq!(h.status, 200);
    assert_eq!(h.json()["ok"], true);
    assert_eq!(h.json()["marf_tip_height"], MARF_BLOCKS - 1);
    assert_eq!(h.json()["bitcoin_tip_height"], HEADERS - 1);
}

fn unhex_field(r: &Reply, field: &str) -> Vec<u8> {
    let v = r.json()[field].as_str().unwrap().to_string();
    hex_bytes(v.strip_prefix("0x").unwrap()).unwrap()
}

/// Check a `/marf` answer with stackslib's own `TrieMerkleProof::verify`
/// against `tip`'s state root; returns the proven leaf value.
fn verified_marf_value(
    r: &Reply,
    marf: &mut ReadOnlyMarf,
    blocks: &[StacksBlockId],
    tip: &StacksBlockId,
    path: &TrieHash,
) -> MARFValue {
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("content-type"), "application/json");
    let value = MARFValue(unhex_field(r, "data").try_into().unwrap());
    let bytes = unhex_field(r, "proof");
    let proof = TrieMerkleProof::<StacksBlockId>::consensus_deserialize(&mut &bytes[..]).unwrap();
    let root_to_block: HashMap<TrieHash, StacksBlockId> = blocks
        .iter()
        .map(|b| (marf.root_hash_at(b).unwrap(), b.clone()))
        .collect();
    let root = marf.root_hash_at(tip).unwrap();
    assert!(
        proof.verify(path, &value, &root, &root_to_block),
        "proof of {path} at {tip} does not verify"
    );
    value
}

#[test]
fn marf_route_proves_height_to_hash_keys_against_the_tip_root() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let mut marf = ReadOnlyMarf::open(&node.local.path).unwrap();
    let blocks = &node.local.blocks;
    let tip = blocks.last().unwrap();
    let mut proofs = vec![];

    for height in [0, 5, MARF_BLOCKS as usize - 2] {
        let key = format!("__MARF_BLOCK_HEIGHT_TO_HASH::{height}");
        let path = TrieHash::from_key(&key);
        let by_key = get(addr, &format!("/marf?key={key}&tip={tip}"));
        let value = verified_marf_value(&by_key, &mut marf, blocks, tip, &path);
        // The value is the block id at that height, zero-padded to 40 bytes.
        assert_eq!(value.0[..32], blocks[height].0, "{key}");
        assert_eq!(value.0[32..], [0; 8]);

        let by_path = get(addr, &format!("/marf/0x{path}?tip=0x{tip}"));
        assert!(by_path.body == by_key.body, "{key}: by path != by key");
        let encoded = key.replace("::", "%3A%3A");
        let decoded = get(addr, &format!("/marf?tip={tip}&key={encoded}"));
        assert!(decoded.body == by_key.body, "{key}: percent-encoded key");
        proofs.push((path, unhex_field(&by_key, "proof")));
    }

    // Byte-identical to the proof a node builds from its read-write MARF.
    drop(marf);
    let mut rw =
        MARF::<StacksBlockId>::from_path(node.local.path.to_str().unwrap(), node_opts(false))
            .unwrap();
    for (path, served) in proofs {
        let (_, proof) = rw.get_with_proof_from_hash(tip, &path).unwrap().unwrap();
        assert!(proof.serialize_to_vec() == served, "proof of {path}");
    }
}

#[test]
fn marf_route_proves_a_stored_key_as_of_an_older_tip() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let mut marf = ReadOnlyMarf::open(&node.local.path).unwrap();
    let tip = &node.local.blocks[20];
    let (key, value) = node.local.writes[20].iter().next().unwrap();
    let path = TrieHash::from_key(key);
    let r = get(addr, &format!("/marf/{path}?tip={tip}"));
    let got = verified_marf_value(&r, &mut marf, &node.local.blocks, tip, &path);
    assert_eq!(got, MARFValue::from_value(value));
}

#[test]
fn marf_route_rejects_unknown_tips_absent_keys_and_malformed_params() {
    let node = NodeDir::new();
    let (addr, _) = node.serve(2);
    let tip = node.local.blocks.last().unwrap();
    let absent = format!("__MARF_BLOCK_HEIGHT_TO_HASH::{MARF_BLOCKS}");

    let r = get(addr, &format!("/marf?key={absent}&tip={tip}"));
    assert_eq!(r.status, 404);
    assert_eq!(r.json()["error"], "no MARF entry at that path as of tip");
    let unknown = "ab".repeat(32);
    let r = get(
        addr,
        &format!("/marf?key=__MARF_BLOCK_HEIGHT_TO_HASH::1&tip={unknown}"),
    );
    assert_eq!(r.status, 404);
    assert_eq!(r.json()["error"], "tip block is not in the MARF");

    let long = "k".repeat(marf_witness::serve::MAX_MARF_KEY + 1);
    for bad in [
        "/marf?key=__MARF_BLOCK_HEIGHT_TO_HASH::1".to_string(),
        format!(
            "/marf?key=__MARF_BLOCK_HEIGHT_TO_HASH::1&tip={}",
            "ab".repeat(31)
        ),
        format!("/marf?key=&tip={tip}"),
        format!("/marf?key=%zz&tip={tip}"),
        format!("/marf?key=%ff&tip={tip}"),
        format!("/marf?key={long}&tip={tip}"),
        format!("/marf?tip={tip}"),
        format!("/marf/{}?tip={tip}", "ab".repeat(31)),
        format!("/marf/not-a-path?tip={tip}"),
    ] {
        let r = get(addr, &bad);
        assert_eq!(r.status, 400, "{bad}");
        assert!(r.json()["error"].is_string(), "{bad}");
    }
}

#[test]
fn saturated_extraction_slots_return_503_with_retry_after_but_cache_hits_still_serve() {
    let node = NodeDir::new();
    let (addr, slots) = node.serve(1);
    let (warm, cold) = (&node.local.blocks[3], &node.local.blocks[4]);
    assert_eq!(get(addr, &format!("/witness/{warm}")).status, 200);

    // Another extraction holds the only slot.
    let held = slots.try_acquire().unwrap();
    assert!(slots.try_acquire().is_none());
    let r = get(addr, &format!("/witness/{cold}"));
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), "1");
    let hit = get(addr, &format!("/witness/{warm}"));
    assert_eq!((hit.status, hit.header("x-cache")), (200, "hit"));
    assert_eq!(get(addr, "/health").status, 200);

    drop(held);
    assert_eq!(get(addr, &format!("/witness/{cold}")).status, 200);
}

#[test]
fn serving_leaves_every_database_file_byte_identical() {
    let node = NodeDir::new();
    let before = node.snapshot();
    let (addr, _) = node.serve(2);
    for block in &node.local.blocks {
        assert_eq!(get(addr, &format!("/witness/{block}")).status, 200);
    }
    let ch = burn_fixture("preimage-970269.json")["consensus_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(get(addr, &format!("/burn/{ch}")).status, 200);
    assert_eq!(get(addr, "/bitcoin/headers?from=0&count=10").status, 200);
    let tip = node.local.blocks.last().unwrap();
    for h in 0..MARF_BLOCKS {
        let r = get(
            addr,
            &format!("/marf?key=__MARF_BLOCK_HEIGHT_TO_HASH::{h}&tip={tip}"),
        );
        assert_eq!(r.status, 200);
    }
    assert_eq!(get(addr, "/health").status, 200);
    node.assert_untouched(&before);
}

#[test]
fn serve_cli_derives_database_paths_from_the_working_dir_and_logs_each_request() {
    let node = NodeDir::new();
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--working-dir",
            node.wd.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut log = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    log.read_line(&mut line).unwrap();
    let addr: SocketAddr = line
        .strip_prefix("listening on ")
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("unexpected first line: {line}"))
        .parse()
        .unwrap();

    let h = get(addr, "/health");
    line.clear();
    log.read_line(&mut line).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    assert_eq!(h.status, 200, "{}", String::from_utf8_lossy(&h.body));
    assert_eq!(h.json()["marf_tip_height"], MARF_BLOCKS - 1);
    assert!(
        line.starts_with(&format!(
            "method=GET path=/health status=200 bytes={} ms=",
            h.body.len()
        )),
        "{line}"
    );
}
