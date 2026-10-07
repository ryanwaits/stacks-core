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

//! Shared test harness: a local Stacks-shaped MARF and file digests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::{Sha512Trunc256Sum, to_hex};
use stackslib::chainstate::stacks::index::marf::{MARF, MARFOpenOpts};
use stackslib::chainstate::stacks::index::{ClarityMarfTrieId, MARFValue};

pub const BIN: &str = env!("CARGO_BIN_EXE_marf-witness");

/// A scratch dir under cargo's target tmpdir. Never `tempfile::tempdir()`:
/// opening a MARF read-write briefly repoints the process-global `TMPDIR`
/// (stackslib's post-migration vacuum), which races with parallel tests.
pub fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

pub fn block(i: u64) -> StacksBlockId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i + 1).to_be_bytes());
    StacksBlockId(b)
}

/// Blocks on a sibling fork get a distinct id space.
pub fn fork_block(i: u64) -> StacksBlockId {
    let mut b = block(i).0;
    b[31] = 0xf0;
    StacksBlockId(b)
}

/// Deterministic xorshift so MARFs (and fixtures) are reproducible.
pub struct Rng(u64);
impl Rng {
    pub fn new() -> Self {
        Rng(0x5eed)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

pub struct LocalMarf {
    pub path: PathBuf,
    /// Main-chain blocks by height.
    pub blocks: Vec<StacksBlockId>,
    /// (key, value) strings written in each main-chain block.
    pub writes: Vec<BTreeMap<String, String>>,
    /// Fork blocks by height offset from `fork_from + 1`.
    pub fork: Vec<StacksBlockId>,
}

fn write_block(
    m: &mut MARF<StacksBlockId>,
    parent: &StacksBlockId,
    cur: &StacksBlockId,
    height: u32,
    rng: &mut Rng,
) -> BTreeMap<String, String> {
    // Mainnet-like skew: most blocks small, every tenth large (5..700 writes).
    let n = if height.is_multiple_of(10) {
        300 + rng.below(400)
    } else {
        5 + rng.below(60)
    };
    let mut w = BTreeMap::new();
    while (w.len() as u64) < n {
        let c = rng.below(80);
        let key = match rng.below(4) {
            0 => format!("vm::SP000.c{c}::1::counter-{}", rng.below(4)),
            1 => format!("vm-account::SP{:04}::stx", rng.below(5000)),
            _ => format!("vm::SP000.c{c}::2::balances::{}", rng.below(5000)),
        };
        w.insert(key, format!("u{}-b{height}", rng.below(1_000_000)));
    }
    let mut tx = m.begin_tx().unwrap();
    tx.begin(parent, cur).unwrap();
    tx.set_block_heights(parent, cur, height).unwrap();
    let (ks, vs): (Vec<String>, Vec<MARFValue>) = w
        .iter()
        .map(|(k, v)| (k.clone(), MARFValue::from_value(v)))
        .unzip();
    tx.insert_batch(&ks, vs).unwrap();
    tx.commit().unwrap();
    w
}

/// Open-opts as a Stacks node uses for the Clarity MARF: external `.blobs`.
pub fn node_opts(compress: bool) -> MARFOpenOpts {
    let mut opts = MARFOpenOpts::default();
    opts.external_blobs = true;
    opts.compress = compress;
    opts
}

/// Build `n` main-chain blocks (and `fork_len` blocks forking off height
/// `n - fork_len - 1`) into `dir/marf.sqlite` + `.blobs`, then close it.
pub fn build_marf(dir: &Path, n: u64, fork_len: u64, compress: bool) -> LocalMarf {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("marf.sqlite");
    let mut m =
        MARF::<StacksBlockId>::from_path(path.to_str().unwrap(), node_opts(compress)).unwrap();
    let mut rng = Rng::new();
    let (mut blocks, mut writes, mut fork) = (vec![], vec![], vec![]);
    let mut parent = StacksBlockId::sentinel();
    for i in 0..n {
        let cur = block(i);
        writes.push(write_block(&mut m, &parent, &cur, i as u32, &mut rng));
        blocks.push(cur.clone());
        parent = cur;
    }
    if fork_len > 0 {
        let base = n - fork_len - 1;
        let mut parent = block(base);
        for i in base + 1..=base + fork_len {
            let cur = fork_block(i);
            write_block(&mut m, &parent, &cur, i as u32, &mut rng);
            fork.push(cur.clone());
            parent = cur;
        }
    }
    drop(m);
    LocalMarf {
        path,
        blocks,
        writes,
        fork,
    }
}

/// sha512/256 of every file in `dir` (non-recursive), keyed by file name.
/// Comparing two snapshots also catches created or deleted files.
pub fn digests(dir: &Path) -> BTreeMap<String, String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (
                name,
                to_hex(&Sha512Trunc256Sum::from_data(&std::fs::read(&p).unwrap()).0),
            )
        })
        .collect()
}

/// Assert a read-only pass left the MARF's database and blob files
/// byte-identical. The only files it may add are the `-shm`/`-wal` that SQLite
/// itself requires to read a WAL-mode database, and the `-wal` must stay empty.
pub fn assert_untouched(dir: &Path, before: &BTreeMap<String, String>) {
    let after = digests(dir);
    for (name, digest) in before {
        assert_eq!(
            after.get(name),
            Some(digest),
            "{name} changed or was removed"
        );
    }
    for name in after.keys().filter(|n| !before.contains_key(*n)) {
        assert!(
            name.ends_with(".sqlite-shm") || name.ends_with(".sqlite-wal"),
            "unexpected new file {name}"
        );
        if name.ends_with("-wal") {
            assert_eq!(
                std::fs::metadata(dir.join(name)).unwrap().len(),
                0,
                "{name} not empty"
            );
        }
    }
}

pub fn run(args: &[&str]) -> Output {
    std::process::Command::new(BIN).args(args).output().unwrap()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
