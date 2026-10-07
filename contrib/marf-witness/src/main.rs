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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use marf_witness::{burn, check, extract, stats, wire};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::to_hex;

/// Extract and verify per-block MARF state witnesses. Opens every database read-only.
#[derive(Parser)]
#[command(name = "marf-witness", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write <block>.witness + <block>.json for each block.
    Extract {
        /// Clarity MARF, e.g. <chainstate>/vm/clarity/marf.sqlite
        #[arg(long)]
        marf: PathBuf,
        /// Index block hash(es) to extract
        #[arg(long, num_args = 1.., required_unless_present = "tip", conflicts_with = "tip")]
        block: Vec<String>,
        /// Newest block to extract; walks parents from here
        #[arg(long, requires = "count")]
        tip: Option<String>,
        /// Number of blocks to extract from --tip (inclusive)
        #[arg(long, requires = "tip")]
        count: Option<u32>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Recompute a witness's root from its bytes alone.
    Verify {
        witness: PathBuf,
        /// Expected root (hex); exit nonzero if the recomputed root differs
        #[arg(long)]
        root: Option<String>,
    },
    /// Print the consensus-hash preimage that binds a tenure to its Bitcoin block.
    Burn {
        /// Sortition DB, e.g. <burnchain>/sortition/marf.sqlite
        #[arg(long)]
        sortition_db: PathBuf,
        #[arg(long)]
        consensus_hash: String,
        #[arg(long, default_value_t = burn::MAINNET_FIRST_BURN_HEIGHT)]
        first_burn_height: u64,
    },
    /// Size distribution of an extract output directory.
    Stats { dir: PathBuf },
    /// Verify a write log against each block's state witness (no re-execution).
    /// Prints a JSON report; exits 1 on any failure.
    Check {
        /// Clarity MARF, e.g. <chainstate>/vm/clarity/marf.sqlite
        #[arg(long, required_unless_present = "witness")]
        marf: Option<PathBuf>,
        /// Index block hash(es) to check
        #[arg(long, num_args = 1.., conflicts_with_all = ["height", "from"])]
        block: Vec<String>,
        /// Height(s) to check, on the fork of the MARF's latest block
        #[arg(long, num_args = 1.., conflicts_with = "from")]
        height: Vec<u32>,
        /// First height of an inclusive range (with --to)
        #[arg(long, requires = "to")]
        from: Option<u32>,
        #[arg(long, requires = "from")]
        to: Option<u32>,
        /// vm_events rows as JSON lines, or - for stdin
        #[arg(long)]
        rows: PathBuf,
        /// Storage-layer writes as JSON lines; every changed leaf must then be named
        #[arg(long)]
        writes: Option<PathBuf>,
        /// Node RPC (http://host:port): also compare the header state_index_root
        #[arg(long)]
        rpc: Option<String>,
        /// Offline: check one witness file instead of a MARF (no root or carried check)
        #[arg(long, hide = true, conflicts_with_all = ["marf", "block", "height", "from", "rpc"])]
        witness: Option<PathBuf>,
    },
}

fn block_id(hex: &str) -> Result<StacksBlockId, String> {
    StacksBlockId::from_hex(hex.trim_start_matches("0x"))
        .map_err(|_| format!("not a 32-byte index block hash: {hex}"))
}

fn read_log<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<Vec<T>, String> {
    if path == Path::new("-") {
        return check::read_jsonl(std::io::stdin().lock(), what);
    }
    let f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    check::read_jsonl(std::io::BufReader::new(f), what)
}

#[allow(clippy::too_many_arguments)]
fn run_check(
    marf: Option<PathBuf>,
    block: Vec<String>,
    height: Vec<u32>,
    range: Option<(u32, u32)>,
    rows: PathBuf,
    writes: Option<PathBuf>,
    rpc: Option<String>,
    witness: Option<PathBuf>,
) -> Result<(), String> {
    let rows: Vec<check::Row> = read_log(&rows, "rows")?;
    let writes: Option<Vec<check::Write>> = writes.map(|w| read_log(&w, "writes")).transpose()?;
    let rpc = rpc.map(|u| check::Rpc::parse(&u)).transpose()?;

    let mut rows_by_height: HashMap<u64, Vec<&check::Row>> = HashMap::new();
    for r in &rows {
        rows_by_height.entry(r.block_height).or_default().push(r);
    }
    let mut writes_by_height: HashMap<u64, Vec<&check::Write>> = HashMap::new();
    for w in writes.iter().flatten() {
        writes_by_height.entry(w.block_height).or_default().push(w);
    }
    let log = |h: u32| check::BlockLog {
        rows: rows_by_height
            .get(&u64::from(h))
            .cloned()
            .unwrap_or_default(),
        writes: writes.as_ref().map(|_| {
            writes_by_height
                .get(&u64::from(h))
                .cloned()
                .unwrap_or_default()
        }),
    };

    let mut tip = None;
    let blocks = if let Some(path) = witness {
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| block_id(s).is_ok())
            .map(str::to_string);
        vec![check::check_witness(&bytes, id, &log)]
    } else {
        let mut m = extract::ReadOnlyMarf::open(&marf.ok_or("--marf is required")?)?;
        let heights: Vec<u32> = match range {
            Some((from, to)) if from > to => return Err(format!("--from {from} > --to {to}")),
            Some((from, to)) => (from..=to).collect(),
            None => height,
        };
        let ids: Vec<Result<StacksBlockId, Box<check::BlockReport>>> = if !heights.is_empty() {
            let latest = m.latest_block()?;
            tip = Some(latest.to_string());
            heights
                .into_iter()
                .map(|h| {
                    m.block_at(h, &latest).map_err(|e| {
                        Box::new(check::BlockReport {
                            height: Some(h),
                            error: Some(e),
                            ..Default::default()
                        })
                    })
                })
                .collect()
        } else if !block.is_empty() {
            block
                .iter()
                .map(|b| {
                    block_id(b).map_err(|e| {
                        Box::new(check::BlockReport {
                            id: Some(b.clone()),
                            error: Some(e),
                            ..Default::default()
                        })
                    })
                })
                .collect()
        } else {
            return Err("give --block, --height or --from/--to".into());
        };
        ids.into_iter()
            .map(|id| match id {
                Ok(id) => check::check_marf_block(&mut m, &id, &log, rpc.as_ref()),
                Err(report) => *report,
            })
            .collect()
    };

    let checked: HashSet<u64> = blocks
        .iter()
        .filter_map(|b| b.height)
        .map(u64::from)
        .collect();
    let unmatched = rows
        .iter()
        .filter(|r| !checked.contains(&r.block_height))
        .count()
        + writes
            .iter()
            .flatten()
            .filter(|w| !checked.contains(&w.block_height))
            .count();
    let report = check::summarize(blocks, writes.is_some(), unmatched, tip);
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    let s = &report.summary;
    match s.ok {
        true => Ok(()),
        false => Err(format!(
            "check failed: {} of {} blocks",
            s.blocks_failed, s.blocks
        )),
    }
}

fn run(cmd: Command) -> Result<(), String> {
    match cmd {
        Command::Extract {
            marf,
            block,
            tip,
            count,
            out,
        } => {
            let mut m = extract::ReadOnlyMarf::open(&marf)?;
            let blocks = match (tip, count) {
                (Some(tip), Some(count)) => extract::walk_parents(&mut m, &block_id(&tip)?, count)?,
                _ => block
                    .iter()
                    .map(|b| block_id(b))
                    .collect::<Result<_, _>>()?,
            };
            // A failed block is reported and skipped; the rest still extract.
            let mut failed = 0usize;
            for block in &blocks {
                match extract::extract_block(&mut m, block, &out) {
                    Ok(meta) => println!(
                        "{} height={} leaves={} nodes={} bytes={} root={}",
                        meta.block, meta.height, meta.leaves, meta.nodes, meta.bytes, meta.root_hex
                    ),
                    Err(e) => {
                        failed += 1;
                        eprintln!("error: block {block}: {e}");
                    }
                }
            }
            match failed {
                0 => Ok(()),
                n => Err(format!("{n} of {} blocks failed", blocks.len())),
            }
        }
        Command::Verify { witness, root } => {
            let bytes =
                std::fs::read(&witness).map_err(|e| format!("read {}: {e}", witness.display()))?;
            let v = wire::verify(&bytes)?;
            let got = to_hex(v.root.as_bytes());
            println!("root={got} leaves={} nodes={}", v.leaves.len(), v.nodes);
            match root {
                Some(want) if !want.trim_start_matches("0x").eq_ignore_ascii_case(&got) => {
                    Err(format!("root mismatch: expected {want}, recomputed {got}"))
                }
                _ => Ok(()),
            }
        }
        Command::Burn {
            sortition_db,
            consensus_hash,
            first_burn_height,
        } => {
            let conn = burn::open_readonly(&sortition_db)?;
            let p = burn::burn_preimage(
                &conn,
                consensus_hash.trim_start_matches("0x"),
                first_burn_height,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Command::Check {
            marf,
            block,
            height,
            from,
            to,
            rows,
            writes,
            rpc,
            witness,
        } => run_check(
            marf,
            block,
            height,
            from.zip(to),
            rows,
            writes,
            rpc,
            witness,
        ),
        Command::Stats { dir } => {
            let s = stats::stats(&dir)?;
            println!("blocks {}", s.count);
            println!(
                "{:<12} {:>10} {:>10} {:>10} {:>10}",
                "", "min", "median", "p95", "max"
            );
            for (label, x) in [("bytes/block", s.per_block), ("bytes/leaf", s.per_leaf)] {
                println!(
                    "{label:<12} {:>10.0} {:>10.0} {:>10.0} {:>10.0}",
                    x.min, x.median, x.p95, x.max
                );
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
