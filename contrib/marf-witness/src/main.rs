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

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use marf_witness::{burn, extract, stats, wire};
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
}

fn block_id(hex: &str) -> Result<StacksBlockId, String> {
    StacksBlockId::from_hex(hex.trim_start_matches("0x"))
        .map_err(|_| format!("not a 32-byte index block hash: {hex}"))
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
            for meta in extract::extract_blocks(&mut m, &blocks, &out)? {
                println!(
                    "{} height={} leaves={} nodes={} bytes={} root={}",
                    meta.block, meta.height, meta.leaves, meta.nodes, meta.bytes, meta.root_hex
                );
            }
            Ok(())
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
