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

//! Verify a mainnet block from a node's proof-carrying read witness and
//! re-execute it statelessly.
//!
//! Fetches `/v3/blocks/<id>` and `/v3/blocks/replay/<id>?read_witness=1&vm_events=1`
//! (or produces both in process from a chainstate copy), checks every witness
//! entry against headers it hashes itself (genesis root pinned), re-executes
//! the block from the witness alone, and compares the writes and events with
//! the node's. Exits 0 if everything verifies.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::chainstate::StacksBlockId;
use stackslib::burnchains::PoxConstants;
use stackslib::chainstate::burn::db::sortdb::SortitionDB;
use stackslib::chainstate::nakamoto::NakamotoBlock;
use stackslib::chainstate::stacks::db::StacksChainState;
use stackslib::clarity_vm::witness_client::{ClientParams, check_replayed_block};
use stackslib::net::api::blockreplay::{
    RPCNakamotoBlockReplayRequestHandler, RPCReplayedBlock, ReplayTrace,
};

#[derive(Parser)]
#[command(about = "Verify a mainnet block's read witness and re-execute it statelessly")]
struct Args {
    /// Block id (index block hash), hex
    block_id: String,
    /// Node RPC base URL, e.g. http://127.0.0.1:20443
    #[arg(
        long,
        required_unless_present = "chainstate",
        conflicts_with = "chainstate"
    )]
    node: Option<String>,
    /// The node's `connection_options.auth_token` (sent as `Authorization`)
    #[arg(long, env = "REPLAY_AUTH_TOKEN")]
    auth: Option<String>,
    /// Instead of RPC, replay in process from a stopped node's
    /// `<working_dir>/mainnet` (use a copy: replay opens it read-write). The
    /// replay response still round-trips through its JSON.
    #[arg(long)]
    chainstate: Option<PathBuf>,
}

fn get(
    client: &reqwest::blocking::Client,
    url: &str,
    auth: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut request = client.get(url);
    if let Some(auth) = auth {
        request = request.header("authorization", auth);
    }
    let response = request.send().map_err(|e| format!("GET {url}: {e}"))?;
    let status = response.status();
    let body = response.bytes().map_err(|e| format!("GET {url}: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "GET {url}: {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(body.to_vec())
}

/// `/v3/blocks/<id>` and `/v3/blocks/replay/<id>?read_witness=1&vm_events=1`.
fn fetch_rpc(
    node: &str,
    auth: Option<&str>,
    block_id: &StacksBlockId,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let node = node.trim_end_matches('/');
    let auth = auth.ok_or("--auth (or REPLAY_AUTH_TOKEN) is required with --node")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1800))
        .build()
        .map_err(|e| e.to_string())?;
    let block = get(&client, &format!("{node}/v3/blocks/{block_id}"), None)?;
    let replay = get(
        &client,
        &format!("{node}/v3/blocks/replay/{block_id}?read_witness=1&vm_events=1"),
        Some(auth),
    )?;
    Ok((block, replay))
}

/// The same two responses, produced in process from a chainstate directory.
fn fetch_local(dir: &Path, block_id: &StacksBlockId) -> Result<(Vec<u8>, Vec<u8>), String> {
    let sortdb = SortitionDB::open(
        &dir.join("burnchain/sortition").to_string_lossy(),
        false,
        PoxConstants::mainnet_default(),
        None,
    )
    .map_err(|e| format!("sortition DB: {e}"))?;
    let (mut chainstate, _) = StacksChainState::open(
        true,
        CHAIN_ID_MAINNET,
        &dir.join("chainstate").to_string_lossy(),
        None,
    )
    .map_err(|e| format!("chainstate: {e}"))?;
    let (block, _) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(block_id)
        .map_err(|e| format!("block: {e}"))?
        .ok_or("no such Nakamoto block")?;
    let mut handler = RPCNakamotoBlockReplayRequestHandler::new(None);
    handler.block_id = Some(block_id.clone());
    handler.trace = ReplayTrace {
        vm_events: true,
        state_writes: false,
        read_witness: true,
    };
    let replay = handler
        .block_replay(&sortdb, &mut chainstate)
        .map_err(|e| format!("replay: {e}"))?;
    let replay = serde_json::to_vec(&replay).map_err(|e| e.to_string())?;
    Ok((block.serialize_to_vec(), replay))
}

fn run(args: &Args) -> Result<bool, String> {
    let block_id =
        StacksBlockId::from_hex(&args.block_id).map_err(|e| format!("block id: {e:?}"))?;

    let started = Instant::now();
    let (block_bytes, replay_bytes) = match (&args.node, &args.chainstate) {
        (_, Some(dir)) => fetch_local(dir, &block_id)?,
        (Some(node), None) => fetch_rpc(node, args.auth.as_deref(), &block_id)?,
        (None, None) => return Err("--node or --chainstate".into()),
    };
    let fetched = started.elapsed();
    let block = NakamotoBlock::consensus_deserialize(&mut &block_bytes[..])
        .map_err(|e| format!("block does not decode: {e:?}"))?;
    let replay: RPCReplayedBlock = serde_json::from_slice(&replay_bytes)
        .map_err(|e| format!("replay response does not parse: {e}"))?;

    let started = Instant::now();
    let report = check_replayed_block(&block_id, &block, &replay, &ClientParams::mainnet());
    println!("{report}");
    println!(
        "block {} bytes + replay {} bytes, fetched in {:?}; verified and re-executed in {:?}",
        block_bytes.len(),
        replay_bytes.len(),
        fetched,
        started.elapsed()
    );
    Ok(report.ok())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
