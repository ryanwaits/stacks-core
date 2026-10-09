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

//! The client side of a served witness: given a block (from `/v3/blocks/<id>`)
//! and its replay with `read_witness=1`, verify every witness entry against
//! headers the client hashed itself, re-execute the block from the witness
//! alone, and compare what re-execution produced with what the node served.
//!
//! Trust: header *authenticity* (signer signatures, the canonical fork) and
//! Bitcoin header heights and proof of work are not checked here. Headers are
//! accepted by block-id hash match; a header-chain verifier (e.g.
//! `@secondlayer/verify`) composes on top by checking the same ids.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::Instant;

use clarity::vm::events::{FTEventType, NFTEventType, StacksTransactionEvent};
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash, Txid};
use stacks_common::util::hash::{hex_bytes, Sha512Trunc256Sum};

use crate::burnchains::PoxConstants;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::db::StacksBlockHeaderTypes;
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::index::MARFValue;
use crate::clarity_vm::read_witness::StoreQuery;
use crate::clarity_vm::state_writes::StateWrite;
use crate::clarity_vm::stateless::{execute_statelessly, BlockLevelWrites, StatelessError};
use crate::clarity_vm::witness_proof::{
    check_read_witness, fill_rederived_metadata, BitcoinChain, ChainHeader, DeploySource, EnvClass,
    HeaderChain, NetworkParams, OpenedProof, StoreProof, TrustedState,
};
use crate::core::{
    BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
    FIRST_STACKS_BLOCK_ID, MAINNET_2_0_GENESIS_ROOT_HASH, STACKS_EPOCHS_MAINNET,
};
use crate::net::api::blockreplay::{block_vm_events, receipt_events, RPCReplayedBlock};

/// What a client pins for a network.
#[derive(Debug, Clone)]
pub struct ClientParams {
    pub net: NetworkParams,
    /// The genesis MARF root (the genesis header carries a zero root).
    pub genesis_root: TrieHash,
}

impl ClientParams {
    /// Mainnet: the node's own epoch list and PoX constants, and the genesis
    /// root every mainnet node checks at boot.
    pub fn mainnet() -> Self {
        ClientParams {
            net: NetworkParams {
                mainnet: true,
                chain_id: CHAIN_ID_MAINNET,
                first_burn_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT as u32,
                epochs: STACKS_EPOCHS_MAINNET.clone().to_vec(),
                pox: PoxConstants::mainnet_default(),
            },
            genesis_root: TrieHash::from_hex(MAINNET_2_0_GENESIS_ROOT_HASH)
                .expect("genesis root constant is hex"),
        }
    }

    fn genesis_header(&self) -> ChainHeader {
        ChainHeader {
            id: FIRST_STACKS_BLOCK_ID.clone(),
            parent: StacksBlockId([0; 32]),
            block_hash: FIRST_STACKS_BLOCK_HASH,
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH,
            height: 0,
            state_index_root: self.genesis_root,
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            timestamp: None,
            vrf_proof: None,
        }
    }
}

/// One check and its outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// What a client established about one block.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub block: Option<StacksBlockId>,
    pub checks: Vec<Check>,
    /// Verified witness entries by kind.
    pub entries: BTreeMap<&'static str, usize>,
    /// The re-executed receipts, if re-execution ran.
    pub receipts: Vec<StacksTransactionReceipt>,
}

impl Report {
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    /// The first failed check.
    pub fn failure(&self) -> Option<&Check> {
        self.checks.iter().find(|c| !c.ok)
    }

    fn pass(&mut self, name: &'static str, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            ok: true,
            detail: detail.into(),
        });
    }

    /// Record a failed check and carry on.
    fn flag(&mut self, name: &'static str, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            ok: false,
            detail: detail.into(),
        });
    }

    /// Record a failed check that ends the run.
    fn fail(mut self, name: &'static str, detail: impl Into<String>) -> Self {
        self.flag(name, detail);
        self
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(block) = &self.block {
            writeln!(f, "block {block}")?;
        }
        if !self.entries.is_empty() {
            writeln!(f, "witness entries verified:")?;
            for (kind, n) in self.entries.iter() {
                writeln!(f, "  {kind:<28} {n}")?;
            }
        }
        for check in self.checks.iter() {
            let mark = if check.ok { "ok  " } else { "FAIL" };
            writeln!(f, "{mark} {:<14} {}", check.name, check.detail)?;
        }
        write!(f, "{}", if self.ok() { "VERIFIED" } else { "REJECTED" })
    }
}

/// What a store entry was proven with, for the report.
fn store_kind(query: &StoreQuery, answer: &Option<String>, proof: &StoreProof) -> &'static str {
    let at_block = matches!(
        query,
        StoreQuery::Data { at: Some(_), .. } | StoreQuery::Path { at: Some(_), .. }
    );
    match (query, proof) {
        (StoreQuery::Metadata { .. }, StoreProof::Served) => "metadata (served, unproven)",
        (StoreQuery::Metadata { .. }, _) => "metadata (re-derived)",
        (_, StoreProof::Marf) => match (at_block, answer.is_some()) {
            (true, true) => "at-block inclusion",
            (true, false) => "at-block absence",
            (false, true) => "parent inclusion",
            (false, false) => "parent absence",
        },
        (_, StoreProof::Ancestor) => "at-block ancestry",
        (_, StoreProof::OpenBlock) => "open-block (deterministic)",
        (_, StoreProof::Rederived) => "metadata (re-derived)",
        (_, StoreProof::Served) => "metadata (served, unproven)",
    }
}

/// The replay's writes as `StateWrite`s (owner txid from `tx_index`).
fn replay_writes(replay: &RPCReplayedBlock) -> Result<Vec<StateWrite>, String> {
    let entries = replay
        .state_writes
        .as_ref()
        .ok_or("replay has no state_writes")?;
    entries
        .iter()
        .map(|e| {
            let txid = match e.tx_index {
                None => None,
                Some(i) => Some(
                    replay
                        .transactions
                        .get(i as usize)
                        .ok_or_else(|| format!("write {} names tx {i}", e.ordinal))?
                        .txid
                        .clone(),
                ),
            };
            let bytes = hex_bytes(&e.value_hex).map_err(|_| "bad value_hex".to_string())?;
            Ok(StateWrite {
                txid,
                key: e.key.clone(),
                value: String::from_utf8(bytes).map_err(|_| "value is not UTF-8".to_string())?,
            })
        })
        .collect()
}

/// Block-level writes split around the transactions' writes.
fn block_level(writes: &[StateWrite], txids: &HashSet<Txid>) -> Result<BlockLevelWrites, String> {
    let is_tx = |w: &StateWrite| w.txid.as_ref().is_some_and(|t| txids.contains(t));
    let first = writes.iter().position(is_tx).unwrap_or(writes.len());
    let last = writes.iter().rposition(is_tx).map_or(first, |i| i + 1);
    if !writes[first..last].iter().all(is_tx) {
        return Err("block-level write between transactions".into());
    }
    Ok(BlockLevelWrites::split(writes, txids))
}

/// One row per event of `receipts` (committed ones only, as `/new_block`
/// emits them), for diffing against an indexer's events: txid, event index,
/// type, contract id (the emitting contract, or the asset's for FT/NFT
/// events), topic, Clarity value as consensus hex and as repr, and the event
/// as `/new_block` serializes it.
pub fn event_rows(receipts: &[StacksTransactionReceipt]) -> Vec<serde_json::Value> {
    let mut rows = vec![];
    for receipt in receipts.iter() {
        let txid = receipt.transaction.txid();
        for (event_index, event) in receipt_events(receipt).into_iter().enumerate() {
            let typed = &receipt.events[event_index];
            let (contract_id, topic, value) = match typed {
                StacksTransactionEvent::SmartContractEvent(e) => (
                    Some(e.key.0.to_string()),
                    Some(e.key.1.clone()),
                    Some(&e.value),
                ),
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, Some(&e.value))
                }
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, Some(&e.value))
                }
                StacksTransactionEvent::NFTEvent(NFTEventType::NFTBurnEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, Some(&e.value))
                }
                StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, None)
                }
                StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, None)
                }
                StacksTransactionEvent::FTEvent(FTEventType::FTBurnEvent(e)) => {
                    (Some(e.asset_identifier.to_string()), None, None)
                }
                StacksTransactionEvent::STXEvent(_) => (None, None, None),
            };
            rows.push(serde_json::json!({
                "txid": format!("0x{txid}"),
                "event_index": event_index,
                "type": event["type"],
                "contract_id": contract_id,
                "topic": topic,
                "value_hex": value.map(|v| v.serialize_to_hex().map(|h| format!("0x{h}")).ok()),
                "value_repr": value.map(|v| v.to_string()),
                "event": event,
            }));
        }
    }
    rows
}

/// Count of `print` events in a transaction's serialized events.
fn prints(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|e| e["contract_event"]["topic"] == "print")
        .count()
}

/// Verify `block` (fetched by its id, `requested`) against its served
/// replay, re-execute it from the witness, and compare.
pub fn check_replayed_block(
    requested: &StacksBlockId,
    block: &NakamotoBlock,
    replay: &RPCReplayedBlock,
    params: &ClientParams,
) -> Report {
    let mut report = Report {
        block: Some(requested.clone()),
        ..Default::default()
    };
    let net = &params.net;

    // the block and the served witness
    let block_id = block.block_id();
    if &block_id != requested || replay.block_id != block_id {
        return report.fail(
            "block",
            format!("fetched {block_id}, replayed {}", replay.block_id),
        );
    }
    report.pass(
        "block",
        format!("{} txs, id hashes from header", block.txs.len()),
    );
    let Some(envelope) = replay.read_witness.as_ref() else {
        return report.fail("witness", "replay carries no read_witness");
    };
    let served = match envelope.decode() {
        Ok(served) => served,
        Err(e) => return report.fail("witness", format!("does not decode: {e}")),
    };
    if served.mainnet != net.mainnet || served.chain_id != net.chain_id {
        return report.fail(
            "witness",
            format!(
                "served for chain {} (mainnet={}), client pins {}",
                served.chain_id, served.mainnet, net.chain_id
            ),
        );
    }

    // headers: each hashed to its id; genesis pinned
    let mut headers = vec![
        params.genesis_header(),
        ChainHeader::from_header(
            &block.header.consensus_hash,
            &StacksBlockHeaderTypes::Nakamoto(block.header.clone()),
        ),
    ];
    for served_header in served.headers.iter() {
        let header = ChainHeader::from_header(&served_header.consensus_hash, &served_header.header);
        if header.id == *FIRST_STACKS_BLOCK_ID {
            return report.fail("headers", "a served header claims the genesis id");
        }
        headers.push(header);
    }
    let header_count = headers.len();
    let headers = HeaderChain::new(headers);
    if headers.get(&block.header.parent_block_id).is_none() {
        return report.fail("headers", "parent header not served");
    }
    let bitcoin = match BitcoinChain::new(served.bitcoin.iter().cloned()) {
        Ok(bitcoin) => bitcoin,
        Err(e) => return report.fail("headers", e),
    };
    report.pass(
        "headers",
        format!(
            "{header_count} Stacks (hashed to their ids, genesis root pinned), {} Bitcoin (heights trusted)",
            served.bitcoin.len()
        ),
    );

    // every witness entry; a rejected entry fails the run, but re-execution
    // and the comparisons still run on the served values, to show the rest
    let mut proven = served.proven;
    let trusted = TrustedState {
        headers: &headers,
        bitcoin: &bitcoin,
        net,
    };
    let started = Instant::now();
    info!(
        "Client: verifying {} store entries, {} lookups, {} contracts",
        proven.witness.store.len(),
        proven.witness.env.len(),
        proven.contracts.len()
    );
    let unfilled = fill_rederived_metadata(&mut proven, &block_id, &trusted);
    let check = check_read_witness(&block_id, &block.txs, &trusted, &proven);
    let rejections = check.rejections;
    match check.marf {
        Some((tries, nodes, bytes)) => info!(
            "Client: verified in {:?}, {} rejected; shared read proof: {tries} tries, {nodes} nodes, {bytes} bytes",
            started.elapsed(),
            rejections.len()
        ),
        None => info!(
            "Client: verified in {:?}, {} rejected",
            started.elapsed(),
            rejections.len()
        ),
    }
    let witness = &proven.witness;
    for ((query, answer), proof) in witness.store.iter().zip(proven.store.iter()) {
        *report
            .entries
            .entry(store_kind(query, answer, proof))
            .or_default() += 1;
    }
    for (kind, n) in check.kinds.iter().filter(|(_, n)| **n > 0) {
        *report.entries.entry(*kind).or_default() += n;
    }
    for read in witness.env.iter() {
        *report
            .entries
            .entry(EnvClass::of(&read.query).label())
            .or_default() += 1;
    }
    for evidence in proven.contracts.iter() {
        let kind = match evidence.source {
            DeploySource::Boot => "contract (bundled boot source)",
            DeploySource::Tx(_) => "contract (deploy tx proven)",
        };
        *report.entries.entry(kind).or_default() += 1;
        if !evidence.deploy_reads.is_empty() || !evidence.deploy_env.is_empty() {
            *report
                .entries
                .entry("contract (with deploy witness)")
                .or_default() += 1;
        }
    }
    let summary = format!(
        "{} store entries, {} lookups, {} contracts, {} burn preimages",
        witness.store.len(),
        witness.env.len(),
        proven.contracts.len(),
        proven.burn.len()
    );
    if rejections.is_empty() {
        report.pass("witness", summary);
    } else {
        let mut detail = format!("{} of {summary} rejected:", rejections.len());
        for rejection in rejections.iter() {
            detail.push_str(&format!(
                "\n       {}: {}",
                rejection.entry, rejection.reason
            ));
        }
        for (contract, reason) in served.unproven_contracts.iter() {
            detail.push_str(&format!("\n       served unproven {contract}: {reason}"));
        }
        report.flag("witness", detail);
    }

    // re-execute from the witness alone
    if !unfilled.is_empty() {
        return report.fail(
            "re-execute",
            format!(
                "skipped: metadata of {} did not re-derive",
                unfilled.join(", ")
            ),
        );
    }
    let served_writes = match replay_writes(replay) {
        Ok(writes) => writes,
        Err(e) => return report.fail("re-execute", e),
    };
    let txids: HashSet<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let levels = match block_level(&served_writes, &txids) {
        Ok(levels) => levels,
        Err(e) => return report.fail("re-execute", e),
    };
    let started = Instant::now();
    info!(
        "Client: re-executing {} txs from the witness",
        block.txs.len()
    );
    let out = match execute_statelessly(witness, &levels, block.txs(), net.mainnet, net.chain_id) {
        Ok(out) => out,
        Err(StatelessError::WitnessIncomplete(missing)) => {
            return report.fail("re-execute", format!("witness incomplete: {missing:?}"))
        }
        Err(StatelessError::Block(e)) => {
            return report.fail("re-execute", format!("block fails: {e:?}"))
        }
    };
    info!("Client: re-executed in {:?}", started.elapsed());
    report.receipts = out.receipts.clone();
    report.pass(
        "re-execute",
        format!(
            "{} receipts, {} writes",
            out.receipts.len(),
            out.writes.len()
        ),
    );
    let started = Instant::now();
    info!(
        "Client: comparing {} writes and {} receipts, checking {} final writes ({} proof bytes)",
        out.writes.len(),
        out.receipts.len(),
        served.writes.keys.len(),
        served.writes.proof.len()
    );

    // writes: the transactions' own, against the replay's
    let tx_writes = |writes: &[StateWrite]| -> Vec<StateWrite> {
        writes
            .iter()
            .filter(|w| w.txid.as_ref().is_some_and(|t| txids.contains(t)))
            .cloned()
            .collect()
    };
    let (ours, theirs) = (tx_writes(&out.writes), tx_writes(&served_writes));
    match ours.iter().zip(theirs.iter()).position(|(a, b)| a != b) {
        None if ours.len() == theirs.len() => report.pass(
            "writes",
            format!("{} tx writes = replay state_writes", ours.len()),
        ),
        None => {
            return report.fail(
                "writes",
                format!("{} tx writes, replay has {}", ours.len(), theirs.len()),
            )
        }
        Some(i) => {
            return report.fail(
                "writes",
                format!(
                    "tx write {i}: re-executed {:?}, replay {:?}",
                    ours[i], theirs[i]
                ),
            )
        }
    }

    // writes: every final value proven at the block's own root, by one
    // shared proof that holds nothing else
    let mut finals: BTreeMap<&str, &str> = BTreeMap::new();
    for w in out.writes.iter() {
        finals.insert(&w.key, &w.value);
    }
    let served_keys: HashSet<&str> = served.writes.keys.iter().map(String::as_str).collect();
    if served_keys.len() != served.writes.keys.len()
        || finals.keys().any(|key| !served_keys.contains(key))
        || served_keys.len() != finals.len()
    {
        return report.fail(
            "write proofs",
            format!(
                "{} keys written, {} served",
                finals.len(),
                served.writes.keys.len()
            ),
        );
    }
    let proof = OpenedProof::open(&served.writes.proof, &headers);
    for (key, value) in finals.iter() {
        if let Err(e) = proof.holds(
            &block_id,
            &TrieHash::from_key(key),
            Some(&MARFValue::from_value(value)),
        ) {
            return report.fail(
                "write proofs",
                format!("{key}: re-executed final value is not in the block's trie ({e})"),
            );
        }
    }
    if let Some(reason) = proof.strictness() {
        return report.fail("write proofs", format!("the shared proof {reason}"));
    }
    report.pass(
        "write proofs",
        format!(
            "{} final values proven at the block's state root",
            finals.len()
        ),
    );

    // events and results, against the replay's receipts
    if out.receipts.len() != replay.transactions.len() {
        return report.fail(
            "events",
            format!(
                "{} receipts, replay has {}",
                out.receipts.len(),
                replay.transactions.len()
            ),
        );
    }
    let (mut events, mut print_events) = (0, 0);
    for (receipt, served_tx) in out.receipts.iter().zip(replay.transactions.iter()) {
        let ours = receipt_events(receipt);
        if receipt.transaction.txid() != served_tx.txid
            || ours != served_tx.events
            || receipt.result != served_tx.result_hex
            || receipt.post_condition_aborted != served_tx.post_condition_aborted
        {
            return report.fail(
                "events",
                format!("tx {} differs from the replay's receipt", served_tx.txid),
            );
        }
        events += ours.len();
        print_events += prints(&ours);
    }
    report.pass(
        "events",
        format!("{events} events ({print_events} prints) and results = replay receipts"),
    );

    if let Some(served_vm) = replay.vm_events.as_ref() {
        let ours = block_vm_events(out.receipts.iter());
        if &ours != served_vm {
            return report.fail(
                "vm_events",
                "re-executed vm_events differ from the replay's",
            );
        }
        report.pass("vm_events", format!("{} = replay vm_events", ours.len()));
    }
    info!("Client: compared in {:?}", started.elapsed());
    report
}
