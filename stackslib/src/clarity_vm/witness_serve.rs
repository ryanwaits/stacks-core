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

//! The node side of a served witness: given a block and the read witness its
//! replay recorded, gather every proof and header a client needs from the
//! node's MARF, headers DB, block stores and sortition DB.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

use clarity::vm::database::{BurnStateDB, HeadersDB};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::ConsensusHashExtensions;
use crate::chainstate::nakamoto::staging_blocks::NakamotoStagingBlocksConn;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::multiproof::MultiproofBuilder;
use crate::chainstate::stacks::{StacksTransaction, TransactionPayload};
use crate::clarity_vm::read_witness::{EnvQuery, EnvRead, ReadWitness, StoreQuery};
use crate::clarity_vm::state_writes::StateWrite;
use crate::clarity_vm::witness_proof::{
    mark_served_metadata, prove_contracts, prove_env_reads, prove_store_reads, prove_writes,
    BitcoinHeader, BurnBinding, DeployEnvSource, NetworkParams, ProvenWitness, TxInclusion,
};
use crate::clarity_vm::witness_wire::{ServedHeader, ServedWitness, WriteProof};
use crate::core::FIRST_STACKS_BLOCK_ID;
use crate::util_lib::db::DBConn;

/// The network constants a node runs with.
pub fn node_network_params(
    sortdb: &SortitionDB,
    chainstate: &StacksChainState,
) -> Result<NetworkParams, String> {
    Ok(NetworkParams {
        mainnet: chainstate.mainnet,
        chain_id: chainstate.chain_id,
        first_burn_height: u32::try_from(sortdb.first_block_height)
            .map_err(|_| "first burn height overflows")?,
        epochs: SortitionDB::get_stacks_epochs(sortdb.conn())
            .map_err(|e| format!("epochs: {e:?}"))?
            .to_vec(),
        pox: sortdb.pox_constants.clone(),
    })
}

/// A consensus hash's preimage, from the sortition DB.
pub fn burn_binding(sortdb: &SortitionDB, ch: &ConsensusHash) -> Result<BurnBinding, String> {
    let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), ch)
        .map_err(|e| format!("{ch}: {e:?}"))?
        .ok_or_else(|| format!("no snapshot for {ch}"))?;
    let handle = sortdb.index_handle(&sn.sortition_id);
    let first = sortdb.first_block_height;
    let parent_height = sn.block_height.saturating_sub(1);
    let mut prev_consensus_hashes = vec![];
    for i in 0..64 {
        let Some(height) = parent_height.checked_sub((1u64 << i) - 1) else {
            break;
        };
        if height < first {
            break;
        }
        prev_consensus_hashes.push(
            handle
                .get_consensus_at(height)
                .map_err(|e| format!("{ch}: {e:?}"))?
                .unwrap_or(ConsensusHash::empty()),
        );
    }
    let binding = BurnBinding {
        burn_header_hash: sn.burn_header_hash.clone(),
        ops_hash: sn.ops_hash.clone(),
        total_burn: sn.total_burn,
        pox_id: handle.get_pox_id().map_err(|e| format!("{ch}: {e:?}"))?,
        prev_consensus_hashes,
    };
    if &binding.consensus_hash() != ch || binding.sortition_id() != sn.sortition_id {
        return Err(format!("preimage does not reproduce {ch}"));
    }
    Ok(binding)
}

fn bitcoin_header(sortdb: &SortitionDB, ch: &ConsensusHash) -> Result<BitcoinHeader, String> {
    let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), ch)
        .map_err(|e| format!("{ch}: {e:?}"))?
        .ok_or_else(|| format!("no snapshot for {ch}"))?;
    Ok(BitcoinHeader {
        height: u32::try_from(sn.block_height).map_err(|_| "burn height overflows")?,
        hash: sn.burn_header_hash,
        parent: sn.parent_burn_header_hash,
        time: sn.burn_header_timestamp,
    })
}

/// The node's stored blocks: headers, and transactions from the Nakamoto
/// staging DB or the epoch 2.x block store. Borrows only those parts of the
/// chainstate, so it can be used while the Clarity MARF is borrowed.
struct NodeBlocks<'a> {
    headers_db: &'a DBConn,
    staged: &'a NakamotoStagingBlocksConn,
    blocks_path: &'a str,
}

impl NodeBlocks<'_> {
    fn header(&self, id: &StacksBlockId) -> Result<StacksHeaderInfo, String> {
        NakamotoChainState::get_block_header(self.headers_db, id)
            .map_err(|e| format!("header {id}: {e:?}"))?
            .ok_or_else(|| format!("no header for {id}"))
    }

    fn txs(&self, id: &StacksBlockId) -> Result<Vec<StacksTransaction>, String> {
        let info = self.header(id)?;
        match &info.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(_) => self
                .staged
                .conn()
                .get_nakamoto_block(id)
                .map_err(|e| format!("block {id}: {e:?}"))?
                .map(|(block, _)| block.txs)
                .ok_or_else(|| format!("no Nakamoto block {id}")),
            StacksBlockHeaderTypes::Epoch2(h) => StacksChainState::load_block(
                self.blocks_path,
                &info.consensus_hash,
                &h.block_hash(),
            )
            .map_err(|e| format!("block {id}: {e:?}"))?
            .map(|block| block.txs)
            .ok_or_else(|| format!("no epoch 2.x block {id}")),
        }
    }

    /// The first transaction of block `id` that `pick` accepts, with its
    /// Merkle path.
    fn include(
        &self,
        id: &StacksBlockId,
        pick: impl Fn(&StacksTransaction) -> bool,
    ) -> Result<Option<TxInclusion>, String> {
        let txs = self.txs(id)?;
        Ok(txs
            .iter()
            .position(pick)
            .map(|index| TxInclusion::new(id.clone(), &txs, index)))
    }

    /// The latest tenure change in tenure `tenure` at or before `start`,
    /// walking back through blocks of that tenure, and every block walked (a
    /// header the client walks too).
    fn burn_view_change(
        &self,
        start: &StacksBlockId,
        tenure: &ConsensusHash,
    ) -> Result<(TxInclusion, Vec<StacksBlockId>), String> {
        let mut walked = vec![];
        let mut cursor = start.clone();
        loop {
            let info = self.header(&cursor)?;
            if &info.consensus_hash != tenure {
                return Err("no tenure change earlier in this tenure".into());
            }
            walked.push(cursor.clone());
            if let Some(inclusion) = self.include(&cursor, is_tenure_change)? {
                return Ok((inclusion, walked));
            }
            let StacksBlockHeaderTypes::Nakamoto(h) = &info.anchored_header else {
                return Err("tenure reaches an epoch 2.x block".into());
            };
            cursor = h.parent_block_id.clone();
        }
    }
}

/// The consensus hash a tenure change sets as the burn view.
fn view_of(tx: &StacksTransaction) -> Result<ConsensusHash, String> {
    match &tx.payload {
        TransactionPayload::TenureChange(tc) => Ok(tc.burn_view_consensus_hash.clone()),
        _ => Err("burn-view proof is not a tenure change".into()),
    }
}

/// A deploy's environment, as the node processed its deploying block: the
/// headers DB, and the sortition DB at that block's burn view.
struct NodeDeployEnv<'a> {
    sortdb: &'a SortitionDB,
    headers: &'a dyn HeadersDB,
    blocks: &'a NodeBlocks<'a>,
}

impl DeployEnvSource for NodeDeployEnv<'_> {
    fn with_env(
        &self,
        block: &StacksBlockId,
        f: &mut dyn FnMut(&dyn HeadersDB, &dyn BurnStateDB),
    ) -> Result<(), String> {
        let info = self.blocks.header(block)?;
        // an epoch 2.x block ran under its own sortition; lookups through it
        // are refused as unprovable when the deploy witness is settled
        let view = match &info.anchored_header {
            StacksBlockHeaderTypes::Nakamoto(_) => view_of(&self.burn_view(block)?.tx)?,
            StacksBlockHeaderTypes::Epoch2(_) => info.consensus_hash,
        };
        let sn = SortitionDB::get_block_snapshot_consensus(self.sortdb.conn(), &view)
            .map_err(|e| format!("burn view {view}: {e:?}"))?
            .ok_or_else(|| format!("burn view {view} has no snapshot"))?;
        let burn = self.sortdb.index_handle(&sn.sortition_id);
        f(self.headers, &burn);
        Ok(())
    }

    fn burn_view(&self, block: &StacksBlockId) -> Result<TxInclusion, String> {
        let info = self.blocks.header(block)?;
        if !matches!(info.anchored_header, StacksBlockHeaderTypes::Nakamoto(_)) {
            return Err("an epoch 2.x block has no tenure-change burn view".into());
        }
        Ok(self.blocks.burn_view_change(block, &info.consensus_hash)?.0)
    }
}

/// What a set of environment lookups needs served besides the lookups:
/// headers of the blocks they name, preimages of the consensus hashes they
/// bind to, tenure-start coinbases (VRF seeds), and Bitcoin headers at burn
/// heights read on a burn view's fork.
#[derive(Default)]
struct EnvNeeds {
    blocks: BTreeSet<StacksBlockId>,
    chs: Vec<ConsensusHash>,
    tenure_starts: BTreeMap<ConsensusHash, StacksBlockId>,
    /// (burn view, height)
    burn_heights: BTreeSet<(ConsensusHash, u32)>,
}

impl EnvNeeds {
    /// Add `reads`, evaluated under burn view `view` (`None`: no burn-view
    /// lookups) on the fork of `tip`.
    fn add(
        &mut self,
        reads: &[EnvRead],
        view: Option<&ConsensusHash>,
        tip: &StacksBlockId,
        blocks: &NodeBlocks,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
    ) -> Result<(), String> {
        for read in reads.iter() {
            use EnvQuery::*;
            match &read.query {
                StacksBlockHeaderHash { id, .. }
                | BurnHeaderHashForBlock { id }
                | ConsensusHashForBlock { id, .. }
                | StacksBlockTime { id }
                | BurnBlockTime { id, .. }
                | BurnBlockHeightForBlock { id }
                | MinerAddress { id, .. }
                | TokensSpent { id, .. }
                | TokensSpentWinning { id, .. }
                | TokensEarned { id, .. } => {
                    self.blocks.insert(id.clone());
                    self.chs.push(blocks.header(id)?.consensus_hash);
                }
                VrfSeed { id, epoch, .. } => {
                    self.blocks.insert(id.clone());
                    let ch = blocks.header(id)?.consensus_hash;
                    if epoch.uses_nakamoto_blocks() && !self.tenure_starts.contains_key(&ch) {
                        let start = NakamotoChainState::get_nakamoto_tenure_start_block_header(
                            &mut chainstate.index_conn(),
                            tip,
                            &ch,
                        )
                        .map_err(|e| format!("tenure {ch}: {e:?}"))?
                        .ok_or_else(|| format!("no tenure start for {ch}"))?;
                        self.tenure_starts
                            .insert(ch.clone(), start.index_block_hash());
                    }
                    self.chs.push(ch);
                }
                SortitionIdFromConsensusHash { consensus_hash } => {
                    self.chs.push(consensus_hash.clone())
                }
                BurnBlockHeight { sortition } => {
                    let sn = SortitionDB::get_block_snapshot(sortdb.conn(), sortition)
                        .map_err(|e| format!("sortition {sortition}: {e:?}"))?
                        .ok_or_else(|| format!("no sortition {sortition}"))?;
                    self.chs.push(sn.consensus_hash);
                }
                TipBurnBlockHeight | TipSortitionId => {
                    self.chs.extend(view.cloned());
                }
                BurnHeaderHash { height, .. } => {
                    if let Some(view) = view {
                        self.chs.push(view.clone());
                        self.burn_heights.insert((view.clone(), *height));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn deploys(contract: &QualifiedContractIdentifier) -> impl Fn(&StacksTransaction) -> bool + '_ {
    move |tx| match &tx.payload {
        TransactionPayload::SmartContract(sc, _) => {
            sc.name == contract.name
                && PrincipalData::from(tx.origin_address())
                    == PrincipalData::Standard(contract.issuer.clone())
        }
        _ => false,
    }
}

fn is_tenure_change(tx: &StacksTransaction) -> bool {
    matches!(tx.payload, TransactionPayload::TenureChange(_))
}

fn is_coinbase(tx: &StacksTransaction) -> bool {
    matches!(tx.payload, TransactionPayload::Coinbase(..))
}

/// Gather a client's evidence for `block`, whose replay recorded `witness`
/// and made `writes`.
pub fn serve_witness(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    block: &NakamotoBlock,
    witness: &ReadWitness,
    writes: &[StateWrite],
) -> Result<ServedWitness, String> {
    let block_id = block.block_id();
    let parent = block.header.parent_block_id.clone();
    let net = node_network_params(sortdb, chainstate)?;
    let mut needed: BTreeSet<StacksBlockId> = BTreeSet::new();
    needed.insert(parent.clone());

    let blocks = NodeBlocks {
        headers_db: chainstate.state_index.sqlite_conn(),
        staged: &chainstate.nakamoto_staging_blocks_conn,
        blocks_path: &chainstate.blocks_path,
    };

    // the burn view: this block's tenure change, else the latest one earlier
    // in its tenure (every block walked is a header the client walks too)
    let burn_view = if block.txs.iter().any(is_tenure_change) {
        None
    } else {
        let (inclusion, walked) = blocks.burn_view_change(&parent, &block.header.consensus_hash)?;
        needed.extend(walked);
        Some(inclusion)
    };
    let view_ch = match block.txs.iter().find(|tx| is_tenure_change(tx)) {
        Some(tx) => view_of(tx)?,
        None => view_of(&burn_view.as_ref().ok_or("no burn view")?.tx)?,
    };

    // what the block's own lookups need
    let mut env = EnvNeeds::default();
    env.chs = vec![view_ch.clone(), blocks.header(&parent)?.consensus_hash];
    env.add(
        &witness.env,
        Some(&view_ch),
        &parent,
        &blocks,
        sortdb,
        chainstate,
    )?;
    let deploy_env = NodeDeployEnv {
        sortdb,
        headers: &chainstate.state_index,
        blocks: &blocks,
    };

    // `at-block` targets
    for (query, _) in witness.store.iter() {
        match query {
            StoreQuery::Data { at: Some(at), .. }
            | StoreQuery::Path { at: Some(at), .. }
            | StoreQuery::BlockAtHeight { at: Some(at), .. }
            | StoreQuery::CurrentHeight { at }
            | StoreQuery::AtBlock { target: at } => {
                needed.insert(at.clone());
            }
            _ => {}
        }
    }

    // MARF proofs: one shared proof for every read (store entries and
    // contract evidence, at the parent, `at-block` targets, deploy blocks and
    // their parents), one for the block's final writes at its own root
    let mut last: BTreeMap<String, String> = BTreeMap::new();
    for write in writes.iter() {
        last.insert(write.key.clone(), write.value.clone());
    }
    let (store, (contracts, unproven), marf, write_proof, tries) =
        chainstate.clarity_state.with_marf(|marf| {
            marf.with_conn(|conn| {
                // a trie's skip-list ancestors are looked up by height; memoize
                // those lookups for this call only. Every root proven here is
                // on the block's own chain.
                conn.enable_lookup_memo(Some(block_id.clone()));
                let proven = (|| {
                    let mut reads = MultiproofBuilder::new();
                    let started = Instant::now();
                    info!("Witness: walking {} store entries", witness.store.len());
                    let store = prove_store_reads(conn, &mut reads, &parent, witness)?;
                    prove_env_reads(conn, &mut reads, &witness.env)?;
                    info!(
                        "Witness: walked {} store entries in {:?}",
                        store.len(),
                        started.elapsed()
                    );
                    let started = Instant::now();
                    let find_deploy =
                        |deploy_block: &StacksBlockId, contract: &QualifiedContractIdentifier| {
                            blocks
                                .include(deploy_block, deploys(contract))
                                .ok()
                                .flatten()
                        };
                    let (contracts, unproven) =
                        prove_contracts(
                            conn,
                            &mut reads,
                            &parent,
                            witness,
                            &net,
                            &find_deploy,
                            Some(&deploy_env),
                        )?;
                    info!(
                        "Witness: proved {} contracts ({} with a deploy witness, {} unprovable) in {:?}",
                        contracts.len(),
                        contracts
                            .iter()
                            .filter(|c| !c.deploy_reads.is_empty() || !c.deploy_env.is_empty())
                            .count(),
                        unproven.len(),
                        started.elapsed()
                    );
                    let started = Instant::now();
                    let marf = reads
                        .encode(conn)
                        .map_err(|e| format!("shared read proof: {e:?}"))?;
                    info!(
                        "Witness: encoded the shared read proof ({} tries, {} bytes) in {:?}",
                        reads.tries().count(),
                        marf.len(),
                        started.elapsed()
                    );
                    let started = Instant::now();
                    let finals: Vec<(String, String)> = last.into_iter().collect();
                    let mut written = MultiproofBuilder::new();
                    prove_writes(conn, &mut written, &block_id, &finals)?;
                    let write_proof = WriteProof {
                        keys: finals.into_iter().map(|(key, _)| key).collect(),
                        proof: written
                            .encode(conn)
                            .map_err(|e| format!("final-write proof: {e:?}"))?,
                    };
                    info!(
                        "Witness: proved {} final writes ({} tries, {} bytes) in {:?}",
                        write_proof.keys.len(),
                        written.tries().count(),
                        write_proof.proof.len(),
                        started.elapsed()
                    );
                    let tries: Vec<StacksBlockId> =
                        reads.tries().chain(written.tries()).cloned().collect();
                    Ok::<_, String>((store, (contracts, unproven), marf, write_proof, tries))
                })();
                if let Some((tries, heights, blocks)) = conn.lookup_memo_len() {
                    info!(
                        "Witness: lookup memo held {tries} tries' ancestor hashes, \
                         {heights} block heights, {blocks} blocks at a height"
                    );
                }
                conn.disable_lookup_memo();
                proven
            })
        })?;

    // what the deploys' lookups need, under each deploying block's burn view
    for evidence in contracts.iter() {
        let view = match &evidence.deploy_burn_view {
            Some(inclusion) => {
                let deployed = blocks.header(&evidence.block)?;
                let (_, walked) =
                    blocks.burn_view_change(&evidence.block, &deployed.consensus_hash)?;
                needed.extend(walked);
                Some(view_of(&inclusion.tx)?)
            }
            None => None,
        };
        env.chs.extend(view.clone());
        env.add(
            &evidence.deploy_env,
            view.as_ref(),
            &parent,
            &blocks,
            sortdb,
            chainstate,
        )?;
    }

    let mut coinbases = vec![];
    for (ch, start) in env.tenure_starts.iter() {
        let inclusion = blocks
            .include(start, is_coinbase)?
            .ok_or_else(|| format!("tenure {ch} starts without a coinbase"))?;
        needed.insert(start.clone());
        coinbases.push(inclusion);
    }
    let mut seen = HashSet::new();
    env.chs.retain(|ch| seen.insert(ch.clone()));
    let burn = env
        .chs
        .iter()
        .map(|ch| burn_binding(sortdb, ch))
        .collect::<Result<Vec<_>, _>>()?;

    // Bitcoin headers: every bound burn block, and burn heights read on a
    // burn view's fork
    let mut bitcoin: BTreeMap<u32, BitcoinHeader> = BTreeMap::new();
    for ch in env.chs.iter() {
        let header = bitcoin_header(sortdb, ch)?;
        bitcoin.insert(header.height, header);
    }
    for (view, height) in env.burn_heights.iter() {
        let view_sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), view)
            .map_err(|e| format!("burn view: {e:?}"))?
            .ok_or("burn view has no snapshot")?;
        let height = u64::from(*height);
        if height > view_sn.block_height || height < sortdb.first_block_height {
            continue;
        }
        let sn = sortdb
            .index_handle(&view_sn.sortition_id)
            .get_block_snapshot_by_height(height)
            .map_err(|e| format!("burn height {height}: {e:?}"))?
            .ok_or_else(|| format!("no burn block at {height}"))?;
        let header = bitcoin_header(sortdb, &sn.consensus_hash)?;
        bitcoin.insert(header.height, header);
    }
    needed.extend(env.blocks);

    let mut proven = ProvenWitness {
        witness: witness.clone(),
        store,
        contracts,
        marf,
        burn,
        burn_view,
        coinbases,
    };
    mark_served_metadata(&mut proven);
    // every trie a proof holds: the client pins each to its header's root
    needed.extend(tries);
    for evidence in proven.contracts.iter() {
        needed.insert(evidence.block.clone());
    }

    // headers, signer signatures stripped (the block hash does not commit to
    // them); the client pins genesis and has the block itself
    needed.remove(&block_id);
    needed.remove(&FIRST_STACKS_BLOCK_ID);
    let mut headers = vec![];
    for id in needed.iter() {
        let info = blocks.header(id)?;
        let mut header = info.anchored_header;
        if let StacksBlockHeaderTypes::Nakamoto(h) = &mut header {
            h.signer_signature.clear();
        }
        headers.push(ServedHeader {
            consensus_hash: info.consensus_hash,
            header,
        });
    }

    Ok(ServedWitness {
        mainnet: net.mainnet,
        chain_id: net.chain_id,
        proven,
        headers,
        bitcoin: bitcoin.into_values().collect(),
        writes: write_proof,
        unproven_contracts: unproven
            .into_iter()
            .map(|(contract, reason)| (contract.to_string(), reason))
            .collect(),
    })
}
