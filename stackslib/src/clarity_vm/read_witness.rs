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

//! Read witness: every value a block's Clarity execution read from outside
//! itself, recorded so the block can be re-executed with nothing else
//! (see [`crate::clarity_vm::stateless`]).
//!
//! Two sources are recorded, both opt-in via
//! [`crate::clarity_vm::clarity::ClarityInstance::set_collect_read_witness`]:
//!
//! * **Store reads** ([`RecordingStore`], wrapping the block's writable MARF
//!   store). A read at the open block is recorded only if the block had not
//!   yet written that key, so its value is the parent's (provable against the
//!   parent's `state_index_root`). Reads inside `at-block` are recorded with
//!   the block they targeted (provable against that block's root), as are the
//!   `at-block` switches themselves, MARF height lookups, and contract
//!   metadata reads (side table, keyed by the deploying block).
//! * **Environment lookups** ([`EnvTap`], wrapping the block's `HeadersDB` and
//!   `BurnStateDB`): block info, burn info, tenure info, VRF seeds, epochs,
//!   PoX parameters. Recorded as `(query, answer)`.
//!
//! Entries are deduplicated and kept in first-read order.

use std::any::Any;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::database::sqlite::sqlite_get_contract_hash;
use clarity::vm::database::{
    BurnStateDB, ClarityBackingStore, HeadersDB, SpecialCaseHandler, SqliteConnection,
};
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::types::{QualifiedContractIdentifier, TupleData};
use rusqlite::Connection;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    TrieHash, VRFSeed,
};
use stacks_common::types::StacksEpochId;

use crate::clarity_vm::clarity::{
    ClarityMarfStore, ClarityMarfStoreTransaction, WritableMarfStore,
};
use crate::clarity_vm::state_writes::StateWriteLog;
use crate::core::StacksEpoch;

/// One question the block's execution asked its backing store.
///
/// `at: None` means the open block (the block being built): its answer is
/// the parent's state. `at: Some(id)` means a read inside `at-block id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreQuery {
    /// MARF value for `key`.
    Data {
        at: Option<StacksBlockId>,
        key: String,
    },
    /// MARF value for a trie path (key hash), when the reader only had the hash.
    Path {
        at: Option<StacksBlockId>,
        path: TrieHash,
    },
    /// MARF height -> block id lookup (`__MARF_BLOCK_HEIGHT_TO_HASH::h`).
    BlockAtHeight {
        at: Option<StacksBlockId>,
        height: u32,
    },
    /// Height of a historical block (`at-block` target).
    CurrentHeight { at: StacksBlockId },
    /// `at-block` switch: answer `Some("ok")` if `target` is an ancestor,
    /// `None` if the switch failed.
    AtBlock { target: StacksBlockId },
    /// Contract metadata (side table, not MARF) of a contract deployed in
    /// `block`, an ancestor.
    Metadata {
        block: StacksBlockId,
        contract: String,
        key: String,
    },
}

impl StoreQuery {
    /// Bytes this query needs on the wire: its key material.
    pub fn wire_len(&self) -> usize {
        match self {
            StoreQuery::Data { at, key } => at_len(at) + key.len(),
            StoreQuery::Path { at, .. } => at_len(at) + 32,
            StoreQuery::BlockAtHeight { at, .. } => at_len(at) + 4,
            StoreQuery::CurrentHeight { .. } => 32,
            StoreQuery::AtBlock { .. } => 32,
            StoreQuery::Metadata { contract, key, .. } => 32 + contract.len() + key.len(),
        }
    }
}

fn at_len(at: &Option<StacksBlockId>) -> usize {
    if at.is_some() {
        32
    } else {
        0
    }
}

/// One `HeadersDB` / `BurnStateDB` question: the trait method and its
/// arguments. `Display` renders it as `method(args)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum EnvQuery {
    StacksBlockHeaderHash {
        id: StacksBlockId,
        epoch: StacksEpochId,
    },
    BurnHeaderHashForBlock {
        id: StacksBlockId,
    },
    ConsensusHashForBlock {
        id: StacksBlockId,
        epoch: StacksEpochId,
    },
    VrfSeed {
        id: StacksBlockId,
        tip: StacksBlockId,
        epoch: StacksEpochId,
    },
    StacksBlockTime {
        id: StacksBlockId,
    },
    BurnBlockTime {
        id: StacksBlockId,
        epoch: Option<StacksEpochId>,
    },
    BurnBlockHeightForBlock {
        id: StacksBlockId,
    },
    MinerAddress {
        id: StacksBlockId,
        tip: StacksBlockId,
        epoch: StacksEpochId,
    },
    TokensSpent {
        id: StacksBlockId,
        tip: StacksBlockId,
        epoch: StacksEpochId,
    },
    TokensSpentWinning {
        id: StacksBlockId,
        tip: StacksBlockId,
        epoch: StacksEpochId,
    },
    TokensEarned {
        id: StacksBlockId,
        tip: StacksBlockId,
        epoch: StacksEpochId,
    },
    StacksHeightForTenureHeight {
        tip: StacksBlockId,
        tenure_height: u32,
    },
    TipBurnBlockHeight,
    TipSortitionId,
    V1UnlockHeight,
    V2UnlockHeight,
    V3UnlockHeight,
    Pox3ActivationHeight,
    Pox4ActivationHeight,
    Pox5ActivationHeight,
    BurnBlockHeight {
        #[serde(with = "sortition_hex")]
        sortition: SortitionId,
    },
    BurnStartHeight,
    PoxPrepareLength,
    PoxRewardCycleLength,
    PoxRejectionFraction,
    BurnHeaderHash {
        height: u32,
        #[serde(with = "sortition_hex")]
        sortition: SortitionId,
    },
    SortitionIdFromConsensusHash {
        consensus_hash: ConsensusHash,
    },
    StacksEpoch {
        height: u32,
    },
    StacksEpochById {
        epoch: StacksEpochId,
    },
    PoxPayoutAddrs {
        height: u32,
        #[serde(with = "sortition_hex")]
        sortition: SortitionId,
    },
}

/// `SortitionId` as a hex string (it has no serde impl of its own).
mod sortition_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    use stacks_common::types::chainstate::SortitionId;

    pub fn serialize<S: Serializer>(id: &SortitionId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&id.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SortitionId, D::Error> {
        let hex = String::deserialize(d)?;
        SortitionId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for EnvQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EnvQuery::*;
        match self {
            StacksBlockHeaderHash { id, epoch } => {
                write!(f, "stacks_block_header_hash_for_block({id},{epoch:?})")
            }
            BurnHeaderHashForBlock { id } => write!(f, "burn_header_hash_for_block({id})"),
            ConsensusHashForBlock { id, epoch } => {
                write!(f, "consensus_hash_for_block({id},{epoch:?})")
            }
            VrfSeed { id, tip, epoch } => write!(f, "vrf_seed_for_block({id},{tip},{epoch:?})"),
            StacksBlockTime { id } => write!(f, "stacks_block_time_for_block({id})"),
            BurnBlockTime { id, epoch } => write!(f, "burn_block_time_for_block({id},{epoch:?})"),
            BurnBlockHeightForBlock { id } => write!(f, "burn_block_height_for_block({id})"),
            MinerAddress { id, tip, epoch } => write!(f, "miner_address({id},{tip},{epoch:?})"),
            TokensSpent { id, tip, epoch } => {
                write!(f, "burnchain_tokens_spent_for_block({id},{tip},{epoch:?})")
            }
            TokensSpentWinning { id, tip, epoch } => write!(
                f,
                "burnchain_tokens_spent_for_winning_block({id},{tip},{epoch:?})"
            ),
            TokensEarned { id, tip, epoch } => {
                write!(f, "tokens_earned_for_block({id},{tip},{epoch:?})")
            }
            StacksHeightForTenureHeight { tip, tenure_height } => {
                write!(f, "stacks_height_for_tenure_height({tip},{tenure_height})")
            }
            TipBurnBlockHeight => write!(f, "tip_burn_block_height()"),
            TipSortitionId => write!(f, "tip_sortition_id()"),
            V1UnlockHeight => write!(f, "v1_unlock_height()"),
            V2UnlockHeight => write!(f, "v2_unlock_height()"),
            V3UnlockHeight => write!(f, "v3_unlock_height()"),
            Pox3ActivationHeight => write!(f, "pox_3_activation_height()"),
            Pox4ActivationHeight => write!(f, "pox_4_activation_height()"),
            Pox5ActivationHeight => write!(f, "pox_5_activation_height()"),
            BurnBlockHeight { sortition } => write!(f, "burn_block_height({sortition})"),
            BurnStartHeight => write!(f, "burn_start_height()"),
            PoxPrepareLength => write!(f, "pox_prepare_length()"),
            PoxRewardCycleLength => write!(f, "pox_reward_cycle_length()"),
            PoxRejectionFraction => write!(f, "pox_rejection_fraction()"),
            BurnHeaderHash { height, sortition } => {
                write!(f, "burn_header_hash({height},{sortition})")
            }
            SortitionIdFromConsensusHash { consensus_hash } => {
                write!(f, "sortition_id_from_consensus_hash({consensus_hash})")
            }
            StacksEpoch { height } => write!(f, "stacks_epoch({height})"),
            StacksEpochById { epoch } => write!(f, "stacks_epoch_by_epoch_id({epoch:?})"),
            PoxPayoutAddrs { height, sortition } => {
                write!(f, "pox_payout_addrs({height},{sortition})")
            }
        }
    }
}

/// One `HeadersDB` / `BurnStateDB` lookup and its answer.
#[derive(Clone)]
pub struct EnvRead {
    pub query: EnvQuery,
    /// The typed answer, as the trait method returned it.
    pub answer: Arc<dyn Any + Send + Sync>,
    /// `Debug` rendering of the answer, for inspection and sizing.
    pub shown: String,
}

impl fmt::Debug for EnvRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = {}", self.query, self.shown)
    }
}

/// Two lookups are equal when they asked the same thing and got answers that
/// render the same.
impl PartialEq for EnvRead {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query && self.shown == other.shown
    }
}

impl EnvRead {
    pub fn new<R: fmt::Debug + Send + Sync + 'static>(query: EnvQuery, answer: R) -> Self {
        EnvRead {
            query,
            shown: format!("{answer:?}"),
            answer: Arc::new(answer),
        }
    }

    /// Replace the answer (tests: tamper with an environment value).
    pub fn set_answer<R: fmt::Debug + Send + Sync + 'static>(&mut self, answer: R) {
        *self = EnvRead::new(self.query.clone(), answer);
    }
}

/// Everything a block's execution read from outside itself.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadWitness {
    /// Id the block was built under (the MARF's temporary miner tip).
    pub open_tip: StacksBlockId,
    /// Height of the block being built.
    pub open_height: u32,
    /// Epoch (and block cost limit) the block was evaluated in.
    pub epoch: StacksEpoch,
    /// Store reads, deduplicated, in first-read order.
    pub store: Vec<(StoreQuery, Option<String>)>,
    /// Environment lookups, deduplicated, in first-lookup order.
    pub env: Vec<EnvRead>,
}

/// Size of a read witness, for measurement.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WitnessSize {
    pub parent_reads: usize,
    pub at_block_reads: usize,
    pub height_lookups: usize,
    pub metadata_reads: usize,
    pub env_lookups: usize,
    /// Query key material plus answer bytes: MARF reads and lookups.
    pub store_bytes: usize,
    /// Same, contract metadata reads (ASTs and analyses: large, and not
    /// provable by MARF proof; see `NOTES.md`).
    pub metadata_bytes: usize,
    /// Query plus `Debug` answer bytes, environment lookups.
    pub env_bytes: usize,
}

impl ReadWitness {
    pub fn size(&self) -> WitnessSize {
        let mut size = WitnessSize::default();
        for (query, answer) in self.store.iter() {
            let bytes = query.wire_len() + answer.as_ref().map_or(0, String::len);
            if matches!(query, StoreQuery::Metadata { .. }) {
                size.metadata_bytes += bytes;
            } else {
                size.store_bytes += bytes;
            }
            match query {
                StoreQuery::Data { at: None, .. } | StoreQuery::Path { at: None, .. } => {
                    size.parent_reads += 1
                }
                StoreQuery::Data { .. } | StoreQuery::Path { .. } => size.at_block_reads += 1,
                StoreQuery::BlockAtHeight { .. }
                | StoreQuery::CurrentHeight { .. }
                | StoreQuery::AtBlock { .. } => size.height_lookups += 1,
                StoreQuery::Metadata { .. } => size.metadata_reads += 1,
            }
        }
        for read in self.env.iter() {
            size.env_lookups += 1;
            size.env_bytes += read.query.to_string().len() + read.shown.len();
        }
        size
    }
}

/// Store reads recorded by a [`RecordingStore`].
#[derive(Debug, Clone)]
pub struct StoreReads {
    pub open_tip: StacksBlockId,
    pub open_height: u32,
    pub reads: Vec<(StoreQuery, Option<String>)>,
}

/// Wraps a block's writable MARF store and records every read the block's
/// execution needed from outside the block (see the module docs).
pub struct RecordingStore<'a> {
    inner: Box<dyn WritableMarfStore + 'a>,
    open_tip: StacksBlockId,
    open_height: u32,
    /// `Some(id)` while inside `at-block id`.
    at: Option<StacksBlockId>,
    seen: HashSet<StoreQuery>,
    reads: Vec<(StoreQuery, Option<String>)>,
    /// Keys (and their paths) this block has written so far: reads of these
    /// at the open block are the block's own state, not the parent's.
    written: HashSet<String>,
    written_paths: HashSet<TrieHash>,
}

impl<'a> RecordingStore<'a> {
    pub fn new(mut inner: Box<dyn WritableMarfStore + 'a>) -> Self {
        let open_tip = inner.get_open_chain_tip();
        let open_height = inner.get_open_chain_tip_height();
        RecordingStore {
            inner,
            open_tip,
            open_height,
            at: None,
            seen: HashSet::new(),
            reads: vec![],
            written: HashSet::new(),
            written_paths: HashSet::new(),
        }
    }

    fn record(&mut self, query: StoreQuery, answer: Option<String>) {
        if self.seen.insert(query.clone()) {
            self.reads.push((query, answer));
        }
    }

    fn reads_parent_key(&self, key: &str) -> bool {
        self.at.is_some() || !self.written.contains(key)
    }

    fn reads_parent_path(&self, path: &TrieHash) -> bool {
        self.at.is_some() || !self.written_paths.contains(path)
    }

    fn read_metadata(
        &mut self,
        block: StacksBlockId,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        let value = SqliteConnection::get_metadata(
            self.inner.get_side_store(),
            &block,
            &contract.to_string(),
            key,
        )?;
        if block != self.open_tip {
            self.record(
                StoreQuery::Metadata {
                    block,
                    contract: contract.to_string(),
                    key: key.to_string(),
                },
                value.clone(),
            );
        }
        Ok(value)
    }
}

impl ClarityBackingStore for RecordingStore<'_> {
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<(), VmExecutionError> {
        for (key, _) in items.iter() {
            self.written_paths.insert(TrieHash::from_key(key));
            self.written.insert(key.clone());
        }
        self.inner.put_all_data(items)
    }

    fn get_data(&mut self, key: &str) -> Result<Option<String>, VmExecutionError> {
        let value = self.inner.get_data(key)?;
        if self.reads_parent_key(key) {
            let query = StoreQuery::Data {
                at: self.at.clone(),
                key: key.to_string(),
            };
            self.record(query, value.clone());
        }
        Ok(value)
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>, VmExecutionError> {
        let value = self.inner.get_data_from_path(hash)?;
        if self.reads_parent_path(hash) {
            let query = StoreQuery::Path {
                at: self.at.clone(),
                path: *hash,
            };
            self.record(query, value.clone());
        }
        Ok(value)
    }

    fn get_data_with_proof(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        let value = self.inner.get_data_with_proof(key)?;
        if self.reads_parent_key(key) {
            let query = StoreQuery::Data {
                at: self.at.clone(),
                key: key.to_string(),
            };
            self.record(query, value.as_ref().map(|(v, _)| v.clone()));
        }
        Ok(value)
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        let value = self.inner.get_data_with_proof_from_path(hash)?;
        if self.reads_parent_path(hash) {
            let query = StoreQuery::Path {
                at: self.at.clone(),
                path: *hash,
            };
            self.record(query, value.as_ref().map(|(v, _)| v.clone()));
        }
        Ok(value)
    }

    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId, VmExecutionError> {
        let result = self.inner.set_block_hash(bhh.clone());
        if bhh == self.open_tip {
            if result.is_ok() {
                self.at = None;
            }
            return result;
        }
        let answer = result.is_ok().then(|| "ok".to_string());
        self.record(
            StoreQuery::AtBlock {
                target: bhh.clone(),
            },
            answer,
        );
        if result.is_ok() {
            self.at = Some(bhh);
        }
        result
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        let block = self.inner.get_block_at_height(height);
        let query = StoreQuery::BlockAtHeight {
            at: self.at.clone(),
            height,
        };
        self.record(query, block.as_ref().map(StacksBlockId::to_hex));
        block
    }

    fn get_current_block_height(&mut self) -> u32 {
        let height = self.inner.get_current_block_height();
        if let Some(at) = self.at.clone() {
            self.record(StoreQuery::CurrentHeight { at }, Some(height.to_string()));
        }
        height
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.inner.get_open_chain_tip_height()
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.inner.get_open_chain_tip()
    }

    fn get_side_store(&mut self) -> &Connection {
        self.inner.get_side_store()
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        self.inner.get_cc_special_cases_handler()
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum), VmExecutionError> {
        // through `self`, so the commitment and height lookups are recorded
        sqlite_get_contract_hash(self, contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), VmExecutionError> {
        self.inner.insert_metadata(contract, key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        let (block, _) = self.get_contract_hash(contract)?;
        self.read_metadata(block, contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        let block = self
            .get_block_at_height(at_height)
            .ok_or_else(|| RuntimeError::BadBlockHeight(at_height.to_string()))?;
        self.read_metadata(block, contract, key)
    }
}

impl ClarityMarfStore for RecordingStore<'_> {}

impl ClarityMarfStoreTransaction for RecordingStore<'_> {
    fn commit_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        self.inner.commit_metadata_for_trie(target)
    }

    fn drop_metadata_for_trie(&mut self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        self.inner.drop_metadata_for_trie(target)
    }

    fn seal_trie(&mut self) -> TrieHash {
        self.inner.seal_trie()
    }

    fn drop_current_trie(self) {
        self.inner.drop_current_trie()
    }

    fn drop_unconfirmed(self) -> Result<(), VmExecutionError> {
        self.inner.drop_unconfirmed()
    }

    fn commit_to_processed_block(self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        self.inner.commit_to_processed_block(target)
    }

    fn commit_to_mined_block(self, target: &StacksBlockId) -> Result<(), VmExecutionError> {
        self.inner.commit_to_mined_block(target)
    }

    fn commit_unconfirmed(self) {
        self.inner.commit_unconfirmed()
    }

    #[cfg(test)]
    fn test_commit(self) {
        self.inner.test_commit()
    }
}

impl WritableMarfStore for RecordingStore<'_> {
    fn enable_state_write_log(&mut self) {
        self.inner.enable_state_write_log()
    }

    fn state_write_log(&mut self) -> Option<&mut StateWriteLog> {
        self.inner.state_write_log()
    }

    fn take_store_reads(&mut self) -> Option<StoreReads> {
        self.seen.clear();
        Some(StoreReads {
            open_tip: self.open_tip.clone(),
            open_height: self.open_height,
            reads: std::mem::take(&mut self.reads),
        })
    }
}

enum EnvSource<'a> {
    /// Answer from the node's databases and record the answers.
    Live {
        headers: &'a dyn HeadersDB,
        burn: &'a dyn BurnStateDB,
        epoch: StacksEpoch,
    },
    /// Answer only from a witness.
    Witness(HashMap<EnvQuery, Arc<dyn Any + Send + Sync>>),
}

#[derive(Default)]
struct EnvLog {
    seen: HashSet<EnvQuery>,
    reads: Vec<EnvRead>,
    missing: Vec<String>,
}

/// `HeadersDB` + `BurnStateDB` that either records a live node's answers or
/// serves answers from a witness alone. Every trait method goes through
/// [`EnvTap::answer`], so recording and replay use the same query strings.
pub struct EnvTap<'a> {
    source: EnvSource<'a>,
    log: RefCell<EnvLog>,
}

impl<'a> EnvTap<'a> {
    pub fn recording(
        headers: &'a dyn HeadersDB,
        burn: &'a dyn BurnStateDB,
        epoch: StacksEpoch,
    ) -> Self {
        EnvTap {
            source: EnvSource::Live {
                headers,
                burn,
                epoch,
            },
            log: RefCell::new(EnvLog::default()),
        }
    }

    pub fn from_witness(reads: &[EnvRead]) -> Self {
        let mut answers = HashMap::new();
        for read in reads.iter() {
            answers
                .entry(read.query.clone())
                .or_insert_with(|| read.answer.clone());
        }
        EnvTap {
            source: EnvSource::Witness(answers),
            log: RefCell::new(EnvLog::default()),
        }
    }

    /// Recorded lookups and the epoch, if recording.
    pub fn take_recorded(&self) -> Option<(StacksEpoch, Vec<EnvRead>)> {
        let EnvSource::Live { epoch, .. } = &self.source else {
            return None;
        };
        let mut log = self.log.borrow_mut();
        log.seen.clear();
        Some((epoch.clone(), std::mem::take(&mut log.reads)))
    }

    /// Queries a witness could not answer.
    pub fn missing(&self) -> Vec<String> {
        self.log.borrow().missing.clone()
    }

    fn answer<R>(
        &self,
        query: EnvQuery,
        if_missing: R,
        live: impl FnOnce(&dyn HeadersDB, &dyn BurnStateDB) -> R,
    ) -> R
    where
        R: Clone + fmt::Debug + Send + Sync + 'static,
    {
        match &self.source {
            EnvSource::Live { headers, burn, .. } => {
                let answer = live(*headers, *burn);
                let mut log = self.log.borrow_mut();
                if log.seen.insert(query.clone()) {
                    log.reads.push(EnvRead::new(query, answer.clone()));
                }
                answer
            }
            EnvSource::Witness(answers) => {
                match answers.get(&query).and_then(|a| a.downcast_ref::<R>()) {
                    Some(answer) => answer.clone(),
                    None => {
                        self.log.borrow_mut().missing.push(query.to_string());
                        if_missing
                    }
                }
            }
        }
    }
}

impl HeadersDB for EnvTap<'_> {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<BlockHeaderHash> {
        self.answer(
            EnvQuery::StacksBlockHeaderHash {
                id: id_bhh.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_stacks_block_header_hash_for_block(id_bhh, epoch),
        )
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        self.answer(
            EnvQuery::BurnHeaderHashForBlock { id: id_bhh.clone() },
            None,
            |h, _| h.get_burn_header_hash_for_block(id_bhh),
        )
    }

    fn get_consensus_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<ConsensusHash> {
        self.answer(
            EnvQuery::ConsensusHashForBlock {
                id: id_bhh.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_consensus_hash_for_block(id_bhh, epoch),
        )
    }

    fn get_vrf_seed_for_block(
        &self,
        id_bhh: &StacksBlockId,
        tip: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<VRFSeed> {
        self.answer(
            EnvQuery::VrfSeed {
                id: id_bhh.clone(),
                tip: tip.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_vrf_seed_for_block(id_bhh, tip, epoch),
        )
    }

    fn get_stacks_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        self.answer(
            EnvQuery::StacksBlockTime { id: id_bhh.clone() },
            None,
            |h, _| h.get_stacks_block_time_for_block(id_bhh),
        )
    }

    fn get_burn_block_time_for_block(
        &self,
        id_bhh: &StacksBlockId,
        epoch: Option<&StacksEpochId>,
    ) -> Option<u64> {
        self.answer(
            EnvQuery::BurnBlockTime {
                id: id_bhh.clone(),
                epoch: epoch.copied(),
            },
            None,
            |h, _| h.get_burn_block_time_for_block(id_bhh, epoch),
        )
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        self.answer(
            EnvQuery::BurnBlockHeightForBlock { id: id_bhh.clone() },
            None,
            |h, _| h.get_burn_block_height_for_block(id_bhh),
        )
    }

    fn get_miner_address(
        &self,
        id_bhh: &StacksBlockId,
        tip: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<StacksAddress> {
        self.answer(
            EnvQuery::MinerAddress {
                id: id_bhh.clone(),
                tip: tip.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_miner_address(id_bhh, tip, epoch),
        )
    }

    fn get_burnchain_tokens_spent_for_block(
        &self,
        id_bhh: &StacksBlockId,
        tip: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<u128> {
        self.answer(
            EnvQuery::TokensSpent {
                id: id_bhh.clone(),
                tip: tip.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_burnchain_tokens_spent_for_block(id_bhh, tip, epoch),
        )
    }

    fn get_burnchain_tokens_spent_for_winning_block(
        &self,
        id_bhh: &StacksBlockId,
        tip: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<u128> {
        self.answer(
            EnvQuery::TokensSpentWinning {
                id: id_bhh.clone(),
                tip: tip.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_burnchain_tokens_spent_for_winning_block(id_bhh, tip, epoch),
        )
    }

    fn get_tokens_earned_for_block(
        &self,
        id_bhh: &StacksBlockId,
        tip: &StacksBlockId,
        epoch: &StacksEpochId,
    ) -> Option<u128> {
        self.answer(
            EnvQuery::TokensEarned {
                id: id_bhh.clone(),
                tip: tip.clone(),
                epoch: *epoch,
            },
            None,
            |h, _| h.get_tokens_earned_for_block(id_bhh, tip, epoch),
        )
    }

    fn get_stacks_height_for_tenure_height(
        &self,
        tip: &StacksBlockId,
        tenure_height: u32,
    ) -> Option<u32> {
        self.answer(
            EnvQuery::StacksHeightForTenureHeight {
                tip: tip.clone(),
                tenure_height,
            },
            None,
            |h, _| h.get_stacks_height_for_tenure_height(tip, tenure_height),
        )
    }
}

impl BurnStateDB for EnvTap<'_> {
    fn get_tip_burn_block_height(&self) -> Option<u32> {
        self.answer(EnvQuery::TipBurnBlockHeight, None, |_, b| {
            b.get_tip_burn_block_height()
        })
    }

    fn get_tip_sortition_id(&self) -> Option<SortitionId> {
        self.answer(EnvQuery::TipSortitionId, None, |_, b| {
            b.get_tip_sortition_id()
        })
    }

    fn get_v1_unlock_height(&self) -> u32 {
        self.answer(EnvQuery::V1UnlockHeight, 0, |_, b| b.get_v1_unlock_height())
    }

    fn get_v2_unlock_height(&self) -> u32 {
        self.answer(EnvQuery::V2UnlockHeight, 0, |_, b| b.get_v2_unlock_height())
    }

    fn get_v3_unlock_height(&self) -> u32 {
        self.answer(EnvQuery::V3UnlockHeight, 0, |_, b| b.get_v3_unlock_height())
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        self.answer(EnvQuery::Pox3ActivationHeight, 0, |_, b| {
            b.get_pox_3_activation_height()
        })
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        self.answer(EnvQuery::Pox4ActivationHeight, 0, |_, b| {
            b.get_pox_4_activation_height()
        })
    }

    fn get_pox_5_activation_height(&self) -> u32 {
        self.answer(EnvQuery::Pox5ActivationHeight, 0, |_, b| {
            b.get_pox_5_activation_height()
        })
    }

    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        self.answer(
            EnvQuery::BurnBlockHeight {
                sortition: sortition_id.clone(),
            },
            None,
            |_, b| b.get_burn_block_height(sortition_id),
        )
    }

    fn get_burn_start_height(&self) -> u32 {
        self.answer(EnvQuery::BurnStartHeight, 0, |_, b| {
            b.get_burn_start_height()
        })
    }

    fn get_pox_prepare_length(&self) -> u32 {
        self.answer(EnvQuery::PoxPrepareLength, 0, |_, b| {
            b.get_pox_prepare_length()
        })
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        self.answer(EnvQuery::PoxRewardCycleLength, 0, |_, b| {
            b.get_pox_reward_cycle_length()
        })
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        self.answer(EnvQuery::PoxRejectionFraction, 0, |_, b| {
            b.get_pox_rejection_fraction()
        })
    }

    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        self.answer(
            EnvQuery::BurnHeaderHash {
                height,
                sortition: sortition_id.clone(),
            },
            None,
            |_, b| b.get_burn_header_hash(height, sortition_id),
        )
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        self.answer(
            EnvQuery::SortitionIdFromConsensusHash {
                consensus_hash: consensus_hash.clone(),
            },
            None,
            |_, b| b.get_sortition_id_from_consensus_hash(consensus_hash),
        )
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        self.answer(EnvQuery::StacksEpoch { height }, None, |_, b| {
            b.get_stacks_epoch(height)
        })
    }

    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.answer(
            EnvQuery::StacksEpochById { epoch: *epoch_id },
            None,
            |_, b| b.get_stacks_epoch_by_epoch_id(epoch_id),
        )
    }

    fn get_pox_payout_addrs(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        self.answer(
            EnvQuery::PoxPayoutAddrs {
                height,
                sortition: sortition_id.clone(),
            },
            None,
            |_, b| b.get_pox_payout_addrs(height, sortition_id),
        )
    }
}
