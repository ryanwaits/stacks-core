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

//! Stateless re-execution: run a block's transactions through the real
//! transaction-processing path with a Clarity store and `HeadersDB` /
//! `BurnStateDB` backed only by a [`ReadWitness`]. A read the witness cannot
//! answer is a hard error ([`StatelessError::WitnessIncomplete`]).
//!
//! Block-level writes (setup before the first transaction and teardown after
//! the last: tenure bookkeeping, matured rewards, unlocks, burnchain ops) are
//! inputs here, not re-executed: their inputs live in the sortition and
//! headers databases, outside Clarity.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::database::sqlite::sqlite_get_contract_hash;
use clarity::vm::database::{ClarityBackingStore, SpecialCaseHandler, SqliteConnection};
use clarity::vm::errors::{RuntimeError, VmExecutionError, VmInternalError};
use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite::Connection;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, TrieHash, Txid};

use crate::chainstate::nakamoto::TxToProcess;
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::Error as ChainstateError;
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityMarfStore, ClarityMarfStoreTransaction, WritableMarfStore,
};
use crate::clarity_vm::read_witness::{EnvTap, ReadWitness, StoreQuery};
use crate::clarity_vm::special::handle_contract_call_special_cases;
use crate::clarity_vm::state_writes::{StateWrite, StateWriteLog};

/// A block's writes made outside any of its transactions, split around them.
#[derive(Debug, Clone, Default)]
pub struct BlockLevelWrites {
    /// Before the first transaction (block setup, burnchain ops).
    pub setup: Vec<StateWrite>,
    /// After the last transaction (block teardown).
    pub teardown: Vec<StateWrite>,
}

impl BlockLevelWrites {
    /// Split a block's recorded writes: those owned by one of `txids` are the
    /// transactions' own, everything before the first of them is setup, and
    /// everything after the last is teardown.
    pub fn split(writes: &[StateWrite], txids: &HashSet<Txid>) -> Self {
        let is_tx = |w: &StateWrite| w.txid.as_ref().is_some_and(|t| txids.contains(t));
        let first = writes.iter().position(is_tx).unwrap_or(writes.len());
        let last = writes.iter().rposition(is_tx).map_or(first, |i| i + 1);
        assert!(
            writes[first..last].iter().all(is_tx),
            "block-level write between transactions"
        );
        BlockLevelWrites {
            setup: writes[..first].to_vec(),
            teardown: writes[last..].to_vec(),
        }
    }
}

/// What re-executing a block produced.
#[derive(Debug)]
pub struct StatelessBlock {
    /// One receipt per transaction, as live block processing builds them.
    pub receipts: Vec<StacksTransactionReceipt>,
    /// Every MARF write of the block in write order: setup, the transactions'
    /// writes (re-executed), teardown.
    pub writes: Vec<StateWrite>,
}

#[derive(Debug)]
pub enum StatelessError {
    /// Execution asked for something the witness does not contain.
    WitnessIncomplete(Vec<String>),
    /// The block failed to process (e.g. a transaction was invalid).
    Block(ChainstateError),
}

/// Re-execute `txs` with nothing but `witness` (and the block-level writes).
pub fn execute_statelessly<'t>(
    witness: &ReadWitness,
    block_level: &BlockLevelWrites,
    txs: impl IntoIterator<Item = TxToProcess<'t>>,
    mainnet: bool,
    chain_id: u32,
) -> Result<StatelessBlock, StatelessError> {
    let missing = Rc::new(RefCell::new(vec![]));
    let store = WitnessStore::new(witness, &block_level.setup, missing.clone());
    let env = EnvTap::from_witness(&witness.env);

    let mut conn = ClarityBlockConnection::from_writable_store(
        Box::new(store),
        &env,
        &env,
        mainnet,
        chain_id,
        witness.epoch.clone(),
    );
    conn.set_emit_vm_trace(true);
    let mut clarity_tx = ClarityTx::from_block_connection(conn);
    let result = StacksChainState::process_block_transactions(&mut clarity_tx, txs, 0);
    let tx_writes = clarity_tx
        .connection()
        .take_state_writes()
        .expect("witness store always records writes");
    clarity_tx.rollback_block();

    let mut missing = missing.take();
    missing.extend(env.missing());
    if !missing.is_empty() {
        return Err(StatelessError::WitnessIncomplete(missing));
    }
    let (_fees, _burns, receipts) = result.map_err(StatelessError::Block)?;

    let mut writes = block_level.setup.clone();
    writes.extend(tx_writes);
    writes.extend(block_level.teardown.iter().cloned());
    Ok(StatelessBlock { receipts, writes })
}

/// A writable Clarity store with no state of its own: reads come from the
/// block's earlier writes or the witness, writes go to memory.
struct WitnessStore {
    answers: HashMap<StoreQuery, Option<String>>,
    open_tip: StacksBlockId,
    open_height: u32,
    at: Option<StacksBlockId>,
    /// This block's writes so far (key and path), and contract metadata it
    /// inserted (contracts deployed in this block).
    overlay: HashMap<String, String>,
    path_overlay: HashMap<TrieHash, String>,
    metadata: HashMap<(String, String), String>,
    missing: Rc<RefCell<Vec<String>>>,
    write_log: StateWriteLog,
    /// Unused; the trait requires a side store.
    side_store: Connection,
}

impl WitnessStore {
    fn new(witness: &ReadWitness, setup: &[StateWrite], missing: Rc<RefCell<Vec<String>>>) -> Self {
        let mut answers = HashMap::new();
        for (query, answer) in witness.store.iter() {
            answers
                .entry(query.clone())
                .or_insert_with(|| answer.clone());
        }
        let mut store = WitnessStore {
            answers,
            open_tip: witness.open_tip.clone(),
            open_height: witness.open_height,
            at: None,
            overlay: HashMap::new(),
            path_overlay: HashMap::new(),
            metadata: HashMap::new(),
            missing,
            write_log: StateWriteLog::default(),
            side_store: SqliteConnection::memory().expect("in-memory sqlite"),
        };
        for write in setup.iter() {
            store.apply(write.key.clone(), write.value.clone());
        }
        store
    }

    fn apply(&mut self, key: String, value: String) {
        self.path_overlay
            .insert(TrieHash::from_key(&key), value.clone());
        self.overlay.insert(key, value);
    }

    /// The witness's answer to `query`, or `None` (recorded as missing).
    fn witnessed(&self, query: StoreQuery) -> Option<Option<String>> {
        let answer = self.answers.get(&query).cloned();
        if answer.is_none() {
            self.missing.borrow_mut().push(format!("{query:?}"));
        }
        answer
    }

    fn lookup(&self, query: StoreQuery) -> Result<Option<String>, VmExecutionError> {
        let description = format!("{query:?}");
        self.witnessed(query).ok_or_else(|| {
            VmInternalError::Expect(format!("witness incomplete: {description}")).into()
        })
    }
}

impl ClarityBackingStore for WitnessStore {
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<(), VmExecutionError> {
        for (key, value) in items.into_iter() {
            self.write_log.record(&key, &value);
            self.apply(key, value);
        }
        Ok(())
    }

    fn get_data(&mut self, key: &str) -> Result<Option<String>, VmExecutionError> {
        if self.at.is_none() {
            if let Some(value) = self.overlay.get(key) {
                return Ok(Some(value.clone()));
            }
        }
        self.lookup(StoreQuery::Data {
            at: self.at.clone(),
            key: key.to_string(),
        })
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>, VmExecutionError> {
        if self.at.is_none() {
            if let Some(value) = self.path_overlay.get(hash) {
                return Ok(Some(value.clone()));
            }
        }
        self.lookup(StoreQuery::Path {
            at: self.at.clone(),
            path: *hash,
        })
    }

    fn get_data_with_proof(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        Ok(self.get_data(key)?.map(|value| (value, vec![])))
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        Ok(self.get_data_from_path(hash)?.map(|value| (value, vec![])))
    }

    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId, VmExecutionError> {
        let previous = self.at.clone().unwrap_or_else(|| self.open_tip.clone());
        if bhh == self.open_tip {
            self.at = None;
            return Ok(previous);
        }
        match self.lookup(StoreQuery::AtBlock {
            target: bhh.clone(),
        })? {
            Some(_) => {
                self.at = Some(bhh);
                Ok(previous)
            }
            None => Err(RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into()),
        }
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        self.witnessed(StoreQuery::BlockAtHeight {
            at: self.at.clone(),
            height,
        })
        .flatten()
        .and_then(|hex| StacksBlockId::from_hex(&hex).ok())
    }

    fn get_current_block_height(&mut self) -> u32 {
        let Some(at) = self.at.clone() else {
            return self.open_height;
        };
        self.witnessed(StoreQuery::CurrentHeight { at })
            .flatten()
            .and_then(|height| height.parse().ok())
            .unwrap_or(0)
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.open_height
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.open_tip.clone()
    }

    fn get_side_store(&mut self) -> &Connection {
        &self.side_store
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        Some(&handle_contract_call_special_cases)
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum), VmExecutionError> {
        sqlite_get_contract_hash(self, contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), VmExecutionError> {
        self.metadata
            .insert((contract.to_string(), key.to_string()), value.to_string());
        Ok(())
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        let (block, _) = self.get_contract_hash(contract)?;
        self.metadata_at(block, contract, key)
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
        self.metadata_at(block, contract, key)
    }
}

impl WitnessStore {
    fn metadata_at(
        &mut self,
        block: StacksBlockId,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        if block == self.open_tip {
            return Ok(self
                .metadata
                .get(&(contract.to_string(), key.to_string()))
                .cloned());
        }
        self.lookup(StoreQuery::Metadata {
            block,
            contract: contract.to_string(),
            key: key.to_string(),
        })
    }
}

impl ClarityMarfStore for WitnessStore {}

/// Nothing is ever persisted: every commit is a no-op.
impl ClarityMarfStoreTransaction for WitnessStore {
    fn commit_metadata_for_trie(
        &mut self,
        _target: &StacksBlockId,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn drop_metadata_for_trie(&mut self, _target: &StacksBlockId) -> Result<(), VmExecutionError> {
        Ok(())
    }

    /// No trie: the root is proven separately, from the state witness.
    fn seal_trie(&mut self) -> TrieHash {
        TrieHash([0; 32])
    }

    fn drop_current_trie(self) {}

    fn drop_unconfirmed(self) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn commit_to_processed_block(self, _target: &StacksBlockId) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn commit_to_mined_block(self, _target: &StacksBlockId) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn commit_unconfirmed(self) {}

    #[cfg(test)]
    fn test_commit(self) {}
}

impl WritableMarfStore for WitnessStore {
    fn state_write_log(&mut self) -> Option<&mut StateWriteLog> {
        Some(&mut self.write_log)
    }
}
