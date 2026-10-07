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

//! Storage-layer state-write collection, checked against real Nakamoto block
//! processing and against the block's own MARF trie.

use std::collections::{HashMap, HashSet};

use clarity::types::chainstate::{StacksAddress, StacksPrivateKey};
use clarity::vm::events::{StorageEvent, VmTraceEvent};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ContractName, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::to_hex;

use crate::burnchains::Txid;
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::index::marf::{
    MarfConnection, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF,
    OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{is_backptr, TrieNodeID, TrieNodeType};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::MARFValue;
use crate::chainstate::stacks::{
    StacksTransaction, TransactionPostConditionMode, MINER_BLOCK_CONSENSUS_HASH,
    MINER_BLOCK_HEADER_HASH,
};
use crate::clarity_vm::state_writes::{
    state_write_entries, tx_index_map, StateWrite, StateWriteEntry,
};
use crate::core::test_util::{
    make_contract_call_tx, make_contract_call_with_post_conditions, make_contract_publish_tx,
    make_stacks_transfer_tx, to_addr,
};
use crate::net::test::{TestEventObserver, TestEventObserverBlock, TestPeer};
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};

const CONTRACT: &str = "state-writes";
const TRAIT_IMPL: &str = "tok-impl";

const CONTRACT_SRC: &str = "
(define-trait tok-trait ((get-x () (response uint uint))))
(define-data-var c uint u10)
(define-map reserve principal uint)
(define-map kv uint uint)
(define-fungible-token tok)
(define-read-only (get-reserve (who principal)) (default-to u0 (map-get? reserve who)))
(define-public (bump) (ok (var-set c (+ (var-get c) u1))))
(define-public (add-reserve (who principal) (amt uint))
  (ok (map-set reserve who (+ amt (get-reserve who)))))
(define-public (add-reserve-of (t <tok-trait>) (amt uint))
  (let ((who (contract-of t))) (ok (map-set reserve who (+ amt (get-reserve who))))))
(define-public (set-sum (k uint)) (ok (map-set kv k (+ u1 u2 u3))))
(define-public (set-at-sum (a uint) (b uint)) (ok (map-set kv (+ a b) u7)))
(define-public (drop (k uint)) (ok (map-delete kv k)))
(define-public (mint (amt uint)) (ft-mint? tok amt tx-sender))
(define-public (send (amt uint) (to principal)) (ft-transfer? tok amt tx-sender to))
(define-public (bump-then-fail) (begin (var-set c u555) (err u1)))
(define-public (bump-and-pay)
  (begin (var-set c u999) (stx-transfer? u100 tx-sender 'ST000000000000000000002AMW42H)))
";

/// The block under test and the transactions it carries.
pub struct StateWriteFixture {
    pub sender: StacksAddress,
    pub recipient: PrincipalData,
    pub contract: QualifiedContractIdentifier,
    pub trait_impl: QualifiedContractIdentifier,
    pub bump: Txid,
    pub add_reserve: Txid,
    pub add_reserve_of: Txid,
    pub set_sum: Txid,
    pub set_at_sum: Txid,
    pub set_then_drop: (Txid, Txid),
    pub mint: Txid,
    pub ft_send: Txid,
    pub stx_transfer: Txid,
    pub fails_by_response: Txid,
    pub fails_by_post_condition: Txid,
}

impl StateWriteFixture {
    /// Deploy the contract in one block, then exercise every write pattern in
    /// the next one (the boot plan's last block, so it is the chain tip).
    pub fn new() -> (Self, Vec<NakamotoBootTenure>, Vec<(PrincipalData, u64)>) {
        let privk = StacksPrivateKey::from_seed(b"state-writes");
        let sender = to_addr(&privk);
        let recipient: PrincipalData =
            to_addr(&StacksPrivateKey::from_seed(b"state-writes-recipient")).into();
        let contract = QualifiedContractIdentifier::new(
            sender.clone().into(),
            ContractName::from_literal(CONTRACT),
        );
        let trait_impl = QualifiedContractIdentifier::new(
            sender.clone().into(),
            ContractName::from_literal(TRAIT_IMPL),
        );
        let fee = 1000;

        let mut nonce = 0;
        let mut next_nonce = || {
            nonce += 1;
            nonce - 1
        };
        let deploy = make_contract_publish_tx(
            &privk,
            next_nonce(),
            fee,
            CHAIN_ID_TESTNET,
            CONTRACT,
            CONTRACT_SRC,
            None,
        );
        let deploy_impl = make_contract_publish_tx(
            &privk,
            next_nonce(),
            fee,
            CHAIN_ID_TESTNET,
            TRAIT_IMPL,
            &format!("(impl-trait '{contract}.tok-trait) (define-public (get-x) (ok u1))"),
            None,
        );

        let mut call = |function: &'static str, args: &[Value]| {
            make_contract_call_tx(
                &privk,
                next_nonce(),
                fee,
                CHAIN_ID_TESTNET,
                &sender,
                ContractName::from_literal(CONTRACT),
                ClarityName::from_literal(function),
                args,
            )
        };
        let bump = call("bump", &[]);
        let add_reserve = call(
            "add-reserve",
            &[Value::Principal(recipient.clone()), Value::UInt(5)],
        );
        let add_reserve_of = call(
            "add-reserve-of",
            &[Value::Principal(trait_impl.clone().into()), Value::UInt(7)],
        );
        let set_sum = call("set-sum", &[Value::UInt(1)]);
        let set_at_sum = call("set-at-sum", &[Value::UInt(2), Value::UInt(3)]);
        let set_nine = call("set-sum", &[Value::UInt(9)]);
        let drop_nine = call("drop", &[Value::UInt(9)]);
        let mint = call("mint", &[Value::UInt(1000)]);
        let ft_send = call(
            "send",
            &[Value::UInt(100), Value::Principal(recipient.clone())],
        );
        let fails_by_response = call("bump-then-fail", &[]);
        let stx_transfer = make_stacks_transfer_tx(
            &privk,
            next_nonce(),
            fee,
            CHAIN_ID_TESTNET,
            &recipient,
            1234,
        );
        let fails_by_post_condition = StacksTransaction::consensus_deserialize(
            &mut make_contract_call_with_post_conditions(
                &privk,
                next_nonce(),
                fee,
                CHAIN_ID_TESTNET,
                &sender,
                CONTRACT,
                "bump-and-pay",
                &[],
                TransactionPostConditionMode::Deny,
                vec![],
            )
            .as_slice(),
        )
        .unwrap();

        let fixture = Self {
            sender: sender.clone(),
            recipient,
            contract,
            trait_impl,
            bump: bump.txid(),
            add_reserve: add_reserve.txid(),
            add_reserve_of: add_reserve_of.txid(),
            set_sum: set_sum.txid(),
            set_at_sum: set_at_sum.txid(),
            set_then_drop: (set_nine.txid(), drop_nine.txid()),
            mint: mint.txid(),
            ft_send: ft_send.txid(),
            stx_transfer: stx_transfer.txid(),
            fails_by_response: fails_by_response.txid(),
            fails_by_post_condition: fails_by_post_condition.txid(),
        };
        let tenures = vec![NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(vec![deploy, deploy_impl]),
            NakamotoBootStep::Block(vec![
                bump,
                add_reserve,
                add_reserve_of,
                set_sum,
                set_at_sum,
                set_nine,
                drop_nine,
                mint,
                ft_send,
                fails_by_response,
                stx_transfer,
                fails_by_post_condition,
            ]),
        ])];
        (fixture, tenures, vec![(sender.into(), 10_000_000)])
    }

    /// The observed block that carries the write patterns.
    pub fn find_block(&self, observer: &TestEventObserver) -> TestEventObserverBlock {
        observer
            .get_blocks()
            .into_iter()
            .find(|block| {
                block
                    .receipts
                    .iter()
                    .any(|receipt| receipt.transaction.txid() == self.bump)
            })
            .expect("the write-pattern block was processed")
    }

    fn var_key(&self, var: &str) -> String {
        format!("vm::{}::1::{var}", self.contract)
    }

    fn map_key(&self, map: &str, key: &Value) -> String {
        format!(
            "vm::{}::0::{map}::{}",
            self.contract,
            key.serialize_to_hex().unwrap()
        )
    }

    fn ft_key(&self, owner: &PrincipalData) -> String {
        format!(
            "vm::{}::2::tok::{}",
            self.contract,
            serde_json::to_string(owner).unwrap()
        )
    }
}

/// The block's writes as the `/new_block` payload reports them.
pub fn payload_entries(block: &TestEventObserverBlock) -> Vec<StateWriteEntry> {
    let writes = block
        .state_writes
        .as_ref()
        .expect("block traces were enabled, so writes were collected");
    let tx_index_of = tx_index_map(block.receipts.iter().map(|r| r.transaction.txid()));
    state_write_entries(writes, &tx_index_of)
}

fn hex_of(value_string: &str) -> String {
    to_hex(value_string.as_bytes())
}

fn value_hex(value: &Value) -> String {
    hex_of(&value.serialize_to_hex().unwrap())
}

fn tx_index(block: &TestEventObserverBlock, txid: &Txid) -> u32 {
    block
        .receipts
        .iter()
        .position(|receipt| &receipt.transaction.txid() == txid)
        .expect("transaction is in the block") as u32
}

fn receipt<'a>(block: &'a TestEventObserverBlock, txid: &Txid) -> &'a StacksTransactionReceipt {
    &block.receipts[tx_index(block, txid) as usize]
}

/// `(key, value_hex)` pairs written by one transaction, in write order.
fn writes_of(entries: &[StateWriteEntry], tx_index: u32) -> Vec<(String, String)> {
    entries
        .iter()
        .filter(|entry| entry.tx_index == Some(tx_index))
        .map(|entry| (entry.key.clone(), entry.value_hex.clone()))
        .collect()
}

fn boot_with_fixture<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
) -> (StateWriteFixture, TestPeer<'a>, TestEventObserverBlock) {
    let (fixture, tenures, balances) = StateWriteFixture::new();
    let (peer, _) = NakamotoBootPlan::new(test_name)
        .with_pox_constants(10, 3)
        .with_initial_balances(balances)
        .with_ignore_transaction_errors(true)
        .with_malleablized_blocks(false)
        .with_block_traces(true)
        .boot_into_nakamoto_peers(tenures, Some(observer));
    let block = fixture.find_block(observer);
    (fixture, peer, block)
}

#[test]
fn state_writes_name_exact_keys_and_values_for_nested_write_arguments() {
    let observer = TestEventObserver::new();
    let (fx, _peer, block) = boot_with_fixture(function_name!(), &observer);
    let entries = payload_entries(&block);

    // ordinals are the block's write order
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.ordinal, i as u32);
    }

    // (var-set c (+ (var-get c) u1)) with c = u10
    assert_eq!(
        writes_of(&entries, tx_index(&block, &fx.bump))
            .into_iter()
            .filter(|(key, _)| key.starts_with("vm::"))
            .collect::<Vec<_>>(),
        vec![(fx.var_key("c"), value_hex(&Value::UInt(11)))]
    );

    // (map-set reserve who (+ amt (get-reserve who))), principal key
    let recipient_key = Value::Principal(fx.recipient.clone());
    assert!(
        writes_of(&entries, tx_index(&block, &fx.add_reserve)).contains(&(
            fx.map_key("reserve", &recipient_key),
            value_hex(&Value::some(Value::UInt(5)).unwrap()),
        ))
    );

    // same pattern, key from a trait-typed argument
    let impl_key = Value::Principal(fx.trait_impl.clone().into());
    assert!(
        writes_of(&entries, tx_index(&block, &fx.add_reserve_of)).contains(&(
            fx.map_key("reserve", &impl_key),
            value_hex(&Value::some(Value::UInt(7)).unwrap()),
        ))
    );

    // (map-set kv k (+ u1 u2 u3)) with k = u1
    assert!(
        writes_of(&entries, tx_index(&block, &fx.set_sum)).contains(&(
            fx.map_key("kv", &Value::UInt(1)),
            value_hex(&Value::some(Value::UInt(6)).unwrap()),
        ))
    );

    // (map-set kv (+ a b) u7) with a = u2, b = u3
    assert!(
        writes_of(&entries, tx_index(&block, &fx.set_at_sum)).contains(&(
            fx.map_key("kv", &Value::UInt(5)),
            value_hex(&Value::some(Value::UInt(7)).unwrap()),
        ))
    );

    // map-delete stores `none` under the entry's key
    assert!(writes_of(&entries, tx_index(&block, &fx.set_then_drop.1))
        .contains(&(fx.map_key("kv", &Value::UInt(9)), value_hex(&Value::none()),)));
    assert_eq!(value_hex(&Value::none()), hex_of("09"));

    // the eval-hook trace of every committed transaction agrees with the
    // storage layer: each traced write is a recorded write of the same tx
    for receipt in block.receipts.iter() {
        if receipt.post_condition_aborted || receipt.problematic_skipped.is_some() {
            continue;
        }
        let written = writes_of(&entries, tx_index(&block, &receipt.transaction.txid()));
        for event in receipt.vm_events.iter() {
            let VmTraceEvent::Storage(storage) = event else {
                continue;
            };
            let strip = |hex: &str| hex.trim_start_matches("0x").to_string();
            let expected = match storage {
                StorageEvent::VarSet(data) => (
                    format!("vm::{}::1::{}", data.contract_identifier, data.var_name),
                    hex_of(&strip(&data.raw_value)),
                ),
                StorageEvent::MapSet(data) | StorageEvent::MapInsert(data) => (
                    format!(
                        "vm::{}::0::{}::{}",
                        data.contract_identifier,
                        data.map_name,
                        strip(&data.raw_key)
                    ),
                    hex_of(&format!("0a{}", strip(&data.raw_value))),
                ),
                StorageEvent::MapDelete(data) => (
                    format!(
                        "vm::{}::0::{}::{}",
                        data.contract_identifier,
                        data.map_name,
                        strip(&data.raw_key)
                    ),
                    hex_of("09"),
                ),
            };
            assert!(
                written.contains(&expected),
                "vm_event {event:?} has no matching state write in {written:?}"
            );
        }
    }
}

#[test]
fn state_writes_attribute_balance_and_nonce_writes_to_their_transaction() {
    let observer = TestEventObserver::new();
    let (fx, _peer, block) = boot_with_fixture(function_name!(), &observer);
    let entries = payload_entries(&block);
    let sender: PrincipalData = fx.sender.clone().into();
    let stx_balance_key = |p: &PrincipalData| format!("vm-account::{p}::19");
    let nonce_key = |p: &PrincipalData| format!("vm-account::{p}::18");

    // STX transfer: sender's balance and nonce, recipient's balance
    let stx = writes_of(&entries, tx_index(&block, &fx.stx_transfer));
    let keys: HashSet<&str> = stx.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        keys,
        HashSet::from([
            stx_balance_key(&sender).as_str(),
            nonce_key(&sender).as_str(),
            stx_balance_key(&fx.recipient).as_str(),
        ])
    );

    // FT transfer: both FT balances, as JSON numbers, plus fee and nonce
    let ft = writes_of(&entries, tx_index(&block, &fx.ft_send));
    assert!(ft.contains(&(fx.ft_key(&sender), hex_of("900"))));
    assert!(ft.contains(&(fx.ft_key(&fx.recipient), hex_of("100"))));
    assert!(ft.iter().any(|(key, _)| key == &nonce_key(&sender)));

    // the mint also moves the token supply
    let minted = writes_of(&entries, tx_index(&block, &fx.mint));
    assert!(minted.contains(&(fx.ft_key(&sender), hex_of("1000"))));
    assert!(minted.contains(&(format!("vm::{}::3::tok", fx.contract), hex_of("1000"))));

    // the block also writes outside any transaction (tenure bookkeeping)
    assert!(entries.iter().any(|entry| entry.tx_index.is_none()));
}

#[test]
fn state_writes_omit_everything_a_failed_transaction_rolled_back() {
    let observer = TestEventObserver::new();
    let (fx, _peer, block) = boot_with_fixture(function_name!(), &observer);
    let entries = payload_entries(&block);
    let sender: PrincipalData = fx.sender.clone().into();
    let account_keys = HashSet::from([
        format!("vm-account::{sender}::19"),
        format!("vm-account::{sender}::18"),
    ]);

    let by_response = receipt(&block, &fx.fails_by_response);
    assert!(matches!(&by_response.result, Value::Response(r) if !r.committed));
    let by_post_condition = receipt(&block, &fx.fails_by_post_condition);
    assert!(by_post_condition.post_condition_aborted);

    // Only the fee debit and nonce bump survive: no var-set, no STX transfer.
    for txid in [&fx.fails_by_response, &fx.fails_by_post_condition] {
        let written = writes_of(&entries, tx_index(&block, txid));
        let keys: HashSet<String> = written.into_iter().map(|(key, _)| key).collect();
        assert_eq!(
            keys, account_keys,
            "tx {txid} wrote more than fee and nonce"
        );
    }

    // and the var was never set to the rolled-back values by anyone
    for entry in entries.iter() {
        if entry.key == fx.var_key("c") {
            assert_eq!(entry.value_hex, value_hex(&Value::UInt(11)));
        }
    }
}

/// Every leaf stored in `block`'s own trie (not reached through a
/// back-pointer into an ancestor), by path.
fn block_trie_leaves(
    marf: &mut MARF<StacksBlockId>,
    block: &StacksBlockId,
) -> HashMap<TrieHash, MARFValue> {
    fn walk(
        conn: &mut TrieStorageConnection<StacksBlockId>,
        node: &TrieNodeType,
        mut path: Vec<u8>,
        out: &mut HashMap<TrieHash, MARFValue>,
    ) {
        path.extend_from_slice(node.path_bytes());
        if let TrieNodeType::Leaf(leaf) = node {
            out.insert(TrieHash::from_bytes(&path).unwrap(), leaf.data.clone());
            return;
        }
        for ptr in node.ptrs() {
            if ptr.id() == TrieNodeID::Empty as u8 || is_backptr(ptr.id()) {
                continue;
            }
            let child = conn.read_nodetype_nohash(ptr).unwrap();
            let mut child_path = path.clone();
            child_path.push(ptr.chr());
            walk(conn, &child, child_path, out);
        }
    }
    marf.with_conn(|conn| {
        conn.open_block(block).unwrap();
        let root = Trie::read_root_nohash(conn).unwrap();
        let mut out = HashMap::new();
        walk(conn, &root, vec![], &mut out);
        out
    })
}

#[test]
fn state_writes_name_every_changed_leaf_of_the_block_trie() {
    let observer = TestEventObserver::new();
    let (_fx, mut peer, block) = boot_with_fixture(function_name!(), &observer);
    let writes: Vec<StateWrite> = block.state_writes.clone().unwrap();
    let block_id = block.metadata.index_block_hash();
    let parent_id = block.parent.clone();

    peer.chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| {
            let leaves = block_trie_leaves(marf, &block_id);
            let height = marf
                .get_block_height_of(&block_id, &block_id)
                .unwrap()
                .unwrap();
            let miner_tip =
                StacksBlockId::new(&MINER_BLOCK_CONSENSUS_HASH, &MINER_BLOCK_HEADER_HASH);
            let internal: HashSet<TrieHash> = [
                OWN_BLOCK_HEIGHT_KEY.to_string(),
                format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}"),
                format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{}", height - 1),
                format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{block_id}"),
                format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{miner_tip}"),
                format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{parent_id}"),
            ]
            .iter()
            .map(|key| TrieHash::from_key(key))
            .collect();
            let mut parent_value =
                |path: &TrieHash| marf.get_from_hash(&parent_id, path).unwrap_or(None);

            // every recorded write landed in this block's trie with its last value
            let mut last_value = HashMap::new();
            for write in writes.iter() {
                last_value.insert(
                    TrieHash::from_key(&write.key),
                    MARFValue::from_value(&write.value),
                );
            }
            for (path, value) in last_value.iter() {
                assert_eq!(
                    leaves.get(path),
                    Some(value),
                    "recorded write is not a block leaf"
                );
            }

            // leaves the block changed, minus MARF bookkeeping
            let changed_leaves: HashSet<TrieHash> = leaves
                .iter()
                .filter(|(path, _)| !internal.contains(*path))
                .filter(|(path, value)| parent_value(path).as_ref() != Some(*value))
                .map(|(path, _)| path.clone())
                .collect();
            // recorded writes that changed the value the parent had
            let changed_writes: HashSet<TrieHash> = last_value
                .iter()
                .filter(|(path, value)| parent_value(path).as_ref() != Some(*value))
                .map(|(path, _)| path.clone())
                .collect();
            assert!(!changed_leaves.is_empty());
            assert_eq!(changed_leaves, changed_writes);
        });
}
