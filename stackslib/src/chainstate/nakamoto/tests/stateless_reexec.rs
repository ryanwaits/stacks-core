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

//! Stateless re-execution from a live block's read witness, checked against
//! the live block's receipts, `vm_events`, state writes and trie.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use clarity::types::chainstate::StacksPrivateKey;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::TrieHash;

use crate::burnchains::Txid;
use crate::chainstate::nakamoto::tests::state_writes::{block_trie_leaves, StateWriteFixture};
use crate::chainstate::nakamoto::TxToProcess;
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MARFValue;
use crate::chainstate::stacks::StacksTransaction;
use crate::clarity_vm::read_witness::{ReadWitness, StoreQuery};
use crate::clarity_vm::state_writes::StateWrite;
use crate::clarity_vm::stateless::{
    execute_statelessly, BlockLevelWrites, StatelessBlock, StatelessError,
};
use crate::core::test_util::{
    make_contract_call_tx, make_contract_publish_tx, make_stacks_transfer_tx, to_addr,
};
use crate::net::api::blockreplay::{remine_nakamoto_block, ReplayTrace};
use crate::net::test::{TestEventObserver, TestEventObserverBlock, TestPeer};
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};

const LEDGER_SRC: &str = "
(define-fungible-token pts)
(define-data-var counter uint u0)
(define-data-var note uint u42)
(define-map snaps uint uint)
(define-map credits principal uint)
(define-public (bump (n uint))
  (begin
    (var-set counter (+ (var-get counter) n))
    (print {event: \"bump\", counter: (var-get counter)})
    (ok (var-get counter))))
(define-public (credit (who principal) (amt uint))
  (let ((prev (default-to u0 (map-get? credits who))))
    (map-set credits who (+ prev amt))
    (print {event: \"credit\", who: who, prev: prev})
    (ft-mint? pts amt who)))
(define-public (pay (amt uint) (to principal))
  (begin
    (try! (ft-transfer? pts amt tx-sender to))
    (try! (stx-transfer? amt tx-sender to))
    (print {event: \"pay\", amt: amt, to: to})
    (ok true)))
(define-public (snapshot (back uint))
  (let ((h (- stacks-block-height back))
        (id (unwrap! (get-stacks-block-info? id-header-hash h) (err u1)))
        (then (at-block id (var-get counter)))
        (then-pts (at-block id (ft-get-balance pts tx-sender))))
    (map-set snaps h then)
    (print {event: \"snapshot\", h: h, then: then, then-pts: then-pts, now: (var-get counter),
            time: (get-stacks-block-info? time h),
            hash: (get-stacks-block-info? header-hash h),
            tenure-time: (get-tenure-info? time h),
            vrf: (get-tenure-info? vrf-seed h),
            burn-hash: (get-burn-block-info? header-hash (- burn-block-height u1)),
            tenure: tenure-height})
    (ok then)))
(define-public (note-time (back uint))
  (begin
    (print {event: \"note\", note: (var-get note),
            time: (get-stacks-block-info? time (- stacks-block-height back))})
    (ok true)))
(define-public (fail-after-write) (begin (var-set counter u999) (err u7)))
";

const RELAY_SRC: &str = "
(define-public (relay-bump (n uint))
  (begin (print {event: \"relay\", n: n}) (contract-call? .ledger bump n)))
";

/// Three blocks in one tenure. The last one (the block under test) writes
/// with nested reads, prints, moves FT and STX, calls across contracts, and
/// reads `at-block` and block info two blocks back, where `counter` was 5
/// (it is 15 at its parent).
struct HistoryFixture {
    ledger: QualifiedContractIdentifier,
    snapshot: Txid,
    note_time: Txid,
}

impl HistoryFixture {
    fn new() -> (Self, Vec<NakamotoBootTenure>, Vec<(PrincipalData, u64)>) {
        let privk = StacksPrivateKey::from_seed(b"stateless-reexec");
        let sender = to_addr(&privk);
        let recipient: PrincipalData =
            to_addr(&StacksPrivateKey::from_seed(b"stateless-reexec-recipient")).into();
        let ledger = QualifiedContractIdentifier::new(
            sender.clone().into(),
            ContractName::from_literal("ledger"),
        );
        let fee = 1000;
        let mut nonce = 0;
        let mut next_nonce = || {
            nonce += 1;
            nonce - 1
        };
        let mut deploy = |name: &str, src: &str| {
            make_contract_publish_tx(
                &privk,
                next_nonce(),
                fee,
                CHAIN_ID_TESTNET,
                name,
                src,
                Some(ClarityVersion::Clarity3),
            )
        };
        let deploy_ledger = deploy("ledger", LEDGER_SRC);
        let deploy_relay = deploy("relay", RELAY_SRC);
        let mut call = |contract: &'static str, function: &'static str, args: &[Value]| {
            make_contract_call_tx(
                &privk,
                next_nonce(),
                fee,
                CHAIN_ID_TESTNET,
                &sender,
                ContractName::from_literal(contract),
                ClarityName::from_literal(function),
                args,
            )
        };
        let me = Value::Principal(sender.clone().into());
        let them = Value::Principal(recipient.clone());

        let block_a = vec![
            deploy_ledger,
            deploy_relay,
            call("ledger", "bump", &[Value::UInt(5)]),
            call("ledger", "credit", &[me.clone(), Value::UInt(1000)]),
        ];
        let block_b = vec![
            call("ledger", "bump", &[Value::UInt(10)]),
            call("ledger", "credit", &[me, Value::UInt(500)]),
        ];
        let relay_bump = call("relay", "relay-bump", &[Value::UInt(1)]);
        let credit = call("ledger", "credit", &[them.clone(), Value::UInt(7)]);
        let pay = call("ledger", "pay", &[Value::UInt(100), them]);
        let snapshot = call("ledger", "snapshot", &[Value::UInt(2)]);
        let note_time = call("ledger", "note-time", &[Value::UInt(1)]);
        let fails = call("ledger", "fail-after-write", &[]);
        let stx = make_stacks_transfer_tx(
            &privk,
            next_nonce(),
            fee,
            CHAIN_ID_TESTNET,
            &recipient,
            1234,
        );
        let fixture = HistoryFixture {
            ledger,
            snapshot: snapshot.txid(),
            note_time: note_time.txid(),
        };
        let block_c = vec![relay_bump, credit, pay, snapshot, note_time, fails, stx];
        let tenures = vec![NakamotoBootTenure::Sortition(vec![
            NakamotoBootStep::Block(block_a),
            NakamotoBootStep::Block(block_b),
            NakamotoBootStep::Block(block_c),
        ])];
        (fixture, tenures, vec![(sender.into(), 10_000_000)])
    }

    fn var_key(&self, var: &str) -> String {
        format!("vm::{}::1::{var}", self.ledger)
    }
}

fn boot<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    tenures: Vec<NakamotoBootTenure>,
    balances: Vec<(PrincipalData, u64)>,
) -> TestPeer<'a> {
    let (peer, _) = NakamotoBootPlan::new(test_name)
        .with_pox_constants(10, 3)
        .with_initial_balances(balances)
        .with_ignore_transaction_errors(true)
        .with_malleablized_blocks(false)
        .with_block_traces(true)
        .boot_into_nakamoto_peers(tenures, Some(observer));
    peer
}

fn block_with_tx(observer: &TestEventObserver, txid: &Txid) -> TestEventObserverBlock {
    observer
        .get_blocks()
        .into_iter()
        .find(|block| {
            block
                .receipts
                .iter()
                .any(|receipt| &receipt.transaction.txid() == txid)
        })
        .expect("the block was processed")
}

/// What a client gets for a block: its transactions, its read witness, and
/// its block-level writes.
struct LiveBlock {
    txs: Vec<StacksTransaction>,
    receipts: Vec<StacksTransactionReceipt>,
    witness: ReadWitness,
    writes: Vec<StateWrite>,
    block_level: BlockLevelWrites,
}

impl LiveBlock {
    fn of(block: &TestEventObserverBlock) -> Self {
        let receipts: Vec<StacksTransactionReceipt> = block
            .receipts
            .iter()
            .filter(|r| matches!(r.transaction, TransactionOrigin::Stacks(_)))
            .cloned()
            .collect();
        let txs: Vec<StacksTransaction> = receipts
            .iter()
            .map(|r| match &r.transaction {
                TransactionOrigin::Stacks(tx) => tx.clone(),
                TransactionOrigin::Burn(_) => unreachable!(),
            })
            .collect();
        let writes = block.state_writes.clone().expect("state writes collected");
        let txids: HashSet<Txid> = txs.iter().map(StacksTransaction::txid).collect();
        LiveBlock {
            block_level: BlockLevelWrites::split(&writes, &txids),
            witness: block.read_witness.clone().expect("read witness collected"),
            txs,
            receipts,
            writes,
        }
    }

    fn reexecute(&self, witness: &ReadWitness) -> Result<StatelessBlock, StatelessError> {
        execute_statelessly(
            witness,
            &self.block_level,
            TxToProcess::all_execute(&self.txs),
            false,
            CHAIN_ID_TESTNET,
        )
    }

    fn receipt(&self, txid: &Txid) -> &StacksTransactionReceipt {
        self.receipts
            .iter()
            .find(|r| &r.transaction.txid() == txid)
            .unwrap()
    }
}

fn receipt_of<'r>(
    receipts: &'r [StacksTransactionReceipt],
    txid: &Txid,
) -> &'r StacksTransactionReceipt {
    receipts
        .iter()
        .find(|r| &r.transaction.txid() == txid)
        .unwrap()
}

/// Last value written per key.
fn last_values(writes: &[StateWrite]) -> HashMap<String, String> {
    writes
        .iter()
        .map(|w| (w.key.clone(), w.value.clone()))
        .collect()
}

fn tamper_store(witness: &mut ReadWitness, query: &StoreQuery, value: Option<String>) {
    let entry = witness
        .store
        .iter_mut()
        .find(|(q, _)| q == query)
        .unwrap_or_else(|| panic!("witness has no {query:?}"));
    entry.1 = value;
}

fn uint_hex(n: u128) -> String {
    Value::UInt(n).serialize_to_hex().unwrap()
}

/// Re-execute `block` from its witness and require the live block's exact
/// writes, receipts (events, results, `vm_events`, costs) and trie leaves.
fn assert_reexecution_reproduces(peer: &mut TestPeer, block: &TestEventObserverBlock, label: &str) {
    let live = LiveBlock::of(block);
    let started = Instant::now();
    let out = live
        .reexecute(&live.witness)
        .expect("re-execution succeeds");
    let elapsed = started.elapsed();

    assert_eq!(out.writes, live.writes, "write set differs");
    assert_eq!(out.receipts, live.receipts, "receipts differ");
    assert!(live.receipts.iter().any(|r| !r.vm_events.is_empty()));

    // the re-executed write set is exactly the block trie's changed leaves
    let block_id = block.metadata.index_block_hash();
    let parent_id = block.parent.clone();
    let last = last_values(&out.writes);
    peer.chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| {
            let leaves = block_trie_leaves(marf, &block_id);
            for (key, value) in last.iter() {
                assert_eq!(
                    leaves.get(&TrieHash::from_key(key)),
                    Some(&MARFValue::from_value(value)),
                    "{key} is not a leaf of the block with its re-executed value"
                );
            }
            let changed = last
                .iter()
                .filter(|(key, value)| {
                    marf.get(&parent_id, key).unwrap_or(None) != Some(MARFValue::from_value(value))
                })
                .count();
            assert!(changed > 0);
        });

    let size = live.witness.size();
    let tx_writes =
        live.writes.len() - live.block_level.setup.len() - live.block_level.teardown.len();
    eprintln!(
        "MEASURE {label}: txs={} writes={} (tx={} block-level={}) distinct-keys={} | witness: parent-reads={} at-block-reads={} height/at-block lookups={} metadata={} env={} | bytes: marf={} metadata={} env={} | reexec={:?}",
        live.txs.len(),
        live.writes.len(),
        tx_writes,
        live.writes.len() - tx_writes,
        last.len(),
        size.parent_reads,
        size.at_block_reads,
        size.height_lookups,
        size.metadata_reads,
        size.env_lookups,
        size.store_bytes,
        size.metadata_bytes,
        size.env_bytes,
        elapsed,
    );
}

#[test]
fn stateless_reexecution_reproduces_live_writes_receipts_and_vm_events() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);

    // the block really did read history: counter was 5 two blocks back
    let live = LiveBlock::of(&block);
    let snapshot = live.receipt(&fx.snapshot);
    assert_eq!(snapshot.result, Value::okay(Value::UInt(5)).unwrap());
    assert!(live
        .witness
        .store
        .iter()
        .any(|(q, _)| matches!(q, StoreQuery::Data { at: Some(_), .. })));

    assert_reexecution_reproduces(&mut peer, &block, "history-fixture");
}

#[test]
fn stateless_reexecution_reproduces_the_state_writes_fixture_block() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = StateWriteFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = fx.find_block(&observer);
    assert_reexecution_reproduces(&mut peer, &block, "state-writes-fixture");
}

#[test]
fn read_witness_entries_hold_at_the_blocks_they_name() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let live = LiveBlock::of(&block);
    let parent = block.parent.clone();

    peer.chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| {
            let (mut parent_reads, mut historical_reads) = (0, 0);
            for (query, answer) in live.witness.store.iter() {
                match query {
                    StoreQuery::Data { at, key } => {
                        let root = at.as_ref().unwrap_or(&parent);
                        let leaf = marf.get(root, key).unwrap_or(None);
                        assert_eq!(
                            leaf,
                            answer.as_deref().map(MARFValue::from_value),
                            "{key} at {root} does not hold the witnessed value"
                        );
                        if at.is_some() {
                            historical_reads += 1;
                        } else {
                            parent_reads += 1;
                        }
                    }
                    StoreQuery::AtBlock { target } => {
                        assert!(answer.is_some());
                        let height = marf.get_block_height_of(target, &parent).unwrap();
                        assert!(height.is_some(), "{target} is not an ancestor");
                    }
                    StoreQuery::BlockAtHeight { at: None, height } => {
                        let at_parent = marf.get_block_at_height(*height, &parent).unwrap();
                        if let Some(id) = at_parent {
                            assert_eq!(answer.as_deref(), Some(id.to_hex().as_str()));
                        } else {
                            // the open block's own height: the miner placeholder id
                            assert_eq!(*height, live.witness.open_height);
                            assert_eq!(
                                answer.as_deref(),
                                Some(live.witness.open_tip.to_hex().as_str())
                            );
                        }
                    }
                    _ => {}
                }
            }
            assert!(parent_reads > 0 && historical_reads > 0);
        });
}

#[test]
fn tampered_parent_read_changes_reexecuted_writes() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let _peer = boot(function_name!(), &observer, tenures, balances);
    let live = LiveBlock::of(&block_with_tx(&observer, &fx.snapshot));

    let mut witness = live.witness.clone();
    let counter = StoreQuery::Data {
        at: None,
        key: fx.var_key("counter"),
    };
    tamper_store(&mut witness, &counter, Some(uint_hex(100)));
    let out = live.reexecute(&witness).expect("re-execution succeeds");

    assert_ne!(out.writes, live.writes);
    assert_eq!(
        last_values(&out.writes).get(&fx.var_key("counter")),
        Some(&uint_hex(101))
    );
}

#[test]
fn tampered_at_block_read_changes_reexecuted_writes() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let _peer = boot(function_name!(), &observer, tenures, balances);
    let live = LiveBlock::of(&block_with_tx(&observer, &fx.snapshot));

    let historical_counter = live
        .witness
        .store
        .iter()
        .find_map(|(q, _)| match q {
            StoreQuery::Data { at: Some(_), key } if key == &fx.var_key("counter") => {
                Some(q.clone())
            }
            _ => None,
        })
        .expect("snapshot read counter at-block");
    let mut witness = live.witness.clone();
    tamper_store(&mut witness, &historical_counter, Some(uint_hex(77)));
    let out = live.reexecute(&witness).expect("re-execution succeeds");

    assert_ne!(out.writes, live.writes);
    let snapshot = receipt_of(&out.receipts, &fx.snapshot);
    assert_eq!(snapshot.result, Value::okay(Value::UInt(77)).unwrap());
}

#[test]
fn dropped_read_fails_as_witness_incomplete() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let _peer = boot(function_name!(), &observer, tenures, balances);
    let live = LiveBlock::of(&block_with_tx(&observer, &fx.snapshot));

    // a parent-state read
    let mut witness = live.witness.clone();
    witness.store.retain(|(q, _)| {
        q != &StoreQuery::Data {
            at: None,
            key: fx.var_key("counter"),
        }
    });
    match live.reexecute(&witness) {
        Err(StatelessError::WitnessIncomplete(missing)) => {
            assert!(
                missing.iter().any(|m| m.contains("::1::counter")),
                "{missing:?}"
            )
        }
        other => panic!("expected an incomplete witness, got {other:?}"),
    }

    // an at-block switch
    let mut witness = live.witness.clone();
    witness
        .store
        .retain(|(q, _)| !matches!(q, StoreQuery::AtBlock { .. }));
    assert!(matches!(
        live.reexecute(&witness),
        Err(StatelessError::WitnessIncomplete(_))
    ));

    // an environment lookup
    let mut witness = live.witness.clone();
    witness
        .env
        .retain(|read| !read.query.starts_with("stacks_block_time_for_block"));
    match live.reexecute(&witness) {
        Err(StatelessError::WitnessIncomplete(missing)) => {
            assert!(missing
                .iter()
                .any(|m| m.starts_with("stacks_block_time_for_block")))
        }
        other => panic!("expected an incomplete witness, got {other:?}"),
    }
}

/// A read that only feeds a print (or an event) changes no write, so the
/// write set cannot catch it: every witness entry must be proven on its own.
#[test]
fn tampered_print_only_inputs_change_events_but_not_writes() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let _peer = boot(function_name!(), &observer, tenures, balances);
    let live = LiveBlock::of(&block_with_tx(&observer, &fx.snapshot));

    // a parent-state read
    let mut witness = live.witness.clone();
    let note = StoreQuery::Data {
        at: None,
        key: fx.var_key("note"),
    };
    tamper_store(&mut witness, &note, Some(uint_hex(43)));
    let out = live.reexecute(&witness).expect("re-execution succeeds");
    assert_eq!(out.writes, live.writes);
    assert_ne!(
        receipt_of(&out.receipts, &fx.note_time).events,
        live.receipt(&fx.note_time).events
    );

    // an environment lookup (block time two blocks back)
    let mut witness = live.witness.clone();
    for read in witness
        .env
        .iter_mut()
        .filter(|read| read.query.starts_with("stacks_block_time_for_block"))
    {
        read.set_answer(Some(1u64));
    }
    let out = live.reexecute(&witness).expect("re-execution succeeds");
    assert_eq!(out.writes, live.writes);
    assert_ne!(
        receipt_of(&out.receipts, &fx.snapshot).events,
        live.receipt(&fx.snapshot).events
    );
}

/// `/v3/blocks/replay` must read `at-block` values at the block they name,
/// as live processing does.
#[test]
fn block_replay_reads_at_block_values_at_the_named_block() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let live = LiveBlock::of(&block);
    let block_id = block.metadata.index_block_hash();

    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut node = peer.chain.stacks_node.take().unwrap();
    let replayed = remine_nakamoto_block(
        &block_id,
        &sortdb,
        &mut node.chainstate,
        false,
        ReplayTrace::default(),
        |block| block.txs.clone(),
        |_| Ok(()),
    )
    .expect("replay succeeds");
    peer.chain.sortdb = Some(sortdb);
    peer.chain.stacks_node = Some(node);

    let replayed_snapshot = replayed
        .transactions
        .iter()
        .find(|tx| tx.txid == fx.snapshot)
        .unwrap();
    assert_eq!(
        replayed_snapshot.result_hex,
        live.receipt(&fx.snapshot).result,
        "replay read at-block state somewhere other than the named block"
    );
}

/// Replay (the route a deployed node offers) records the read witness live
/// processing recorded, so a client can be served witnesses on demand.
#[test]
fn block_replay_records_the_live_read_witness() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let live = LiveBlock::of(&block);
    let block_id = block.metadata.index_block_hash();

    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut node = peer.chain.stacks_node.take().unwrap();
    let trace = ReplayTrace {
        read_witness: true,
        ..Default::default()
    };
    let replayed = remine_nakamoto_block(
        &block_id,
        &sortdb,
        &mut node.chainstate,
        false,
        trace,
        |block| block.txs.clone(),
        |_| Ok(()),
    )
    .expect("replay succeeds");
    peer.chain.sortdb = Some(sortdb);
    peer.chain.stacks_node = Some(node);

    let replayed = replayed.read_witness.expect("replay recorded a witness");
    assert_eq!(replayed, live.witness);

    let out = live
        .reexecute(&replayed)
        .expect("replay witness is complete");
    assert_eq!(out.writes, live.writes);
    assert_eq!(out.receipts, live.receipts);
}
