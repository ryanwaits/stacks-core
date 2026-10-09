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

//! End to end over the RPC server: a client fetches a block and its replay
//! with `read_witness=1`, verifies every witness entry, re-executes the
//! block, and compares with what the node served.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use clarity::types::chainstate::StacksPrivateKey;
use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value as ClarityValue};
use serde_json::Value;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::burnchains::Txid;
use crate::chainstate::nakamoto::tests::stateless_reexec::{
    block_with_tx, BurnViewFixture, HistoryFixture,
};
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::clarity_vm::witness_client::{check_replayed_block, event_rows, ClientParams, Report};
use crate::clarity_vm::witness_serve::node_network_params;
use crate::core::test_util::{
    make_contract_call_tx, make_contract_publish_tx, make_stacks_transfer_tx, to_addr,
};
use crate::core::FIRST_STACKS_BLOCK_ID;
use crate::net::api::blockreplay::{receipt_events, RPCReplayedBlock, ReplayTrace};
use crate::net::api::tests::TestRPC;
use crate::net::httpcore::StacksHttpRequest;
use crate::net::test::{TestEventObserver, TestEventObserverBlock};
use crate::net::tests::{NakamotoBootStep, NakamotoBootTenure};

/// What a client fetched for one block, over HTTP.
struct Fetched {
    block_id: StacksBlockId,
    block: NakamotoBlock,
    /// The replay response body, as JSON text off the wire.
    replay_body: String,
    params: ClientParams,
    live: TestEventObserverBlock,
}

impl Fetched {
    fn check(&self, body: &str) -> Report {
        let replay: RPCReplayedBlock = serde_json::from_str(body).expect("replay body parses");
        check_replayed_block(&self.block_id, &self.block, &replay, &self.params)
    }

    /// The replay body with `edit` applied to its JSON.
    fn tampered(&self, edit: impl FnOnce(&mut Value)) -> String {
        let mut body: Value = serde_json::from_str(&self.replay_body).unwrap();
        edit(&mut body);
        body.to_string()
    }
}

/// Boot a chain over `tenures`, then fetch `pick`'s block over the RPC server:
/// `/v3/blocks/<id>` and `/v3/blocks/replay/<id>?read_witness=1&vm_events=1`.
fn fetch(
    test_name: &str,
    tenures: Vec<NakamotoBootTenure>,
    balances: Vec<(PrincipalData, u64)>,
    txid: &Txid,
) -> Fetched {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let observer = TestEventObserver::new();
    let mut rpc_test = TestRPC::setup_nakamoto_with_boot_plan(test_name, &observer, |plan| {
        plan.with_boot_tenures(tenures)
            .with_initial_balances(balances)
            .with_ignore_transaction_errors(true)
    });
    let live = block_with_tx(&observer, txid);
    let block_id = live.metadata.index_block_hash();

    // what the client pins for this (test) network
    let sortdb = rpc_test.peer_1.chain.sortdb.take().unwrap();
    let chainstate = rpc_test.peer_1.chainstate();
    let net = node_network_params(&sortdb, chainstate).unwrap();
    let genesis_root = chainstate
        .clarity_state
        .with_marf(|marf| marf.get_root_hash_at(&FIRST_STACKS_BLOCK_ID))
        .unwrap();
    rpc_test.peer_1.chain.sortdb = Some(sortdb);
    let params = ClientParams { net, genesis_root };

    let trace = ReplayTrace {
        vm_events: true,
        state_writes: false,
        read_witness: true,
    };
    let mut replay = StacksHttpRequest::new_block_replay_with_trace(addr.into(), &block_id, trace);
    replay.add_header("authorization".into(), "password".into());
    let get = StacksHttpRequest::new_get_nakamoto_block(addr.into(), block_id.clone());
    let mut responses = rpc_test.run(vec![replay, get]);

    let replay_body = {
        let payload = responses
            .remove(0)
            .get_http_payload_ok()
            .expect("replay is 200");
        let json: Value = payload.try_into().expect("replay is JSON");
        json.to_string()
    };
    let block = responses
        .remove(0)
        .decode_nakamoto_block()
        .expect("block decodes");
    let body: Value = serde_json::from_str(&replay_body).unwrap();
    let hex_len = |v: &Value| v.as_str().map_or(0, str::len) / 2;
    eprintln!(
        "MEASURE-HTTP {test_name}: replay body {} bytes, shared read proof {} bytes, final-write proof {} bytes",
        replay_body.len(),
        hex_len(&body["read_witness"]["marf"]),
        hex_len(&body["read_witness"]["writes"]["proof"]),
    );
    Fetched {
        block_id,
        block,
        replay_body,
        params,
        live,
    }
}

fn history_block(test_name: &str) -> (Fetched, HistoryFixture) {
    let (fx, tenures, balances) = HistoryFixture::new();
    let fetched = fetch(test_name, tenures, balances, &fx.snapshot);
    (fetched, fx)
}

/// The store entry for `key` in the served witness.
fn store_entry<'a>(body: &'a mut Value, key: &str) -> &'a mut Value {
    body["read_witness"]["witness"]["store"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|e| e["query"]["key"] == key)
        .unwrap_or_else(|| panic!("no store entry for {key}"))
}

/// Flip one bit of the shared read proof's first ancestor hash, which the
/// first trie the proof holds (the first root walked) hashes with.
fn tamper_shared_proof(body: &mut Value) {
    let proof = &mut body["read_witness"]["marf"];
    let mut bytes = hex_bytes(proof.as_str().unwrap()).unwrap();
    let n_blocks = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    let first_hash = 1 + 4 + 32 * n_blocks + 4;
    bytes[first_hash] ^= 1;
    *proof = Value::String(to_hex(&bytes));
}

/// Flip the last hex digit of a string.
fn flip_last_hex(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    let last = chars.last_mut().unwrap();
    *last = if *last == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

#[test]
fn served_witness_verifies_and_reexecutes_over_http() {
    let (fetched, _) = history_block(function_name!());
    let report = fetched.check(&fetched.replay_body);
    eprintln!("{report}");
    assert!(report.ok(), "{report}");
    for kind in [
        "parent inclusion",
        "parent absence",
        "at-block inclusion",
        "at-block ancestry",
        "metadata (re-derived)",
        "env (a) header",
        "env (b) burn",
        "contract (bundled boot source)",
        "contract (deploy tx proven)",
    ] {
        assert!(
            report.entries.contains_key(kind),
            "no {kind} entry: {report}"
        );
    }

    // the replay's receipts, which re-execution matched, are the live block's
    let replay: RPCReplayedBlock = serde_json::from_str(&fetched.replay_body).unwrap();
    let live: Vec<_> = fetched
        .live
        .receipts
        .iter()
        .filter(|r| matches!(r.transaction, TransactionOrigin::Stacks(_)))
        .collect();
    assert_eq!(live.len(), replay.transactions.len());
    for (receipt, tx) in live.iter().zip(replay.transactions.iter()) {
        assert_eq!(receipt_events(receipt), tx.events);
        assert_eq!(receipt.result, tx.result_hex);
    }

    // `--events-out` rows: one per replay event, each print with its value
    // as the event's raw hex and as Clarity repr
    let rows = event_rows(&report.receipts);
    let events: Vec<&serde_json::Value> = replay
        .transactions
        .iter()
        .flat_map(|t| t.events.iter())
        .collect();
    assert_eq!(rows.len(), events.len());
    for (row, event) in rows.iter().zip(events.iter()) {
        assert_eq!(&&row["event"], event);
        assert_eq!(row["txid"], event["txid"]);
        assert_eq!(row["event_index"], event["event_index"]);
        assert_eq!(row["type"], event["type"]);
    }
    let prints: Vec<_> = rows.iter().filter(|r| r["topic"] == "print").collect();
    assert!(!prints.is_empty());
    for print in prints {
        assert_eq!(
            print["value_hex"],
            print["event"]["contract_event"]["raw_value"]
        );
        assert_eq!(
            print["contract_id"],
            print["event"]["contract_event"]["contract_identifier"]
        );
        assert!(!print["value_repr"].as_str().unwrap().is_empty());
    }
}

/// A tenure-start block: the burn view comes from its own tenure change.
#[test]
fn served_witness_verifies_a_tenure_start_block_over_http() {
    let (fx, tenures, balances) = BurnViewFixture::new();
    let fetched = fetch(function_name!(), tenures, balances, &fx.call);
    let report = fetched.check(&fetched.replay_body);
    eprintln!("{report}");
    assert!(report.ok(), "{report}");
}

/// One byte of a witness value changed in transit: the entry's own proof
/// rejects it, and the report names the entry.
#[test]
fn tampered_witness_byte_fails_naming_the_entry() {
    let (fetched, fx) = history_block(function_name!());
    let note = fx.var_key("note");

    // the value (`note` only feeds a print, so the writes cannot catch it)
    let body = fetched.tampered(|body| {
        let entry = store_entry(body, &note);
        let value = entry["value"].as_str().unwrap().to_string();
        entry["value"] = Value::String(flip_last_hex(&value));
    });
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered witness is rejected");
    assert_eq!(failure.name, "witness", "{report}");
    assert!(failure.detail.contains(&note), "{report}");
    assert!(failure.detail.contains("MARF proof fails"), "{report}");

    // a byte of the shared proof (in the parent's trie, which `note` is
    // read through)
    let body = fetched.tampered(tamper_shared_proof);
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered proof is rejected");
    assert!(failure.detail.contains(&note), "{report}");
    assert!(failure.detail.contains("does not hash"), "{report}");

    // and of the final-write proof
    let body = fetched.tampered(|body| {
        let proof = &mut body["read_witness"]["writes"]["proof"];
        let hex = proof.as_str().unwrap().to_string();
        *proof = Value::String(flip_last_hex(&hex));
    });
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered write proof is rejected");
    assert_eq!(failure.name, "write proofs", "{report}");

    // an environment answer (a block time, also print-only)
    let body = fetched.tampered(|body| {
        let env = body["read_witness"]["witness"]["env"]
            .as_array_mut()
            .unwrap();
        let read = env
            .iter_mut()
            .find(|e| e["query"]["method"] == "stacks_block_time")
            .expect("a block-time lookup");
        let time = read["answer"].as_u64().unwrap();
        read["answer"] = Value::from(time + 1);
    });
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered lookup is rejected");
    assert!(
        failure.detail.contains("stacks_block_time_for_block"),
        "{report}"
    );

    // and the honest body still verifies
    assert!(fetched.check(&fetched.replay_body).ok());
}

/// A contract whose initialization makes a lookup not provable yet (here
/// the winning miner's spend, class (c)) cannot be re-derived. The node
/// serves its metadata as is; the client rejects those entries (naming the
/// contract and why) but still re-executes and compares everything else.
#[test]
fn unprovable_metadata_is_served_and_rejected_but_reexecution_still_runs() {
    let privk = StacksPrivateKey::from_seed(b"unprovable-metadata");
    let sender = to_addr(&privk);
    let deploy = make_contract_publish_tx(
        &privk,
        0,
        1000,
        CHAIN_ID_TESTNET,
        "spent",
        "(define-data-var spent (optional uint)
           (get-tenure-info? miner-spend-winner (- stacks-block-height u1)))
         (define-public (show)
           (begin (print {spent: (var-get spent), now: burn-block-height}) (ok true)))",
        Some(ClarityVersion::Clarity3),
    );
    let call = make_contract_call_tx(
        &privk,
        1,
        1000,
        CHAIN_ID_TESTNET,
        &sender,
        ContractName::from_literal("spent"),
        ClarityName::from_literal("show"),
        &[],
    );
    let txid = call.txid();
    let tenures = vec![NakamotoBootTenure::Sortition(vec![
        NakamotoBootStep::Block(vec![deploy]),
        NakamotoBootStep::Block(vec![call]),
    ])];
    let fetched = fetch(
        function_name!(),
        tenures,
        vec![(sender.into(), 10_000_000)],
        &txid,
    );
    let report = fetched.check(&fetched.replay_body);
    eprintln!("{report}");
    let failure = report.failure().expect("unprovable metadata is rejected");
    assert_eq!(failure.name, "witness");
    assert!(failure.detail.contains("not provable yet"), "{report}");
    assert!(failure.detail.contains("served unproven"), "{report}");
    assert!(
        failure
            .detail
            .contains("burnchain_tokens_spent_for_winning_block"),
        "{report}"
    );
    assert!(failure.detail.contains(".spent"), "{report}");
    assert!(report.entries.contains_key("metadata (served, unproven)"));
    for name in ["re-execute", "writes", "write proofs", "events"] {
        assert!(
            report.checks.iter().any(|c| c.name == name && c.ok),
            "{name} did not pass: {report}"
        );
    }
}

/// Clarity 3: burn height and burn header hash through the burn view, and
/// an older block's id, time, burn block time and burn header hash (each
/// lookup by id also asks for that block's burn height, to pick its epoch).
const CLOCK_SRC: &str = "
(define-constant born-burn burn-block-height)
(define-constant born-burn-hash (get-burn-block-info? header-hash (- burn-block-height u1)))
(define-constant born-id (get-stacks-block-info? id-header-hash (- stacks-block-height u2)))
(define-constant born-time (get-stacks-block-info? time (- stacks-block-height u2)))
(define-constant born-tenure-hash (get-tenure-info? burnchain-header-hash (- stacks-block-height u2)))
(define-constant born-tenure-time (get-tenure-info? time (- stacks-block-height u2)))
(define-public (tick)
  (begin
    (print {born: born-burn, born-hash: born-burn-hash, born-id: born-id, born-time: born-time,
            born-tenure-hash: born-tenure-hash, born-tenure-time: born-tenure-time,
            now: burn-block-height,
            hash: (get-burn-block-info? header-hash (- burn-block-height u2)),
            id: (get-stacks-block-info? id-header-hash (- stacks-block-height u3)),
            time: (get-stacks-block-info? time (- stacks-block-height u3)),
            tenure-time: (get-tenure-info? time (- stacks-block-height u3))})
    (ok true)))
";

/// Clarity 2 on Nakamoto: `block-height` is the tenure height. On mainnet
/// `get-block-info?` would map it to the tenure's first block (the
/// tenure-height lookup, proven in `proven_witness.rs`); on the test chain's
/// testnet chain id Clarity reads it as a Stacks height, so here it reads an
/// older block's id, time and burn header hash.
const LEGACY_SRC: &str = "
(define-constant born block-height)
(define-constant born-id (get-block-info? id-header-hash (- block-height u1)))
(define-constant born-time (get-block-info? time (- block-height u1)))
(define-constant born-burn-hash (get-block-info? burnchain-header-hash (- block-height u1)))
(define-public (tick)
  (begin
    (print {born: born, born-id: born-id, born-time: born-time, born-burn-hash: born-burn-hash,
            now: block-height, burn: burn-block-height,
            id: (get-block-info? id-header-hash (- block-height u2)),
            time: (get-block-info? time (- block-height u2))})
    (ok true)))
";

/// The env lookups of `contract`'s deploy, as served.
fn deploy_env<'a>(body: &'a mut Value, contract: &str) -> &'a mut Vec<Value> {
    body["read_witness"]["contracts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c["contract"].as_str().unwrap().ends_with(contract))
        .unwrap_or_else(|| panic!("no evidence for {contract}"))["deploy_env"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("{contract} has no deploy lookups"))
}

/// Contracts whose deploy (and a later call) read burn heights, burn header
/// hashes, and older blocks' ids, times and burn heights. Each deploy's
/// lookups are served with its deploying block's burn view and checked like
/// the block's own; both contracts re-derive and the calling block verifies
/// end to end. A tampered burn height (through the burn view, and for an
/// older block) and a dropped deploy burn view are each rejected, naming the
/// entry.
#[test]
fn deploys_reading_burn_and_header_lookups_rederive_and_verify() {
    let privk = StacksPrivateKey::from_seed(b"burn-lookups");
    let sender = to_addr(&privk);
    let publish = |nonce, name: &str, src: &str, version| {
        make_contract_publish_tx(
            &privk,
            nonce,
            1000,
            CHAIN_ID_TESTNET,
            name,
            src,
            Some(version),
        )
    };
    let call = |nonce, contract: &'static str| {
        make_contract_call_tx(
            &privk,
            nonce,
            1000,
            CHAIN_ID_TESTNET,
            &sender,
            ContractName::from_literal(contract),
            ClarityName::from_literal("tick"),
            &[],
        )
    };
    // blocks of their own, so the lookups reach back past them
    let filler_key = StacksPrivateKey::from_seed(b"burn-lookups-filler");
    let filler = |nonce| {
        let to = PrincipalData::from(sender.clone());
        NakamotoBootStep::Block(vec![make_stacks_transfer_tx(
            &filler_key,
            nonce,
            1000,
            CHAIN_ID_TESTNET,
            &to,
            1,
        )])
    };
    let tick_clock = call(2, "clock");
    let txid = tick_clock.txid();
    let tenures = vec![
        NakamotoBootTenure::Sortition(vec![filler(0), filler(1)]),
        NakamotoBootTenure::Sortition(vec![
            filler(2),
            NakamotoBootStep::Block(vec![publish(
                0,
                "clock",
                CLOCK_SRC,
                ClarityVersion::Clarity3,
            )]),
            NakamotoBootStep::Block(vec![publish(
                1,
                "legacy",
                LEGACY_SRC,
                ClarityVersion::Clarity2,
            )]),
        ]),
        NakamotoBootTenure::Sortition(vec![
            filler(3),
            NakamotoBootStep::Block(vec![tick_clock, call(3, "legacy")]),
        ]),
    ];
    let fetched = fetch(
        function_name!(),
        tenures,
        vec![
            (sender.clone().into(), 10_000_000),
            (to_addr(&filler_key).into(), 10_000_000),
        ],
        &txid,
    );
    let report = fetched.check(&fetched.replay_body);
    eprintln!("{report}");
    assert!(report.ok(), "{report}");
    for kind in [
        "deploy env (a) header",
        "deploy env (b) burn",
        "env (a) header",
        "env (b) burn",
    ] {
        assert!(
            report.entries.contains_key(kind),
            "no {kind} entry: {report}"
        );
    }
    let mut body: Value = serde_json::from_str(&fetched.replay_body).unwrap();
    let methods: Vec<String> = deploy_env(&mut body, ".clock")
        .iter()
        .map(|e| e["query"]["method"].as_str().unwrap().to_string())
        .collect();
    for method in [
        "tip_burn_block_height",
        "burn_header_hash",
        "burn_block_height_for_block",
        "stacks_block_time",
        "burn_block_time",
        "burn_header_hash_for_block",
    ] {
        assert!(methods.iter().any(|m| m == method), "{methods:?}");
    }

    // the clock deploy's burn height, one higher
    let tampered = fetched.tampered(|body| {
        let read = deploy_env(body, ".clock")
            .iter_mut()
            .find(|e| e["query"]["method"] == "tip_burn_block_height")
            .unwrap();
        let height = read["answer"].as_u64().unwrap();
        read["answer"] = Value::from(height + 1);
    });
    let report = fetched.check(&tampered);
    let failure = report
        .failure()
        .expect("tampered deploy lookup is rejected");
    assert_eq!(failure.name, "witness", "{report}");
    assert!(
        failure
            .detail
            .contains("ContractName(\"clock\") }: deploy lookup tip_burn_block_height()"),
        "{report}"
    );
    assert!(failure.detail.contains("answered"), "{report}");

    // an older block's burn height the clock deploy read, one lower
    let tampered = fetched.tampered(|body| {
        let read = deploy_env(body, ".clock")
            .iter_mut()
            .find(|e| e["query"]["method"] == "burn_block_height_for_block")
            .unwrap();
        let height = read["answer"].as_u64().unwrap();
        read["answer"] = Value::from(height - 1);
    });
    let report = fetched.check(&tampered);
    let failure = report.failure().expect("tampered burn height is rejected");
    assert!(
        failure
            .detail
            .contains("ContractName(\"clock\") }: deploy lookup burn_block_height_for_block("),
        "{report}"
    );

    // the clock deploy's burn view dropped
    let tampered = fetched.tampered(|body| {
        let clock = body["read_witness"]["contracts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|c| c["contract"].as_str().unwrap().ends_with(".clock"))
            .unwrap();
        clock.as_object_mut().unwrap().remove("burn_view");
    });
    let report = fetched.check(&tampered);
    let failure = report
        .failure()
        .expect("missing deploy burn view is rejected");
    assert!(failure.detail.contains("no burn view proven"), "{report}");

    // and the honest body still verifies
    assert!(fetched.check(&fetched.replay_body).ok());
}

const KIKI_SRC: &str = "
(define-fungible-token kiki)
(define-constant liquid-at-deploy stx-liquid-supply)
(ft-mint? kiki u1000000 tx-sender)
(define-read-only (backing) liquid-at-deploy)
(define-read-only (minted) (ft-get-supply kiki))
(define-public (send (amount uint) (to principal))
  (ft-transfer? kiki amount tx-sender to))
";

const WRAPPER_SRC: &str = "
(define-constant wrapped-at-deploy (contract-call? .kiki-token minted))
(define-constant backing-at-deploy (contract-call? .kiki-token backing))
(define-public (report)
  (begin
    (print {wrapped: wrapped-at-deploy, backing: backing-at-deploy,
            now: (contract-call? .kiki-token minted)})
    (ok true)))
";

/// Contracts whose deploy reads chain state: `kiki-token` stores
/// `stx-liquid-supply` in a constant and mints at deploy; `kiki-wrapper`
/// (a later block) stores what it reads from `kiki-token` at deploy. Each
/// carries a deploy witness (its reads, proven at its deploying block's
/// parent), the client re-derives both, and the block calling them verifies.
/// A tampered deploy-witness entry is rejected, naming it.
#[test]
fn contracts_whose_deploy_reads_chain_state_rederive_from_a_deploy_witness() {
    let privk = StacksPrivateKey::from_seed(b"deploy-witness");
    let sender = to_addr(&privk);
    let recipient = to_addr(&StacksPrivateKey::from_seed(b"deploy-witness-recipient"));
    let publish = |nonce, name: &str, src: &str| {
        make_contract_publish_tx(
            &privk,
            nonce,
            1000,
            CHAIN_ID_TESTNET,
            name,
            src,
            Some(ClarityVersion::Clarity3),
        )
    };
    let call = |nonce, contract: &'static str, function: &'static str, args: &[ClarityValue]| {
        make_contract_call_tx(
            &privk,
            nonce,
            1000,
            CHAIN_ID_TESTNET,
            &sender,
            ContractName::from_literal(contract),
            ClarityName::from_literal(function),
            args,
        )
    };
    let report = call(2, "kiki-wrapper", "report", &[]);
    let send = call(
        3,
        "kiki-token",
        "send",
        &[
            ClarityValue::UInt(10),
            ClarityValue::Principal(recipient.into()),
        ],
    );
    let txid = report.txid();
    let tenures = vec![NakamotoBootTenure::Sortition(vec![
        NakamotoBootStep::Block(vec![publish(0, "kiki-token", KIKI_SRC)]),
        NakamotoBootStep::Block(vec![publish(1, "kiki-wrapper", WRAPPER_SRC)]),
        NakamotoBootStep::Block(vec![report, send]),
    ])];
    let fetched = fetch(
        function_name!(),
        tenures,
        vec![(sender.clone().into(), 10_000_000)],
        &txid,
    );
    let report = fetched.check(&fetched.replay_body);
    eprintln!("{report}");
    assert!(report.ok(), "{report}");
    assert_eq!(
        report.entries.get("contract (with deploy witness)"),
        Some(&2),
        "{report}"
    );
    let body: Value = serde_json::from_str(&fetched.replay_body).unwrap();
    let contracts = body["read_witness"]["contracts"].as_array().unwrap();
    let reads_of = |name: &str| -> Vec<String> {
        contracts
            .iter()
            .find(|c| c["contract"].as_str().unwrap().ends_with(name))
            .unwrap_or_else(|| panic!("no evidence for {name}"))["deploy_reads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["query"].to_string())
            .collect()
    };
    assert!(
        reads_of(".kiki-token")
            .iter()
            .any(|q| q.contains("_stx-data::ustx_liquid_supply")),
        "{:?}",
        reads_of(".kiki-token")
    );
    assert!(
        reads_of(".kiki-wrapper")
            .iter()
            .any(|q| q.contains(".kiki-token::")),
        "{:?}",
        reads_of(".kiki-wrapper")
    );

    // one deploy-witness value changed in transit
    let body = fetched.tampered(|body| {
        let entry = body["read_witness"]["contracts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .flat_map(|c| c["deploy_reads"].as_array_mut().unwrap().iter_mut())
            .find(|e| e["query"]["key"] == "_stx-data::ustx_liquid_supply")
            .expect("the liquid-supply deploy read");
        let value = entry["value"].as_str().unwrap().to_string();
        entry["value"] = Value::String(flip_last_hex(&value));
    });
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered deploy read is rejected");
    assert_eq!(failure.name, "witness", "{report}");
    assert!(
        failure
            .detail
            .contains("deploy read Data { at: None, key: \"_stx-data::ustx_liquid_supply\" }: MARF proof fails"),
        "{report}"
    );
}
