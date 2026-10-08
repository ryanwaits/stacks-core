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
use clarity::vm::{ClarityName, ClarityVersion, ContractName};
use serde_json::Value;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::StacksBlockId;

use crate::burnchains::Txid;
use crate::chainstate::nakamoto::tests::stateless_reexec::{
    block_with_tx, BurnViewFixture, HistoryFixture,
};
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::clarity_vm::witness_client::{check_replayed_block, event_rows, ClientParams, Report};
use crate::clarity_vm::witness_serve::node_network_params;
use crate::core::test_util::{make_contract_call_tx, make_contract_publish_tx, to_addr};
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

    // a byte of its proof
    let body = fetched.tampered(|body| {
        let entry = store_entry(body, &note);
        let proof = &mut entry["proof"]["marf"]["present"];
        let hex = proof.as_str().unwrap().to_string();
        *proof = Value::String(flip_last_hex(&hex));
    });
    let report = fetched.check(&body);
    let failure = report.failure().expect("tampered proof is rejected");
    assert!(failure.detail.contains(&note), "{report}");

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

/// A contract whose initialization reads chain state cannot be re-derived
/// from its deploy alone. The node serves its metadata as is; the client
/// rejects those entries (naming the contract and why) but still re-executes
/// and compares everything else.
#[test]
fn unprovable_metadata_is_served_and_rejected_but_reexecution_still_runs() {
    let privk = StacksPrivateKey::from_seed(b"unprovable-metadata");
    let sender = to_addr(&privk);
    let deploy = make_contract_publish_tx(
        &privk,
        0,
        1000,
        CHAIN_ID_TESTNET,
        "born",
        "(define-data-var born uint burn-block-height)
         (define-public (age)
           (begin (print {born: (var-get born), now: burn-block-height}) (ok true)))",
        Some(ClarityVersion::Clarity3),
    );
    let call = make_contract_call_tx(
        &privk,
        1,
        1000,
        CHAIN_ID_TESTNET,
        &sender,
        ContractName::from_literal("born"),
        ClarityName::from_literal("age"),
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
    assert!(failure.detail.contains(".born"), "{report}");
    assert!(report.entries.contains_key("metadata (served, unproven)"));
    for name in ["re-execute", "writes", "write proofs", "events"] {
        assert!(
            report.checks.iter().any(|c| c.name == name && c.ok),
            "{name} did not pass: {report}"
        );
    }
}
