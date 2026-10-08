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

//! Proof-carrying read witnesses: a client that trusts only headers, Bitcoin
//! headers and network constants verifies every witness entry, then
//! re-executes the block.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};

use super::stateless_reexec::{
    block_with_tx, boot, receipt_of, tamper_store, uint_hex, HistoryFixture, LiveBlock,
};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::tests::state_writes::StateWriteFixture;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::chainstate::stacks::index::absence::TrieAbsenceProof;
use crate::chainstate::stacks::index::Error as MarfError;
use crate::chainstate::stacks::{StacksTransaction, TransactionPayload};
use crate::clarity_vm::read_witness::{EnvQuery, ReadWitness, StoreQuery};
use crate::clarity_vm::witness_proof::{
    prove_contracts, prove_store_reads, verify_read_witness, BitcoinChain, BitcoinHeader,
    ChainHeader, DeploySource, HeaderChain, MarfProof, NetworkParams, ProvenWitness, Rejection,
    StoreProof, TrustedState, TxInclusion,
};
use crate::clarity_vm::witness_serve::burn_binding;
use crate::clarity_vm::witness_wire::WitnessEnvelope;
use crate::net::api::blockreplay::{remine_nakamoto_block, ReplayTrace};
use crate::net::test::{TestEventObserver, TestEventObserverBlock, TestPeer};
use crate::net::tests::NakamotoBootTenure;

/// Everything a client holds for one block: what it trusts, and the
/// proof-carrying witness a node served.
struct Served {
    block: StacksBlockId,
    live: LiveBlock,
    headers: HeaderChain,
    bitcoin: BitcoinChain,
    net: NetworkParams,
    proven: ProvenWitness,
}

impl Served {
    fn verify(&self, proven: &ProvenWitness) -> Result<(), Rejection> {
        let trusted = TrustedState {
            headers: &self.headers,
            bitcoin: &self.bitcoin,
            net: &self.net,
        };
        verify_read_witness(&self.block, &self.live.txs, &trusted, proven)
    }
}

fn block_txs(block: &TestEventObserverBlock) -> Vec<StacksTransaction> {
    block
        .receipts
        .iter()
        .filter_map(|r| match &r.transaction {
            TransactionOrigin::Stacks(tx) => Some(tx.clone()),
            TransactionOrigin::Burn(_) => None,
        })
        .collect()
}

/// Gather what a client trusts and what a node proves for `block`.
fn serve(
    peer: &mut TestPeer,
    observer: &TestEventObserver,
    block: &TestEventObserverBlock,
) -> Served {
    let live = LiveBlock::of(block);
    let block_id = block.metadata.index_block_hash();
    let parent = block.parent.clone();

    // trusted: Stacks headers
    let chainstate = &peer.chain.coord.chain_state_db;
    let rows: Vec<(String, String)> = {
        let mut stmt = chainstate
            .db()
            .prepare(
                "SELECT index_block_hash, parent_block_id FROM block_headers \
                 UNION ALL SELECT index_block_hash, parent_block_id FROM nakamoto_block_headers",
            )
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let mut headers: Vec<ChainHeader> = rows
        .iter()
        .map(|(id, parent)| {
            let id = StacksBlockId::from_hex(id).unwrap();
            let info = NakamotoChainState::get_block_header(chainstate.db(), &id)
                .unwrap()
                .unwrap();
            ChainHeader::from_header_info(&info, StacksBlockId::from_hex(parent).unwrap())
        })
        .collect();
    // the genesis header carries no MARF root: the client pins the genesis
    // state root (boot code plus allocations) as a network constant
    let genesis = headers.iter_mut().find(|h| h.height == 0).unwrap();
    genesis.state_index_root = peer
        .chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| marf.get_root_hash_at(&genesis.id))
        .unwrap();
    let headers = HeaderChain::new(headers);

    // trusted: Bitcoin headers and network constants
    let sortdb = peer.chain.sortdb.as_ref().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let handle = sortdb.index_handle(&tip.sortition_id);
    let bitcoin = BitcoinChain::new((sortdb.first_block_height..=tip.block_height).map(|h| {
        let sn = handle.get_block_snapshot_by_height(h).unwrap().unwrap();
        BitcoinHeader {
            height: h as u32,
            hash: sn.burn_header_hash,
            parent: sn.parent_burn_header_hash,
            time: sn.burn_header_timestamp,
        }
    }))
    .unwrap();
    let net = NetworkParams {
        mainnet: false,
        chain_id: CHAIN_ID_TESTNET,
        first_burn_height: sortdb.first_block_height as u32,
        epochs: SortitionDB::get_stacks_epochs(sortdb.conn())
            .unwrap()
            .to_vec(),
        pox: sortdb.pox_constants.clone(),
    };

    // served: transactions of every block, for tx inclusion proofs
    let blocks: HashMap<StacksBlockId, Vec<StacksTransaction>> = observer
        .get_blocks()
        .iter()
        .map(|b| (b.metadata.index_block_hash(), block_txs(b)))
        .collect();
    let include = |block: &StacksBlockId, pick: &dyn Fn(&StacksTransaction) -> bool| {
        let txs = blocks.get(block)?;
        let index = txs.iter().position(|tx| pick(tx))?;
        Some(TxInclusion::new(block.clone(), txs, index))
    };

    // served: the burn view's tenure change, earlier in this tenure
    let is_tenure_change =
        |tx: &StacksTransaction| matches!(tx.payload, TransactionPayload::TenureChange(_));
    let burn_view = if live.txs.iter().any(is_tenure_change) {
        None
    } else {
        let mut cursor = headers.get(&parent);
        let mut found = None;
        while let Some(h) = cursor {
            if let Some(inclusion) = include(&h.id, &is_tenure_change) {
                found = Some(inclusion);
                break;
            }
            cursor = headers.get(&h.parent);
        }
        found
    };
    let view_ch = match live
        .txs
        .iter()
        .chain(burn_view.iter().map(|i| &i.tx))
        .find_map(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(tc.burn_view_consensus_hash.clone()),
            _ => None,
        }) {
        Some(ch) => ch,
        None => panic!("no burn view"),
    };

    // served: preimages of every consensus hash a lookup touches, and tenure coinbases
    let witness = &live.witness;
    let mut chs: Vec<ConsensusHash> = vec![
        view_ch,
        headers.get(&parent).unwrap().consensus_hash.clone(),
    ];
    let mut coinbases = vec![];
    for read in witness.env.iter() {
        let id = match &read.query {
            EnvQuery::StacksBlockHeaderHash { id, .. }
            | EnvQuery::BurnHeaderHashForBlock { id }
            | EnvQuery::ConsensusHashForBlock { id, .. }
            | EnvQuery::VrfSeed { id, .. }
            | EnvQuery::StacksBlockTime { id }
            | EnvQuery::BurnBlockTime { id, .. }
            | EnvQuery::BurnBlockHeightForBlock { id } => Some(id),
            _ => None,
        };
        let Some(ch) = id
            .and_then(|id| headers.get(id))
            .map(|h| h.consensus_hash.clone())
        else {
            continue;
        };
        if let EnvQuery::VrfSeed { epoch, .. } = &read.query {
            if epoch.uses_nakamoto_blocks() {
                let tenure_start = blocks
                    .keys()
                    .filter(|id| headers.get(id).is_some_and(|h| h.consensus_hash == ch))
                    .find_map(|id| {
                        include(id, &|tx| {
                            matches!(tx.payload, TransactionPayload::Coinbase(..))
                        })
                    })
                    .expect("tenure coinbase");
                coinbases.push(tenure_start);
            }
        }
        chs.push(ch);
    }
    let mut seen = HashSet::new();
    chs.retain(|ch| seen.insert(ch.clone()));
    let burn = chs
        .iter()
        .map(|ch| burn_binding(sortdb, ch).unwrap())
        .collect();

    // served: MARF proofs and contract evidence
    let find_deploy = |block: &StacksBlockId, contract: &QualifiedContractIdentifier| {
        include(block, &|tx| match &tx.payload {
            TransactionPayload::SmartContract(sc, _) => {
                sc.name == contract.name
                    && PrincipalData::from(tx.origin_address())
                        == PrincipalData::Standard(contract.issuer.clone())
            }
            _ => false,
        })
    };
    let (store, contracts) = peer
        .chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| {
            let mut conn = marf.borrow_storage_backend();
            let store = prove_store_reads(&mut conn, &parent, witness).unwrap();
            let (contracts, unproven) =
                prove_contracts(&mut conn, &parent, witness, &net, &find_deploy).unwrap();
            assert!(unproven.is_empty(), "{unproven:?}");
            (store, contracts)
        });

    let proven = ProvenWitness {
        witness: witness.clone(),
        store,
        contracts,
        burn,
        burn_view,
        coinbases,
    };
    Served {
        block: block_id,
        live,
        headers,
        bitcoin,
        net,
        proven,
    }
}

fn store_index(proven: &ProvenWitness, query: &StoreQuery) -> usize {
    proven
        .witness
        .store
        .iter()
        .position(|(q, _)| q == query)
        .unwrap_or_else(|| panic!("witness has no {query:?}"))
}

fn measure(label: &str, served: &Served) {
    let witness_size = served.proven.witness.size();
    let proof_size = served.proven.proof_size();
    let witness_bytes =
        witness_size.store_bytes + witness_size.metadata_bytes + witness_size.env_bytes;
    let proofs = proof_size.marf_proofs + proof_size.contracts + proof_size.env;

    // the same witness without its metadata entries, to split verify time
    let mut without_metadata = served.proven.clone();
    let keep: Vec<bool> = without_metadata
        .witness
        .store
        .iter()
        .map(|(q, _)| !matches!(q, StoreQuery::Metadata { .. }))
        .collect();
    let mut keep_iter = keep.iter();
    without_metadata
        .witness
        .store
        .retain(|_| *keep_iter.next().unwrap());
    let mut keep_iter = keep.iter();
    without_metadata
        .store
        .retain(|_| *keep_iter.next().unwrap());
    without_metadata.contracts.clear();

    let runs = 5;
    let mut verify_without_metadata = Duration::ZERO;
    let mut verify = Duration::ZERO;
    let mut reexec = Duration::ZERO;
    for _ in 0..runs {
        let started = Instant::now();
        served
            .verify(&served.proven)
            .expect("honest witness verifies");
        verify += started.elapsed();
        let started = Instant::now();
        served.verify(&without_metadata).unwrap();
        verify_without_metadata += started.elapsed();
        let started = Instant::now();
        served.live.reexecute(&served.proven.witness).unwrap();
        reexec += started.elapsed();
    }
    eprintln!(
        "MEASURE-PROOF {label}: store entries={} (inclusion={} absence={}) contracts={:?} env={} burn-bindings={} | \
         witness bytes={} (marf={} metadata={} env={}) | proof bytes={} (marf={} contracts={} env={}) | \
         with proofs={} | with proofs, metadata derived not shipped={} | MARF as one multiproof={} (compact {}) | verify={:?} (without metadata re-derivation {:?}) reexec={:?}",
        served.proven.witness.store.len(),
        proof_size.inclusion_proofs,
        proof_size.absence_proofs,
        served
            .proven
            .contracts
            .iter()
            .map(|c| c.contract.name.to_string())
            .collect::<Vec<_>>(),
        served.proven.witness.env.len(),
        served.proven.burn.len(),
        witness_bytes,
        witness_size.store_bytes,
        witness_size.metadata_bytes,
        witness_size.env_bytes,
        proofs,
        proof_size.marf_proofs,
        proof_size.contracts,
        proof_size.env,
        witness_bytes + proofs,
        witness_bytes - witness_size.metadata_bytes + proofs,
        proof_size.marf_multiproof,
        proof_size.marf_multiproof_compact,
        verify / runs,
        verify_without_metadata / runs,
        reexec / runs,
    );
}

fn history_block() -> (
    TestEventObserver,
    HistoryFixture,
    Vec<NakamotoBootTenure>,
    Vec<(PrincipalData, u64)>,
) {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = HistoryFixture::new();
    (observer, fx, tenures, balances)
}

#[test]
fn honest_proof_carrying_witness_verifies_and_reexecution_reproduces_the_block() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);

    // the witness needs both kinds of MARF proof and re-derived metadata
    assert!(served
        .proven
        .store
        .iter()
        .any(|p| matches!(p, StoreProof::Marf(MarfProof::Absent(_)))));
    assert!(served
        .proven
        .store
        .iter()
        .any(|p| matches!(p, StoreProof::Ancestor { .. })));
    assert!(served
        .proven
        .contracts
        .iter()
        .any(|c| matches!(c.source, DeploySource::Boot)));
    assert!(served
        .proven
        .contracts
        .iter()
        .any(|c| matches!(c.source, DeploySource::Tx(_))));

    served
        .verify(&served.proven)
        .expect("honest witness verifies");
    let out = served.live.reexecute(&served.proven.witness).unwrap();
    assert_eq!(out.writes, served.live.writes);
    assert_eq!(out.receipts, served.live.receipts);
    measure("history-fixture", &served);
}

#[test]
fn honest_proof_carrying_witness_verifies_for_the_state_writes_fixture() {
    let observer = TestEventObserver::new();
    let (fx, tenures, balances) = StateWriteFixture::new();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = fx.find_block(&observer);
    let served = serve(&mut peer, &observer, &block);

    served
        .verify(&served.proven)
        .expect("honest witness verifies");
    let out = served.live.reexecute(&served.proven.witness).unwrap();
    assert_eq!(out.writes, served.live.writes);
    assert_eq!(out.receipts, served.live.receipts);
    measure("state-writes-fixture", &served);
}

/// Phase 1 showed a read that only feeds a print changes no write, so the
/// write set cannot catch a forged one. Its own proof does.
#[test]
fn forged_print_only_read_is_caught_by_its_proof() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);

    // a parent-state read
    let mut forged = served.proven.clone();
    let note = StoreQuery::Data {
        at: None,
        key: fx.var_key("note"),
    };
    tamper_store(&mut forged.witness, &note, Some(uint_hex(43)));
    let out = served.live.reexecute(&forged.witness).unwrap();
    assert_eq!(out.writes, served.live.writes, "writes cannot catch it");
    assert_ne!(
        receipt_of(&out.receipts, &fx.note_time).events,
        served.live.receipt(&fx.note_time).events,
        "but the printed event is forged"
    );
    let rejection = served.verify(&forged).unwrap_err();
    assert!(rejection.entry.contains("::1::note"), "{rejection:?}");
    assert_eq!(rejection.reason, "MARF proof fails");

    // an environment lookup (block time two blocks back)
    let mut forged = served.proven.clone();
    for read in forged
        .witness
        .env
        .iter_mut()
        .filter(|read| matches!(read.query, EnvQuery::StacksBlockTime { .. }))
    {
        read.set_answer(Some(1u64));
    }
    let out = served.live.reexecute(&forged.witness).unwrap();
    assert_eq!(out.writes, served.live.writes);
    let rejection = served.verify(&forged).unwrap_err();
    assert!(
        rejection.entry.contains("stacks_block_time_for_block"),
        "{rejection:?}"
    );
}

#[test]
fn forged_absence_is_caught() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);
    let proven = &served.proven;

    let absent = proven
        .store
        .iter()
        .position(|p| matches!(p, StoreProof::Marf(MarfProof::Absent(_))))
        .unwrap();
    let counter = store_index(
        proven,
        &StoreQuery::Data {
            at: None,
            key: fx.var_key("counter"),
        },
    );

    // a present key claimed absent, carrying another key's absence proof
    let mut forged = proven.clone();
    forged.witness.store[counter].1 = None;
    forged.store[counter] = proven.store[absent].clone();
    let rejection = served.verify(&forged).unwrap_err();
    assert!(rejection.entry.contains("::1::counter"), "{rejection:?}");

    // and no honest absence proof exists for it
    let path = TrieHash::from_key(&fx.var_key("counter"));
    let parent = block.parent.clone();
    let proved = peer
        .chain
        .coord
        .chain_state_db
        .clarity_state
        .with_marf(|marf| {
            TrieAbsenceProof::from_path(&mut marf.borrow_storage_backend(), &path, &parent)
        });
    assert!(matches!(proved, Err(MarfError::NotFoundError)));

    // an absent key claimed present, keeping its absence proof
    let mut forged = proven.clone();
    forged.witness.store[absent].1 = Some(uint_hex(5));
    assert!(served.verify(&forged).is_err());
}

/// The replay bug (`f0f9d6b`) served `at-block` reads from the parent. A
/// witness with the parent's value and the parent's proof is rejected.
#[test]
fn forged_at_block_value_is_caught() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);
    let proven = &served.proven;

    let historical = proven
        .witness
        .store
        .iter()
        .position(|(q, _)| {
            matches!(q, StoreQuery::Data { at: Some(_), key } if key == &fx.var_key("counter"))
        })
        .unwrap();
    let at_parent = store_index(
        proven,
        &StoreQuery::Data {
            at: None,
            key: fx.var_key("counter"),
        },
    );
    assert_eq!(proven.witness.store[historical].1, Some(uint_hex(5)));
    assert_eq!(proven.witness.store[at_parent].1, Some(uint_hex(15)));

    let mut forged = proven.clone();
    forged.witness.store[historical].1 = Some(uint_hex(15));
    forged.store[historical] = proven.store[at_parent].clone();
    let out = served.live.reexecute(&forged.witness).unwrap();
    assert_ne!(
        receipt_of(&out.receipts, &fx.snapshot).result,
        served.live.receipt(&fx.snapshot).result
    );
    let rejection = served.verify(&forged).unwrap_err();
    assert!(rejection.entry.contains("at: Some("), "{rejection:?}");
}

#[test]
fn forged_metadata_is_caught() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);
    let proven = &served.proven;
    let ledger = fx.ledger.to_string();

    // a metadata value: the ledger's contract context
    let context = proven
        .witness
        .store
        .iter()
        .position(|(q, _)| {
            matches!(q, StoreQuery::Metadata { contract, key, .. }
                if contract == &ledger && key == "vm-metadata::9::contract")
        })
        .unwrap();
    let mut forged = proven.clone();
    let mut value: serde_json::Value =
        serde_json::from_str(forged.witness.store[context].1.as_ref().unwrap()).unwrap();
    let fields = value
        .get_mut("contract_context")
        .expect("a contract context");
    let size = fields["data_size"].as_u64().unwrap();
    fields["data_size"] = (size + 1).into();
    forged.witness.store[context].1 = Some(value.to_string());
    let rejection = served.verify(&forged).unwrap_err();
    assert_eq!(rejection.reason, "metadata differs from its re-derivation");

    // the deploy source: another contract's deploy tx
    let ledger_evidence = proven
        .contracts
        .iter()
        .position(|c| c.contract == fx.ledger)
        .unwrap();
    let other = proven
        .contracts
        .iter()
        .find(|c| c.contract != fx.ledger && matches!(c.source, DeploySource::Tx(_)))
        .unwrap();
    let mut forged = proven.clone();
    forged.contracts[ledger_evidence].source = other.source.clone();
    assert!(served.verify(&forged).is_err());

    // a dropped contract
    let mut forged = proven.clone();
    forged.contracts.remove(ledger_evidence);
    assert!(served.verify(&forged).is_err());
}

/// Every store entry kind maps to the proof the verifier expects.
#[test]
fn every_witness_entry_has_its_own_evidence() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let served = serve(&mut peer, &observer, &block);
    let witness: &ReadWitness = &served.proven.witness;
    for ((query, _), proof) in witness.store.iter().zip(served.proven.store.iter()) {
        let ok = match query {
            StoreQuery::Metadata { .. } => matches!(proof, StoreProof::Rederived),
            StoreQuery::AtBlock { .. } => {
                matches!(proof, StoreProof::Ancestor { .. } | StoreProof::OpenBlock)
            }
            StoreQuery::BlockAtHeight { .. } => {
                matches!(proof, StoreProof::Marf(_) | StoreProof::OpenBlock)
            }
            _ => matches!(proof, StoreProof::Marf(_)),
        };
        assert!(ok, "{query:?} has {proof:?}");
    }
}

/// What a node serves survives JSON: decoding and re-encoding gives the same
/// envelope, and the decoded witness is the live one, but for metadata values
/// (left out for the client to re-derive).
#[test]
fn served_witness_round_trips_through_json() {
    let (observer, fx, tenures, balances) = history_block();
    let mut peer = boot(function_name!(), &observer, tenures, balances);
    let block = block_with_tx(&observer, &fx.snapshot);
    let live = LiveBlock::of(&block);

    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut node = peer.chain.stacks_node.take().unwrap();
    let trace = ReplayTrace {
        read_witness: true,
        ..Default::default()
    };
    let replayed = remine_nakamoto_block(
        &block.metadata.index_block_hash(),
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

    let envelope = replayed.read_witness.expect("replay served a witness");
    let text = serde_json::to_string(&envelope).unwrap();
    let parsed: WitnessEnvelope = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed, envelope);
    let served = parsed.decode().expect("envelope decodes");
    assert_eq!(served.to_envelope().unwrap(), envelope);

    let mut expected = live.witness.clone();
    for (query, answer) in expected.store.iter_mut() {
        if matches!(query, StoreQuery::Metadata { .. }) {
            *answer = None;
        }
    }
    assert_eq!(served.proven.witness, expected);
    assert_eq!(served.proven.store.len(), expected.store.len());
    assert!(!served.headers.is_empty() && !served.bitcoin.is_empty());
    assert_eq!(
        served.writes.len(),
        live.writes
            .iter()
            .map(|w| &w.key)
            .collect::<HashSet<_>>()
            .len()
    );

    let mut future = envelope.clone();
    future.version += 1;
    assert!(future.decode().unwrap_err().contains("wire version"));

    eprintln!(
        "MEASURE-WIRE history-fixture: envelope={} bytes, headers={}, bitcoin headers={}, write proofs={}",
        text.len(),
        served.headers.len(),
        served.bitcoin.len(),
        served.writes.len()
    );
}
