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

//! Wire format v1 of a proof-carrying read witness: what a node serves with
//! `/v3/blocks/replay/<id>?read_witness=1` ([`WitnessEnvelope`]), and its
//! in-memory form ([`ServedWitness`]).
//!
//! JSON, with every binary value as lowercase hex without `0x`:
//!
//! * hashes and ids: their bytes;
//! * MARF proofs, transactions, headers, addresses: their consensus encoding
//!   (`TrieMerkleProof`, `TrieAbsenceProof`, `StacksTransaction`,
//!   `NakamotoBlockHeader` / `StacksBlockHeader`, `StacksAddress`);
//! * store values: the side-store value string as is (it is already text).
//!
//! Metadata values are left out: the client re-derives them
//! ([`crate::clarity_vm::witness_proof::fill_rederived_metadata`]). See
//! `NOTES.md` for the field list and how each entry is verified.

use std::fmt;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{QualifiedContractIdentifier, TupleData};
use clarity::vm::Value as ClarityValue;
use serde_json::{json, Value};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, PoxId, SortitionId, StacksAddress,
    StacksBlockId, TrieHash, VRFSeed,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{
    hex_bytes, to_hex, MerklePathOrder, MerklePathPoint, Sha512Trunc256Sum,
};

use crate::chainstate::burn::OpsHash;
use crate::chainstate::nakamoto::NakamotoBlockHeader;
use crate::chainstate::stacks::db::StacksBlockHeaderTypes;
use crate::chainstate::stacks::index::absence::TrieAbsenceProof;
use crate::chainstate::stacks::index::TrieMerkleProof;
use crate::chainstate::stacks::{StacksBlockHeader, StacksTransaction};
use crate::clarity_vm::read_witness::{EnvQuery, EnvRead, ReadWitness, StoreQuery};
use crate::clarity_vm::witness_proof::{
    BitcoinHeader, BurnBinding, ContractEvidence, DeploySource, MarfProof, ProvenWitness,
    StoreProof, TxInclusion,
};
use crate::core::StacksEpoch;

pub const WITNESS_WIRE_VERSION: u32 = 1;

/// A Stacks header as served: the client hashes it to its block id.
#[derive(Debug, Clone, PartialEq)]
pub struct ServedHeader {
    pub consensus_hash: ConsensusHash,
    pub header: StacksBlockHeaderTypes,
}

/// Everything a node serves for one block so a client can verify every
/// witness entry and re-execute the block.
#[derive(Debug, Clone)]
pub struct ServedWitness {
    pub mainnet: bool,
    pub chain_id: u32,
    /// Metadata answers are `None` as served; the client fills them.
    pub proven: ProvenWitness,
    /// Headers the proofs refer to, other than the block's own and genesis
    /// (signer signatures stripped: the block hash does not commit to them).
    pub headers: Vec<ServedHeader>,
    /// Bitcoin headers the burn lookups refer to (heights from the node's
    /// sortition DB).
    pub bitcoin: Vec<BitcoinHeader>,
    /// Every key the block wrote, with an inclusion proof of its final value
    /// at the block's own root.
    pub writes: Vec<(String, MarfProof)>,
    /// Contracts whose metadata is served as is, and why they cannot be
    /// re-derived (diagnostic; their entries fail verification).
    pub unproven_contracts: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The JSON a node serves (`read_witness` in the block replay response).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub version: u32,
    pub network: WireNetwork,
    pub witness: WireWitness,
    pub contracts: Vec<WireContract>,
    pub burn: Vec<WireBurnBinding>,
    pub burn_view: Option<WireTxInclusion>,
    pub coinbases: Vec<WireTxInclusion>,
    pub headers: Vec<WireHeader>,
    pub bitcoin: Vec<WireBitcoinHeader>,
    pub writes: Vec<WireWriteProof>,
    /// `[contract, reason]` for metadata served as is.
    pub unproven_contracts: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireNetwork {
    pub mainnet: bool,
    pub chain_id: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireWitness {
    pub open_tip: String,
    pub open_height: u32,
    pub epoch: Value,
    pub store: Vec<WireStoreEntry>,
    pub env: Vec<WireEnvEntry>,
}

/// One store read: the query, its answer (`null`: absent, or a metadata
/// value left for the client to re-derive) and its evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireStoreEntry {
    pub query: StoreQuery,
    pub value: Option<String>,
    pub proof: WireStoreProof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireStoreProof {
    Marf(WireMarfProof),
    /// `[hash_to_height, height_to_hash]` at the parent's root.
    Ancestor(WireMarfProof, WireMarfProof),
    OpenBlock,
    Rederived,
    Served,
}

/// A MARF proof's consensus encoding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMarfProof {
    Present(String),
    Absent(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireEnvEntry {
    pub query: EnvQuery,
    pub answer: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireContract {
    pub contract: String,
    pub block: String,
    /// `"boot"`, or the deploy transaction and its Merkle path.
    pub source: WireSource,
    pub commitment: String,
    pub commitment_proof: WireMarfProof,
    pub epoch_key: Option<String>,
    pub epoch_key_proof: WireMarfProof,
    pub ancestry: Option<(WireMarfProof, WireMarfProof)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireSource {
    Boot,
    Tx(WireTxInclusion),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireTxInclusion {
    pub block: String,
    pub tx: String,
    /// Sibling hashes from the leaf up, each on the `left` or `right`.
    pub merkle_path: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireBurnBinding {
    pub burn_header_hash: String,
    pub ops_hash: String,
    pub total_burn: u64,
    /// One `0`/`1` per reward cycle.
    pub pox_id: String,
    pub prev_consensus_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireHeaderBody {
    Nakamoto(String),
    Epoch2(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireHeader {
    pub consensus_hash: String,
    #[serde(flatten)]
    pub header: WireHeaderBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireBitcoinHeader {
    pub height: u32,
    pub hash: String,
    pub parent: String,
    pub time: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireWriteProof {
    pub key: String,
    pub proof: WireMarfProof,
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn codec_hex<T: StacksMessageCodec>(t: &T) -> String {
    to_hex(&t.serialize_to_vec())
}

fn from_codec_hex<T: StacksMessageCodec>(hex: &str) -> Result<T, String> {
    let bytes = hex_bytes(hex).map_err(|e| format!("bad hex: {e:?}"))?;
    let mut cursor = &bytes[..];
    let t = T::consensus_deserialize(&mut cursor).map_err(|e| format!("bad encoding: {e:?}"))?;
    if !cursor.is_empty() {
        return Err(format!("{} trailing bytes", cursor.len()));
    }
    Ok(t)
}

/// 32- and 20-byte ids and hashes, as hex.
trait HexId: Sized {
    fn hex(&self) -> String;
    fn parse(hex: &str) -> Result<Self, String>;
}

macro_rules! hex_id {
    ($($t:ty),*) => {$(
        impl HexId for $t {
            fn hex(&self) -> String {
                self.to_hex()
            }
            fn parse(hex: &str) -> Result<Self, String> {
                <$t>::from_hex(hex).map_err(|e| format!("bad {}: {e:?}", stringify!($t)))
            }
        }

        impl WireAnswer for $t {
            fn to_wire(&self) -> Value {
                Value::String(self.hex())
            }
            fn from_wire(v: &Value) -> Result<Self, String> {
                <$t>::parse(v.as_str().ok_or("expected a hex string")?)
            }
        }
    )*};
}

hex_id!(
    StacksBlockId,
    ConsensusHash,
    BurnchainHeaderHash,
    BlockHeaderHash,
    VRFSeed,
    SortitionId,
    OpsHash,
    TrieHash,
    Sha512Trunc256Sum
);

fn marf_to_wire(proof: &MarfProof) -> WireMarfProof {
    match proof {
        MarfProof::Present(p) => WireMarfProof::Present(codec_hex(p)),
        MarfProof::Absent(p) => WireMarfProof::Absent(codec_hex(p)),
    }
}

fn marf_from_wire(proof: &WireMarfProof) -> Result<MarfProof, String> {
    Ok(match proof {
        WireMarfProof::Present(hex) => {
            MarfProof::Present(from_codec_hex::<TrieMerkleProof<StacksBlockId>>(hex)?)
        }
        WireMarfProof::Absent(hex) => {
            MarfProof::Absent(from_codec_hex::<TrieAbsenceProof<StacksBlockId>>(hex)?)
        }
    })
}

fn inclusion_to_wire(inclusion: &TxInclusion) -> WireTxInclusion {
    WireTxInclusion {
        block: inclusion.block.hex(),
        tx: codec_hex(&inclusion.tx),
        merkle_path: inclusion
            .path
            .iter()
            .map(|point| {
                let side = match point.order {
                    MerklePathOrder::Left => "left",
                    MerklePathOrder::Right => "right",
                };
                (side.to_string(), point.hash.hex())
            })
            .collect(),
    }
}

fn inclusion_from_wire(wire: &WireTxInclusion) -> Result<TxInclusion, String> {
    let path = wire
        .merkle_path
        .iter()
        .map(|(side, hash)| {
            let order = match side.as_str() {
                "left" => MerklePathOrder::Left,
                "right" => MerklePathOrder::Right,
                other => return Err(format!("bad Merkle path side {other}")),
            };
            Ok(MerklePathPoint {
                order,
                hash: Sha512Trunc256Sum::parse(hash)?,
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(TxInclusion {
        block: StacksBlockId::parse(&wire.block)?,
        tx: from_codec_hex::<StacksTransaction>(&wire.tx)?,
        path,
    })
}

fn epoch_to_wire(epoch: &StacksEpoch) -> Value {
    json!({
        "epoch_id": epoch.epoch_id,
        "start_height": epoch.start_height,
        "end_height": epoch.end_height,
        "block_limit": epoch.block_limit,
        "network_epoch": epoch.network_epoch,
    })
}

fn epoch_from_wire(v: &Value) -> Result<StacksEpoch, String> {
    let field = |name: &str| v.get(name).ok_or_else(|| format!("epoch has no {name}"));
    let u64_field = |name: &str| {
        field(name)?
            .as_u64()
            .ok_or_else(|| format!("epoch {name} is not a number"))
    };
    Ok(StacksEpoch {
        epoch_id: serde_json::from_value::<StacksEpochId>(field("epoch_id")?.clone())
            .map_err(|e| format!("epoch id: {e}"))?,
        start_height: u64_field("start_height")?,
        end_height: u64_field("end_height")?,
        block_limit: serde_json::from_value::<ExecutionCost>(field("block_limit")?.clone())
            .map_err(|e| format!("block limit: {e}"))?,
        network_epoch: u8::try_from(u64_field("network_epoch")?)
            .map_err(|_| "network epoch out of range".to_string())?,
    })
}

// ---------------------------------------------------------------------------
// Environment answers: the type each `EnvQuery` answers with
// ---------------------------------------------------------------------------

/// An environment answer's JSON form, for each type a lookup answers with.
trait WireAnswer: Sized + fmt::Debug + Send + Sync + 'static {
    fn to_wire(&self) -> Value;
    fn from_wire(v: &Value) -> Result<Self, String>;
}

macro_rules! wire_number {
    ($($t:ty),*) => {$(
        impl WireAnswer for $t {
            fn to_wire(&self) -> Value {
                Value::from(*self)
            }
            fn from_wire(v: &Value) -> Result<Self, String> {
                v.as_u64()
                    .and_then(|n| <$t>::try_from(n).ok())
                    .ok_or_else(|| format!("expected a {}", stringify!($t)))
            }
        }
    )*};
}

wire_number!(u32, u64);

/// A decimal string: JSON numbers do not hold a `u128`.
impl WireAnswer for u128 {
    fn to_wire(&self) -> Value {
        Value::String(self.to_string())
    }
    fn from_wire(v: &Value) -> Result<Self, String> {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "expected a decimal u128 string".into())
    }
}

impl WireAnswer for StacksAddress {
    fn to_wire(&self) -> Value {
        Value::String(codec_hex(self))
    }
    fn from_wire(v: &Value) -> Result<Self, String> {
        from_codec_hex(v.as_str().ok_or("expected a hex string")?)
    }
}

impl WireAnswer for StacksEpoch {
    fn to_wire(&self) -> Value {
        epoch_to_wire(self)
    }
    fn from_wire(v: &Value) -> Result<Self, String> {
        epoch_from_wire(v)
    }
}

/// `get-burn-block-info? pox-addrs`: each address tuple as a serialized
/// Clarity value, and the payout.
impl WireAnswer for (Vec<TupleData>, u128) {
    fn to_wire(&self) -> Value {
        let (addrs, payout) = self;
        let addrs: Vec<Value> = addrs
            .iter()
            .map(|t| {
                let hex = ClarityValue::Tuple(t.clone())
                    .serialize_to_hex()
                    .expect("a tuple read from the chain serializes");
                Value::String(hex)
            })
            .collect();
        json!({ "addrs": addrs, "payout": payout.to_wire() })
    }
    fn from_wire(v: &Value) -> Result<Self, String> {
        let addrs = v
            .get("addrs")
            .and_then(Value::as_array)
            .ok_or("expected addrs")?
            .iter()
            .map(|a| {
                let hex = a.as_str().ok_or("expected a hex string")?;
                match ClarityValue::try_deserialize_hex_untyped(hex) {
                    Ok(ClarityValue::Tuple(t)) => Ok(t),
                    _ => Err("expected a serialized tuple".to_string()),
                }
            })
            .collect::<Result<_, String>>()?;
        let payout = u128::from_wire(v.get("payout").ok_or("expected payout")?)?;
        Ok((addrs, payout))
    }
}

impl<T: WireAnswer> WireAnswer for Option<T> {
    fn to_wire(&self) -> Value {
        self.as_ref().map_or(Value::Null, T::to_wire)
    }
    fn from_wire(v: &Value) -> Result<Self, String> {
        if v.is_null() {
            Ok(None)
        } else {
            T::from_wire(v).map(Some)
        }
    }
}

/// Call `$f::<T>($args)` with `T` the type `$query`'s trait method returns
/// (see the `HeadersDB` / `BurnStateDB` impls of `EnvTap`).
macro_rules! by_answer_type {
    ($query:expr, $f:ident, $($arg:expr),*) => {{
        use EnvQuery::*;
        match $query {
            StacksBlockHeaderHash { .. } => $f::<Option<BlockHeaderHash>>($($arg),*),
            BurnHeaderHashForBlock { .. } | BurnHeaderHash { .. } => {
                $f::<Option<BurnchainHeaderHash>>($($arg),*)
            }
            ConsensusHashForBlock { .. } => $f::<Option<ConsensusHash>>($($arg),*),
            VrfSeed { .. } => $f::<Option<VRFSeed>>($($arg),*),
            StacksBlockTime { .. } | BurnBlockTime { .. } => $f::<Option<u64>>($($arg),*),
            BurnBlockHeightForBlock { .. }
            | StacksHeightForTenureHeight { .. }
            | TipBurnBlockHeight
            | BurnBlockHeight { .. } => $f::<Option<u32>>($($arg),*),
            MinerAddress { .. } => $f::<Option<StacksAddress>>($($arg),*),
            TokensSpent { .. } | TokensSpentWinning { .. } | TokensEarned { .. } => {
                $f::<Option<u128>>($($arg),*)
            }
            TipSortitionId | SortitionIdFromConsensusHash { .. } => {
                $f::<Option<SortitionId>>($($arg),*)
            }
            V1UnlockHeight
            | V2UnlockHeight
            | V3UnlockHeight
            | Pox3ActivationHeight
            | Pox4ActivationHeight
            | Pox5ActivationHeight
            | BurnStartHeight
            | PoxPrepareLength
            | PoxRewardCycleLength => $f::<u32>($($arg),*),
            PoxRejectionFraction => $f::<u64>($($arg),*),
            StacksEpoch { .. } | StacksEpochById { .. } => {
                $f::<Option<crate::core::StacksEpoch>>($($arg),*)
            }
            PoxPayoutAddrs { .. } => $f::<Option<(Vec<TupleData>, u128)>>($($arg),*),
        }
    }};
}

fn encode_answer(read: &EnvRead) -> Result<Value, String> {
    fn encode<T: WireAnswer>(read: &EnvRead) -> Result<Value, String> {
        read.answer
            .downcast_ref::<T>()
            .map(T::to_wire)
            .ok_or_else(|| format!("{}: answer has the wrong type", read.query))
    }
    by_answer_type!(&read.query, encode, read)
}

fn decode_answer(query: &EnvQuery, answer: &Value) -> Result<EnvRead, String> {
    fn decode<T: WireAnswer>(query: &EnvQuery, answer: &Value) -> Result<EnvRead, String> {
        let answer = T::from_wire(answer).map_err(|e| format!("{query}: {e}"))?;
        Ok(EnvRead::new(query.clone(), answer))
    }
    by_answer_type!(query, decode, query, answer)
}

// ---------------------------------------------------------------------------
// Served witness <-> envelope
// ---------------------------------------------------------------------------

fn store_proof_to_wire(proof: &StoreProof) -> WireStoreProof {
    match proof {
        StoreProof::Marf(p) => WireStoreProof::Marf(marf_to_wire(p)),
        StoreProof::Ancestor {
            hash_to_height,
            height_to_hash,
        } => WireStoreProof::Ancestor(marf_to_wire(hash_to_height), marf_to_wire(height_to_hash)),
        StoreProof::OpenBlock => WireStoreProof::OpenBlock,
        StoreProof::Rederived => WireStoreProof::Rederived,
        StoreProof::Served => WireStoreProof::Served,
    }
}

fn store_proof_from_wire(proof: &WireStoreProof) -> Result<StoreProof, String> {
    Ok(match proof {
        WireStoreProof::Marf(p) => StoreProof::Marf(marf_from_wire(p)?),
        WireStoreProof::Ancestor(a, b) => StoreProof::Ancestor {
            hash_to_height: marf_from_wire(a)?,
            height_to_hash: marf_from_wire(b)?,
        },
        WireStoreProof::OpenBlock => StoreProof::OpenBlock,
        WireStoreProof::Rederived => StoreProof::Rederived,
        WireStoreProof::Served => StoreProof::Served,
    })
}

fn header_to_wire(header: &ServedHeader) -> WireHeader {
    WireHeader {
        consensus_hash: header.consensus_hash.hex(),
        header: match &header.header {
            StacksBlockHeaderTypes::Nakamoto(h) => WireHeaderBody::Nakamoto(codec_hex(h)),
            StacksBlockHeaderTypes::Epoch2(h) => WireHeaderBody::Epoch2(codec_hex(h)),
        },
    }
}

fn header_from_wire(wire: &WireHeader) -> Result<ServedHeader, String> {
    Ok(ServedHeader {
        consensus_hash: ConsensusHash::parse(&wire.consensus_hash)?,
        header: match &wire.header {
            WireHeaderBody::Nakamoto(hex) => {
                StacksBlockHeaderTypes::Nakamoto(from_codec_hex::<NakamotoBlockHeader>(hex)?)
            }
            WireHeaderBody::Epoch2(hex) => {
                StacksBlockHeaderTypes::Epoch2(from_codec_hex::<StacksBlockHeader>(hex)?)
            }
        },
    })
}

fn pox_id_from_wire(bits: &str) -> Result<PoxId, String> {
    let bits = bits
        .chars()
        .map(|c| match c {
            '0' => Ok(false),
            '1' => Ok(true),
            other => Err(format!("bad PoX id bit {other}")),
        })
        .collect::<Result<_, _>>()?;
    Ok(PoxId::new(bits))
}

impl ServedWitness {
    pub fn to_envelope(&self) -> Result<WitnessEnvelope, String> {
        let proven = &self.proven;
        let w = &proven.witness;
        if proven.store.len() != w.store.len() {
            return Err("one proof per store entry".into());
        }
        let store = w
            .store
            .iter()
            .zip(proven.store.iter())
            .map(|((query, value), proof)| WireStoreEntry {
                query: query.clone(),
                // the client re-derives metadata it can
                value: match proof {
                    StoreProof::Rederived => None,
                    _ => value.clone(),
                },
                proof: store_proof_to_wire(proof),
            })
            .collect();
        let env = w
            .env
            .iter()
            .map(|read| {
                Ok(WireEnvEntry {
                    query: read.query.clone(),
                    answer: encode_answer(read)?,
                })
            })
            .collect::<Result<_, String>>()?;
        let contracts = proven
            .contracts
            .iter()
            .map(|c| WireContract {
                contract: c.contract.to_string(),
                block: c.block.hex(),
                source: match &c.source {
                    DeploySource::Boot => WireSource::Boot,
                    DeploySource::Tx(inclusion) => WireSource::Tx(inclusion_to_wire(inclusion)),
                },
                commitment: c.commitment.clone(),
                commitment_proof: marf_to_wire(&c.commitment_proof),
                epoch_key: c.epoch_key.clone(),
                epoch_key_proof: marf_to_wire(&c.epoch_key_proof),
                ancestry: c
                    .ancestry
                    .as_ref()
                    .map(|(a, b)| (marf_to_wire(a), marf_to_wire(b))),
            })
            .collect();
        let burn = proven
            .burn
            .iter()
            .map(|b| WireBurnBinding {
                burn_header_hash: b.burn_header_hash.hex(),
                ops_hash: b.ops_hash.hex(),
                total_burn: b.total_burn,
                pox_id: b.pox_id.to_string(),
                prev_consensus_hashes: b.prev_consensus_hashes.iter().map(HexId::hex).collect(),
            })
            .collect();
        Ok(WitnessEnvelope {
            version: WITNESS_WIRE_VERSION,
            network: WireNetwork {
                mainnet: self.mainnet,
                chain_id: self.chain_id,
            },
            witness: WireWitness {
                open_tip: w.open_tip.hex(),
                open_height: w.open_height,
                epoch: epoch_to_wire(&w.epoch),
                store,
                env,
            },
            contracts,
            burn,
            burn_view: proven.burn_view.as_ref().map(inclusion_to_wire),
            coinbases: proven.coinbases.iter().map(inclusion_to_wire).collect(),
            headers: self.headers.iter().map(header_to_wire).collect(),
            bitcoin: self
                .bitcoin
                .iter()
                .map(|h| WireBitcoinHeader {
                    height: h.height,
                    hash: h.hash.hex(),
                    parent: h.parent.hex(),
                    time: h.time,
                })
                .collect(),
            writes: self
                .writes
                .iter()
                .map(|(key, proof)| WireWriteProof {
                    key: key.clone(),
                    proof: marf_to_wire(proof),
                })
                .collect(),
            unproven_contracts: self.unproven_contracts.clone(),
        })
    }
}

impl WitnessEnvelope {
    /// Decode every field. Errors name the field that failed; nothing is
    /// verified here (see `witness_proof::verify_read_witness`).
    pub fn decode(&self) -> Result<ServedWitness, String> {
        if self.version != WITNESS_WIRE_VERSION {
            return Err(format!(
                "witness wire version {} (this client reads {WITNESS_WIRE_VERSION})",
                self.version
            ));
        }
        let w = &self.witness;
        let mut store = vec![];
        let mut store_proofs = vec![];
        for (i, entry) in w.store.iter().enumerate() {
            store.push((entry.query.clone(), entry.value.clone()));
            store_proofs.push(
                store_proof_from_wire(&entry.proof)
                    .map_err(|e| format!("store[{i}] {:?}: {e}", entry.query))?,
            );
        }
        let env = w
            .env
            .iter()
            .enumerate()
            .map(|(i, e)| {
                decode_answer(&e.query, &e.answer).map_err(|err| format!("env[{i}] {err}"))
            })
            .collect::<Result<_, _>>()?;
        let witness = ReadWitness {
            open_tip: StacksBlockId::parse(&w.open_tip)?,
            open_height: w.open_height,
            epoch: epoch_from_wire(&w.epoch)?,
            store,
            env,
        };
        let contracts = self
            .contracts
            .iter()
            .map(|c| {
                let named = |e: String| format!("contract {}: {e}", c.contract);
                Ok(ContractEvidence {
                    contract: QualifiedContractIdentifier::parse(&c.contract)
                        .map_err(|e| named(format!("bad contract id: {e:?}")))?,
                    block: StacksBlockId::parse(&c.block).map_err(named)?,
                    source: match &c.source {
                        WireSource::Boot => DeploySource::Boot,
                        WireSource::Tx(inclusion) => {
                            DeploySource::Tx(inclusion_from_wire(inclusion).map_err(named)?)
                        }
                    },
                    commitment: c.commitment.clone(),
                    commitment_proof: marf_from_wire(&c.commitment_proof).map_err(named)?,
                    epoch_key: c.epoch_key.clone(),
                    epoch_key_proof: marf_from_wire(&c.epoch_key_proof).map_err(named)?,
                    ancestry: match &c.ancestry {
                        None => None,
                        Some((a, b)) => Some((
                            marf_from_wire(a).map_err(named)?,
                            marf_from_wire(b).map_err(named)?,
                        )),
                    },
                })
            })
            .collect::<Result<_, String>>()?;
        let burn = self
            .burn
            .iter()
            .map(|b| {
                Ok(BurnBinding {
                    burn_header_hash: BurnchainHeaderHash::parse(&b.burn_header_hash)?,
                    ops_hash: OpsHash::parse(&b.ops_hash)?,
                    total_burn: b.total_burn,
                    pox_id: pox_id_from_wire(&b.pox_id)?,
                    prev_consensus_hashes: b
                        .prev_consensus_hashes
                        .iter()
                        .map(|ch| ConsensusHash::parse(ch))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, String>>()
            .map_err(|e| format!("burn: {e}"))?;
        let proven = ProvenWitness {
            witness,
            store: store_proofs,
            contracts,
            burn,
            burn_view: self
                .burn_view
                .as_ref()
                .map(inclusion_from_wire)
                .transpose()
                .map_err(|e| format!("burn_view: {e}"))?,
            coinbases: self
                .coinbases
                .iter()
                .map(inclusion_from_wire)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("coinbases: {e}"))?,
        };
        Ok(ServedWitness {
            mainnet: self.network.mainnet,
            chain_id: self.network.chain_id,
            proven,
            headers: self
                .headers
                .iter()
                .map(header_from_wire)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("headers: {e}"))?,
            bitcoin: self
                .bitcoin
                .iter()
                .map(|h| {
                    Ok(BitcoinHeader {
                        height: h.height,
                        hash: BurnchainHeaderHash::parse(&h.hash)?,
                        parent: BurnchainHeaderHash::parse(&h.parent)?,
                        time: h.time,
                    })
                })
                .collect::<Result<_, String>>()
                .map_err(|e| format!("bitcoin: {e}"))?,
            writes: self
                .writes
                .iter()
                .map(|w| Ok((w.key.clone(), marf_from_wire(&w.proof)?)))
                .collect::<Result<_, String>>()
                .map_err(|e| format!("writes: {e}"))?,
            unproven_contracts: self.unproven_contracts.clone(),
        })
    }
}
