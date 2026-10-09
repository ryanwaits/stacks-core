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

//! Proof-carrying read witness: every entry of a [`ReadWitness`] with the
//! evidence that makes it true on its own, and the verifier a client runs
//! before re-executing the block from it.
//!
//! The client is assumed to hold:
//!
//! * the **Stacks header chain** ([`HeaderChain`]), authenticated by signer
//!   signatures (checking those is out of scope here). Headers give block ids,
//!   heights, consensus hashes, `state_index_root` (MARF roots),
//!   `tx_merkle_root` and timestamps;
//! * the **Bitcoin header chain** ([`BitcoinChain`]), authenticated by
//!   proof of work (SPV, out of scope here);
//! * **network constants** ([`NetworkParams`]): epochs and PoX parameters.
//!
//! What each witness entry is checked against:
//!
//! | Entry | Evidence |
//! |---|---|
//! | store read at the open block | a walk of the shared MARF proof from the parent's `state_index_root` (value or absence) |
//! | store read inside `at-block X` | same, from X's root |
//! | `at-block` switch | walks of `__MARF_BLOCK_HASH_TO_HEIGHT::X` and back |
//! | the open block's own bookkeeping | deterministic from the parent id and height |
//! | contract metadata | re-derived from the deploy (see [`derive_contract_metadata`]), with the deploy's own reads proven at its parent (deploy witness) |
//! | header lookups | the header chain |
//! | burn lookups | consensus-hash preimages ([`BurnBinding`]) plus the Bitcoin chain; through the burn view, its tenure change too |
//! | tenure height to block | walks of `_stx-data::tenure_height` at the tenure's first block and its parent |
//! | epochs, PoX parameters | network constants |
//! | a deploy's own lookups | the same, with the deploying block's burn view |
//!
//! See `NOTES.md` for the lookups that are not provable yet.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::time::Instant;

use clarity::vm::database::clarity_db::TENURE_HEIGHT_KEY;
use clarity::vm::database::clarity_store::{make_contract_hash_key, ContractCommitment};
use clarity::vm::database::{
    BurnStateDB, ClarityDeserializable, ClaritySerializable, HeadersDB, SqliteConnection,
};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, ContractName};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
    TrieHash, VRFSeed,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{MerklePath, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::{ConsensusHashExtensions, OpsHash};
use crate::chainstate::stacks::boot::{
    make_pox_5_body, make_sip_031_body, BOOT_CODE_BNS, BOOT_CODE_COSTS, BOOT_CODE_COSTS_2,
    BOOT_CODE_COSTS_2_TESTNET, BOOT_CODE_COSTS_3, BOOT_CODE_COSTS_4, BOOT_CODE_COST_VOTING_MAINNET,
    BOOT_CODE_COST_VOTING_TESTNET, BOOT_CODE_GENESIS, BOOT_CODE_LOCKUP, BOOT_CODE_POX_MAINNET,
    BOOT_CODE_POX_TESTNET, COSTS_1_NAME, COSTS_2_NAME, COSTS_3_NAME, COSTS_4_NAME,
    POX_2_MAINNET_CODE, POX_2_NAME, POX_2_TESTNET_CODE, POX_3_MAINNET_CODE, POX_3_NAME,
    POX_3_TESTNET_CODE, POX_4_CODE, POX_4_NAME, POX_5_NAME, SIGNERS_BODY, SIGNERS_DB_0_BODY,
    SIGNERS_DB_1_BODY, SIGNERS_NAME, SIGNERS_VOTING_BODY, SIGNERS_VOTING_NAME, SIP_031_NAME,
};
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
use crate::chainstate::stacks::index::marf::{
    BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::multiproof::{Multiproof, MultiproofBuilder, WalkEnd};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::{Error as MarfError, MARFValue};
use crate::chainstate::stacks::{
    StacksTransaction, TransactionPayload, TransactionSmartContract, TransactionVersion,
    MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity_vm::read_witness::{EnvQuery, EnvRead, EnvTap, ReadWitness, StoreQuery};
use crate::clarity_vm::stateless::{
    derive_contract_metadata, ContractDeployment, ContractMetadata, DeriveError, EPOCH_VERSION_KEY,
};
use crate::core::StacksEpoch;
use crate::util_lib::boot::{boot_code_addr, boot_code_tx_auth};
use crate::util_lib::strings::StacksString;

// ---------------------------------------------------------------------------
// What the client already trusts
// ---------------------------------------------------------------------------

/// The parts of a Stacks block header the verifier uses.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainHeader {
    pub id: StacksBlockId,
    pub parent: StacksBlockId,
    pub block_hash: BlockHeaderHash,
    pub consensus_hash: ConsensusHash,
    /// Stacks height (equal to the MARF height of the block's trie).
    pub height: u32,
    pub state_index_root: TrieHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    /// Nakamoto headers only.
    pub timestamp: Option<u64>,
    /// Epoch 2.x headers carry the block's VRF proof.
    pub vrf_proof: Option<VRFProof>,
}

impl ChainHeader {
    pub fn is_nakamoto(&self) -> bool {
        self.timestamp.is_some()
    }

    /// A header the client hashed itself: its id is computed from the
    /// header and consensus hash, never taken on trust. An epoch 2.x header
    /// names its parent by block hash only, so its `parent` is unknown (zero).
    pub fn from_header(consensus_hash: &ConsensusHash, header: &StacksBlockHeaderTypes) -> Self {
        let parent = match header {
            StacksBlockHeaderTypes::Nakamoto(h) => h.parent_block_id.clone(),
            StacksBlockHeaderTypes::Epoch2(_) => StacksBlockId([0; 32]),
        };
        Self::with_parent(consensus_hash, header, parent)
    }

    /// A header from the node's own headers DB (tests, and the prover).
    pub fn from_header_info(info: &StacksHeaderInfo, parent: StacksBlockId) -> Self {
        ChainHeader {
            id: info.index_block_hash(),
            height: info.stacks_block_height as u32,
            ..Self::with_parent(&info.consensus_hash, &info.anchored_header, parent)
        }
    }

    fn with_parent(
        consensus_hash: &ConsensusHash,
        header: &StacksBlockHeaderTypes,
        parent: StacksBlockId,
    ) -> Self {
        let (height, state_index_root, tx_merkle_root, timestamp, vrf_proof) = match header {
            StacksBlockHeaderTypes::Epoch2(h) => (
                h.total_work.work,
                h.state_index_root,
                h.tx_merkle_root.clone(),
                None,
                Some(h.proof.clone()),
            ),
            StacksBlockHeaderTypes::Nakamoto(h) => (
                h.chain_length,
                h.state_index_root,
                h.tx_merkle_root.clone(),
                Some(h.timestamp),
                None,
            ),
        };
        let block_hash = header.block_hash();
        ChainHeader {
            id: StacksBlockId::new(consensus_hash, &block_hash),
            parent,
            block_hash,
            consensus_hash: consensus_hash.clone(),
            height: height as u32,
            state_index_root,
            tx_merkle_root,
            timestamp,
            vrf_proof,
        }
    }
}

/// Authenticated Stacks headers, by block id.
pub struct HeaderChain {
    headers: HashMap<StacksBlockId, ChainHeader>,
}

impl HeaderChain {
    pub fn new(headers: impl IntoIterator<Item = ChainHeader>) -> Self {
        HeaderChain {
            headers: headers.into_iter().map(|h| (h.id.clone(), h)).collect(),
        }
    }

    pub fn get(&self, id: &StacksBlockId) -> Option<&ChainHeader> {
        self.headers.get(id)
    }

    /// The MARF root of `id`'s trie (`state_index_root`).
    pub fn root_of(&self, id: &StacksBlockId) -> Option<TrieHash> {
        self.get(id).map(|h| h.state_index_root)
    }

    /// Open a shared MARF proof against these headers' roots.
    pub fn open_proof(&self, bytes: &[u8]) -> Result<Multiproof<StacksBlockId>, String> {
        Multiproof::open(bytes, |id| self.root_of(id))
    }
}

/// One Bitcoin block header, as an SPV client holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinHeader {
    pub height: u32,
    pub hash: BurnchainHeaderHash,
    pub parent: BurnchainHeaderHash,
    pub time: u64,
}

/// The client's Bitcoin header chain (one fork).
pub struct BitcoinChain {
    by_height: BTreeMap<u32, BitcoinHeader>,
    height_of: HashMap<BurnchainHeaderHash, u32>,
}

impl BitcoinChain {
    /// Errors if the headers do not link up by parent hash.
    pub fn new(headers: impl IntoIterator<Item = BitcoinHeader>) -> Result<Self, String> {
        let by_height: BTreeMap<_, _> = headers.into_iter().map(|h| (h.height, h)).collect();
        for (height, header) in by_height.iter() {
            if let Some(parent) = by_height.get(&height.wrapping_sub(1)) {
                if parent.hash != header.parent {
                    return Err(format!(
                        "Bitcoin header {height} does not link to {}",
                        height - 1
                    ));
                }
            }
        }
        let height_of = by_height
            .values()
            .map(|h| (h.hash.clone(), h.height))
            .collect();
        Ok(BitcoinChain {
            by_height,
            height_of,
        })
    }

    pub fn at(&self, height: u32) -> Option<&BitcoinHeader> {
        self.by_height.get(&height)
    }

    pub fn find(&self, hash: &BurnchainHeaderHash) -> Option<&BitcoinHeader> {
        self.height_of.get(hash).and_then(|h| self.by_height.get(h))
    }
}

/// Network constants the client pins.
#[derive(Debug, Clone)]
pub struct NetworkParams {
    pub mainnet: bool,
    pub chain_id: u32,
    pub first_burn_height: u32,
    pub epochs: Vec<StacksEpoch>,
    pub pox: PoxConstants,
}

impl NetworkParams {
    pub fn epoch_at(&self, burn_height: u32) -> Option<&StacksEpoch> {
        let h = u64::from(burn_height);
        self.epochs
            .iter()
            .find(|e| e.start_height <= h && h < e.end_height)
    }

    pub fn epoch(&self, id: &StacksEpochId) -> Option<&StacksEpoch> {
        self.epochs.iter().find(|e| &e.epoch_id == id)
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A consensus hash's preimage:
/// `ripemd160(sha256(fork-set version ‖ burn_header_hash ‖ ops_hash ‖
/// total_burn ‖ pox_id ‖ previous consensus hashes))`. It pins a consensus
/// hash to a Bitcoin block and carries the PoX id, so it also yields the
/// sortition id.
#[derive(Debug, Clone, PartialEq)]
pub struct BurnBinding {
    pub burn_header_hash: BurnchainHeaderHash,
    pub ops_hash: OpsHash,
    pub total_burn: u64,
    pub pox_id: PoxId,
    pub prev_consensus_hashes: Vec<ConsensusHash>,
}

impl BurnBinding {
    pub fn consensus_hash(&self) -> ConsensusHash {
        ConsensusHash::from_ops(
            &self.burn_header_hash,
            &self.ops_hash,
            self.total_burn,
            &self.prev_consensus_hashes,
            &self.pox_id,
        )
    }

    pub fn sortition_id(&self) -> SortitionId {
        SortitionId::new(&self.burn_header_hash, &self.pox_id)
    }

    pub fn byte_len(&self) -> usize {
        32 + 32 + 8 + self.pox_id.len().div_ceil(8) + 20 * self.prev_consensus_hashes.len()
    }
}

/// A transaction and its Merkle path to a block's `tx_merkle_root`.
#[derive(Debug, Clone, PartialEq)]
pub struct TxInclusion {
    pub block: StacksBlockId,
    pub tx: StacksTransaction,
    pub path: MerklePath<Sha512Trunc256Sum>,
}

impl TxInclusion {
    /// Prove `txs[index]` is in `block`.
    pub fn new(block: StacksBlockId, txs: &[StacksTransaction], index: usize) -> Self {
        let txids: Vec<Vec<u8>> = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();
        let tree = MerkleTree::<Sha512Trunc256Sum>::new(&txids);
        let path = tree.path(&txids[index]).expect("tx is in its own tree");
        TxInclusion {
            block,
            tx: txs[index].clone(),
            path,
        }
    }

    fn holds(&self, headers: &HeaderChain) -> bool {
        let Some(header) = headers.get(&self.block) else {
            return false;
        };
        MerkleTree::<Sha512Trunc256Sum>::path_verify(
            self.tx.txid().as_bytes(),
            &self.path,
            &header.tx_merkle_root,
        )
    }

    pub fn byte_len(&self) -> usize {
        32 + self.tx.serialize_to_vec().len() + 33 * self.path.len()
    }
}

/// Evidence for one store entry of the witness. MARF-backed entries carry
/// no bytes of their own: they are walks of the shared proof
/// ([`ProvenWitness::marf`]) from the root their query names.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreProof {
    /// The entry's key at the root of the block it was read at (present or
    /// absent, as the entry's answer says).
    Marf,
    /// An `at-block` target is (or is not) an ancestor: its height
    /// (`__MARF_BLOCK_HASH_TO_HEIGHT`) and that height's block
    /// (`__MARF_BLOCK_HEIGHT_TO_HASH`), both at the parent.
    Ancestor,
    /// The open block's own bookkeeping: determined by the parent and the
    /// open height.
    OpenBlock,
    /// Contract metadata: re-derived from [`ProvenWitness::contracts`].
    Rederived,
    /// Contract metadata served as is: the contract cannot be re-derived (its
    /// deploy reads something not provable yet, or it depends on such a
    /// contract). The verifier rejects it.
    Served,
}

/// Where a contract's source comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum DeploySource {
    /// A user contract: its deploy transaction in the deploying block.
    Tx(TxInclusion),
    /// A boot contract: the client's bundled boot code.
    Boot,
}

/// What re-deriving one contract's metadata needs. Its MARF facts are walks
/// of the shared proof: the commitment and epoch key at the deploying
/// block's root, the deploying block's ancestry at the parent's root, and
/// for a deploy witness, the deploying block's parent at its root and each
/// deploy read at that parent's root.
#[derive(Debug, Clone, PartialEq)]
pub struct ContractEvidence {
    pub contract: QualifiedContractIdentifier,
    /// The deploying block.
    pub block: StacksBlockId,
    pub source: DeploySource,
    /// `clarity-contract::<contract>` (source hash and deploy height) at the
    /// deploying block's root.
    pub commitment: String,
    /// `vm-epoch::epoch-version` at the deploying block's root.
    pub epoch_key: Option<String>,
    /// The deploy witness: chain state the deploy read, as it answered, in
    /// the order re-derivation asked for it. Empty when the deploy reads only
    /// itself and the contracts it depends on.
    pub deploy_reads: Vec<(StoreQuery, Option<String>)>,
    /// One per deploy read: proven at the deploying block's parent (or an
    /// `at-block` target), as a block's own reads are at its parent.
    pub deploy_proofs: Vec<StoreProof>,
    /// Environment lookups the deploy made, as they answered, checked as a
    /// block's own lookups are (header chain, burn preimages and Bitcoin
    /// headers, tenure-height walks, constants).
    pub deploy_env: Vec<EnvRead>,
    /// The tenure change that set the deploying block's burn view (in that
    /// block, else earlier in its tenure), when a deploy lookup reads the burn
    /// view (`burn-block-height` on Nakamoto, `get-burn-block-info?`).
    pub deploy_burn_view: Option<TxInclusion>,
}

impl ContractEvidence {
    pub fn byte_len(&self) -> usize {
        let source = match &self.source {
            DeploySource::Tx(inclusion) => inclusion.byte_len(),
            DeploySource::Boot => 0,
        };
        self.contract.to_string().len()
            + 32
            + source
            + self.commitment.len()
            + self.epoch_key.as_ref().map_or(0, String::len)
            + self
                .deploy_reads
                .iter()
                .map(|(q, a)| q.wire_len() + a.as_ref().map_or(0, String::len))
                .sum::<usize>()
            + self
                .deploy_env
                .iter()
                .map(|r| r.query.to_string().len() + r.shown.len())
                .sum::<usize>()
            + self
                .deploy_burn_view
                .as_ref()
                .map_or(0, TxInclusion::byte_len)
    }
}

/// A read witness with evidence for every entry.
#[derive(Debug, Clone)]
pub struct ProvenWitness {
    pub witness: ReadWitness,
    /// One per `witness.store` entry, in order.
    pub store: Vec<StoreProof>,
    /// Contracts whose metadata execution read, and the contracts their
    /// analysis depends on, dependencies first.
    pub contracts: Vec<ContractEvidence>,
    /// The shared MARF proof (a [`Multiproof`]) every MARF-backed store
    /// entry and contract fact is a walk of.
    pub marf: Vec<u8>,
    /// Preimages of every consensus hash a lookup touches.
    pub burn: Vec<BurnBinding>,
    /// The tenure change that set the block's burn view, when it is in an
    /// ancestor (a block carrying its own tenure change needs none).
    pub burn_view: Option<TxInclusion>,
    /// Tenure coinbases, for VRF seeds.
    pub coinbases: Vec<TxInclusion>,
}

/// Evidence sizes, in bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProofSize {
    /// The shared MARF proof.
    pub marf: usize,
    /// Deploy txs, commitments, epoch keys and deploy witnesses.
    pub contracts: usize,
    /// Burn bindings, burn-view and coinbase tx proofs.
    pub env: usize,
}

impl ProvenWitness {
    pub fn proof_size(&self) -> ProofSize {
        ProofSize {
            marf: self.marf.len(),
            contracts: self.contracts.iter().map(ContractEvidence::byte_len).sum(),
            env: self.burn.iter().map(BurnBinding::byte_len).sum::<usize>()
                + self.burn_view.as_ref().map_or(0, TxInclusion::byte_len)
                + self
                    .coinbases
                    .iter()
                    .map(TxInclusion::byte_len)
                    .sum::<usize>(),
        }
    }
}

// ---------------------------------------------------------------------------
// Where each store entry is proven
// ---------------------------------------------------------------------------

/// What a store entry claims about the MARF.
enum Claim {
    /// `path` at `block` holds `value` (`None`: absent).
    Key {
        block: StacksBlockId,
        path: TrieHash,
        value: Option<MARFValue>,
    },
    /// `target` is (`is`) or is not an ancestor of the parent.
    Ancestor {
        target: StacksBlockId,
        is: bool,
    },
    /// The open block's own bookkeeping; the answer must be `expected`.
    OpenBlock {
        expected: Option<String>,
    },
    Metadata,
}

fn miner_tip() -> StacksBlockId {
    StacksBlockId::new(&MINER_BLOCK_CONSENSUS_HASH, &MINER_BLOCK_HEADER_HASH)
}

fn height_to_hash_key(height: u32) -> String {
    format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}")
}

fn hash_to_height_key(block: &StacksBlockId) -> String {
    format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{block}")
}

fn block_answer(answer: &Option<String>) -> Result<Option<MARFValue>, String> {
    answer
        .as_ref()
        .map(|hex| {
            StacksBlockId::from_hex(hex)
                .map(MARFValue::from)
                .map_err(|_| format!("answer {hex} is not a block id"))
        })
        .transpose()
}

/// What `(query, answer)` claims, read in the block whose parent is `parent`
/// at `open_height` (a block being processed, or a deploy being re-derived;
/// both run at the miner tip). `at_height` gives the height of an `at-block`
/// target (from the header chain on the verifier side, the MARF on the
/// prover side).
fn claim_of(
    query: &StoreQuery,
    answer: &Option<String>,
    open_height: u32,
    parent: &StacksBlockId,
    mut at_height: impl FnMut(&StacksBlockId) -> Option<u32>,
) -> Result<Claim, String> {
    let root_of = |at: &Option<StacksBlockId>| at.clone().unwrap_or_else(|| parent.clone());
    Ok(match query {
        StoreQuery::Data { at, key } => Claim::Key {
            block: root_of(at),
            path: TrieHash::from_key(key),
            value: answer.as_deref().map(MARFValue::from_value),
        },
        StoreQuery::Path { at, path } => Claim::Key {
            block: root_of(at),
            path: *path,
            value: answer.as_deref().map(MARFValue::from_value),
        },
        StoreQuery::BlockAtHeight { at: None, height } if *height == open_height => {
            Claim::OpenBlock {
                expected: Some(miner_tip().to_hex()),
            }
        }
        StoreQuery::BlockAtHeight { at: None, height } if height + 1 == open_height => {
            // the open trie rewrites its parent's entry with the parent's real id
            Claim::OpenBlock {
                expected: Some(parent.to_hex()),
            }
        }
        StoreQuery::BlockAtHeight {
            at: Some(at),
            height,
        } if Some(*height) == at_height(at) => Claim::OpenBlock {
            expected: Some(at.to_hex()),
        },
        StoreQuery::BlockAtHeight { at, height } => Claim::Key {
            block: root_of(at),
            path: TrieHash::from_key(&height_to_hash_key(*height)),
            value: block_answer(answer)?,
        },
        StoreQuery::CurrentHeight { at } => Claim::Key {
            block: at.clone(),
            path: TrieHash::from_key(OWN_BLOCK_HEIGHT_KEY),
            value: answer
                .as_ref()
                .map(|h| h.parse::<u32>().map(MARFValue::from))
                .transpose()
                .map_err(|_| "height is not a number".to_string())?,
        },
        StoreQuery::AtBlock { target } if target == parent => Claim::OpenBlock {
            expected: Some("ok".into()),
        },
        StoreQuery::AtBlock { target } => Claim::Ancestor {
            target: target.clone(),
            is: answer.is_some(),
        },
        StoreQuery::Metadata { .. } => Claim::Metadata,
    })
}

// ---------------------------------------------------------------------------
// What each environment lookup is proven by
// ---------------------------------------------------------------------------

/// The evidence an environment lookup is checked against (`NOTES.md`,
/// "Environment lookups").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvClass {
    /// (a) The header of the block it names.
    Header,
    /// (b) The consensus-hash preimage of a named block or sortition, and
    /// that Bitcoin block's header.
    Burn,
    /// (b) Through the burn view of the block (or deploy) being evaluated:
    /// its tenure change, that consensus hash's preimage, Bitcoin headers.
    BurnView,
    /// Walks of `_stx-data::tenure_height` (and block-at-height) in the
    /// shared MARF proof.
    TenureHeight,
    /// Network constants.
    Constant,
    /// (c)/(d): needs evidence outside headers, preimages and the MARF.
    Unprovable,
}

impl EnvClass {
    pub fn of(query: &EnvQuery) -> Self {
        use EnvQuery::*;
        match query {
            StacksBlockHeaderHash { .. }
            | ConsensusHashForBlock { .. }
            | StacksBlockTime { .. }
            | VrfSeed { .. } => EnvClass::Header,
            BurnHeaderHashForBlock { .. }
            | BurnBlockHeightForBlock { .. }
            | BurnBlockTime { .. }
            | BurnBlockHeight { .. }
            | SortitionIdFromConsensusHash { .. } => EnvClass::Burn,
            TipBurnBlockHeight | TipSortitionId | BurnHeaderHash { .. } => EnvClass::BurnView,
            StacksHeightForTenureHeight { .. } => EnvClass::TenureHeight,
            StacksEpoch { .. }
            | StacksEpochById { .. }
            | BurnStartHeight
            | V1UnlockHeight
            | V2UnlockHeight
            | V3UnlockHeight
            | Pox3ActivationHeight
            | Pox4ActivationHeight
            | Pox5ActivationHeight
            | PoxPrepareLength
            | PoxRewardCycleLength
            | PoxRejectionFraction => EnvClass::Constant,
            MinerAddress { .. }
            | TokensSpent { .. }
            | TokensSpentWinning { .. }
            | TokensEarned { .. }
            | PoxPayoutAddrs { .. } => EnvClass::Unprovable,
        }
    }

    /// How a client report names the class.
    pub fn label(self) -> &'static str {
        match self {
            EnvClass::Header => "env (a) header",
            EnvClass::Burn | EnvClass::BurnView => "env (b) burn",
            EnvClass::TenureHeight => "env tenure height",
            EnvClass::Constant => "env constant",
            EnvClass::Unprovable => "env (c/d) unprovable",
        }
    }

    /// The same, for a lookup a contract's deploy made.
    pub fn deploy_label(self) -> &'static str {
        match self {
            EnvClass::Header => "deploy env (a) header",
            EnvClass::Burn | EnvClass::BurnView => "deploy env (b) burn",
            EnvClass::TenureHeight => "deploy env tenure height",
            EnvClass::Constant => "deploy env constant",
            EnvClass::Unprovable => "deploy env (c/d) unprovable",
        }
    }
}

/// The MARF facts that pin `stacks_height_for_tenure_height(tip, th) = s`:
/// the block `b` at height `s` on `tip`'s fork has tenure height `th`, and
/// its parent `th - 1`. Tenure height is the coinbase height, which every
/// tenure-start block sets to its parent's plus one and every other block
/// keeps, so `b` is the first block of tenure `th`: the block the headers DB
/// maps `th` to (`nakamoto::tenures::ongoing_tenure_coinbase_height`).
/// `walk(block, path)` returns the value hash the walk ends at.
fn tenure_start_facts(
    tip: &StacksBlockId,
    tip_height: u32,
    tenure_height: u32,
    answer: Option<u32>,
    mut walk: impl FnMut(&StacksBlockId, &TrieHash) -> Result<Option<MARFValue>, String>,
) -> Result<(), String> {
    let s = answer.ok_or("no such tenure on the fork: not provable yet")?;
    if s == 0 || tenure_height == 0 {
        return Err("genesis starts no tenure".into());
    }
    if s > tip_height {
        return Err(format!("height {s} is above the tip's {tip_height}"));
    }
    let block = if s == tip_height {
        tip.clone()
    } else {
        walk(tip, &TrieHash::from_key(&height_to_hash_key(s)))?
            .map(StacksBlockId::from)
            .ok_or_else(|| format!("no block at height {s}"))?
    };
    let tenure_key = TrieHash::from_key(TENURE_HEIGHT_KEY);
    let has = |v: Option<MARFValue>, th: u32| v == Some(MARFValue::from_value(&th.serialize()));
    if !has(walk(&block, &tenure_key)?, tenure_height) {
        return Err(format!(
            "block at height {s} is not in tenure {tenure_height}"
        ));
    }
    // the child trie rewrites its parent's entry with the parent's real id
    let parent = walk(&block, &TrieHash::from_key(&height_to_hash_key(s - 1)))?
        .map(StacksBlockId::from)
        .ok_or("tenure-start block has no parent entry")?;
    if !has(walk(&parent, &tenure_key)?, tenure_height - 1) {
        return Err(format!(
            "block at height {s} does not start tenure {tenure_height} \
             (its parent is not in tenure {}, or predates epoch 3.0)",
            tenure_height - 1
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// A deploy whose re-derivation keeps asking for more chain state than this
/// many rounds of reads is not served.
const MAX_DEPLOY_READ_ROUNDS: usize = 256;

/// How deep contract dependencies (each re-derived first, possibly with its
/// own deploy witness) may nest.
pub const MAX_DEPENDENCY_DEPTH: usize = 16;

/// The value a MARF leaf hashes (leaves hold value hashes; values live in the
/// side table).
fn side_value(conn: &TrieStorageConnection<StacksBlockId>, value: &MARFValue) -> Option<String> {
    SqliteConnection::get(conn.sqlite_conn(), &value.to_hex())
        .ok()
        .flatten()
}

/// Walk `path` at `block` into the shared proof.
fn walk(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    block: &StacksBlockId,
    path: &TrieHash,
) -> Result<WalkEnd<StacksBlockId>, String> {
    proof
        .walk(conn, block, path)
        .map_err(|e| format!("walk at {block}: {e:?}"))
}

/// Walk `path` at `block` into the shared proof and require it to hold
/// `value` (`None`: absent).
fn prove_key(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    block: &StacksBlockId,
    path: &TrieHash,
    value: Option<&MARFValue>,
) -> Result<(), String> {
    let end = walk(conn, proof, block, path)?;
    if end.value.as_ref() != value {
        return Err(format!(
            "{block} holds {:?} at {path}, not {value:?}",
            end.value
        ));
    }
    Ok(())
}

/// Whether `target` is an ancestor of `parent`, as `parent`'s MARF records
/// it: `__MARF_BLOCK_HASH_TO_HEIGHT::target` and, if present, the block at
/// that height (`check_ancestor_block_hash`). Both walks go into the proof.
fn prove_ancestry(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    parent: &StacksBlockId,
    target: &StacksBlockId,
) -> Result<bool, String> {
    let path = TrieHash::from_key(&hash_to_height_key(target));
    let Some(height) = walk(conn, proof, parent, &path)?.value else {
        return Ok(false);
    };
    let path = TrieHash::from_key(&height_to_hash_key(u32::from(height)));
    let block = walk(conn, proof, parent, &path)?.value;
    Ok(block == Some(MARFValue::from(target.clone())))
}

/// Evidence for one store entry read at `open_height` on top of `parent` (a
/// block's own read, or a deploy's), its MARF walks added to the proof.
fn prove_store_entry(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    query: &StoreQuery,
    answer: &Option<String>,
    open_height: u32,
    parent: &StacksBlockId,
) -> Result<StoreProof, String> {
    let claim = claim_of(query, answer, open_height, parent, |at| {
        MARF::get_block_height_miner_tip(conn, at, at)
            .ok()
            .flatten()
    })?;
    Ok(match claim {
        Claim::Key { block, path, value } => {
            prove_key(conn, proof, &block, &path, value.as_ref())?;
            StoreProof::Marf
        }
        Claim::Ancestor { target, is } => {
            if prove_ancestry(conn, proof, parent, &target)? != is {
                return Err(format!("{target} is not an ancestor as answered"));
            }
            StoreProof::Ancestor
        }
        Claim::OpenBlock { .. } => StoreProof::OpenBlock,
        Claim::Metadata => StoreProof::Rederived,
    })
}

/// Evidence for every store entry of a witness recorded for the block whose
/// parent is `parent` (metadata entries are re-derived instead). MARF walks
/// go into `proof`.
pub fn prove_store_reads(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    parent: &StacksBlockId,
    witness: &ReadWitness,
) -> Result<Vec<StoreProof>, String> {
    let mut proofs = vec![];
    let started = Instant::now();
    for (i, (query, answer)) in witness.store.iter().enumerate() {
        if i > 0 && i % 1000 == 0 {
            info!(
                "Witness: walked {i} of {} store entries in {:?}",
                witness.store.len(),
                started.elapsed()
            );
        }
        proofs.push(
            prove_store_entry(conn, proof, query, answer, witness.open_height, parent)
                .map_err(|e| format!("{query:?}: {e}"))?,
        );
    }
    Ok(proofs)
}

/// Walk each `(key, value)` at `block`'s root into `proof`: a block's final
/// writes, proven against its own header.
pub fn prove_writes(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    block: &StacksBlockId,
    writes: &[(String, String)],
) -> Result<(), String> {
    for (key, value) in writes.iter() {
        prove_key(
            conn,
            proof,
            block,
            &TrieHash::from_key(key),
            Some(&MARFValue::from_value(value)),
        )
        .map_err(|e| format!("write {key}: {e}"))?;
    }
    Ok(())
}

/// Walk the MARF facts behind every tenure-height lookup in `reads` into
/// `proof` (see [`tenure_start_facts`]); other lookups need no MARF walks.
pub fn prove_env_reads(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    reads: &[EnvRead],
) -> Result<(), String> {
    for read in reads.iter() {
        let EnvQuery::StacksHeightForTenureHeight { tip, tenure_height } = &read.query else {
            continue;
        };
        let named = |e: String| format!("{}: {e}", read.query);
        let answer = *read
            .answer
            .downcast_ref::<Option<u32>>()
            .ok_or_else(|| named("answer has the wrong type".into()))?;
        let tip_height = MARF::get_block_height_miner_tip(conn, tip, tip)
            .map_err(|e| named(format!("{e:?}")))?
            .ok_or_else(|| named("tip has no height".into()))?;
        tenure_start_facts(tip, tip_height, *tenure_height, answer, |block, path| {
            Ok(walk(conn, proof, block, path)?.value)
        })
        .map_err(named)?;
    }
    Ok(())
}

/// The node side of a deploy's environment lookups.
pub trait DeployEnvSource {
    /// Run `f` with the headers DB and the burn state the deploying block
    /// `block` was processed under (its burn view, for a Nakamoto block).
    fn with_env(
        &self,
        block: &StacksBlockId,
        f: &mut dyn FnMut(&dyn HeadersDB, &dyn BurnStateDB),
    ) -> Result<(), String>;

    /// The tenure change that set `block`'s burn view: in `block`, else the
    /// latest earlier in its tenure. Errors for an epoch 2.x block.
    fn burn_view(&self, block: &StacksBlockId) -> Result<TxInclusion, String>;
}

/// The answer a deploy at `open_height` on top of `parent` gets for `query`,
/// read from the MARF. Answers are what [`claim_of`] claims, so each is
/// provable the way a block's own reads are.
fn answer_store_query(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    query: &StoreQuery,
    open_height: u32,
    parent: &StacksBlockId,
) -> Result<Option<String>, String> {
    let marf = |e: MarfError| format!("{query:?}: {e:?}");
    let value_at = |conn: &mut TrieStorageConnection<StacksBlockId>,
                    block: &StacksBlockId,
                    key: &str|
     -> Result<Option<MARFValue>, String> {
        MARF::get_by_key(conn, block, key).map_err(marf)
    };
    let side = |conn: &TrieStorageConnection<StacksBlockId>, value: Option<MARFValue>| {
        value
            .map(|v| side_value(conn, &v).ok_or_else(|| format!("{query:?}: no side-table value")))
            .transpose()
    };
    let root_of = |at: &Option<StacksBlockId>| at.clone().unwrap_or_else(|| parent.clone());
    Ok(match query {
        StoreQuery::Data { at, key } => {
            let value = value_at(conn, &root_of(at), key)?;
            side(conn, value)?
        }
        StoreQuery::Path { at, path } => {
            let value = MARF::get_by_path(conn, &root_of(at), path).map_err(marf)?;
            side(conn, value)?
        }
        StoreQuery::BlockAtHeight { at: None, height } if *height == open_height => {
            Some(miner_tip().to_hex())
        }
        StoreQuery::BlockAtHeight { at: None, height } if height + 1 == open_height => {
            Some(parent.to_hex())
        }
        StoreQuery::BlockAtHeight { at, height } => {
            let tip = root_of(at);
            let own = MARF::get_block_height_miner_tip(conn, &tip, &tip).map_err(marf)?;
            if at.is_some() && own == Some(*height) {
                Some(tip.to_hex())
            } else {
                value_at(conn, &tip, &height_to_hash_key(*height))?
                    .map(|v| StacksBlockId::from(v).to_hex())
            }
        }
        StoreQuery::CurrentHeight { at } => {
            value_at(conn, at, OWN_BLOCK_HEIGHT_KEY)?.map(|v| u32::from(v).to_string())
        }
        StoreQuery::AtBlock { target } if target == parent => Some("ok".into()),
        StoreQuery::AtBlock { target } => {
            let ancestor = match value_at(conn, parent, &hash_to_height_key(target))? {
                Some(height) => {
                    value_at(conn, parent, &height_to_hash_key(u32::from(height)))?
                        == Some(MARFValue::from(target.clone()))
                }
                None => false,
            };
            ancestor.then(|| "ok".to_string())
        }
        StoreQuery::Metadata { .. } => {
            return Err(format!(
                "{query:?}: the deploy reads metadata of a contract not re-derived"
            ))
        }
    })
}

/// A contract's commitment, deploying block, source and epoch key, read from
/// the MARF at `parent` (nothing proven yet).
fn contract_evidence(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    parent: &StacksBlockId,
    contract: &QualifiedContractIdentifier,
    find_deploy: &dyn Fn(&StacksBlockId, &QualifiedContractIdentifier) -> Option<TxInclusion>,
    mainnet: bool,
) -> Result<ContractEvidence, String> {
    let commitment_key = make_contract_hash_key(contract);
    let commitment = MARF::get_by_key(conn, parent, &commitment_key)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("not deployed")?;
    // MARF leaves hold value hashes; the value itself is in the side table
    let commitment =
        side_value(conn, &commitment).ok_or("no side-table value for its commitment")?;
    let height = ContractCommitment::deserialize(&commitment)
        .map_err(|e| format!("{e:?}"))?
        .block_height;
    let block = MARF::get_block_at_height(conn, height, parent)
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| format!("no block at height {height}"))?;
    let source = if boot_contract_source(contract, mainnet).is_some() {
        DeploySource::Boot
    } else {
        DeploySource::Tx(
            find_deploy(&block, contract)
                .ok_or_else(|| format!("deploy tx not found in {block}"))?,
        )
    };
    let epoch_key = MARF::get_by_path(conn, &block, &TrieHash::from_key(EPOCH_VERSION_KEY))
        .map_err(|e| format!("{e:?}"))?
        .map(|value| side_value(conn, &value).ok_or("no side-table value for the epoch"))
        .transpose()?;
    Ok(ContractEvidence {
        contract: contract.clone(),
        block,
        source,
        commitment,
        epoch_key,
        deploy_reads: vec![],
        deploy_proofs: vec![],
        deploy_env: vec![],
        deploy_burn_view: None,
    })
}

/// The commitment height a contract's evidence names.
fn deploy_height(evidence: &ContractEvidence) -> Result<u32, String> {
    ContractCommitment::deserialize(&evidence.commitment)
        .map(|c| c.block_height)
        .map_err(|e| format!("bad commitment: {e:?}"))
}

/// The key whose value at the deploying block, `height` high, is its
/// parent's id: the child trie rewrites the parent's height-to-hash entry
/// with the real id.
fn deploy_parent_path(height: u32) -> Result<TrieHash, String> {
    let parent_height = height
        .checked_sub(1)
        .ok_or("a genesis deploy has no parent")?;
    Ok(TrieHash::from_key(&height_to_hash_key(parent_height)))
}

/// The MARF path of a deploy read whose key someone else could have written
/// earlier in the deploying block: an open-block read of a key outside the
/// contract's own storage. (A contract's own keys cannot exist before its
/// deploy.)
fn foreign_read_path(
    contract: &QualifiedContractIdentifier,
    query: &StoreQuery,
) -> Option<TrieHash> {
    match query {
        StoreQuery::Data { at: None, key } => {
            (!key.starts_with(&format!("vm::{contract}::"))).then(|| TrieHash::from_key(key))
        }
        StoreQuery::Path { at: None, path } => Some(*path),
        _ => None,
    }
}

/// A contract that cannot be resolved yet, or at all.
enum Resolve {
    /// Its analysis needs these contracts first.
    Needs(Vec<QualifiedContractIdentifier>),
    /// It cannot be re-derived, and why.
    Fails(String),
}

/// A commitment read of another contract: re-derivation needs it first.
fn dependency_of(
    query: &StoreQuery,
    contract: &QualifiedContractIdentifier,
) -> Option<QualifiedContractIdentifier> {
    let StoreQuery::Data { at: None, key } = query else {
        return None;
    };
    let id = QualifiedContractIdentifier::parse(key.strip_prefix("clarity-contract::")?).ok()?;
    (&id != contract).then_some(id)
}

/// Gather `contract`'s evidence and re-derive it given `known` contracts,
/// answering the chain state its deploy reads from the MARF at the deploying
/// block's parent (the deploy witness).
fn resolve_contract(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    parent: &StacksBlockId,
    contract: &QualifiedContractIdentifier,
    net: &NetworkParams,
    find_deploy: &dyn Fn(&StacksBlockId, &QualifiedContractIdentifier) -> Option<TxInclusion>,
    env_source: Option<&dyn DeployEnvSource>,
    known: &HashMap<QualifiedContractIdentifier, (Sha512Trunc256Sum, ContractMetadata)>,
) -> Result<(ContractEvidence, Sha512Trunc256Sum, ContractMetadata), Resolve> {
    let mut evidence = contract_evidence(conn, parent, contract, find_deploy, net.mainnet)
        .map_err(Resolve::Fails)?;
    let height = deploy_height(&evidence).map_err(Resolve::Fails)?;
    let mut deploy_parent = None;
    for _ in 0..MAX_DEPLOY_READ_ROUNDS {
        let (store, env) = match rederive_recording(&evidence, net, known, env_source) {
            Ok((hash, rows, lookups)) => {
                settle_deploy_env(&mut evidence, lookups, env_source).map_err(Resolve::Fails)?;
                return Ok((evidence, hash, rows));
            }
            Err(Rederive::Invalid(e)) => return Err(Resolve::Fails(e)),
            Err(Rederive::Missing { store, env }) => (store, env),
        };
        if !env.is_empty() {
            return Err(Resolve::Fails(format!(
                "its deploy makes lookups no node answered: {env:?}"
            )));
        }
        let deps: Vec<_> = store
            .iter()
            .filter_map(|q| dependency_of(q, contract))
            .collect();
        if !deps.is_empty() {
            return Err(Resolve::Needs(deps));
        }
        let deploy_parent = match &deploy_parent {
            Some(p) => p,
            None => {
                let path = deploy_parent_path(height).map_err(Resolve::Fails)?;
                let id = MARF::get_by_path(conn, &evidence.block, &path)
                    .map_err(|e| Resolve::Fails(format!("deploy block's parent: {e:?}")))?
                    .ok_or_else(|| Resolve::Fails("deploy block has no parent entry".into()))?;
                deploy_parent.insert(StacksBlockId::from(id))
            }
        };
        for query in store {
            if evidence.deploy_reads.iter().any(|(q, _)| q == &query) {
                return Err(Resolve::Fails(format!(
                    "its deploy asks for {query:?} again"
                )));
            }
            let answer =
                answer_store_query(conn, &query, height, deploy_parent).map_err(Resolve::Fails)?;
            evidence.deploy_reads.push((query, answer));
        }
    }
    Err(Resolve::Fails(format!(
        "its deploy reads chain state in more than {MAX_DEPLOY_READ_ROUNDS} rounds"
    )))
}

/// Re-derive `evidence`'s contract (the prover: no proofs checked), answering
/// its environment lookups from `env_source` and recording them. Without a
/// source, any lookup is missing.
fn rederive_recording(
    evidence: &ContractEvidence,
    net: &NetworkParams,
    known: &HashMap<QualifiedContractIdentifier, (Sha512Trunc256Sum, ContractMetadata)>,
    env_source: Option<&dyn DeployEnvSource>,
) -> Result<(Sha512Trunc256Sum, ContractMetadata, Vec<EnvRead>), Rederive> {
    let deploy = Deploy::of(evidence, net)?;
    let Some(source) = env_source else {
        let env = EnvTap::from_witness(&[]);
        return deploy
            .derive(evidence, net, known, &env)
            .map(|(hash, rows)| (hash, rows, vec![]));
    };
    let epoch = net
        .epoch(&deploy.epoch)
        .cloned()
        .ok_or_else(|| Rederive::Invalid(format!("no epoch {}", deploy.epoch)))?;
    let mut result = None;
    source
        .with_env(&evidence.block, &mut |headers, burn| {
            let env = EnvTap::recording(headers, burn, epoch.clone());
            let derived = deploy.derive(evidence, net, known, &env);
            let lookups = env
                .take_recorded()
                .map(|(_, reads)| reads)
                .unwrap_or_default();
            result = Some(derived.map(|(hash, rows)| (hash, rows, lookups)));
        })
        .map_err(|e| Rederive::Invalid(format!("deploy lookups: {e}")))?;
    result.unwrap_or_else(|| Err(Rederive::Invalid("deploy lookups were not answered".into())))
}

/// Keep a re-derived deploy's lookups as its evidence, refusing those not
/// provable yet and adding the burn-view proof when a lookup reads it.
fn settle_deploy_env(
    evidence: &mut ContractEvidence,
    lookups: Vec<EnvRead>,
    env_source: Option<&dyn DeployEnvSource>,
) -> Result<(), String> {
    let unprovable: Vec<String> = lookups
        .iter()
        .filter(|r| EnvClass::of(&r.query) == EnvClass::Unprovable)
        .map(|r| r.query.to_string())
        .collect();
    if !unprovable.is_empty() {
        return Err(format!(
            "its deploy reads chain state not provable yet: {unprovable:?}"
        ));
    }
    let reads_view = lookups
        .iter()
        .any(|r| EnvClass::of(&r.query) == EnvClass::BurnView);
    evidence.deploy_burn_view = match (reads_view, env_source) {
        (true, Some(source)) => Some(
            source
                .burn_view(&evidence.block)
                .map_err(|e| format!("its deploy reads the burn view, not provable: {e}"))?,
        ),
        _ => None,
    };
    evidence.deploy_env = lookups;
    Ok(())
}

/// Walk every MARF fact `evidence` stands on into `proof`: commitment and
/// epoch key at the deploying block, its ancestry at `parent`, and for a
/// deploy witness, the deploying block's parent and each deploy read (plus,
/// for reads of keys outside the contract, the same key at the deploying
/// block, so the client can tell whether that block also wrote it).
fn prove_contract_facts(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    parent: &StacksBlockId,
    evidence: &mut ContractEvidence,
) -> Result<(), String> {
    let block = evidence.block.clone();
    let commitment_path = TrieHash::from_key(&make_contract_hash_key(&evidence.contract));
    let commitment = MARFValue::from_value(&evidence.commitment);
    prove_key(conn, proof, &block, &commitment_path, Some(&commitment))?;
    let epoch = evidence.epoch_key.as_deref().map(MARFValue::from_value);
    prove_key(
        conn,
        proof,
        &block,
        &TrieHash::from_key(EPOCH_VERSION_KEY),
        epoch.as_ref(),
    )?;
    if &block != parent && !prove_ancestry(conn, proof, parent, &block)? {
        return Err("deploy block is not an ancestor".into());
    }
    evidence.deploy_proofs.clear();
    prove_env_reads(conn, proof, &evidence.deploy_env)?;
    if evidence.deploy_reads.is_empty() {
        return Ok(());
    }
    let height = deploy_height(evidence)?;
    let deploy_parent = walk(conn, proof, &block, &deploy_parent_path(height)?)?
        .value
        .map(StacksBlockId::from)
        .ok_or("deploy block has no parent entry")?;
    for (query, answer) in evidence.deploy_reads.iter() {
        let proven = prove_store_entry(conn, proof, query, answer, height, &deploy_parent)
            .map_err(|e| format!("deploy read {query:?}: {e}"))?;
        if let Some(path) = foreign_read_path(&evidence.contract, query) {
            walk(conn, proof, &block, &path)?;
        }
        evidence.deploy_proofs.push(proven);
    }
    Ok(())
}

/// Contracts whose metadata `witness` read.
pub fn metadata_contracts(witness: &ReadWitness) -> Vec<QualifiedContractIdentifier> {
    let mut seen = HashSet::new();
    witness
        .store
        .iter()
        .filter_map(|(query, _)| match query {
            StoreQuery::Metadata { contract, .. } => Some(contract.clone()),
            _ => None,
        })
        .filter(|c| seen.insert(c.clone()))
        .filter_map(|c| QualifiedContractIdentifier::parse(&c).ok())
        .collect()
}

/// Contracts that cannot be re-derived, and why.
pub type UnprovenContracts = Vec<(QualifiedContractIdentifier, String)>;

/// Contract evidence for every contract whose metadata `witness` read, plus
/// whatever their analysis depends on, ordered so each contract's
/// dependencies come first. Dependencies are found by re-deriving (at most
/// [`MAX_DEPENDENCY_DEPTH`] deep). A contract whose deploy reads chain state
/// carries a deploy witness: those reads, answered at its deploying block's
/// parent, and its environment lookups, answered by `env_source` (without
/// one, a deploy that makes lookups is not re-derivable). Contracts that
/// cannot be re-derived come back separately, with the reason (their
/// metadata can only be served as is). Only the evidence that is served has
/// its MARF facts walked into `proof`.
pub fn prove_contracts(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    proof: &mut MultiproofBuilder<StacksBlockId>,
    parent: &StacksBlockId,
    witness: &ReadWitness,
    net: &NetworkParams,
    find_deploy: &dyn Fn(&StacksBlockId, &QualifiedContractIdentifier) -> Option<TxInclusion>,
    env_source: Option<&dyn DeployEnvSource>,
) -> Result<(Vec<ContractEvidence>, UnprovenContracts), String> {
    let mut ordered: Vec<ContractEvidence> = vec![];
    // contracts still to resolve, with how deep a dependency each is
    let mut pending: Vec<(QualifiedContractIdentifier, usize)> = metadata_contracts(witness)
        .into_iter()
        .map(|c| (c, 0))
        .collect();
    let mut derived = HashMap::new();
    let mut failed: BTreeMap<QualifiedContractIdentifier, String> = BTreeMap::new();
    let mut attempts = 0;
    while let Some((contract, depth)) = pending.last().cloned() {
        attempts += 1;
        if attempts > 1000 {
            return Err("contract dependencies do not resolve".into());
        }
        if derived.contains_key(&contract) || failed.contains_key(&contract) {
            pending.pop();
            continue;
        }
        match resolve_contract(
            conn,
            parent,
            &contract,
            net,
            find_deploy,
            env_source,
            &derived,
        ) {
            Ok((evidence, hash, rows)) => {
                derived.insert(contract, (hash, rows));
                ordered.push(evidence);
            }
            Err(Resolve::Needs(deps)) => {
                if let Some(dep) = deps.iter().find(|d| failed.contains_key(d)) {
                    failed.insert(
                        contract,
                        format!("depends on {dep}, which is not re-derivable"),
                    );
                } else if depth >= MAX_DEPENDENCY_DEPTH {
                    failed.insert(
                        contract,
                        format!("its dependencies nest deeper than {MAX_DEPENDENCY_DEPTH}"),
                    );
                } else {
                    pending.extend(deps.into_iter().map(|d| (d, depth + 1)));
                    continue;
                }
            }
            Err(Resolve::Fails(reason)) => {
                failed.insert(contract, reason);
            }
        }
        pending.pop();
    }
    for evidence in ordered.iter_mut() {
        prove_contract_facts(conn, proof, parent, evidence)
            .map_err(|e| format!("{}: {e}", evidence.contract))?;
    }
    Ok((ordered, failed.into_iter().collect()))
}

/// Mark the metadata entries of contracts without evidence as served as is.
pub fn mark_served_metadata(proven: &mut ProvenWitness) {
    let derivable: HashSet<String> = proven
        .contracts
        .iter()
        .map(|c| c.contract.to_string())
        .collect();
    for ((query, _), proof) in proven.witness.store.iter().zip(proven.store.iter_mut()) {
        if let StoreQuery::Metadata { contract, .. } = query {
            if !derivable.contains(contract) {
                *proof = StoreProof::Served;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Contract metadata re-derivation
// ---------------------------------------------------------------------------

/// The client's bundled source for a boot contract, and the Clarity version
/// its epoch transition pins (`None`: the epoch default). Mirrors
/// `StacksChainState::instantiate_boot_code` and the
/// `ClarityBlockConnection::initialize_epoch_*` transitions. `sip-031` and
/// `pox-5` bodies are generated per network (on testnet from node config, so
/// a testnet client must match the node's settings).
pub fn boot_contract_source(
    contract: &QualifiedContractIdentifier,
    mainnet: bool,
) -> Option<(String, Option<ClarityVersion>)> {
    if contract.issuer != boot_code_addr(mainnet).into() {
        return None;
    }
    let pick = |main: &str, test: &str| if mainnet { main } else { test }.to_string();
    let v2 = Some(ClarityVersion::Clarity2);
    let name = contract.name.as_str();
    Some(match name {
        "pox" => (pick(&BOOT_CODE_POX_MAINNET, &BOOT_CODE_POX_TESTNET), None),
        "lockup" => (BOOT_CODE_LOCKUP.into(), None),
        COSTS_1_NAME => (BOOT_CODE_COSTS.into(), None),
        "cost-voting" => (
            pick(
                BOOT_CODE_COST_VOTING_MAINNET,
                &BOOT_CODE_COST_VOTING_TESTNET,
            ),
            None,
        ),
        "bns" => (BOOT_CODE_BNS.into(), None),
        "genesis" => (BOOT_CODE_GENESIS.into(), None),
        COSTS_2_NAME => (pick(BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET), None),
        POX_2_NAME => (pick(&POX_2_MAINNET_CODE, &POX_2_TESTNET_CODE), v2),
        COSTS_3_NAME => (BOOT_CODE_COSTS_3.into(), None),
        POX_3_NAME => (pick(&POX_3_MAINNET_CODE, &POX_3_TESTNET_CODE), v2),
        POX_4_NAME => (POX_4_CODE.to_string(), v2),
        SIGNERS_NAME => (SIGNERS_BODY.into(), v2),
        SIGNERS_VOTING_NAME => (SIGNERS_VOTING_BODY.into(), v2),
        SIP_031_NAME => (make_sip_031_body(mainnet), Some(ClarityVersion::Clarity3)),
        COSTS_4_NAME => (BOOT_CODE_COSTS_4.into(), None),
        POX_5_NAME => (make_pox_5_body(mainnet), Some(ClarityVersion::Clarity6)),
        _ => (signers_db_body(name)?.into(), v2),
    })
}

/// `signers-<0|1>-<message id>`: the signer StackerDB contracts epoch 2.5
/// deploys (`NakamotoSigners::make_signers_db_name`).
fn signers_db_body(name: &str) -> Option<&'static str> {
    let rest = name.strip_prefix(SIGNERS_NAME)?.strip_prefix('-')?;
    let (set, message_id) = rest.split_once('-')?;
    let message_id: u32 = message_id.parse().ok()?;
    if message_id >= SIGNER_SLOTS_PER_USER || message_id.to_string() != rest[2..] {
        return None;
    }
    match set {
        "0" => Some(SIGNERS_DB_0_BODY),
        "1" => Some(SIGNERS_DB_1_BODY),
        _ => None,
    }
}

/// The synthetic transaction a boot contract is deployed with.
fn boot_deploy_tx(
    contract: &QualifiedContractIdentifier,
    net: &NetworkParams,
) -> Option<StacksTransaction> {
    let (code, clarity_version) = boot_contract_source(contract, net.mainnet)?;
    let version = if net.mainnet {
        TransactionVersion::Mainnet
    } else {
        TransactionVersion::Testnet
    };
    let payload = TransactionPayload::SmartContract(
        TransactionSmartContract {
            name: ContractName::try_from(contract.name.to_string()).ok()?,
            code_body: StacksString::from_str(&code)?,
        },
        clarity_version,
    );
    Some(StacksTransaction::new(
        version,
        boot_code_tx_auth(boot_code_addr(net.mainnet)),
        payload,
    ))
}

enum Rederive {
    /// Re-derivation asked for chain state the deploy witness does not hold
    /// (store reads), or lookups not provable in a deploy yet (environment).
    Missing {
        store: Vec<StoreQuery>,
        env: Vec<String>,
    },
    Invalid(String),
}

/// A shared MARF proof a client opened against its headers, or why it could
/// not be opened.
pub struct OpenedProof {
    proof: Result<Multiproof<StacksBlockId>, String>,
}

impl OpenedProof {
    pub fn open(bytes: &[u8], headers: &HeaderChain) -> Self {
        OpenedProof {
            proof: headers.open_proof(bytes),
        }
    }

    /// Where `path`'s walk from `block`'s root ends.
    pub fn get(
        &self,
        block: &StacksBlockId,
        path: &TrieHash,
    ) -> Result<WalkEnd<StacksBlockId>, String> {
        match &self.proof {
            Ok(proof) => proof.get(block, path),
            Err(e) => Err(format!("the shared proof does not decode: {e}")),
        }
    }

    /// `path` holds `value` (`None`: absent) at `block`'s root.
    pub fn holds(
        &self,
        block: &StacksBlockId,
        path: &TrieHash,
        value: Option<&MARFValue>,
    ) -> Result<(), String> {
        let end = self
            .get(block, path)
            .map_err(|e| format!("MARF proof fails: {e}"))?;
        if end.value.as_ref() == value {
            Ok(())
        } else {
            Err("MARF proof fails".into())
        }
    }

    /// Why the proof is not exact: it did not decode, or it carries nodes no
    /// walk so far reached (extra nodes).
    pub fn strictness(&self) -> Option<String> {
        match &self.proof {
            Err(e) => Some(format!("does not decode: {e}")),
            Ok(proof) if proof.unvisited() > 0 => Some(format!(
                "{} of its {} nodes are reached by no entry",
                proof.unvisited(),
                proof.nodes()
            )),
            Ok(_) => None,
        }
    }

    /// `(tries, nodes, bytes)`.
    pub fn stats(&self) -> Option<(usize, usize, usize)> {
        self.proof
            .as_ref()
            .ok()
            .map(|p| (p.tries(), p.nodes(), p.byte_len()))
    }
}

/// Deploy reads, by whether the deploying block also wrote the key read.
/// Each is proven at the deploying block's parent, which is the value the
/// deploy saw unless something earlier in that same block wrote the key. A
/// key the block never wrote is settled; for one it also wrote, the client
/// cannot tell from roots alone whether that write came before the deploy
/// (e.g. `_stx-data::ustx_liquid_supply`, which every block's teardown
/// rewrites after its transactions).
pub const DEPLOY_READ_SETTLED: &str = "deploy read (key not written in its block)";
pub const DEPLOY_READ_ORDER_ASSUMED: &str = "deploy read (block also wrote key; assumed after)";

/// Check one contract's evidence (deploy block an ancestor of `parent`,
/// commitment, epoch, source, deploy witness) and re-derive its metadata.
/// `ctx` checks the deploy's lookups (its burn view is the deploy's own).
fn rederive(
    evidence: &ContractEvidence,
    parent: &StacksBlockId,
    ctx: &EnvContext,
    known: &HashMap<QualifiedContractIdentifier, (Sha512Trunc256Sum, ContractMetadata)>,
    kinds: &mut BTreeMap<&'static str, usize>,
) -> Result<(Sha512Trunc256Sum, ContractMetadata), Rederive> {
    let (headers, marf, net) = (ctx.headers, ctx.marf, ctx.net);
    let invalid = |s: String| Rederive::Invalid(s);
    let header = headers
        .get(&evidence.block)
        .ok_or_else(|| invalid(format!("unknown deploy block {}", evidence.block)))?;
    if &evidence.block != parent && !ancestry_of(marf, &evidence.block, parent).map_err(invalid)? {
        return Err(invalid("deploy block is not an ancestor".into()));
    }

    // the commitment pins the source hash and the deploy height
    let commitment_key = make_contract_hash_key(&evidence.contract);
    marf.holds(
        &evidence.block,
        &TrieHash::from_key(&commitment_key),
        Some(&MARFValue::from_value(&evidence.commitment)),
    )
    .map_err(|e| invalid(format!("commitment: {e}")))?;
    // the epoch the deploy ran in
    marf.holds(
        &evidence.block,
        &TrieHash::from_key(EPOCH_VERSION_KEY),
        evidence
            .epoch_key
            .as_deref()
            .map(MARFValue::from_value)
            .as_ref(),
    )
    .map_err(|e| invalid(format!("epoch key: {e}")))?;
    if let DeploySource::Tx(inclusion) = &evidence.source {
        if !inclusion.holds(headers) {
            return Err(invalid("deploy tx is not in the deploy block".into()));
        }
    }
    let deploy = Deploy::of(evidence, net)?;
    if deploy.commitment.block_height != header.height {
        return Err(invalid(format!(
            "commitment height {} is not the deploy block's {}",
            deploy.commitment.block_height, header.height
        )));
    }
    verify_deploy_reads(evidence, header, headers, marf, kinds)?;
    verify_deploy_env(evidence, header, ctx, kinds)?;
    let env = EnvTap::from_witness(&evidence.deploy_env);
    deploy.derive(evidence, net, known, &env)
}

/// Check every lookup a contract's deploy made, as a block's own lookups are
/// checked, with the deploying block's burn view (from its tenure change).
fn verify_deploy_env(
    evidence: &ContractEvidence,
    header: &ChainHeader,
    ctx: &EnvContext,
    kinds: &mut BTreeMap<&'static str, usize>,
) -> Result<(), Rederive> {
    let invalid = |s: String| Rederive::Invalid(s);
    let view = match &evidence.deploy_burn_view {
        None => None,
        Some(inclusion) => {
            if !header.is_nakamoto() {
                return Err(invalid(
                    "an epoch 2.x deploy has no tenure-change burn view".into(),
                ));
            }
            let ch = tenure_change_view(header, inclusion, ctx.headers)
                .map_err(|e| invalid(format!("deploy burn view: {e}")))?;
            let (binding, btc) = ctx
                .burn
                .block_of(&ch)
                .map_err(|e| invalid(format!("deploy burn view: {e}")))?;
            Some((binding.sortition_id(), btc.height))
        }
    };
    let ctx = EnvContext {
        view,
        ..ctx.clone()
    };
    for read in evidence.deploy_env.iter() {
        verify_env(read, &ctx).map_err(|e| invalid(format!("deploy lookup {read:?}: {e}")))?;
        *kinds
            .entry(EnvClass::of(&read.query).deploy_label())
            .or_default() += 1;
    }
    Ok(())
}

/// Check a contract's deploy witness: the deploying block's parent (its own
/// trie names it), then every read as a block's own reads are checked, at
/// that parent's root.
fn verify_deploy_reads(
    evidence: &ContractEvidence,
    header: &ChainHeader,
    headers: &HeaderChain,
    marf: &OpenedProof,
    kinds: &mut BTreeMap<&'static str, usize>,
) -> Result<(), Rederive> {
    let invalid = |s: String| Rederive::Invalid(s);
    if evidence.deploy_proofs.len() != evidence.deploy_reads.len() {
        return Err(invalid("one proof per deploy read".into()));
    }
    if evidence.deploy_reads.is_empty() {
        return Ok(());
    }
    let path = deploy_parent_path(header.height).map_err(invalid)?;
    let deploy_parent = marf
        .get(&evidence.block, &path)
        .map_err(|e| invalid(format!("deploy block's parent: MARF proof fails: {e}")))?
        .value
        .map(StacksBlockId::from)
        .ok_or_else(|| invalid("deploy block has no parent entry".into()))?;
    if header.is_nakamoto() && header.parent != deploy_parent {
        return Err(invalid(format!(
            "deploy block's trie names parent {deploy_parent}, its header {}",
            header.parent
        )));
    }
    let (mut settled, mut assumed) = (0, 0);
    for ((query, answer), proof) in evidence
        .deploy_reads
        .iter()
        .zip(evidence.deploy_proofs.iter())
    {
        let named = |e: String| invalid(format!("deploy read {query:?}: {e}"));
        if matches!(query, StoreQuery::Metadata { .. })
            || matches!(proof, StoreProof::Rederived | StoreProof::Served)
        {
            return Err(named("not a chain-state read".into()));
        }
        verify_store_entry(
            query,
            answer,
            proof,
            header.height,
            &deploy_parent,
            headers,
            marf,
        )
        .map_err(named)?;
        let also_written = match foreign_read_path(&evidence.contract, query) {
            Some(path) => {
                let end = marf
                    .get(&evidence.block, &path)
                    .map_err(|e| named(format!("at the deploy block: MARF proof fails: {e}")))?;
                end.value.is_some() && end.trie == evidence.block
            }
            None => false,
        };
        if also_written {
            assumed += 1;
        } else {
            settled += 1;
        }
    }
    *kinds.entry(DEPLOY_READ_SETTLED).or_default() += settled;
    *kinds.entry(DEPLOY_READ_ORDER_ASSUMED).or_default() += assumed;
    Ok(())
}

/// The deploy a contract's evidence describes.
struct Deploy {
    tx: StacksTransaction,
    commitment: ContractCommitment,
    epoch: StacksEpochId,
}

impl Deploy {
    /// Parse the evidence and require the source to hash to the commitment.
    fn of(evidence: &ContractEvidence, net: &NetworkParams) -> Result<Self, Rederive> {
        let invalid = |s: String| Rederive::Invalid(s);
        let commitment = ContractCommitment::deserialize(&evidence.commitment)
            .map_err(|e| invalid(format!("bad commitment: {e:?}")))?;
        let epoch = match evidence.epoch_key.as_deref() {
            None => StacksEpochId::Epoch20,
            Some(v) => {
                let id = u32::deserialize(v).map_err(|e| invalid(format!("bad epoch: {e:?}")))?;
                StacksEpochId::try_from(id).map_err(|_| invalid(format!("bad epoch {id}")))?
            }
        };
        let tx = match &evidence.source {
            DeploySource::Tx(inclusion) => {
                if inclusion.block != evidence.block {
                    return Err(invalid("deploy tx is not in the deploy block".into()));
                }
                inclusion.tx.clone()
            }
            DeploySource::Boot => boot_deploy_tx(&evidence.contract, net)
                .ok_or_else(|| invalid("no bundled source for this boot contract".into()))?,
        };
        let TransactionPayload::SmartContract(ref payload, _) = tx.payload else {
            return Err(invalid("deploy tx is not a contract deploy".into()));
        };
        let hash = Sha512Trunc256Sum::from_data(payload.code_body.to_string().as_bytes());
        if hash != commitment.hash {
            return Err(invalid("source does not hash to the commitment".into()));
        }
        Ok(Deploy {
            tx,
            commitment,
            epoch,
        })
    }

    fn derive(
        &self,
        evidence: &ContractEvidence,
        net: &NetworkParams,
        known: &HashMap<QualifiedContractIdentifier, (Sha512Trunc256Sum, ContractMetadata)>,
        env: &EnvTap,
    ) -> Result<(Sha512Trunc256Sum, ContractMetadata), Rederive> {
        let deploy = ContractDeployment {
            tx: &self.tx,
            height: self.commitment.block_height,
            epoch: self.epoch,
            epoch_key: evidence.epoch_key.clone(),
            reads: &evidence.deploy_reads,
            env,
        };
        match derive_contract_metadata(&deploy, known, net.mainnet, net.chain_id) {
            Ok((id, rows)) if id == evidence.contract => Ok((self.commitment.hash.clone(), rows)),
            Ok((id, _)) => Err(Rederive::Invalid(format!("deploy tx deploys {id}"))),
            Err(DeriveError::Missing { store, env }) => Err(Rederive::Missing { store, env }),
            Err(DeriveError::Failed(e)) => Err(Rederive::Invalid(format!("deploy failed: {e:?}"))),
        }
    }
}

/// Field names of `ContractContext` that serialize from hash sets (their
/// array order is arbitrary).
const UNORDERED_FIELDS: [&str; 2] = ["implemented_traits", "persisted_names"];

fn canonical_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                canonical_json(v);
                if UNORDERED_FIELDS.contains(&key.as_str()) {
                    if let serde_json::Value::Array(items) = v {
                        items.sort_by_key(|item| item.to_string());
                    }
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(canonical_json),
        _ => {}
    }
}

/// Metadata values are equal, up to the order of maps and sets (contract
/// contexts serialize hash maps).
fn same_metadata(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (
        serde_json::from_str::<serde_json::Value>(a),
        serde_json::from_str::<serde_json::Value>(b),
    ) {
        (Ok(mut a), Ok(mut b)) => {
            canonical_json(&mut a);
            canonical_json(&mut b);
            a == b
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// The first witness entry that failed, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    pub entry: String,
    pub reason: String,
}

fn reject(entry: impl fmt::Debug, reason: impl Into<String>) -> Rejection {
    Rejection {
        entry: format!("{entry:?}"),
        reason: reason.into(),
    }
}

/// Burn facts derived from bindings and the Bitcoin chain.
struct BurnFacts<'a> {
    by_ch: HashMap<ConsensusHash, &'a BurnBinding>,
    by_sortition: HashMap<SortitionId, &'a BurnBinding>,
    bitcoin: &'a BitcoinChain,
}

impl<'a> BurnFacts<'a> {
    fn new(bindings: &'a [BurnBinding], bitcoin: &'a BitcoinChain) -> Self {
        let mut by_ch = HashMap::new();
        let mut by_sortition = HashMap::new();
        for binding in bindings {
            by_ch.insert(binding.consensus_hash(), binding);
            by_sortition.insert(binding.sortition_id(), binding);
        }
        BurnFacts {
            by_ch,
            by_sortition,
            bitcoin,
        }
    }

    /// The Bitcoin block a consensus hash commits to.
    fn block_of(&self, ch: &ConsensusHash) -> Result<(&'a BurnBinding, &'a BitcoinHeader), String> {
        let binding = self
            .by_ch
            .get(ch)
            .ok_or_else(|| format!("no preimage for consensus hash {ch}"))?;
        let header = self
            .bitcoin
            .find(&binding.burn_header_hash)
            .ok_or_else(|| format!("{} is not on the Bitcoin chain", binding.burn_header_hash))?;
        Ok((binding, header))
    }

    fn height_of_sortition(&self, sortition: &SortitionId) -> Result<u32, String> {
        let binding = self
            .by_sortition
            .get(sortition)
            .ok_or_else(|| format!("no preimage for sortition {sortition}"))?;
        Ok(self.block_of(&binding.consensus_hash())?.1.height)
    }
}

fn expect_answer<R: PartialEq + fmt::Debug + 'static>(
    read: &EnvRead,
    expected: R,
) -> Result<(), String> {
    match read.answer.downcast_ref::<R>() {
        Some(got) if *got == expected => Ok(()),
        Some(got) => Err(format!("answered {got:?}, proven {expected:?}")),
        None => Err("answer has the wrong type".into()),
    }
}

/// Everything [`verify_read_witness`] checks against.
pub struct TrustedState<'a> {
    pub headers: &'a HeaderChain,
    pub bitcoin: &'a BitcoinChain,
    pub net: &'a NetworkParams,
}

/// Verify every entry of `proven` for `block`, whose transactions are `txs`.
///
/// The roots come from the header chain: the parent's `state_index_root` for
/// open-block reads, each `at-block` target's for reads inside it. Returns the
/// first entry that fails.
pub fn verify_read_witness(
    block: &StacksBlockId,
    txs: &[StacksTransaction],
    trusted: &TrustedState,
    proven: &ProvenWitness,
) -> Result<(), Rejection> {
    match check_read_witness(block, txs, trusted, proven)
        .rejections
        .into_iter()
        .next()
    {
        Some(rejection) => Err(rejection),
        None => Ok(()),
    }
}

/// What [`check_read_witness`] established.
#[derive(Debug, Default)]
pub struct WitnessCheck {
    /// Every entry that failed.
    pub rejections: Vec<Rejection>,
    /// Entries checked whose kind the witness alone does not show (deploy
    /// reads, see [`DEPLOY_READ_SETTLED`]).
    pub kinds: BTreeMap<&'static str, usize>,
    /// The shared MARF proof: tries, nodes, bytes (`None`: it did not decode).
    pub marf: Option<(usize, usize, usize)>,
}

/// [`verify_read_witness`], reporting every entry that fails rather than the
/// first (a block, its parent, burn view or epoch that fails stops it).
pub fn check_read_witness(
    block: &StacksBlockId,
    txs: &[StacksTransaction],
    trusted: &TrustedState,
    proven: &ProvenWitness,
) -> WitnessCheck {
    match check_block_context(block, txs, trusted, proven) {
        Ok(check) => check,
        Err(rejection) => WitnessCheck {
            rejections: vec![rejection],
            ..Default::default()
        },
    }
}

fn check_block_context(
    block: &StacksBlockId,
    txs: &[StacksTransaction],
    trusted: &TrustedState,
    proven: &ProvenWitness,
) -> Result<WitnessCheck, Rejection> {
    let TrustedState {
        headers,
        bitcoin,
        net,
    } = trusted;
    let witness = &proven.witness;

    // the block, its transactions and its parent
    let header = headers
        .get(block)
        .ok_or_else(|| reject(block, "unknown block"))?;
    let txids: Vec<Vec<u8>> = txs.iter().map(|tx| tx.txid().as_bytes().to_vec()).collect();
    if MerkleTree::<Sha512Trunc256Sum>::new(&txids).root() != header.tx_merkle_root {
        return Err(reject(
            "txs",
            "transactions do not match the header's tx root",
        ));
    }
    let parent = headers
        .get(&header.parent)
        .ok_or_else(|| reject(&header.parent, "unknown parent"))?;
    if witness.open_tip != miner_tip() || witness.open_height != parent.height + 1 {
        return Err(reject(
            ("open_tip", &witness.open_tip, witness.open_height),
            "not the miner tip one above the parent",
        ));
    }

    // burn view and epoch
    let burn = BurnFacts::new(&proven.burn, bitcoin);
    let burn_view =
        burn_view_of(block, txs, headers, proven).map_err(|e| reject("burn view", e))?;
    let (view_binding, view_block) = burn
        .block_of(&burn_view)
        .map_err(|e| reject("burn view", e))?;
    let (_, parent_burn) = burn
        .block_of(&parent.consensus_hash)
        .map_err(|e| reject("parent burn block", e))?;
    if net.epoch_at(parent_burn.height) != Some(&witness.epoch) {
        return Err(reject(
            &witness.epoch,
            "not the epoch of the parent's burn block",
        ));
    }
    if proven.store.len() != witness.store.len() {
        return Err(reject("store", "one proof per store entry"));
    }

    let marf = OpenedProof::open(&proven.marf, headers);
    let mut check = WitnessCheck {
        marf: marf.stats(),
        ..Default::default()
    };
    let ctx = EnvContext {
        view: Some((view_binding.sortition_id(), view_block.height)),
        ..EnvContext::new(trusted, &burn, &marf, &proven.coinbases)
    };
    // store entries
    for ((query, answer), proof) in witness.store.iter().zip(proven.store.iter()) {
        if let Err(e) = verify_store_entry(
            query,
            answer,
            proof,
            witness.open_height,
            &parent.id,
            headers,
            &marf,
        ) {
            check.rejections.push(reject(query, e));
        }
    }

    // contract metadata
    let rejections = verify_metadata(witness, proven, &parent.id, &ctx, &mut check.kinds);
    check.rejections.extend(rejections);

    // environment lookups
    for read in witness.env.iter() {
        if let Err(e) = verify_env(read, &ctx) {
            check.rejections.push(reject(read, e));
        }
    }

    // the shared proof is exact: every node it carries is on some entry's walk
    if let Some(reason) = marf.strictness() {
        check.rejections.push(reject("shared MARF proof", reason));
    }
    Ok(check)
}

/// Check one store entry read at `open_height` on top of `parent` (a block's
/// own read, or a deploy's) against the shared proof.
fn verify_store_entry(
    query: &StoreQuery,
    answer: &Option<String>,
    proof: &StoreProof,
    open_height: u32,
    parent: &StacksBlockId,
    headers: &HeaderChain,
    marf: &OpenedProof,
) -> Result<(), String> {
    let claim = claim_of(query, answer, open_height, parent, |at| {
        headers.get(at).map(|h| h.height)
    })?;
    match (claim, proof) {
        (Claim::Key { block, path, value }, StoreProof::Marf) => {
            marf.holds(&block, &path, value.as_ref())
        }
        (Claim::Ancestor { target, is }, StoreProof::Ancestor) => {
            let proven = ancestry_of(marf, &target, parent)?;
            if proven == is {
                Ok(())
            } else {
                Err(format!("ancestry is {proven}"))
            }
        }
        (Claim::OpenBlock { expected }, StoreProof::OpenBlock) => {
            if answer == &expected {
                Ok(())
            } else {
                Err(format!("the open block answers {expected:?}"))
            }
        }
        (Claim::Metadata, StoreProof::Rederived) => Ok(()),
        (Claim::Metadata, StoreProof::Served) => {
            Err("not provable yet: its contract is not re-derivable".into())
        }
        _ => Err("wrong kind of proof".into()),
    }
}

/// Whether the shared proof shows `target` is an ancestor of `parent`:
/// `__MARF_BLOCK_HASH_TO_HEIGHT::target` at the parent's root and, if
/// present, the block at that height.
fn ancestry_of(
    marf: &OpenedProof,
    target: &StacksBlockId,
    parent: &StacksBlockId,
) -> Result<bool, String> {
    let path = TrieHash::from_key(&hash_to_height_key(target));
    let height = marf
        .get(parent, &path)
        .map_err(|e| format!("height proof fails: {e}"))?
        .value;
    let Some(height) = height else {
        return Ok(false);
    };
    let path = TrieHash::from_key(&height_to_hash_key(u32::from(height)));
    let block = marf
        .get(parent, &path)
        .map_err(|e| format!("block-at-height proof fails: {e}"))?
        .value;
    Ok(block == Some(MARFValue::from(target.clone())))
}

/// Contract metadata re-derived from evidence: rows by contract, and the
/// block each contract was deployed in.
struct Rederived {
    rows: HashMap<String, ContractMetadata>,
    deployed_in: HashMap<String, StacksBlockId>,
}

/// Check every contract's evidence and re-derive its metadata, dependencies
/// first. A contract that fails is rejected and left out (so are contracts
/// that depend on it).
fn rederive_contracts(
    proven: &ProvenWitness,
    parent: &StacksBlockId,
    ctx: &EnvContext,
    kinds: &mut BTreeMap<&'static str, usize>,
) -> (Rederived, Vec<Rejection>) {
    let mut known = HashMap::new();
    let mut deployed_in = HashMap::new();
    let mut rejections = vec![];
    for evidence in proven.contracts.iter() {
        match rederive(evidence, parent, ctx, &known, kinds) {
            Ok(derived) => {
                known.insert(evidence.contract.clone(), derived);
                deployed_in.insert(evidence.contract.to_string(), evidence.block.clone());
            }
            Err(Rederive::Missing { store, env }) => rejections.push(reject(
                &evidence.contract,
                format!("its deploy witness lacks reads: {store:?} {env:?}"),
            )),
            Err(Rederive::Invalid(e)) => rejections.push(reject(&evidence.contract, e)),
        }
    }
    let rows = known
        .into_iter()
        .map(|(id, (_, rows))| (id.to_string(), rows))
        .collect();
    (Rederived { rows, deployed_in }, rejections)
}

/// The re-derived answer to a metadata entry.
fn rederived_answer(
    query: &StoreQuery,
    rederived: &Rederived,
) -> Result<Option<String>, Rejection> {
    let StoreQuery::Metadata {
        block,
        contract,
        key,
    } = query
    else {
        return Err(reject(query, "not a metadata entry"));
    };
    let (Some(rows), Some(deployed)) = (
        rederived.rows.get(contract),
        rederived.deployed_in.get(contract),
    ) else {
        return Err(reject(query, "contract not re-derived"));
    };
    if deployed != block {
        return Err(reject(
            query,
            format!("contract was deployed in {deployed}"),
        ));
    }
    Ok(rows.get(key).cloned())
}

/// Re-derive every contract in `proven.contracts` and require each metadata
/// read proven by re-derivation to match it.
fn verify_metadata(
    witness: &ReadWitness,
    proven: &ProvenWitness,
    parent: &StacksBlockId,
    ctx: &EnvContext,
    kinds: &mut BTreeMap<&'static str, usize>,
) -> Vec<Rejection> {
    let (rederived, mut rejections) = rederive_contracts(proven, parent, ctx, kinds);
    for ((query, answer), proof) in witness.store.iter().zip(proven.store.iter()) {
        if !matches!(query, StoreQuery::Metadata { .. }) || !matches!(proof, StoreProof::Rederived)
        {
            continue;
        }
        let ok = match rederived_answer(query, &rederived) {
            Ok(derived) => match (answer, derived) {
                (Some(read), Some(derived)) => same_metadata(read, &derived),
                (None, None) => true,
                _ => false,
            },
            Err(rejection) => {
                rejections.push(rejection);
                continue;
            }
        };
        if !ok {
            rejections.push(reject(query, "metadata differs from its re-derivation"));
        }
    }
    rejections
}

/// Fill every re-derivable metadata entry's answer from its re-derivation. A
/// served witness leaves those values out (they are ~95% of a plain
/// witness), so a client calls this before [`verify_read_witness`] (which
/// checks the contract evidence and reports what did not re-derive) and
/// re-execution. Returns the contracts whose entries stay unfilled because
/// they did not re-derive: re-executing without their metadata is
/// meaningless.
pub fn fill_rederived_metadata(
    proven: &mut ProvenWitness,
    block: &StacksBlockId,
    trusted: &TrustedState,
) -> Vec<String> {
    let Some(parent) = trusted.headers.get(block).map(|h| h.parent.clone()) else {
        return vec![];
    };
    let marf = OpenedProof::open(&proven.marf, trusted.headers);
    let burn = BurnFacts::new(&proven.burn, trusted.bitcoin);
    let ctx = EnvContext::new(trusted, &burn, &marf, &proven.coinbases);
    let (rederived, _) = rederive_contracts(proven, &parent, &ctx, &mut BTreeMap::new());
    let mut unfilled = BTreeSet::new();
    for ((query, answer), proof) in proven.witness.store.iter_mut().zip(proven.store.iter()) {
        if !matches!(proof, StoreProof::Rederived) {
            continue;
        }
        match rederived_answer(query, &rederived) {
            Ok(derived) => *answer = derived,
            Err(_) => {
                if let StoreQuery::Metadata { contract, .. } = query {
                    unfilled.insert(contract.clone());
                }
            }
        }
    }
    unfilled.into_iter().collect()
}

/// The consensus hash of `block`'s burn view: its own tenure change, else the
/// latest one in its tenure (proven by `proven.burn_view`).
fn burn_view_of(
    block: &StacksBlockId,
    txs: &[StacksTransaction],
    headers: &HeaderChain,
    proven: &ProvenWitness,
) -> Result<ConsensusHash, String> {
    let tenure_change = |tx: &StacksTransaction| match &tx.payload {
        TransactionPayload::TenureChange(tc) => Some(tc.burn_view_consensus_hash.clone()),
        _ => None,
    };
    if let Some(ch) = txs.iter().find_map(tenure_change) {
        return Ok(ch);
    }
    let inclusion = proven
        .burn_view
        .as_ref()
        .ok_or("no tenure change in the block and no burn-view proof")?;
    let header = headers.get(block).ok_or("unknown block")?;
    tenure_change_view(header, inclusion, headers)
}

/// The burn view `inclusion` sets for `block`: a tenure change in `block`
/// itself, or in an earlier block of its tenure (reached through parents with
/// the same consensus hash). Whether a later tenure extend came in between
/// is not checked (`NOTES.md`, burn-view recency).
fn tenure_change_view(
    block: &ChainHeader,
    inclusion: &TxInclusion,
    headers: &HeaderChain,
) -> Result<ConsensusHash, String> {
    if !inclusion.holds(headers) {
        return Err("burn-view tenure change is not in its block".into());
    }
    let mut found = inclusion.block == block.id;
    let mut cursor = headers.get(&block.parent);
    while let Some(h) = cursor.filter(|_| !found) {
        if h.consensus_hash != block.consensus_hash {
            break;
        }
        found = h.id == inclusion.block;
        cursor = headers.get(&h.parent);
    }
    if !found {
        return Err("burn-view tenure change is not earlier in this tenure".into());
    }
    match &inclusion.tx.payload {
        TransactionPayload::TenureChange(tc) => Ok(tc.burn_view_consensus_hash.clone()),
        _ => Err("burn-view proof is not a tenure change".into()),
    }
}

/// What environment lookups are checked against.
#[derive(Clone)]
struct EnvContext<'a> {
    headers: &'a HeaderChain,
    burn: &'a BurnFacts<'a>,
    net: &'a NetworkParams,
    coinbases: &'a [TxInclusion],
    marf: &'a OpenedProof,
    /// The burn view's sortition and Bitcoin height (`None`: not proven, so
    /// lookups through it are rejected).
    view: Option<(SortitionId, u32)>,
}

impl<'a> EnvContext<'a> {
    fn new(
        trusted: &TrustedState<'a>,
        burn: &'a BurnFacts<'a>,
        marf: &'a OpenedProof,
        coinbases: &'a [TxInclusion],
    ) -> Self {
        EnvContext {
            headers: trusted.headers,
            burn,
            net: trusted.net,
            coinbases,
            marf,
            view: None,
        }
    }
}

/// Header lookups go through one of two tables picked by the epoch argument;
/// a block in the other table reads as none.
fn header_in_table<'a>(
    headers: &'a HeaderChain,
    id: &StacksBlockId,
    epoch: &StacksEpochId,
) -> Result<Option<&'a ChainHeader>, String> {
    let header = headers
        .get(id)
        .ok_or_else(|| format!("unknown block {id}"))?;
    Ok((header.is_nakamoto() == epoch.uses_nakamoto_blocks()).then_some(header))
}

fn verify_env(read: &EnvRead, ctx: &EnvContext) -> Result<(), String> {
    use EnvQuery::*;
    let header = |id: &StacksBlockId| {
        ctx.headers
            .get(id)
            .ok_or_else(|| format!("unknown block {id}"))
    };
    let pox = &ctx.net.pox;
    let view = || {
        ctx.view
            .clone()
            .ok_or("no burn view proven for this lookup")
    };
    match &read.query {
        // (a) the header chain
        StacksBlockHeaderHash { id, epoch } => expect_answer(
            read,
            header_in_table(ctx.headers, id, epoch)?.map(|h| h.block_hash.clone()),
        ),
        ConsensusHashForBlock { id, epoch } => expect_answer(
            read,
            header_in_table(ctx.headers, id, epoch)?.map(|h| h.consensus_hash.clone()),
        ),
        StacksBlockTime { id } => expect_answer(read, header(id)?.timestamp),
        VrfSeed { id, epoch, .. } => {
            let h = header(id)?;
            let proof = if epoch.uses_nakamoto_blocks() {
                tenure_vrf_proof(&h.consensus_hash, ctx)?
            } else {
                h.vrf_proof.clone()
            };
            expect_answer(read, proof.as_ref().map(VRFSeed::from_proof))
        }
        // (b) consensus-hash preimage + Bitcoin headers
        BurnHeaderHashForBlock { id } => {
            let (binding, _) = ctx.burn.block_of(&header(id)?.consensus_hash)?;
            expect_answer(read, Some(binding.burn_header_hash.clone()))
        }
        BurnBlockHeightForBlock { id } => {
            let (_, btc) = ctx.burn.block_of(&header(id)?.consensus_hash)?;
            expect_answer(read, Some(btc.height))
        }
        BurnBlockTime { id, epoch } => {
            let h = match epoch {
                Some(epoch) => header_in_table(ctx.headers, id, epoch)?,
                None => Some(header(id)?),
            };
            let time = match h {
                Some(h) => Some(ctx.burn.block_of(&h.consensus_hash)?.1.time),
                None => None,
            };
            expect_answer(read, time)
        }
        TipBurnBlockHeight => expect_answer(read, Some(view()?.1)),
        TipSortitionId => expect_answer(read, Some(view()?.0)),
        BurnBlockHeight { sortition } => {
            expect_answer(read, Some(ctx.burn.height_of_sortition(sortition)?))
        }
        SortitionIdFromConsensusHash { consensus_hash } => {
            let (binding, _) = ctx.burn.block_of(consensus_hash)?;
            expect_answer(read, Some(binding.sortition_id()))
        }
        BurnHeaderHash { height, sortition } => {
            let (view_sortition, view_height) = view()?;
            if sortition != &view_sortition {
                return Err("only the burn view's fork is proven".into());
            }
            let expected = if *height > view_height || *height < ctx.net.first_burn_height {
                None
            } else {
                Some(
                    ctx.burn
                        .bitcoin
                        .at(*height)
                        .ok_or_else(|| format!("no Bitcoin header at {height}"))?
                        .hash
                        .clone(),
                )
            };
            expect_answer(read, expected)
        }
        // network constants
        StacksEpoch { height } => expect_answer(read, ctx.net.epoch_at(*height).cloned()),
        StacksEpochById { epoch } => expect_answer(read, ctx.net.epoch(epoch).cloned()),
        BurnStartHeight => expect_answer(read, ctx.net.first_burn_height),
        V1UnlockHeight => expect_answer(read, pox.v1_unlock_height),
        V2UnlockHeight => expect_answer(read, pox.v2_unlock_height),
        V3UnlockHeight => expect_answer(read, pox.v3_unlock_height),
        Pox3ActivationHeight => expect_answer(read, pox.pox_3_activation_height),
        Pox4ActivationHeight => expect_answer(read, pox.pox_4_activation_height),
        Pox5ActivationHeight => expect_answer(read, pox.pox_5_activation_height),
        PoxPrepareLength => expect_answer(read, pox.prepare_length),
        PoxRewardCycleLength => expect_answer(read, pox.reward_cycle_length),
        PoxRejectionFraction => expect_answer(read, pox.pox_rejection_fraction),
        // MARF walks at the tip's fork
        StacksHeightForTenureHeight { tip, tenure_height } => {
            let answer = *read
                .answer
                .downcast_ref::<Option<u32>>()
                .ok_or("answer has the wrong type")?;
            tenure_start_facts(
                tip,
                header(tip)?.height,
                *tenure_height,
                answer,
                |block, path| {
                    ctx.marf
                        .get(block, path)
                        .map(|end| end.value)
                        .map_err(|e| format!("MARF proof fails: {e}"))
                },
            )
        }
        // (c)/(d): not provable yet
        MinerAddress { .. }
        | TokensSpent { .. }
        | TokensSpentWinning { .. }
        | TokensEarned { .. }
        | PoxPayoutAddrs { .. } => Err("not provable yet".into()),
    }
}

/// The VRF proof of the coinbase that started the tenure with consensus hash
/// `ch`: a coinbase is only valid in a tenure's first block.
fn tenure_vrf_proof(ch: &ConsensusHash, ctx: &EnvContext) -> Result<Option<VRFProof>, String> {
    for inclusion in ctx.coinbases.iter() {
        let Some(h) = ctx.headers.get(&inclusion.block) else {
            continue;
        };
        if &h.consensus_hash != ch || !inclusion.holds(ctx.headers) {
            continue;
        }
        if let TransactionPayload::Coinbase(_, _, proof) = &inclusion.tx.payload {
            return Ok(proof.clone());
        }
    }
    Err(format!("no coinbase proof for tenure {ch}"))
}

#[cfg(test)]
mod tests {
    use stacks_common::consts::CHAIN_ID_MAINNET;

    use super::*;
    use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
    use crate::clarity_vm::witness_client::ClientParams;
    use crate::util_lib::boot::boot_code_id;

    /// Every mainnet boot contract re-derives from its bundled source in the
    /// epoch whose transition deploys it, given the boot contracts before it,
    /// except two, which name what they need. `signers-voting` stores a
    /// constant read from `pox-4` state at deploy time (`pox-info`): a deploy
    /// witness carries those reads. `pox-5` needs the user-deployed sBTC
    /// token re-derived first.
    #[test]
    fn mainnet_boot_contracts_rederive_from_bundled_sources() {
        use StacksEpochId::*;
        let net = ClientParams::mainnet().net;
        let mut deploys: Vec<(String, StacksEpochId)> = [
            ("pox", Epoch20),
            ("lockup", Epoch20),
            ("costs", Epoch20),
            ("cost-voting", Epoch20),
            ("bns", Epoch20),
            ("genesis", Epoch20),
            ("costs-2", Epoch2_05),
            ("pox-2", Epoch21),
            ("costs-3", Epoch21),
            ("pox-3", Epoch24),
            ("pox-4", Epoch25),
            ("signers", Epoch25),
        ]
        .iter()
        .map(|(name, epoch)| (name.to_string(), *epoch))
        .collect();
        for set in 0..2 {
            for message_id in 0..SIGNER_SLOTS_PER_USER {
                let name = NakamotoSigners::make_signers_db_name(set, message_id);
                deploys.push((name, Epoch25));
            }
        }
        deploys.extend([
            ("sip-031".to_string(), Epoch32),
            ("costs-4".to_string(), Epoch33),
        ]);

        let mut known = HashMap::new();
        let deploy_with = |name: &str, epoch: StacksEpochId, known: &HashMap<_, _>| {
            let id = boot_code_id(name, true);
            let tx = boot_deploy_tx(&id, &net).unwrap_or_else(|| panic!("no source for {name}"));
            let env = EnvTap::from_witness(&[]);
            let deploy = ContractDeployment {
                tx: &tx,
                height: 1,
                epoch,
                epoch_key: (epoch != Epoch20).then(|| (epoch as u32).serialize()),
                reads: &[],
                env: &env,
            };
            let TransactionPayload::SmartContract(ref payload, _) = tx.payload else {
                unreachable!()
            };
            let hash = Sha512Trunc256Sum::from_data(payload.code_body.to_string().as_bytes());
            (
                id,
                hash,
                derive_contract_metadata(&deploy, known, true, CHAIN_ID_MAINNET),
            )
        };
        for (name, epoch) in deploys.iter() {
            let (id, hash, derived) = deploy_with(name, *epoch, &known);
            match derived {
                Ok((derived_id, rows)) => {
                    assert_eq!(derived_id, id);
                    assert!(rows.contains_key("vm-metadata::9::contract"), "{name}");
                    known.insert(id, (hash, rows));
                }
                Err(DeriveError::Missing { store, env }) => {
                    panic!("{name} needs {store:?} {env:?}")
                }
                Err(DeriveError::Failed(e)) => panic!("{name} fails to deploy: {e:?}"),
            }
        }

        for (name, epoch, needs) in [
            ("signers-voting", Epoch25, "ustx_liquid_supply"),
            ("pox-5", Epoch40, "sbtc-token"),
        ] {
            match deploy_with(name, epoch, &known).2 {
                Err(DeriveError::Missing { store, .. }) => {
                    assert!(
                        store.iter().any(|q| format!("{q:?}").contains(needs)),
                        "{store:?}"
                    )
                }
                other => panic!("{name} re-derived alone: {other:?}"),
            }
        }
    }
}
