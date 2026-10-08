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
//! | store read at the open block | MARF inclusion or absence proof against the parent's `state_index_root` |
//! | store read inside `at-block X` | same, against X's root |
//! | `at-block` switch | MARF proofs of `__MARF_BLOCK_HASH_TO_HEIGHT::X` and back |
//! | the open block's own bookkeeping | deterministic from the parent id and height |
//! | contract metadata | re-derived from the deploy (see [`derive_contract_metadata`]) |
//! | header lookups | the header chain |
//! | burn lookups | consensus-hash preimages ([`BurnBinding`]) plus the Bitcoin chain |
//! | epochs, PoX parameters | network constants |
//!
//! See `NOTES.md` for the lookups that are not provable yet.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use clarity::vm::database::clarity_store::{make_contract_hash_key, ContractCommitment};
use clarity::vm::database::{ClarityDeserializable, SqliteConnection};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, ContractName};
use stacks_common::codec::StacksMessageCodec;
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
    BOOT_CODE_BNS, BOOT_CODE_COSTS, BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET,
    BOOT_CODE_COSTS_3, BOOT_CODE_COSTS_4, BOOT_CODE_COST_VOTING_MAINNET,
    BOOT_CODE_COST_VOTING_TESTNET, BOOT_CODE_GENESIS, BOOT_CODE_LOCKUP, BOOT_CODE_POX_MAINNET,
    BOOT_CODE_POX_TESTNET, COSTS_1_NAME, COSTS_2_NAME, COSTS_3_NAME, COSTS_4_NAME,
    POX_2_MAINNET_CODE, POX_2_NAME, POX_2_TESTNET_CODE, POX_3_MAINNET_CODE, POX_3_NAME,
    POX_3_TESTNET_CODE, POX_4_CODE, POX_4_NAME, SIGNERS_BODY, SIGNERS_NAME, SIGNERS_VOTING_BODY,
    SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksHeaderInfo};
use crate::chainstate::stacks::index::absence::{AbsenceEnd, TrieAbsenceProof};
use crate::chainstate::stacks::index::bits::{get_leaf_hash, get_node_hash};
use crate::chainstate::stacks::index::marf::{
    BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, MARF, OWN_BLOCK_HEIGHT_KEY,
};
use crate::chainstate::stacks::index::node::{is_backptr, TrieNodeID};
use crate::chainstate::stacks::index::storage::TrieStorageConnection;
use crate::chainstate::stacks::index::{
    ClarityMarfTrieId, Error as MarfError, MARFValue, ProofTriePtr, TrieMerkleProof,
    TrieMerkleProofType,
};
use crate::chainstate::stacks::{
    StacksTransaction, TransactionPayload, TransactionSmartContract, TransactionVersion,
    MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity_vm::read_witness::{EnvQuery, EnvRead, ReadWitness, StoreQuery};
use crate::clarity_vm::stateless::{
    derive_contract_metadata, ContractDeployment, ContractMetadata, StatelessError,
    EPOCH_VERSION_KEY,
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

    pub fn from_header_info(info: &StacksHeaderInfo, parent: StacksBlockId) -> Self {
        let (state_index_root, tx_merkle_root, timestamp, vrf_proof) = match &info.anchored_header {
            StacksBlockHeaderTypes::Epoch2(h) => (
                h.state_index_root,
                h.tx_merkle_root.clone(),
                None,
                Some(h.proof.clone()),
            ),
            StacksBlockHeaderTypes::Nakamoto(h) => (
                h.state_index_root,
                h.tx_merkle_root.clone(),
                Some(h.timestamp),
                None,
            ),
        };
        ChainHeader {
            id: info.index_block_hash(),
            parent,
            block_hash: info.anchored_header.block_hash(),
            consensus_hash: info.consensus_hash.clone(),
            height: info.stacks_block_height as u32,
            state_index_root,
            tx_merkle_root,
            timestamp,
            vrf_proof,
        }
    }
}

/// Authenticated Stacks headers, by block id and by MARF root.
pub struct HeaderChain {
    headers: HashMap<StacksBlockId, ChainHeader>,
    root_to_block: HashMap<TrieHash, StacksBlockId>,
}

impl HeaderChain {
    pub fn new(headers: impl IntoIterator<Item = ChainHeader>) -> Self {
        let headers: HashMap<_, _> = headers.into_iter().map(|h| (h.id.clone(), h)).collect();
        let root_to_block = headers
            .values()
            .map(|h| (h.state_index_root, h.id.clone()))
            .collect();
        HeaderChain {
            headers,
            root_to_block,
        }
    }

    pub fn get(&self, id: &StacksBlockId) -> Option<&ChainHeader> {
        self.headers.get(id)
    }

    /// Whether `ancestor` is `block` or one of its ancestors.
    pub fn is_ancestor(&self, ancestor: &StacksBlockId, block: &StacksBlockId) -> bool {
        let Some(target) = self.headers.get(ancestor) else {
            return false;
        };
        let mut cursor = self.headers.get(block);
        while let Some(h) = cursor {
            if h.id == target.id {
                return true;
            }
            if h.height <= target.height {
                return false;
            }
            cursor = self.headers.get(&h.parent);
        }
        false
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

/// MARF evidence for one key at one block root.
#[derive(Debug, Clone)]
pub enum MarfProof {
    Present(TrieMerkleProof<StacksBlockId>),
    Absent(TrieAbsenceProof<StacksBlockId>),
}

impl MarfProof {
    /// The leaf value an inclusion proof proves.
    fn present_value(&self) -> Option<MARFValue> {
        match self {
            MarfProof::Present(proof) => match proof.0.first() {
                Some(TrieMerkleProofType::Leaf((_, leaf))) => Some(leaf.data.clone()),
                _ => None,
            },
            MarfProof::Absent(_) => None,
        }
    }

    fn holds(
        &self,
        path: &TrieHash,
        value: Option<&MARFValue>,
        root: &TrieHash,
        headers: &HeaderChain,
    ) -> bool {
        match (self, value) {
            (MarfProof::Present(proof), Some(value)) => {
                proof.verify(path, value, root, &headers.root_to_block)
            }
            (MarfProof::Absent(proof), None) => proof.verify(path, root, &headers.root_to_block),
            _ => false,
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            MarfProof::Present(proof) => proof.serialize_to_vec().len(),
            MarfProof::Absent(proof) => proof.byte_len(),
        }
    }
}

/// Evidence for one store entry of the witness.
#[derive(Debug, Clone)]
pub enum StoreProof {
    /// The entry's key at the root of the block it was read at.
    Marf(MarfProof),
    /// An `at-block` target is an ancestor: its height
    /// (`__MARF_BLOCK_HASH_TO_HEIGHT`) and that height's block
    /// (`__MARF_BLOCK_HEIGHT_TO_HASH`), both at the parent.
    Ancestor {
        hash_to_height: MarfProof,
        height_to_hash: MarfProof,
    },
    /// The open block's own bookkeeping: determined by the parent and the
    /// open height.
    OpenBlock,
    /// Contract metadata: re-derived from [`ProvenWitness::contracts`].
    Rederived,
}

impl StoreProof {
    pub fn byte_len(&self) -> usize {
        match self {
            StoreProof::Marf(p) => p.byte_len(),
            StoreProof::Ancestor {
                hash_to_height,
                height_to_hash,
            } => hash_to_height.byte_len() + height_to_hash.byte_len(),
            StoreProof::OpenBlock | StoreProof::Rederived => 0,
        }
    }
}

/// Where a contract's source comes from.
#[derive(Debug, Clone)]
pub enum DeploySource {
    /// A user contract: its deploy transaction in the deploying block.
    Tx(TxInclusion),
    /// A boot contract: the client's bundled boot code.
    Boot,
}

/// What re-deriving one contract's metadata needs.
#[derive(Debug, Clone)]
pub struct ContractEvidence {
    pub contract: QualifiedContractIdentifier,
    /// The deploying block.
    pub block: StacksBlockId,
    pub source: DeploySource,
    /// `clarity-contract::<contract>` (source hash and deploy height) at the
    /// deploying block's root.
    pub commitment: String,
    pub commitment_proof: MarfProof,
    /// `vm-epoch::epoch-version` at the deploying block's root.
    pub epoch_key: Option<String>,
    pub epoch_key_proof: MarfProof,
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
            + self.commitment_proof.byte_len()
            + self.epoch_key.as_ref().map_or(0, String::len)
            + self.epoch_key_proof.byte_len()
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
    /// Preimages of every consensus hash a lookup touches.
    pub burn: Vec<BurnBinding>,
    /// The tenure change that set the block's burn view, when it is in an
    /// ancestor (a block carrying its own tenure change needs none).
    pub burn_view: Option<TxInclusion>,
    /// Tenure coinbases, for VRF seeds.
    pub coinbases: Vec<TxInclusion>,
}

/// Witness and evidence sizes, in bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProofSize {
    /// MARF proofs for store entries.
    pub marf_proofs: usize,
    pub inclusion_proofs: usize,
    pub absence_proofs: usize,
    /// Deploy txs, commitments and epoch proofs for metadata re-derivation.
    pub contracts: usize,
    /// Burn bindings, burn-view and coinbase tx proofs.
    pub env: usize,
    /// All MARF proofs (store and contract evidence) as one multiproof: each
    /// distinct trie node once, with all its child hashes, and each distinct
    /// shunt once.
    pub marf_multiproof: usize,
    /// The same, without the child hashes a verifier can rebuild (empty and
    /// back-pointer children).
    pub marf_multiproof_compact: usize,
}

impl MarfProof {
    /// Every node and shunt of the proof as `(identity, bytes, compact
    /// bytes)`, identity being the node's hash (shunts: their bytes). A node
    /// costs its pointers plus one hash per child; compact, only its inline
    /// children need hashes, because an empty child hashes as
    /// `TrieHash::EMPTY` and a back-pointer child as the `back_block` its
    /// pointer already carries.
    fn multiproof_items(&self) -> Vec<(Vec<u8>, usize, usize)> {
        let child_hashes = |ptrs: &[ProofTriePtr<StacksBlockId>]| {
            let inline = ptrs
                .iter()
                .filter(|p| p.id != TrieNodeID::Empty as u8 && !is_backptr(p.id))
                .count();
            (32 * ptrs.len(), 32 * inline)
        };
        let mut out = vec![];
        let (steps, mut hash) = match self {
            MarfProof::Present(proof) => (&proof.0, None),
            MarfProof::Absent(proof) => {
                let (hash, bytes, full, compact) = match &proof.end {
                    AbsenceEnd::Leaf(leaf) => {
                        let bytes = leaf.serialize_to_vec().len();
                        (get_leaf_hash(leaf), bytes, 0, 0)
                    }
                    AbsenceEnd::Node { node, hashes } => {
                        let (full, compact) = child_hashes(&node.ptrs);
                        (
                            get_node_hash(node, hashes, &mut ()),
                            node.serialize_to_vec().len(),
                            full,
                            compact,
                        )
                    }
                };
                out.push((hash.as_bytes().to_vec(), bytes + full, bytes + compact));
                (&proof.proof, Some(hash))
            }
        };
        for step in steps.iter() {
            let node = match step {
                TrieMerkleProofType::Leaf((_, leaf)) => {
                    let h = get_leaf_hash(leaf);
                    let len = leaf.serialize_to_vec().len();
                    out.push((h.as_bytes().to_vec(), len, len));
                    hash = Some(h);
                    continue;
                }
                TrieMerkleProofType::Shunt(_) => {
                    let bytes = step.serialize_to_vec();
                    let len = bytes.len();
                    out.push((bytes, len, len));
                    hash = None;
                    continue;
                }
                TrieMerkleProofType::Node4((chr, node, siblings)) => (chr, node, &siblings[..]),
                TrieMerkleProofType::Node16((chr, node, siblings)) => (chr, node, &siblings[..]),
                TrieMerkleProofType::Node48((chr, node, siblings)) => (chr, node, &siblings[..]),
                TrieMerkleProofType::Node256((chr, node, siblings)) => (chr, node, &siblings[..]),
            };
            let (chr, node, siblings) = node;
            let on_path = node
                .ptrs
                .iter()
                .position(|p| p.id != TrieNodeID::Empty as u8 && p.chr == *chr);
            // after a shunt, the on-path child is a back-pointer: its hash is its block
            let child = hash
                .or_else(|| on_path.map(|i| TrieHash(node.ptrs[i].back_block.clone().to_bytes())));
            let (Some(on_path), Some(child)) = (on_path, child) else {
                continue;
            };
            let mut all = siblings.to_vec();
            all.insert(on_path.min(all.len()), child);
            let h = get_node_hash(node, &all, &mut ());
            let bytes = node.serialize_to_vec().len();
            let (full, compact) = child_hashes(&node.ptrs);
            out.push((h.as_bytes().to_vec(), bytes + full, bytes + compact));
            hash = Some(h);
        }
        out
    }
}

impl ProvenWitness {
    pub fn proof_size(&self) -> ProofSize {
        let mut size = ProofSize::default();
        for proof in self.store.iter() {
            size.marf_proofs += proof.byte_len();
            match proof {
                StoreProof::Marf(MarfProof::Present(_)) => size.inclusion_proofs += 1,
                StoreProof::Marf(MarfProof::Absent(_)) => size.absence_proofs += 1,
                StoreProof::Ancestor { .. } => size.inclusion_proofs += 2,
                _ => {}
            }
        }
        size.contracts = self.contracts.iter().map(ContractEvidence::byte_len).sum();
        let mut proofs: Vec<&MarfProof> = vec![];
        for proof in self.store.iter() {
            match proof {
                StoreProof::Marf(p) => proofs.push(p),
                StoreProof::Ancestor {
                    hash_to_height,
                    height_to_hash,
                } => proofs.extend([hash_to_height, height_to_hash]),
                _ => {}
            }
        }
        for c in self.contracts.iter() {
            proofs.extend([&c.commitment_proof, &c.epoch_key_proof]);
        }
        let mut seen = HashSet::new();
        for (identity, full, compact) in proofs.iter().flat_map(|p| p.multiproof_items()) {
            if seen.insert(identity) {
                size.marf_multiproof += full;
                size.marf_multiproof_compact += compact;
            }
        }
        size.env = self.burn.iter().map(BurnBinding::byte_len).sum::<usize>()
            + self.burn_view.as_ref().map_or(0, TxInclusion::byte_len)
            + self
                .coinbases
                .iter()
                .map(TxInclusion::byte_len)
                .sum::<usize>();
        size
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
/// at `witness.open_height`. `at_height` gives the height of an `at-block`
/// target (from the header chain on the verifier side, the MARF on the
/// prover side).
fn claim_of(
    query: &StoreQuery,
    answer: &Option<String>,
    witness: &ReadWitness,
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
        StoreQuery::BlockAtHeight { at: None, height } if *height == witness.open_height => {
            Claim::OpenBlock {
                expected: Some(witness.open_tip.to_hex()),
            }
        }
        StoreQuery::BlockAtHeight { at: None, height } if height + 1 == witness.open_height => {
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
// Prover
// ---------------------------------------------------------------------------

fn prove_key(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    block: &StacksBlockId,
    path: &TrieHash,
    value: Option<&MARFValue>,
) -> Result<MarfProof, MarfError> {
    match value {
        Some(value) => Ok(MarfProof::Present(TrieMerkleProof::from_path(
            conn, path, value, block,
        )?)),
        None => Ok(MarfProof::Absent(TrieAbsenceProof::from_path(
            conn, path, block,
        )?)),
    }
}

/// The value a MARF leaf hashes (leaves hold value hashes; values live in the
/// side table).
fn side_value(conn: &TrieStorageConnection<StacksBlockId>, value: &MARFValue) -> Option<String> {
    SqliteConnection::get(conn.sqlite_conn(), &value.to_hex())
        .ok()
        .flatten()
}

/// Prove whatever `path` holds at `block`, present or absent.
fn prove_current(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    block: &StacksBlockId,
    path: &TrieHash,
) -> Result<MarfProof, MarfError> {
    let value = MARF::get_by_path(conn, block, path)?;
    prove_key(conn, block, path, value.as_ref())
}

/// MARF evidence for every store entry of a witness recorded for the block
/// whose parent is `parent` (metadata entries are re-derived instead).
pub fn prove_store_reads(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    parent: &StacksBlockId,
    witness: &ReadWitness,
) -> Result<Vec<StoreProof>, String> {
    let mut proofs = vec![];
    for (query, answer) in witness.store.iter() {
        let claim = claim_of(query, answer, witness, parent, |at| {
            MARF::get_block_height_miner_tip(conn, at, at)
                .ok()
                .flatten()
        })?;
        let proof = match claim {
            Claim::Key { block, path, value } => StoreProof::Marf(
                prove_key(conn, &block, &path, value.as_ref())
                    .map_err(|e| format!("{query:?}: {e:?}"))?,
            ),
            Claim::Ancestor { target, .. } => {
                let path = TrieHash::from_key(&hash_to_height_key(&target));
                let hash_to_height =
                    prove_current(conn, parent, &path).map_err(|e| format!("{query:?}: {e:?}"))?;
                let height_to_hash = match hash_to_height.present_value() {
                    Some(height) => {
                        let path = TrieHash::from_key(&height_to_hash_key(u32::from(height)));
                        prove_current(conn, parent, &path)
                            .map_err(|e| format!("{query:?}: {e:?}"))?
                    }
                    None => hash_to_height.clone(),
                };
                StoreProof::Ancestor {
                    hash_to_height,
                    height_to_hash,
                }
            }
            Claim::OpenBlock { .. } => StoreProof::OpenBlock,
            Claim::Metadata => StoreProof::Rederived,
        };
        proofs.push(proof);
    }
    Ok(proofs)
}

/// Evidence for re-deriving `contract`, deployed in `block` (found through
/// the commitment at `parent`).
pub fn prove_contract(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    parent: &StacksBlockId,
    contract: &QualifiedContractIdentifier,
    find_deploy: &dyn Fn(&StacksBlockId, &QualifiedContractIdentifier) -> Option<TxInclusion>,
    mainnet: bool,
) -> Result<ContractEvidence, String> {
    let commitment_key = make_contract_hash_key(contract);
    let commitment = MARF::get_by_key(conn, parent, &commitment_key)
        .map_err(|e| format!("{contract}: {e:?}"))?
        .ok_or_else(|| format!("{contract} is not deployed"))?;
    // MARF leaves hold value hashes; the value itself is in the side table
    let commitment = side_value(conn, &commitment)
        .ok_or_else(|| format!("{contract}: no side-table value for its commitment"))?;
    let height = ContractCommitment::deserialize(&commitment)
        .map_err(|e| format!("{contract}: {e:?}"))?
        .block_height;
    let block = MARF::get_block_at_height(conn, height, parent)
        .map_err(|e| format!("{contract}: {e:?}"))?
        .ok_or_else(|| format!("{contract}: no block at height {height}"))?;
    let source = if boot_contract_source(contract, mainnet).is_some() {
        DeploySource::Boot
    } else {
        DeploySource::Tx(
            find_deploy(&block, contract)
                .ok_or_else(|| format!("{contract}: deploy tx not found in {block}"))?,
        )
    };
    let commitment_proof = prove_key(
        conn,
        &block,
        &TrieHash::from_key(&commitment_key),
        Some(&MARFValue::from_value(&commitment)),
    )
    .map_err(|e| format!("{contract}: {e:?}"))?;
    let epoch_path = TrieHash::from_key(EPOCH_VERSION_KEY);
    let epoch_key = MARF::get_by_path(conn, &block, &epoch_path)
        .map_err(|e| format!("{contract}: {e:?}"))?
        .map(|value| side_value(conn, &value).expect("epoch value in the side table"));
    let epoch_key_proof = prove_key(
        conn,
        &block,
        &epoch_path,
        epoch_key.as_deref().map(MARFValue::from_value).as_ref(),
    )
    .map_err(|e| format!("{contract}: {e:?}"))?;
    Ok(ContractEvidence {
        contract: contract.clone(),
        block,
        source,
        commitment,
        commitment_proof,
        epoch_key,
        epoch_key_proof,
    })
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

/// Contract evidence for every contract whose metadata `witness` read, plus
/// whatever their analysis depends on, ordered so each contract's
/// dependencies come first. Dependencies are found by re-deriving.
pub fn prove_contracts(
    conn: &mut TrieStorageConnection<StacksBlockId>,
    parent: &StacksBlockId,
    witness: &ReadWitness,
    headers: &HeaderChain,
    net: &NetworkParams,
    find_deploy: &dyn Fn(&StacksBlockId, &QualifiedContractIdentifier) -> Option<TxInclusion>,
) -> Result<Vec<ContractEvidence>, String> {
    let mut ordered: Vec<ContractEvidence> = vec![];
    let mut pending = metadata_contracts(witness);
    let mut derived = HashMap::new();
    let mut attempts = 0;
    while let Some(contract) = pending.last().cloned() {
        attempts += 1;
        if attempts > 1000 {
            return Err("contract dependencies do not resolve".into());
        }
        if derived.contains_key(&contract) {
            pending.pop();
            continue;
        }
        let evidence = prove_contract(conn, parent, &contract, find_deploy, net.mainnet)?;
        match rederive(&evidence, headers, net, &derived) {
            Ok((hash, rows)) => {
                derived.insert(contract.clone(), (hash, rows));
                ordered.push(evidence);
                pending.pop();
            }
            Err(Rederive::Missing(missing)) => {
                let deps: Vec<_> = missing
                    .iter()
                    .filter_map(|m| m.split("clarity-contract::").nth(1))
                    .filter_map(|rest| rest.split('"').next())
                    .filter_map(|id| QualifiedContractIdentifier::parse(id).ok())
                    .filter(|id| !derived.contains_key(id) && id != &contract)
                    .collect();
                if deps.is_empty() {
                    return Err(format!("{contract} cannot be re-derived: {missing:?}"));
                }
                pending.extend(deps);
            }
            Err(Rederive::Invalid(e)) => return Err(format!("{contract}: {e}")),
        }
    }
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// Contract metadata re-derivation
// ---------------------------------------------------------------------------

/// The client's bundled source for a boot contract, and the Clarity version
/// its epoch transition pins (`None`: the epoch default). Mirrors
/// `StacksChainState::instantiate_boot_code` and the
/// `ClarityBlockConnection::initialize_epoch_*` transitions.
fn boot_contract_source(
    contract: &QualifiedContractIdentifier,
    mainnet: bool,
) -> Option<(&'static str, Option<ClarityVersion>)> {
    if contract.issuer != boot_code_addr(mainnet).into() {
        return None;
    }
    let pick = |main: &'static str, test: &'static str| if mainnet { main } else { test };
    let v2 = Some(ClarityVersion::Clarity2);
    Some(match contract.name.as_str() {
        "pox" => (pick(&BOOT_CODE_POX_MAINNET, &BOOT_CODE_POX_TESTNET), None),
        "lockup" => (BOOT_CODE_LOCKUP, None),
        COSTS_1_NAME => (BOOT_CODE_COSTS, None),
        "cost-voting" => (
            pick(
                BOOT_CODE_COST_VOTING_MAINNET,
                &BOOT_CODE_COST_VOTING_TESTNET,
            ),
            None,
        ),
        "bns" => (BOOT_CODE_BNS, None),
        "genesis" => (BOOT_CODE_GENESIS, None),
        COSTS_2_NAME => (pick(BOOT_CODE_COSTS_2, BOOT_CODE_COSTS_2_TESTNET), None),
        POX_2_NAME => (pick(&POX_2_MAINNET_CODE, &POX_2_TESTNET_CODE), v2),
        COSTS_3_NAME => (BOOT_CODE_COSTS_3, None),
        POX_3_NAME => (pick(&POX_3_MAINNET_CODE, &POX_3_TESTNET_CODE), v2),
        POX_4_NAME => (&POX_4_CODE, v2),
        SIGNERS_NAME => (SIGNERS_BODY, v2),
        SIGNERS_VOTING_NAME => (SIGNERS_VOTING_BODY, v2),
        COSTS_4_NAME => (BOOT_CODE_COSTS_4, None),
        _ => return None,
    })
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
            code_body: StacksString::from_str(code)?,
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
    /// Re-derivation needed something outside the deploy and the known
    /// contracts.
    Missing(Vec<String>),
    Invalid(String),
}

/// Check one contract's evidence and re-derive its metadata.
fn rederive(
    evidence: &ContractEvidence,
    headers: &HeaderChain,
    net: &NetworkParams,
    known: &HashMap<QualifiedContractIdentifier, (Sha512Trunc256Sum, ContractMetadata)>,
) -> Result<(Sha512Trunc256Sum, ContractMetadata), Rederive> {
    let invalid = |s: String| Rederive::Invalid(s);
    let header = headers
        .get(&evidence.block)
        .ok_or_else(|| invalid(format!("unknown deploy block {}", evidence.block)))?;
    let root = header.state_index_root;

    // the commitment pins the source hash and the deploy height
    let commitment_key = make_contract_hash_key(&evidence.contract);
    if !evidence.commitment_proof.holds(
        &TrieHash::from_key(&commitment_key),
        Some(&MARFValue::from_value(&evidence.commitment)),
        &root,
        headers,
    ) {
        return Err(invalid("commitment proof fails".into()));
    }
    let commitment = ContractCommitment::deserialize(&evidence.commitment)
        .map_err(|e| invalid(format!("bad commitment: {e:?}")))?;
    if commitment.block_height != header.height {
        return Err(invalid(format!(
            "commitment height {} is not the deploy block's {}",
            commitment.block_height, header.height
        )));
    }

    // the epoch the deploy ran in
    if !evidence.epoch_key_proof.holds(
        &TrieHash::from_key(EPOCH_VERSION_KEY),
        evidence
            .epoch_key
            .as_deref()
            .map(MARFValue::from_value)
            .as_ref(),
        &root,
        headers,
    ) {
        return Err(invalid("epoch proof fails".into()));
    }
    let epoch = match evidence.epoch_key.as_deref() {
        None => StacksEpochId::Epoch20,
        Some(v) => {
            let id = u32::deserialize(v).map_err(|e| invalid(format!("bad epoch: {e:?}")))?;
            StacksEpochId::try_from(id).map_err(|_| invalid(format!("bad epoch {id}")))?
        }
    };

    // the source
    let tx = match &evidence.source {
        DeploySource::Tx(inclusion) => {
            if inclusion.block != evidence.block || !inclusion.holds(headers) {
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

    let deploy = ContractDeployment {
        tx: &tx,
        height: header.height,
        epoch,
        epoch_key: evidence.epoch_key.clone(),
    };
    match derive_contract_metadata(&deploy, known, net.mainnet, net.chain_id) {
        Ok((id, rows)) if id == evidence.contract => Ok((hash, rows)),
        Ok((id, _)) => Err(invalid(format!("deploy tx deploys {id}"))),
        Err(StatelessError::WitnessIncomplete(missing)) => Err(Rederive::Missing(missing)),
        Err(StatelessError::Block(e)) => Err(invalid(format!("deploy failed: {e:?}"))),
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

    // store entries
    if proven.store.len() != witness.store.len() {
        return Err(reject("store", "one proof per store entry"));
    }
    for ((query, answer), proof) in witness.store.iter().zip(proven.store.iter()) {
        verify_store_entry(query, answer, proof, witness, &parent.id, headers)
            .map_err(|e| reject(query, e))?;
    }

    // contract metadata
    verify_metadata(witness, proven, &parent.id, headers, net)?;

    // environment lookups
    let ctx = EnvContext {
        headers,
        burn: &burn,
        net,
        coinbases: &proven.coinbases,
        view_sortition: view_binding.sortition_id(),
        view_height: view_block.height,
    };
    for read in witness.env.iter() {
        verify_env(read, &ctx).map_err(|e| reject(read, e))?;
    }
    Ok(())
}

fn verify_store_entry(
    query: &StoreQuery,
    answer: &Option<String>,
    proof: &StoreProof,
    witness: &ReadWitness,
    parent: &StacksBlockId,
    headers: &HeaderChain,
) -> Result<(), String> {
    let root_of = |block: &StacksBlockId| {
        headers
            .get(block)
            .map(|h| h.state_index_root)
            .ok_or_else(|| format!("unknown block {block}"))
    };
    let claim = claim_of(query, answer, witness, parent, |at| {
        headers.get(at).map(|h| h.height)
    })?;
    match (claim, proof) {
        (Claim::Key { block, path, value }, StoreProof::Marf(proof)) => {
            if proof.holds(&path, value.as_ref(), &root_of(&block)?, headers) {
                Ok(())
            } else {
                Err("MARF proof fails".into())
            }
        }
        (
            Claim::Ancestor { target, is },
            StoreProof::Ancestor {
                hash_to_height,
                height_to_hash,
            },
        ) => {
            let root = root_of(parent)?;
            let height = hash_to_height.present_value();
            let path = TrieHash::from_key(&hash_to_height_key(&target));
            if !hash_to_height.holds(&path, height.as_ref(), &root, headers) {
                return Err("height proof fails".into());
            }
            let at_height = match height {
                Some(height) => {
                    let path = TrieHash::from_key(&height_to_hash_key(u32::from(height)));
                    let block = height_to_hash.present_value();
                    if !height_to_hash.holds(&path, block.as_ref(), &root, headers) {
                        return Err("block-at-height proof fails".into());
                    }
                    block
                }
                None => None,
            };
            let proven = at_height == Some(MARFValue::from(target.clone()));
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
        _ => Err("wrong kind of proof".into()),
    }
}

/// Re-derive every contract in `proven.contracts` and require each metadata
/// read to match its re-derivation.
fn verify_metadata(
    witness: &ReadWitness,
    proven: &ProvenWitness,
    parent: &StacksBlockId,
    headers: &HeaderChain,
    net: &NetworkParams,
) -> Result<(), Rejection> {
    let mut known = HashMap::new();
    let mut deployed_in = HashMap::new();
    for evidence in proven.contracts.iter() {
        if !headers.is_ancestor(&evidence.block, parent) {
            return Err(reject(
                &evidence.contract,
                "deploy block is not an ancestor",
            ));
        }
        match rederive(evidence, headers, net, &known) {
            Ok(derived) => {
                known.insert(evidence.contract.clone(), derived);
                deployed_in.insert(evidence.contract.to_string(), evidence.block.clone());
            }
            Err(Rederive::Missing(missing)) => {
                return Err(reject(
                    &evidence.contract,
                    format!("not re-derivable from its deploy alone: {missing:?}"),
                ))
            }
            Err(Rederive::Invalid(e)) => return Err(reject(&evidence.contract, e)),
        }
    }
    let rows: HashMap<String, &ContractMetadata> = known
        .iter()
        .map(|(id, (_, rows))| (id.to_string(), rows))
        .collect();
    for (query, answer) in witness.store.iter() {
        let StoreQuery::Metadata {
            block,
            contract,
            key,
        } = query
        else {
            continue;
        };
        let (Some(rows), Some(deployed)) = (rows.get(contract), deployed_in.get(contract)) else {
            return Err(reject(query, "contract not re-derived"));
        };
        if deployed != block {
            return Err(reject(
                query,
                format!("contract was deployed in {deployed}"),
            ));
        }
        let ok = match (answer, rows.get(key)) {
            (Some(read), Some(derived)) => same_metadata(read, derived),
            (None, None) => true,
            _ => false,
        };
        if !ok {
            return Err(reject(query, "metadata differs from its re-derivation"));
        }
    }
    Ok(())
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
    if !inclusion.holds(headers) {
        return Err("burn-view tenure change is not in its block".into());
    }
    let header = headers.get(block).ok_or("unknown block")?;
    let source = headers
        .get(&inclusion.block)
        .ok_or("unknown burn-view block")?;
    // same tenure: an ancestor reached through blocks of this consensus hash
    let mut cursor = headers.get(&header.parent);
    let mut found = false;
    while let Some(h) = cursor {
        if h.consensus_hash != header.consensus_hash {
            break;
        }
        if h.id == source.id {
            found = true;
            break;
        }
        cursor = headers.get(&h.parent);
    }
    if !found {
        return Err("burn-view tenure change is not earlier in this tenure".into());
    }
    tenure_change(&inclusion.tx).ok_or_else(|| "burn-view proof is not a tenure change".into())
}

struct EnvContext<'a> {
    headers: &'a HeaderChain,
    burn: &'a BurnFacts<'a>,
    net: &'a NetworkParams,
    coinbases: &'a [TxInclusion],
    view_sortition: SortitionId,
    view_height: u32,
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
        TipBurnBlockHeight => expect_answer(read, Some(ctx.view_height)),
        TipSortitionId => expect_answer(read, Some(ctx.view_sortition.clone())),
        BurnBlockHeight { sortition } => {
            expect_answer(read, Some(ctx.burn.height_of_sortition(sortition)?))
        }
        SortitionIdFromConsensusHash { consensus_hash } => {
            let (binding, _) = ctx.burn.block_of(consensus_hash)?;
            expect_answer(read, Some(binding.sortition_id()))
        }
        BurnHeaderHash { height, sortition } => {
            if sortition != &ctx.view_sortition {
                return Err("only the burn view's fork is proven".into());
            }
            let expected = if *height > ctx.view_height || *height < ctx.net.first_burn_height {
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
        // (c)/(d): not provable yet
        MinerAddress { .. }
        | TokensSpent { .. }
        | TokensSpentWinning { .. }
        | TokensEarned { .. }
        | PoxPayoutAddrs { .. }
        | StacksHeightForTenureHeight { .. } => Err("not provable yet".into()),
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
