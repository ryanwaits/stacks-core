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

//! Storage-layer record of every Clarity MARF write a block makes.
//!
//! The collector sits in the writable MARF stores' `put_all_data`, below the
//! Clarity evaluator, so it sees exactly the `(key, value)` pairs that reach the
//! trie. Writes from a Clarity transaction only get there when that transaction
//! commits: anything rolled back (an aborted transaction, a post-condition
//! abort's payload, a failed nested call) never reaches `put_all_data` and so is
//! never recorded.
//!
//! Encoding of what is recorded (see `clarity::vm::database::clarity_db`):
//!
//! | write                  | key                                         | value string                       |
//! |------------------------|---------------------------------------------|------------------------------------|
//! | `var-set`              | `vm::<contract>::1::<var>`                  | serialized value hex               |
//! | `map-set`/`map-insert` | `vm::<contract>::0::<map>::<key value hex>` | serialized `(some v)` hex (`0a..`) |
//! | `map-delete`           | same as `map-set`                           | serialized `none` hex (`09`)       |
//! | FT balance             | `vm::<contract>::2::<token>::<principal json>` | JSON number, e.g. `100`         |
//! | FT supply              | `vm::<contract>::3::<token>`                | JSON number                        |
//! | NFT owner              | `vm::<contract>::4::<token>::<asset value hex>` | `(some principal)` / `none` hex |
//! | STX balance            | `vm-account::<principal>::19`               | `STXBalance` bytes as hex          |
//! | nonce                  | `vm-account::<principal>::18`               | JSON number                        |
//! | contract commitment    | `clarity-contract::<contract>`              | source hash hex + height hex       |
//!
//! Values are not always hex, so consumers get the raw value string's bytes
//! as `value_hex`. The MARF leaf for a write is
//! `TrieHash::from_key(key) -> MARFValue::from_value(value)`.
//!
//! The MARF's own bookkeeping keys (`__MARF_BLOCK_HEIGHT_SELF`,
//! `__MARF_BLOCK_HEIGHT_TO_HASH::*`, `__MARF_BLOCK_HASH_TO_HEIGHT::*`) are
//! inserted by the MARF itself when a block trie is opened, not through
//! `put_all_data`, and are never recorded. Contract metadata (`vm-metadata::*`)
//! lives in the side table, not the trie, and is not recorded either.

use std::collections::HashMap;

use stacks_common::types::chainstate::Txid;
use stacks_common::util::hash::to_hex;

/// One `(key, value)` pair handed to a writable MARF store's `put_all_data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWrite {
    /// The transaction (or burnchain operation) whose execution made the write,
    /// or `None` for a block-level write made outside any transaction (block
    /// setup and teardown: matured rewards, PoX unlocks, epoch transitions,
    /// tenure bookkeeping, signer-set updates).
    pub txid: Option<Txid>,
    /// MARF key string. The trie path is `TrieHash::from_key(&key)`.
    pub key: String,
    /// Side-store value string. The leaf value is `MARFValue::from_value(&value)`.
    pub value: String,
}

/// In-order record of a block's MARF writes. A store only carries one when
/// collection is enabled, so the off path is a single `Option` check.
#[derive(Debug, Default)]
pub struct StateWriteLog {
    owner: Option<Txid>,
    writes: Vec<StateWrite>,
}

impl StateWriteLog {
    pub fn record(&mut self, key: &str, value: &str) {
        self.writes.push(StateWrite {
            txid: self.owner.clone(),
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    /// Attribute subsequent writes to `owner` (`None` = block-level).
    pub fn set_owner(&mut self, owner: Option<Txid>) {
        self.owner = owner;
    }

    /// Take every write recorded so far, in write order.
    pub fn take(&mut self) -> Vec<StateWrite> {
        std::mem::take(&mut self.writes)
    }
}

/// Wire form of one write in `/new_block.state_writes` and the block replay
/// response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateWriteEntry {
    /// `tx_index` of the producing transaction in the same payload's
    /// `transactions` array, or `null` for a block-level write.
    pub tx_index: Option<u32>,
    /// Position of this write in the block's write order, from 0.
    pub ordinal: u32,
    /// MARF key string.
    pub key: String,
    /// Hex of the side-store value string's bytes.
    pub value_hex: String,
}

/// Resolve each write's producing transaction to its `tx_index`. `tx_index_of`
/// maps a txid to its index in the payload's transaction list; a write whose
/// owner is absent from it (an operation that produced no receipt) is reported
/// as block-level.
pub fn state_write_entries(
    writes: &[StateWrite],
    tx_index_of: &HashMap<Txid, u32>,
) -> Vec<StateWriteEntry> {
    writes
        .iter()
        .enumerate()
        .map(|(ordinal, write)| StateWriteEntry {
            tx_index: write
                .txid
                .as_ref()
                .and_then(|txid| tx_index_of.get(txid).copied()),
            ordinal: u32::try_from(ordinal).expect("more than u32::MAX state writes in a block"),
            key: write.key.clone(),
            value_hex: to_hex(write.value.as_bytes()),
        })
        .collect()
}

/// Map each txid to its position in `txids`; the first occurrence wins.
pub fn tx_index_map(txids: impl IntoIterator<Item = Txid>) -> HashMap<Txid, u32> {
    let mut map = HashMap::new();
    for (i, txid) in txids.into_iter().enumerate() {
        map.entry(txid)
            .or_insert(u32::try_from(i).expect("more than u32::MAX transactions in a block"));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_resolve_owners_to_tx_index_and_keep_write_order() {
        let (a, b, unknown) = (Txid([1; 32]), Txid([2; 32]), Txid([3; 32]));
        let mut log = StateWriteLog::default();
        log.record("block-level", "1");
        log.set_owner(Some(b.clone()));
        log.record("k", "0a01");
        log.set_owner(Some(unknown));
        log.record("no-receipt", "x");
        log.set_owner(None);
        log.record("teardown", "2");

        let tx_index_of = tx_index_map([a, b.clone(), b]);
        let entries = state_write_entries(&log.take(), &tx_index_of);
        let summary: Vec<_> = entries
            .iter()
            .map(|e| (e.tx_index, e.ordinal, e.key.as_str(), e.value_hex.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (None, 0, "block-level", "31"),
                (Some(1), 1, "k", "30613031"),
                (None, 2, "no-receipt", "78"),
                (None, 3, "teardown", "32"),
            ]
        );
        assert!(log.take().is_empty());
    }
}
