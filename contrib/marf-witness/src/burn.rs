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

//! Consensus-hash preimage from a sortition DB.
//!
//! `consensus_hash = ripemd160(sha256(preimage))` with
//!
//! ```text
//! preimage = SYSTEM_FORK_SET_VERSION ‖ burn_header_hash(32) ‖ ops_hash(32)
//!          ‖ total_burn(u64 BE) ‖ pox_id bit string ‖ prev consensus hashes (≤64 × 20)
//! ```
//!
//! The burn block hash sits at bytes 4..36, so a preimage that reproduces a
//! Stacks header's consensus hash pins that header's tenure to a Bitcoin block.
//! The pox_id is not stored; it is recovered from
//! `sortition_id = sha512/256(burn_header_hash ‖ pox_id)`.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum, hex_bytes, to_hex};
use stackslib::core::SYSTEM_FORK_SET_VERSION;

/// Mainnet's first burnchain block height.
pub const MAINNET_FIRST_BURN_HEIGHT: u64 = 666050;

/// Longest pox_id tried (one bit per reward cycle; mainnet is ~150).
const MAX_POX_ID_LEN: usize = 1024;

#[derive(Debug, Serialize)]
pub struct BurnPreimage {
    pub consensus_hash: String,
    pub burn_height: u64,
    pub bitcoin_block_hash: String,
    pub preimage: String,
}

struct Snapshot {
    height: u64,
    sortition_id: String,
    parent_sortition_id: String,
}

fn hash32(hex: &str, what: &str) -> Result<[u8; 32], String> {
    hex_bytes(hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{what} is not 32 bytes of hex: {hex}"))
}

/// Open the sortition DB strictly read-only.
pub fn open_readonly(path: &Path) -> Result<Connection, String> {
    crate::open_sqlite_readonly(path, "sortition DB")
}

fn snapshot_by_sortition_id(conn: &Connection, id: &str) -> Result<Option<Snapshot>, String> {
    conn.query_row(
        "SELECT block_height, sortition_id, parent_sortition_id \
         FROM snapshots WHERE sortition_id = ?1",
        [id],
        |r| {
            Ok(Snapshot {
                height: r.get::<_, i64>(0)? as u64,
                sortition_id: r.get(1)?,
                parent_sortition_id: r.get(2)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("read snapshot {id}: {e}"))
}

/// Consensus hashes at descending heights on the sortition fork ending at `tip`.
///
/// One row at a height is used directly; when burnchain or PoX forks left
/// several, the fork's parent links are walked to pick the ancestor.
struct ForkWalker<'a> {
    conn: &'a Connection,
    cursor: Snapshot,
}

impl ForkWalker<'_> {
    fn consensus_hash_at(&mut self, height: u64) -> Result<[u8; 20], String> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT consensus_hash FROM snapshots WHERE block_height = ?1")
            .map_err(|e| e.to_string())?;
        let rows: Vec<String> = stmt
            .query_map([height as i64], |r| r.get(0))
            .and_then(|rows| rows.collect())
            .map_err(|e| format!("snapshots at {height}: {e}"))?;
        let ch_hex = match rows.as_slice() {
            // stacks-core hashes in the empty consensus hash when a height has no snapshot
            [] => return Ok([0u8; 20]),
            [only] => only.clone(),
            _ => {
                while self.cursor.height > height {
                    let parent = self.cursor.parent_sortition_id.clone();
                    self.cursor = snapshot_by_sortition_id(self.conn, &parent)?
                        .ok_or_else(|| format!("missing parent sortition {parent}"))?;
                }
                self.conn
                    .query_row(
                        "SELECT consensus_hash FROM snapshots WHERE sortition_id = ?1",
                        [&self.cursor.sortition_id],
                        |r| r.get(0),
                    )
                    .map_err(|e| format!("consensus hash at {height}: {e}"))?
            }
        };
        hex_bytes(&ch_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("bad consensus hash at {height}: {ch_hex}"))
    }
}

/// Recover the PoX fork bit string from `sortition_id = sha512/256(bhh ‖ pox_id)`.
/// Tries the empty (stubbed) id, all-'1' strings, then strings with a single '0'.
fn recover_pox_id(bhh: &[u8; 32], sortition_id: &[u8; 32]) -> Option<String> {
    if bhh == sortition_id {
        return Some(String::new());
    }
    let matches = |pox: &[u8]| {
        let mut buf = Vec::with_capacity(32 + pox.len());
        buf.extend_from_slice(bhh);
        buf.extend_from_slice(pox);
        Sha512Trunc256Sum::from_data(&buf).0 == *sortition_id
    };
    for n in 1..=MAX_POX_ID_LEN {
        let ones = vec![b'1'; n];
        if matches(&ones) {
            return Some(String::from_utf8(ones).expect("ascii"));
        }
    }
    for n in 1..=MAX_POX_ID_LEN {
        let mut s = vec![b'1'; n];
        for j in 0..n {
            s[j] = b'0';
            if matches(&s) {
                return Some(String::from_utf8(s).expect("ascii"));
            }
            s[j] = b'1';
        }
    }
    None
}

/// Rebuild and check the consensus-hash preimage of the snapshot with
/// `consensus_hash`; `None` when the DB has no such snapshot.
pub fn burn_preimage(
    conn: &Connection,
    consensus_hash: &str,
    first_burn_height: u64,
) -> Result<Option<BurnPreimage>, String> {
    let ch: [u8; 20] = hex_bytes(consensus_hash)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("consensus hash is not 20 bytes of hex: {consensus_hash}"))?;
    let ch_hex = to_hex(&ch);

    let snapshot: Option<(i64, String, String, String, String, String)> = conn
        .query_row(
            "SELECT block_height, burn_header_hash, ops_hash, total_burn, sortition_id, \
             parent_sortition_id FROM snapshots WHERE consensus_hash = ?1",
            [&ch_hex],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| format!("read snapshot {ch_hex}: {e}"))?;
    let Some((height, bhh_hex, ops_hex, total_burn, sortition_id, parent_sortition_id)) = snapshot
    else {
        return Ok(None);
    };
    let height = height as u64;
    let bhh = hash32(&bhh_hex, "burn_header_hash")?;
    let ops = hash32(&ops_hex, "ops_hash")?;
    let total_burn: u64 = total_burn
        .parse()
        .map_err(|_| format!("total_burn is not a u64: {total_burn}"))?;
    let pox_id = recover_pox_id(&bhh, &hash32(&sortition_id, "sortition_id")?)
        .ok_or_else(|| format!("could not recover pox_id for sortition {sortition_id}"))?;

    let mut pre = Vec::with_capacity(4 + 32 + 32 + 8 + pox_id.len() + 64 * 20);
    pre.extend_from_slice(&SYSTEM_FORK_SET_VERSION);
    pre.extend_from_slice(&bhh);
    pre.extend_from_slice(&ops);
    pre.extend_from_slice(&total_burn.to_be_bytes());
    pre.extend_from_slice(pox_id.as_bytes());

    // Same walk as ConsensusHash::get_prev_consensus_hashes(parent height, first height).
    let mut walker = ForkWalker {
        conn,
        cursor: Snapshot {
            height,
            sortition_id,
            parent_sortition_id,
        },
    };
    if let Some(parent) = height.checked_sub(1) {
        for i in 0..64u32 {
            let Some(prev) = parent.checked_sub((1u64 << i) - 1) else {
                break;
            };
            if prev < first_burn_height {
                break;
            }
            pre.extend_from_slice(&walker.consensus_hash_at(prev)?);
        }
    }

    if Hash160::from_data(&pre).0 != ch {
        return Err(format!(
            "rebuilt preimage does not hash to consensus hash {ch_hex} \
             (wrong --first-burn-height, or the sortition DB is inconsistent)"
        ));
    }
    Ok(Some(BurnPreimage {
        consensus_hash: ch_hex,
        burn_height: height,
        bitcoin_block_hash: to_hex(&bhh),
        preimage: to_hex(&pre),
    }))
}
