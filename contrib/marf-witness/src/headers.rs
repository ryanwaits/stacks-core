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

//! Bitcoin block headers from the node's SPV headers DB (`headers.sqlite`).
//!
//! The node stores each header's fields in columns (`SpvClient` in
//! stackslib's `burnchains/bitcoin/spv.rs`): `version`, `time`, `bits`,
//! `nonce` as integers and `prev_blockhash`, `merkle_root` as display-order
//! (byte-reversed) hex. They are reassembled into Bitcoin's 80-byte wire
//! header with stackslib's own `BlockHeader` encoding, so
//! `sha256d(header)` reversed is the block hash.

use std::path::Path;

use rusqlite::Connection;
use stacks_common::deps_common::bitcoin::blockdata::block::BlockHeader;
use stacks_common::deps_common::bitcoin::network::serialize::serialize;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;

/// Most headers returned by one read: one difficulty adjustment period.
pub const MAX_HEADERS: u64 = 2016;

/// Open the SPV headers DB strictly read-only.
pub fn open_readonly(path: &Path) -> Result<Connection, String> {
    crate::open_sqlite_readonly(path, "headers DB")
}

/// Highest stored header height, or `None` for an empty DB.
pub fn tip_height(conn: &Connection) -> Result<Option<u64>, String> {
    conn.query_row("SELECT MAX(height) FROM headers", [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .map(|h| h.map(|h| h as u64))
    .map_err(|e| format!("headers tip: {e}"))
}

fn hash_column(row: &rusqlite::Row, col: &str, height: i64) -> rusqlite::Result<Sha256dHash> {
    let hex: String = row.get(col)?;
    Sha256dHash::from_hex(&hex).map_err(|_| {
        rusqlite::Error::InvalidColumnType(
            0,
            format!("{col} at height {height}: {hex}"),
            rusqlite::types::Type::Text,
        )
    })
}

/// Up to `count` consecutive 80-byte headers starting at `from`, in height
/// order. Stops early at the tip or at the first missing height.
pub fn read_headers(conn: &Connection, from: u64, count: u64) -> Result<Vec<[u8; 80]>, String> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT height, version, prev_blockhash, merkle_root, time, bits, nonce \
             FROM headers WHERE height >= ?1 AND height < ?2 ORDER BY height",
        )
        .map_err(|e| format!("read headers: {e}"))?;
    let end = from.saturating_add(count);
    let rows = stmt
        .query_map([from as i64, end.min(i64::MAX as u64) as i64], |r| {
            let height: i64 = r.get("height")?;
            Ok((
                height as u64,
                BlockHeader {
                    version: r.get("version")?,
                    prev_blockhash: hash_column(r, "prev_blockhash", height)?,
                    merkle_root: hash_column(r, "merkle_root", height)?,
                    time: r.get("time")?,
                    bits: r.get("bits")?,
                    nonce: r.get("nonce")?,
                },
            ))
        })
        .map_err(|e| format!("read headers from {from}: {e}"))?;
    let mut out = Vec::new();
    for (expected, row) in (from..).zip(rows) {
        let (height, header) = row.map_err(|e| format!("read headers from {from}: {e}"))?;
        if height != expected {
            break;
        }
        let bytes = serialize(&header).map_err(|e| format!("encode header {height}: {e:?}"))?;
        out.push(
            bytes
                .try_into()
                .map_err(|b: Vec<u8>| format!("header {height} encodes to {} bytes", b.len()))?,
        );
    }
    Ok(out)
}
