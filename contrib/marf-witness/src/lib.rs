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

//! Read-only extraction of per-block MARF state witnesses.
//!
//! A witness lets a client recompute a block's `state_index_root` from the
//! witness bytes alone and enumerate every leaf of that block's trie: the
//! block's complete write set plus copy-on-write carried leaves and the MARF's
//! own `__MARF_BLOCK_*` keys. See `wire` for the format.

pub mod burn;
pub mod check;
pub mod extract;
pub mod stats;
pub mod wire;
