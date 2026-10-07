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

//! Size distribution over an `extract` output directory.

use std::path::Path;

use crate::extract::WitnessMeta;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub min: f64,
    pub median: f64,
    pub p95: f64,
    pub max: f64,
}

/// Nearest-rank percentiles; `None` for no samples.
pub fn summarize(mut xs: Vec<f64>) -> Option<Summary> {
    if xs.is_empty() {
        return None;
    }
    xs.sort_by(f64::total_cmp);
    let rank = |p: f64| xs[((p * xs.len() as f64).ceil() as usize).clamp(1, xs.len()) - 1];
    Some(Summary {
        min: xs[0],
        median: rank(0.5),
        p95: rank(0.95),
        max: xs[xs.len() - 1],
    })
}

pub struct Stats {
    pub count: usize,
    pub per_block: Summary,
    pub per_leaf: Summary,
}

/// Read every `<block>.json` in `dir` and summarize witness bytes per block and per leaf.
pub fn stats(dir: &Path) -> Result<Stats, String> {
    let mut metas = vec![];
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|x| x == "json") {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            let meta: WitnessMeta = serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse {}: {e}", path.display()))?;
            metas.push(meta);
        }
    }
    let per_block = summarize(metas.iter().map(|m| m.bytes as f64).collect())
        .ok_or_else(|| format!("no witness metadata (*.json) in {}", dir.display()))?;
    let per_leaf = summarize(
        metas
            .iter()
            .filter(|m| m.leaves > 0)
            .map(|m| m.bytes as f64 / m.leaves as f64)
            .collect(),
    )
    .ok_or("no witness has leaves")?;
    Ok(Stats {
        count: metas.len(),
        per_block,
        per_leaf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let s = summarize((1..=100).map(f64::from).collect()).unwrap();
        assert_eq!((s.min, s.median, s.p95, s.max), (1.0, 50.0, 95.0, 100.0));
        let one = summarize(vec![7.0]).unwrap();
        assert_eq!(
            (one.min, one.median, one.p95, one.max),
            (7.0, 7.0, 7.0, 7.0)
        );
        assert!(summarize(vec![]).is_none());
    }
}
