# marf-witness

Offline, read-only CLI that extracts per-block **state witnesses** from a Stacks
node's Clarity MARF. A witness lets a client, with no access to the node:

- recompute the block's `state_index_root` from the witness bytes alone, and
- enumerate every leaf of that block's trie: the block's complete write set,
  plus copy-on-write carried leaves and the MARF's own `__MARF_BLOCK_*` keys.

It also rebuilds the consensus-hash preimage that binds a tenure to its
Bitcoin block, from the sortition DB.

## Build

From the repository root:

```bash
cargo build -p marf-witness --release
```

### Linux x86_64 binary (to run next to a node)

Build in the pinned toolchain's image so the binary matches the node host:

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD":/src -w /src \
  -e CARGO_TARGET_DIR=/src/target/linux-amd64 \
  rust:1.98-bookworm \
  cargo build -p marf-witness --release
# -> target/linux-amd64/release/marf-witness
```

SQLite is bundled (rusqlite `bundled`), so the binary only needs glibc.

## Usage

```bash
# Witnesses for explicit blocks, or for a tip and its N-1 ancestors
marf-witness extract --marf /data/mainnet/chainstate/vm/clarity/marf.sqlite \
  --block <index_block_hash> [<index_block_hash>...] --out ./witnesses
marf-witness extract --marf /data/mainnet/chainstate/vm/clarity/marf.sqlite \
  --tip <index_block_hash> --count 1000 --out ./witnesses

# Recompute a root from bytes only (exit 1 on mismatch with --root)
marf-witness verify ./witnesses/<block>.witness --root <state_index_root hex>

# Consensus-hash preimage for a tenure (bytes 4..36 = Bitcoin block hash)
marf-witness burn --sortition-db /data/mainnet/burnchain/sortition/marf.sqlite \
  --consensus-hash <hex> [--first-burn-height 666050]

# Size distribution of an extract run
marf-witness stats ./witnesses
```

`extract` writes `<block>.witness` (wire format v2, see `src/wire.rs`) and
`<block>.json`:

```json
{ "block": "…", "height": 123, "root_hex": "…", "leaves": 68, "nodes": 135, "bytes": 19461 }
```

Before writing, every witness is verified and its recomputed root must equal
the MARF's root for that block; otherwise extraction stops with an error.

## Read-only guarantees

| Database | How it is opened |
|---|---|
| Clarity MARF (`marf.sqlite`) | `TrieFileStorage::open_readonly`: `SQLITE_OPEN_READ_ONLY`, no table creation or migration (schema mismatch is an error), plus `PRAGMA query_only` |
| MARF blobs (`marf.sqlite.blobs`) | `OpenOptions` read-only, no create |
| Sortition DB | `SQLITE_OPEN_READ_ONLY` plus `PRAGMA query_only` |

- A missing database is an error; nothing is created.
- A squashed MARF is refused: its per-block tries below the squash height no
  longer exist. Use an unsquashed (archival) chainstate.
- The tests hash the database and blob files before and after `extract` and
  assert they are byte-identical.
- SQLite itself needs `-shm`/`-wal` files to read a WAL-mode database. A running
  node already has them; on a stopped node's copy, SQLite creates them (the
  `-wal` stays empty). Nothing else is written next to the databases.

## Tests

```bash
cargo test -p marf-witness
```

Builds local MARFs (300 blocks, 5-700 writes per block, a sibling fork, a
compressed variant, a squashed copy) and checks read-only access, root
equality for every block, write completeness, tamper detection, and the burn
preimage against mainnet sortition rows for burn block 970269.

`tests/fixtures/witness/` holds three witnesses with their expected roots for
cross-language verifiers. They are regenerated, deterministically, with:

```bash
MARF_WITNESS_WRITE_FIXTURES=1 cargo test -p marf-witness --test extract
```
