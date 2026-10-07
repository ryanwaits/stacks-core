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

`extract` writes `<block>.witness` (wire format v3, see below) and
`<block>.json`:

```json
{ "block": "…", "height": 123, "root_hex": "…", "leaves": 68, "nodes": 135, "bytes": 19461 }
```

Before writing, every witness is verified and its recomputed root must equal
the MARF's root for that block. A block that fails is reported on stderr with
its id and skipped; the rest still extract, and the exit status is 1.

## Wire format v3

```text
witness := u8 version=3 | u32 n_anc | [32]*n_anc ancestor roots
         | u32 n_tbl | [32]*n_tbl ancestor block ids | node
node    := u8 id | u8 path_len | path | u16 n_ptrs | ptr* | child*   (one child per local ptr, in order)
ptr     := u8 id | (id != 0: u8 chr) | (id & 0x80: u32 table index)
leaf    := u8 1 | u8 path_len | path | [32] value hash
```

Big-endian. Node ids: 1 leaf, 2/3/4/5 = Node4/16/48/256 (`n_ptrs` 4/16/48/256);
`id & 0x80` marks a backptr into an ancestor trie. A ptr is 1 byte (empty),
2 (local) or 6 (backptr); each distinct ancestor block costs 32 bytes once.
v3 widens v2's u16 counts and table indexes: busy mainnet blocks reference
more than 65,535 ancestor tries. Hashing is documented in `src/wire.rs`.

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
equality for every block, write completeness, tamper detection, a witness
with more than 65,535 ancestor blocks, and the burn preimage against mainnet
sortition rows for burn block 970269.

`tests/fixtures/witness/` holds three witnesses with their expected roots for
cross-language verifiers. They are regenerated, deterministically, with:

```bash
MARF_WITNESS_WRITE_FIXTURES=1 cargo test -p marf-witness --test extract
```
