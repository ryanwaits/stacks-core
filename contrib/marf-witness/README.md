# marf-witness

Offline, read-only CLI that extracts per-block **state witnesses** from a Stacks
node's Clarity MARF. A witness lets a client, with no access to the node:

- recompute the block's `state_index_root` from the witness bytes alone, and
- enumerate every leaf of that block's trie: the block's complete write set,
  plus copy-on-write carried leaves and the MARF's own `__MARF_BLOCK_*` keys.

`check` uses witnesses to verify a write log (the fork's `vm_events` rows,
optionally storage-layer writes) block by block, without re-executing.

It also rebuilds the consensus-hash preimage that binds a tenure to its
Bitcoin block, from the sortition DB, and `serve` exposes witnesses,
preimages and Bitcoin headers over a private HTTP sidecar.

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

## Check a write log

```bash
marf-witness check --marf /data/mainnet/chainstate/vm/clarity/marf.sqlite \
  --from 1230000 --to 1230200 --rows rows.jsonl [--writes writes.jsonl] \
  [--rpc http://localhost:20443]
# or: --block <index_block_hash>...   or: --height <h>...
```

`--height`/`--from`/`--to` resolve on the fork of the MARF's most recently
committed block (`summary.tip`). Inputs are JSON lines:

| Flag | Line |
|---|---|
| `--rows <file \| ->` | `{block_height, ordinal, type, tx_id, data}`; `type` is `var_set`, `map_set`, `map_insert`, `map_delete` or `nested_contract_call` (ignored); `data` is the node's event (`contract_identifier`, `var_name` or `map_name`, `raw_key`, `raw_value`) |
| `--writes <file>` | `{block_height, tx_index \| null, ordinal, key, value_hex}`: full MARF key, hex of the side-store value string's bytes |

Per block, without re-executing anything:

1. The witness is extracted in-process; its root must equal the MARF root
   and, with `--rpc`, the header `state_index_root` from `/v3/blocks/<id>`
   (epoch 2.x blocks are not served there: skipped with a note).
2. Each row maps to its MARF key (`vm::<contract>::1::<var>`,
   `vm::<contract>::0::<map>::<raw_key hex>`), which must be a leaf of the
   block (else `key_not_written`). The last write per key, by `ordinal`, must
   match the leaf's value hash (else `value_mismatch`): the stored string is
   `raw_value` for a var, `0a‖raw_value` (`some`) for a map set/insert, `09`
   (`none`) for a map delete. `--writes` entries are checked the same way,
   ordered by `tx_index` (null first) then `ordinal`.
3. Every leaf is classified: `written_named` (by a row or write), `internal`
   (`__MARF_BLOCK_*`, values checked: the block's own height keys use the
   temporary trie hash the MARF builds a block under; the parent's real id
   arrives at `HEIGHT_TO_HASH::{h-1}`), `carried` (copy-on-write: same value
   at the parent), else `unnamed`.

Exit 1 on any row/write failure, root mismatch, block error, or, when
`--writes` is given, any unnamed leaf (rows alone never name account or
token-balance keys, so unnamed leaves are only reported). The report (abridged):

```json
{
  "blocks": [
    {
      "height": 1230200,
      "id": "68df6083…",
      "root": "d7947b1b…",
      "root_ok": true,
      "rows_checked": 2,
      "row_failures": [
        {
          "source": "row",
          "reason": "key_not_written",
          "ordinal": 19,
          "type": "map_set",
          "tx_id": "0xf53d8610…",
          "key": "vm::SP102V8P0F7JX67ARQ77WEA3D3CFB5XW39REDT0AM.amm-vault-v2-01::0::reserve::01000000000000000000078aa28083f47b",
          "path": "2a903200…",
          "expected": "60362327…"
        }
      ],
      "leaves": { "written_named": 1, "internal": 5, "carried": 0, "unnamed": 9 },
      "unnamed_paths": ["00992ddb…", "8b37d712…"]
    }
  ],
  "summary": {
    "ok": false, "blocks": 1, "blocks_failed": 1, "errors": 0,
    "root_mismatches": 0, "rows_checked": 2, "row_failures": 1,
    "unnamed": 9, "rows_unmatched": 0, "tip": "…"
  }
}
```

Failure `source` is `row`, `write` or `internal`; `reason` is
`key_not_written`, `value_mismatch`, `bad_row` or `internal`. `expected` and
`leaf` are value hashes. A block that cannot be checked carries `error` and
counts as failed; the remaining blocks are still checked. `writes_checked`
appears with `--writes`, `notes` when there is something to say.

Wrapper for one block, straight from the indexer DB (`-q` keeps psql from
printing the `SET` tag into the JSON lines):

```bash
N=1230200
psql "$DATABASE_URL" -qAt -c "SET statement_timeout='10s'" -c "
  SELECT json_build_object('block_height', block_height, 'ordinal', ordinal,
                           'type', type, 'tx_id', tx_id, 'data', data)
  FROM vm_events WHERE block_height = $N ORDER BY ordinal" |
marf-witness check --marf /data/mainnet/chainstate/vm/clarity/marf.sqlite \
  --height "$N" --rows - > "check-$N.json"
```

## Serve

A private HTTP sidecar next to a node, for a trustless index to fetch proof
material from. It does **no auth and no rate limiting**: bind it to localhost
behind an API that does both.

```bash
marf-witness serve --working-dir /data/mainnet
# same as:
marf-witness serve \
  --marf /data/mainnet/chainstate/vm/clarity/marf.sqlite \
  --sortition-db /data/mainnet/burnchain/sortition/marf.sqlite \
  --headers-db /data/mainnet/headers.sqlite \
  --listen 127.0.0.1:20450 --max-concurrent-extractions 2 \
  --cache-bytes 268435456 --request-timeout-secs 30
```

An explicit path overrides the one derived from `--working-dir`. Every
database is opened read-only at startup (a missing one is an error), then
once per worker on first use.

| Route | 200 response | Errors |
|---|---|---|
| `GET /witness/{index_block_hash}` | `application/octet-stream`: wire format v3 bytes, identical to `extract`'s `.witness`. Headers `x-block-height`, `x-state-root` (hex), `cache-control: public, max-age=31536000, immutable`, `x-cache: hit\|miss` | 400 bad hash, 404 not in the MARF, 503 + `retry-after: 1` when every extraction slot is busy |
| `GET /burn/{consensus_hash}` | `{consensus_hash, burn_height, bitcoin_block_hash, preimage}`, as `burn` (mainnet first burn height); `preimage[4..36]` is the Bitcoin block hash in display order, no reversal | 400 bad hash, 404 unknown |
| `GET /bitcoin/headers?from=H&count=N` | `{from, headers: [hex of the 80-byte wire header, …]}` in height order, `1 ≤ N ≤ 2016`; truncated at the tip (or a gap), empty past it | 400 bad or missing params |
| `GET /marf/{path}?tip={index_block_hash}` | `{data, proof}`: inclusion proof of the leaf at a 32-byte hashed MARF path as of `tip`. `proof` is `0x` hex of the consensus-serialized `TrieMerkleProof`, byte-identical to a node's `/v2/clarity/marf/{path}?tip=…&proof=1`; `data` is `0x` hex of the leaf's raw 40-byte value | 400 bad path or tip, 404 tip not in the MARF or no such key at `tip` |
| `GET /marf?key={key}&tip={index_block_hash}` | Same, by key string (percent-encoded, at most 4096 bytes decoded), hashed with `TrieHash::from_key` | 400 bad, empty or oversize key, 404 as above |
| `GET /health` | `{ok: true, marf_tip_height, bitcoin_tip_height}` | 503 `{ok: false, …, error}` |

Errors are JSON `{error}`; other methods get 405. Every response closes the
connection. Each served witness is self-checked like `extract`: its
recomputed root must equal the MARF's root, else 500.

`/marf` serves any key, including the MARF's own bookkeeping keys a node's
`/v2/clarity/marf` 404s because they have no stored value string, e.g.
`__MARF_BLOCK_HEIGHT_TO_HASH::<h>`, whose value is the id of the block at
height `h` on `tip`'s fork (zero-padded to 40 bytes):

```bash
curl -s "localhost:20450/marf?key=__MARF_BLOCK_HEIGHT_TO_HASH::150000&tip=<index_block_hash>"
# {"data":"0x7172a926…00000000","proof":"0x…"}
```

Verify it as any node proof: the leaf value is `data`, the root is `tip`'s
`state_index_root`. Upstream stackslib cannot build a proof from read-only
storage: `write_children_hashes`, a pure read, refused it. This branch drops
that check.

Headers come from the SPV DB's columns (`SpvClient` in stackslib's
`burnchains/bitcoin/spv.rs`) re-encoded with stackslib's `BlockHeader`
consensus encoding, so `sha256d(header)` reversed is the block hash and
bytes 4..36 are the previous header's `sha256d`.

How it behaves under load:

- The accept loop only queues connections (64 deep); a full queue gets an
  immediate 503. `max-concurrent-extractions + 8` workers serve the queue,
  each with its own read-only handles, so no handle crosses threads.
- A witness that is not cached takes an extraction slot or gets 503 at
  once, never waiting. Cache hits, burn, headers, `/marf` and health need
  no slot.
- Extracted witnesses live in an LRU bounded by `--cache-bytes` (busy
  mainnet blocks are up to ~12.5 MB) and are served without copying.
- `--request-timeout-secs` is the socket read/write timeout. An extraction
  in progress is not interrupted; the slot limit bounds how many run.
- One log line per request on stderr:
  `method=GET path=/witness/… status=200 bytes=19461 ms=12`.

Run it as the node's uid (it needs read access to the databases and their
`-shm`/`-wal`), niced, on loopback. systemd:

```ini
[Service]
User=stacks
ExecStart=/usr/local/bin/marf-witness serve --working-dir /data/mainnet --listen 127.0.0.1:20450
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=true
Restart=on-failure
```

Docker, sharing the host's loopback and the node's uid (the data mount is
not `:ro`: SQLite maps the node's `-shm` to read a WAL database; the open
flags keep it read-only):

```bash
docker run -d --name marf-witness --restart unless-stopped --network host \
  --user "$(stat -c %u:%g /data/mainnet)" \
  -v /data/mainnet:/data/mainnet \
  -v "$PWD/target/linux-amd64/release/marf-witness:/usr/local/bin/marf-witness:ro" \
  debian:bookworm-slim \
  nice -n 10 marf-witness serve --working-dir /data/mainnet --listen 127.0.0.1:20450
```

A non-loopback `--listen` starts with a warning.

## Read-only guarantees

| Database | How it is opened |
|---|---|
| Clarity MARF (`marf.sqlite`) | `TrieFileStorage::open_readonly`: `SQLITE_OPEN_READ_ONLY`, no table creation or migration (schema mismatch is an error), plus `PRAGMA query_only` |
| MARF blobs (`marf.sqlite.blobs`) | `OpenOptions` read-only, no create |
| Sortition DB, SPV headers DB | `SQLITE_OPEN_READ_ONLY` plus `PRAGMA query_only` |

- A missing database is an error; nothing is created.
- A squashed MARF is refused: its per-block tries below the squash height no
  longer exist. Use an unsquashed (archival) chainstate.
- The tests hash the database and blob files before and after `extract` and
  `serve` and assert they are byte-identical.
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

`check` runs against a MARF built from a known write log (correct logs pass;
a row keyed by the previous value, a wrong final value and a missing write
each fail as expected; carried and internal leaves are never flagged) and,
offline, against mainnet block 1,230,200 (`tests/fixtures/mainnet/`): its
witness plus two rows from the buggy collector, where ordinal 19 (`reserve`
keyed by the previous value) is `key_not_written` and ordinal 22 passes.

`serve` runs against a node-shaped working dir (local MARF, the mainnet
sortition rows, an SPV headers DB of mainnet genesis plus chained headers):
served witnesses equal `extract` output and recompute the MARF root, unknown
blocks are 404, burn returns the mainnet preimage, header ranges come back
in order as 80-byte wire headers (400 past 2016), held slots turn uncached
witnesses into 503 while cache hits still serve, `/marf` proofs of
`__MARF_BLOCK_HEIGHT_TO_HASH::<h>` and stored keys verify against the tip's
root with stackslib's `TrieMerkleProof::verify` and equal the bytes a
read-write MARF builds, and every database file is byte-identical afterwards.

`tests/fixtures/witness/` holds three witnesses with their expected roots for
cross-language verifiers. They are regenerated, deterministically, with:

```bash
MARF_WITNESS_WRITE_FIXTURES=1 cargo test -p marf-witness --test extract
```
