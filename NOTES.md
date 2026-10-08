# Stateless re-execution spike (phase 1)

Goal: prove a block's prints, events and inner calls the way its state diff
is proven. Re-execute the block's transactions (proven by `tx_merkle_root`)
using only a **read witness**: every value execution read, each provable on
its own. If the re-executed writes equal the proven state diff and every
witness entry checks out, the events re-execution produced are the real ones.

```
live block ──► RecordingStore + EnvTap ──► ReadWitness ─┐
                                                        ▼
txs (tx root) + block-level writes ──► execute_statelessly ──► receipts, vm_events, writes
                                                        ▲
                       WitnessStore + EnvTap(witness) ──┘   (missing read = WitnessIncomplete)
```

| Piece | Where |
|---|---|
| Recorder (store wrapper + `HeadersDB`/`BurnStateDB` tap) | `stackslib/src/clarity_vm/read_witness.rs` |
| Wiring (opt-in `ClarityInstance::set_collect_read_witness`, `take_read_witness`) | `clarity_vm/clarity.rs`, receipt `read_witness`, dispatcher arg, replay `ReplayTrace.read_witness` (in-process only) |
| Executor (`execute_statelessly`, witness-only store) | `stackslib/src/clarity_vm/stateless.rs` |
| Tests | `stackslib/src/chainstate/nakamoto/tests/stateless_reexec.rs` |

The executor runs the real `StacksChainState::process_block_transactions`
through `ClarityBlockConnection::from_writable_store` and
`ClarityTx::from_block_connection`. It doesn't reimplement any consensus logic.

## What works (tests)

| Test | Shows |
|---|---|
| `stateless_reexecution_reproduces_live_writes_receipts_and_vm_events` | 7-tx block (nested map/var reads and writes, prints, FT mint/transfer, STX transfer, cross-contract call, `at-block` + `get-stacks-block-info?`/`get-tenure-info?`/`get-burn-block-info?` 2 blocks back, failed tx): re-executed writes == live `state_writes`, writes == block trie leaves, receipts (events, results, `vm_events`, costs) == live |
| `stateless_reexecution_reproduces_the_state_writes_fixture_block` | Same for the 12-tx state-writes fixture (trait args, post-condition abort) |
| `read_witness_entries_hold_at_the_blocks_they_name` | Each `Data` entry equals the MARF value at the parent (or at its `at-block` target); `at-block` targets are ancestors; height lookups match |
| `tampered_parent_read_changes_reexecuted_writes` / `tampered_at_block_read_changes_reexecuted_writes` | A tampered input that feeds a write gets caught |
| `dropped_read_fails_as_witness_incomplete` | A dropped parent read, `at-block` switch or env lookup each fail with `WitnessIncomplete` |
| `tampered_print_only_inputs_change_events_but_not_writes` | **A read that only feeds a print changes no write.** Matching writes don't prove the events, so each witness entry has to be proven on its own |
| `block_replay_reads_at_block_values_at_the_named_block` | Regression test for the replay bug below |
| `block_replay_records_the_live_read_witness` | Replay's witness equals the live one exactly, and re-executing from it reproduces the live block |

## Measurements (test blocks)

| Block | txs | writes (tx / block-level) | distinct keys | parent reads | at-block reads | height/switch lookups | metadata reads | env lookups | MARF bytes | metadata bytes | env bytes | re-exec |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| history fixture | 7 | 25 / 1 | 10 | 18 | 2 | 5 | 10 | 14 | 2.3 KB | 88.7 KB | 1.5 KB | ~1.7–2.3 ms |
| state-writes fixture | 12 | 37 / 1 | 13 | 18 | 0 | 3 | 8 | 5 | 2.1 KB | 84.8 KB | 0.4 KB | ~2–5 ms |

- Reads are about the same count as distinct writes, and the MARF part is small.
- About 95% of the bytes are contract metadata (`vm-metadata::9::contract` = stored AST + analysis). `costs-3` alone is 76 KB, read by the cost tracker in every block. A client should keep boot contracts locally and derive user contracts from their source (see gaps), not download metadata.
- Re-execution is milliseconds. Test profile is optimized + debuginfo, on Apple silicon.

## What gets read

Store reads (`StoreQuery`). An open-block read is recorded only if the block
hasn't written that key yet, so its answer is the parent's value. After the
block writes a key, later reads come from the executor's overlay.

| Kind | Examples seen | Provable against |
|---|---|---|
| `Data{at: None}` | `vm::<c>::{0..4}::…`, `vm-account::<p>::{18,19}`, `clarity-contract::<c>`, `vm-epoch::epoch-version`, `_stx-data::tenure_height`, `_stx-data::ustx_liquid_supply`, `chainstate_pox::handled_cycle_start::N`, `vm::…lockup::0::lockups::…` | parent `state_index_root` |
| `Data{at: Some(X)}` | `at-block` reads (`counter`, FT balance at block X) | X's `state_index_root` |
| `AtBlock{target}` | `at-block` switch (ok / not an ancestor) | parent root: `__MARF_BLOCK_HASH_TO_HEIGHT::X` |
| `BlockAtHeight{at, h}` | contract-commitment heights, `get-stacks-block-info?` height to id | parent root: `__MARF_BLOCK_HEIGHT_TO_HASH::h`. Exception: h = open height, which returns the miner placeholder id (deterministic) |
| `CurrentHeight{at: X}` | height inside `at-block` | X's root: `__MARF_BLOCK_HEIGHT_SELF` |
| `Metadata{block, contract, key}` | `vm-metadata::9::contract`/`contract-size`/`contract-data-size`, `vm-metadata::5::<map>` | **Can't be checked with a MARF proof** (side table). See gaps |

Environment lookups (`EnvTap`, keyed by method plus args). Seen in the
fixtures: `stacks_block_time_for_block`,
`stacks_block_header_hash_for_block`, `burn_block_time_for_block`,
`burn_block_height_for_block`, `vrf_seed_for_block`, `tip_burn_block_height`,
`tip_sortition_id`, `burn_header_hash(h, sortition)`, `stacks_epoch(h)`, and the
`v{1,2,3}_unlock_height` constants.

Lookups that needed special handling:

- **`at-block`.** The recorder tracks the current tip. Reads inside `at-block` are keyed by the target. The switch itself is a witness entry. Switching back to the open block isn't recorded. Height at the open block is `open_height`, which is deterministic.
- **Metadata.** The recorder sends `get_contract_hash` / `get_metadata` back through itself, so the commitment and height lookups that resolve the deploying block get recorded too. Metadata from contracts deployed earlier in the same block stays in the overlay.
- **PoX special-case handler.** The witness store has to return `handle_contract_call_special_cases`, or stacking calls diverge.
- **The env traits have no error channel.** A missing answer returns `None` or `0`, gets logged, and the executor reports `WitnessIncomplete` after the run. Store misses also raise a VM internal error.
- **Answers are typed in memory** (`Arc<dyn Any>` + `Debug` text), because `StacksEpoch` / `TupleData` answers don't serialize. Phase 2 needs a wire format.
- **Epoch and block cost limit** are captured at `begin_block`.
- **Block-level writes** (setup before the first tx, teardown after the last) are inputs here, not re-executed (`BlockLevelWrites::split`). Their inputs (matured rewards, burn ops, reward sets) live in the sortition/headers SQLite DBs.
- **Initial tenure cost** starts at zero. For a valid block it only feeds the block-limit check: receipt costs are deltas and matched live.

## Why `/v3/blocks/replay` diverged for historical-lookup contracts

`EphemeralMarfStore::set_block_hash` (the replay store) handled a
disk-backed target by checking that it is an ancestor, then only flipping
`open_tip`. It never re-pointed `read_only_marf`, so every read inside
`at-block X` was served at the replay's base tip, which is the parent. Height
inside `at-block` came from the parent too.

In the test, `(at-block <2 blocks back> (var-get counter))` returned `u15`
(the parent's value) under replay and `u5` live.

`sbtc-yield-rewards-v3` reads balances with `at-block` +
`get-stacks-block-info? id-header-hash`, so under replay it saw parent-state
values where it expected the snapshot block's. That is consistent with
printing 0 instead of the real balance. I didn't inspect the contract source.

Fix: `f0f9d6b` (one line: `read_only_marf.set_block_hash(bhh)`). Worth sending
upstream.

There is a second, untested source of divergence: replay builds its burn view
with `sortdb.index_handle_at_block(parent)`, while live processing uses the
tenure-change burn view. For tenure-start or extend blocks,
`burn-block-height`, `get-burn-block-info?` and the tip sortition can differ.
The fixture block is mid-tenure, where the two agree.

**Does the read witness fix this by construction? Only together with
per-entry proofs.**

- A witness recorded by the buggy replay records the wrong values faithfully, and re-execution reproduces them faithfully.
- If the `at-block` value only feeds a print, the writes still match, so the write comparison can't catch it.
- What catches it is the entry's own proof: `Data{at: X, key}` must verify against X's root, and the parent's value fails that check.
- With proofs, a buggy or lying server can't make a client accept wrong history.

## How a client verifies each entry

| Entry | Check |
|---|---|
| tx list | `tx_merkle_root` in a signer-signed header |
| `Data{at: None}` / `Path` | MARF proof of `TrieHash::from_key(key)` → `MARFValue::from_value(value)` against the parent's `state_index_root`. The leaf commits to `hash(value string)`. `None` needs a **non-membership** proof |
| `Data{at: X}`, `CurrentHeight{X}` | Same, against X's root. X's header comes from the authenticated header chain |
| `AtBlock`, `BlockAtHeight` | MARF bookkeeping leaves against the parent's root. Not an ancestor = non-membership |
| `Metadata` | Get the deploy tx (tx root of block `block`), check `hash(source)` against the `clarity-contract::` commitment (a proven `Data` read), re-run analysis under that block's epoch and Clarity version, and compare. Boot contracts: ship locally |
| header env (`stacks_block_header_hash`, `stacks_block_time`, `consensus_hash`, `burn_block_height_for_block`) | Authenticated headers. Id = hash(consensus_hash, block_hash) |
| burn env (`burn_header_hash`, `burn_block_time`, `tip_burn_block_height`, `tip_sortition_id`) | Consensus-hash preimage (marf-witness `burn`) plus Bitcoin headers, under the block's burn view (tenure-change tx) |
| `vrf_seed_for_block` | VRF proof in the tenure's coinbase tx (proven by tx root) |
| `miner_address`, `tokens_spent_*`, `tokens_earned`, `pox_payout_addrs` | Block-commit Bitcoin tx plus sortition rules / reward accounting. Not covered |
| epochs, unlock heights, PoX lengths | Network constants |
| block-level writes | Compare with the proven state diff where no tx overwrites the key. Otherwise the check is only indirect |
| final | Re-executed writes == proven state diff (marf-witness); receipts are the output |

## Gaps

1. **Non-membership proofs.** In the fixture, 5 of 18 parent reads were `None` (absent map entry, zero balance, unhandled cycle). MARF ships inclusion proofs (`get_with_proof`) but no absence proofs. A path walk over trie nodes (like the state witness) or a new proof type is needed.
2. **Metadata is about 95% of bytes and can't be MARF-proven.** It needs deterministic re-analysis (version- and epoch-sensitive) or an AST cache keyed by source hash.
3. **Block-level writes aren't re-executed.** Lockup, unlock and SIP-031 events attached to the coinbase receipt are block-level and are not covered.
4. **Env authentication for burnchain-derived answers** (spend, payout, reward) isn't covered. Neither is the burn view for replayed tenure-start/extend blocks.
5. Epoch 2.x / microblocks and problematic-tx markers: the executor takes `TxToProcess`, but the tests don't cover them.
6. The witness has no wire format yet. Env answers are typed in memory.

## Phase 2: a mainnet block via replay on a fixed-image node

- Build a node image from this branch. It needs `f0f9d6b`, or replay witnesses are wrong for `at-block`.
- Add a `read_witness=1` replay query flag and a JSON wire format:
  - store: `{kind, at, key | path | height, value_hex | null}`
  - env: `{method, args, answer}` as typed JSON (needs serde for `StacksEpoch` and `TupleData`).
- Fix the replay burn view to match live: use the block's tenure-change burn view, not `index_handle_at_block(parent)`.
- First target: the `sbtc-yield-rewards-v3` block.
  - Replay with witness, re-execute offline.
  - Compare the writes to that block's marf-witness state diff, and the prints to live `/new_block`.
- Produce a proof per entry: MARF `get_with_proof` at the parent or the `at-block` target, plus absence proofs. Measure proof bytes against witness bytes on real blocks.
- Client cache for boot-contract metadata (`costs-3`, `pox-4`, …).
