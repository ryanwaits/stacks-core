# Stateless re-execution spike

Phase 1 (below, through "Why replay diverged"): re-execute a block from a
read witness. Phase 2a (after it): make every witness entry provable and
verify it. Phase 2b prep: serve the proof-carrying witness from
`/v3/blocks/replay`, a wire format, and a client that verifies and
re-executes a mainnet block. Phase 2c (last): deploy witnesses for
contracts whose deploy reads chain state, and one shared MARF proof per
served witness instead of one proof per read (wire format v2).

# Phase 1: re-execute from a read witness

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

# Phase 2a: proof-carrying witness

Rebased onto `6e005af` (dispatcher emits microblock receipts first). It
applied cleanly: the dispatcher keeps both the `_read_witness` argument and
the microblock-first partition. Phase-1 tests pass.

Phase 1 showed the gap: a read that only feeds a print changes no write, so
matching the state diff proves nothing about events. Phase 2a gives every
witness entry its own evidence and adds a verifier.

```
node (prover)                                  client (verifier)
ReadWitness ─► prove_store_reads   ─► StoreProof per entry ─┐
            ─► prove_contracts     ─► ContractEvidence      ├─► verify_read_witness ─► execute_statelessly
            ─► burn preimages, tenure txs                   │     ▲
                                                            │     HeaderChain + BitcoinChain + NetworkParams
                                                            └─► Ok | Rejection { entry, reason }
```

| Piece | Where |
|---|---|
| MARF absence proofs | `stackslib/src/chainstate/stacks/index/absence.rs`, tests in `index/test/absence.rs` |
| Evidence types, prover, verifier | `stackslib/src/clarity_vm/witness_proof.rs` |
| Metadata re-derivation | `stateless.rs::derive_contract_metadata` |
| Typed environment queries (`EnvQuery`) | `read_witness.rs` |
| Clarity-level tests | `stackslib/src/chainstate/nakamoto/tests/proven_witness.rs` |

`verify_read_witness(block, txs, trusted, proven)` takes the block id, its
transactions and `TrustedState { headers, bitcoin, net }`. The parent root and
every `at-block` root come from the header chain, so they are not separate
arguments. It checks the tx list against the header's tx root, then every
store entry, the metadata, and every environment lookup. It returns the first
failing entry.

## Absence proofs

Superseded in phase 2c: absence is now a walk of the shared proof that ends
without a leaf (`index/multiproof.rs`), and `absence.rs` is gone. The
semantics below (where a walk ends, "absent" = never written) still hold.

The MARF only had inclusion proofs. An absence proof is the read's own walk:
start at the tip trie's root and follow back-pointers into ancestor tries,
exactly as `MARF::walk` does, until the walk stops without a leaf for the key.

- **Shape.** Same as an inclusion proof: one segment proof per trie, oldest first. Shunt proofs link each trie's root into the next trie's skip-list. The difference is the deepest node. Instead of the value's leaf, the proof carries the node where the walk ended, whole, with every child hash (`AbsenceEnd`):
  - an intermediate node with no child, not even a back-pointer, at the key's next byte, or
  - a node whose compressed path, or a leaf whose remaining path, differs from the key's.
- **Hashing.** The MARF's own: a back-pointer child hashes as the ancestor block id, an empty child as `TrieHash::EMPTY`, a trie root as its node hash plus its ancestors' roots (the skip-list).
- **Verifier.** It accepts only if all of these hold:
  - the bytes walked above the end node are a prefix of the key;
  - the end node shows the key cannot continue;
  - every newer trie's segment walks a prefix of that path;
  - the hash chain reaches the root. This reuses the inclusion verifier's chain check (`verify_proof_chain`, refactored out of `verify_proof`).
- **Inclusion verifier hardening.** The chain check now rejects a node with the wrong number of children. Before, `get_segment_proof_hash` asserted on it and a malformed proof panicked.
- **No deletions.** `map-delete` writes a none value, so "absent" means never written on this fork.

| Test (`index/test/absence.rs`, 8-block MARF, 40 keys per block) | Shows |
|---|---|
| `absent_paths_verify_and_present_paths_cannot_be_proven_absent` | 300 absent keys verify, with both leaf ends and node ends, including walks across back-pointers. The prover refuses all 320 written keys |
| `near_miss_of_a_written_leaf_is_absent_but_the_leaf_is_not` | A path one byte off a written key (bytes 31, 20, 5, 1) is provably absent and ends at that leaf. The same proof fails for the written key, and so does the written key's inclusion proof dressed as an absence proof |
| `tampering_with_any_part_of_an_absence_proof_breaks_it` | Flipping an end-node child hash, emptying an occupied child slot, or changing any segment node or shunt hash fails. A different root fails too |
| `absence_holds_until_the_block_that_writes_the_key` | A key written in block 5 is provably absent at block 4, through a root back-pointer into block 0. That proof fails at block 5 and the tip, where only inclusion proves |

## Store entries

| Entry | Evidence |
|---|---|
| `Data` / `Path` at the open block | Inclusion or absence proof against the parent's `state_index_root` |
| `Data` / `Path` inside `at-block X` | Same, against X's root from its header |
| `CurrentHeight { at: X }` | `__MARF_BLOCK_HEIGHT_SELF` at X |
| `BlockAtHeight { h }` | `__MARF_BLOCK_HEIGHT_TO_HASH::h` at the parent, or at X inside `at-block`. Deterministic, no proof: h = open height gives the miner tip; h = open height - 1 gives the parent id; inside `at-block X` with h = X's height gives X (MARF shortcut) |
| `AtBlock { X }` | `__MARF_BLOCK_HASH_TO_HEIGHT::X` and back, at the parent (`check_ancestor_block_hash`). Not an ancestor: absence, or a mismatched height. X = parent is deterministic |
| `Metadata` | Re-derived (next section) |

Two findings fixed the special cases:

- **The open trie rewrites its parent's height-to-hash entry.** A processed Nakamoto block's own trie maps its height to the miner placeholder id. The child trie rewrites it to the real id. So `BlockAtHeight(parent height)` can't be proven against the parent root, and the verifier derives it from the parent id instead.
- **The genesis header has a zero `state_index_root`.** The client pins the genesis MARF root (boot code plus allocations) as a network constant. Every other header root equals the MARF root.

## Contract metadata

Contract metadata is not in the MARF. What the MARF does commit is
`clarity-contract::<id>` = sha512/256(source) plus the deploy height
(`ContractCommitment`, written by `insert_contract_hash`). Boot contracts get
the same commitment, because epoch transitions deploy them as synthetic
boot-code transactions through the same path.

Evidence per contract (`ContractEvidence`):

- the deploying block D (an ancestor, header authenticated);
- the commitment at D's root (inclusion proof);
- `vm-epoch::epoch-version` at D's root (inclusion proof, or absence, which means 2.0);
- the source: for a user contract, the deploy tx plus its Merkle path to D's tx root; for a boot contract, the client's bundled boot code.

The verifier:

1. Checks that hash(source) equals the commitment and the commitment height equals D's height.
2. Re-runs the real deploy path (`process_transaction_payload`: analysis, initialization, `save_analysis`). It runs in an empty, unmetered store that holds only contracts already derived.
3. Compares every witnessed metadata row with its re-derivation. `ContractContext` serializes hash maps and sets, so JSON is compared up to their order.

**Dependencies.** The prover finds them by re-deriving and reading which commitment was missing: `relay` needs `ledger`, and the state-writes fixture needs `tok-impl`. The verifier re-derives in that order.

**Limit.** Any other read during re-derivation fails as `WitnessIncomplete`. A contract whose initialization reads chain state (a top-level `contract-call?`, balances, block info) needs the deploy block's own witness. That recursion is phase 2b or later.

**Boot table.** `pox`, `lockup`, `costs`, `cost-voting`, `bns`, `genesis`, `costs-2`, `pox-2`, `costs-3`, `pox-3`, `pox-4`, `signers`, `signers-{0,1}-{0..12}` (the signer StackerDBs), `signers-voting`, `sip-031` (generated body), `costs-4` and `pox-5` (generated body), each with the Clarity version its transition pins. In the fixtures, `lockup` and `costs-3` are read every block. Both re-derive. Mainnet sources: see phase 2b.

**Cost.** Re-derivation is about 90% of verify time (below). Cache the results by source hash; boot contracts need it once per network.

## Environment lookups

| Lookup (`EnvQuery`) | Clarity surface | Class | Verified by |
|---|---|---|---|
| `StacksBlockHeaderHash` | `get-stacks-block-info? header-hash`, `get-block-info? header-hash` | a | Header block hash (or none if the epoch picks the other header table) |
| `ConsensusHashForBlock` | tenure lookups | a | Header consensus hash |
| `StacksBlockTime` | `get-stacks-block-info? time`, `stacks-block-time` | a | Nakamoto header timestamp. None for 2.x |
| `VrfSeed` | `get-tenure-info? vrf-seed`, `get-block-info? vrf-seed` | a | Nakamoto: the tenure coinbase's VRF proof, with a tx Merkle path in a block of that tenure (a coinbase only appears in a tenure's first block). 2.x: the header's VRF proof |
| `BurnHeaderHashForBlock` | `get-block-info? burnchain-header-hash`, `get-tenure-info? burnchain-header-hash` | b | Preimage of the header's consensus hash |
| `BurnBlockHeightForBlock` | epoch of the parent, tenure info | b | Preimage, then that Bitcoin block's height |
| `BurnBlockTime` | `get-block-info? time`, `get-tenure-info? time` | b | Bitcoin header timestamp |
| `TipBurnBlockHeight` | `burn-block-height` | b | Burn view preimage, then Bitcoin height |
| `TipSortitionId` | key for burn lookups | b | sha512/256(burn hash ‖ pox_id), both from the burn view preimage |
| `BurnHeaderHash(h, sortition)` | `get-burn-block-info? header-hash` | b | Bitcoin header at h, if first burn height ≤ h ≤ burn view. Only the burn view's sortition is accepted |
| `BurnBlockHeight(sortition)`, `SortitionIdFromConsensusHash` | internal | b | Preimage of a sortition's consensus hash |
| `StacksEpoch`, `StacksEpochById`, unlock heights, PoX activation heights, `BurnStartHeight`, prepare and cycle lengths, rejection fraction | epoch gates, PoX, lockup | const | Network constants |
| `StacksHeightForTenureHeight` | `get-block-info?` and `block-height` in Clarity 1/2 contracts on Nakamoto | c | Provable with MARF proofs of `_stx-data::tenure_height` at two adjacent headers. Not implemented |
| `MinerAddress` | `get-block-info? miner-address`, `get-tenure-info? miner-address` | c | Tenure's miner payment address (headers DB `payments`). Likely the coinbase's origin or alt recipient, so provable by coinbase inclusion once that equality is checked. Not implemented |
| `TokensSpentWinning` | `get-tenure-info? miner-spend-winner` | c | The winning block-commit's burn: an SPV tx proof of the commit in the sortition's Bitcoin block, then parse it |
| `TokensSpent` | `get-tenure-info? miner-spend-total` | c | Sum over all of the sortition's block-commits: the full Bitcoin block (or a proof of every commit in it) |
| `PoxPayoutAddrs` | `get-burn-block-info? pox-addrs` | c | The reward set (pox state at the anchor block, MARF-provable) plus the reward slots each burn block pays (commit outputs) |
| `TokensEarned` | `get-tenure-info? block-reward`, `get-block-info? block-reward` | d | Matured miner reward (coinbase plus fees after maturity, reward accounting in the headers DB). No proof format. Reproducible only by replaying reward accounting over the tenure tx lists |

The verifier rejects every class (c) and (d) lookup as "not provable yet".
Class (b) uses the same consensus-hash preimage that marf-witness `burn`
serves. The pox_id inside the preimage also yields the sortition id.

Other environment checks:

- **Burn view.** The last tenure change's `burn_view_consensus_hash`: in the block itself, else proven by a tx Merkle path in an earlier block of the same tenure.
- **Epoch.** The witness epoch must be the epoch of the parent's burn height (`ClarityInstance::get_epoch_of`).

## Results (`proven_witness.rs`)

| Test | Shows |
|---|---|
| `honest_proof_carrying_witness_verifies_and_reexecution_reproduces_the_block` | History fixture: 35 store entries, 14 lookups, 4 contracts (`lockup`, `costs-3` from boot code; `ledger`, `relay` from deploy txs). It verifies, and re-execution reproduces the live writes and receipts |
| `honest_proof_carrying_witness_verifies_for_the_state_writes_fixture` | Same for the 12-tx fixture (trait dependency `tok-impl`) |
| `forged_print_only_read_is_caught_by_its_proof` | **The phase-1 hole, closed.** Forging `note` (feeds only a print) still re-executes to the live writes with a forged event, but the verifier rejects it: "MARF proof fails" on `vm::…::1::note`. A forged block time (also print-only) is rejected on `stacks_block_time_for_block` |
| `forged_absence_is_caught` | A present key claimed absent with another key's absence proof is rejected, and the prover can't make an honest one. An absent key claimed present is rejected |
| `forged_at_block_value_is_caught` | The replay bug's output (parent value 15 at `at-block`, with the parent read's valid proof) is rejected: the proof doesn't hold at X's root |
| `forged_metadata_is_caught` | A contract context with `data_size + 1` fails ("metadata differs from its re-derivation"). So does another contract's deploy tx as the source, and so does dropping the contract's evidence |
| `every_witness_entry_has_its_own_evidence` | Every store entry kind maps to the evidence the verifier expects |

## Measurements (test blocks, optimized + debuginfo, Apple silicon)

| | history fixture | state-writes fixture |
|---|---|---|
| Store entries (inclusion / absence proofs) | 35 (20 / 5) | 29 (13 / 7) |
| Witness without proofs | 92.6 KB (metadata 88.7 KB) | 87.2 KB (metadata 84.8 KB) |
| MARF proofs, one per entry | 654 KB | 552 KB |
| Contract evidence (deploy txs, commitment and epoch proofs) | 140 KB | 141 KB |
| Burn preimages, tenure-tx proofs | 0.9 KB | 0.5 KB |
| Witness with naive proofs | 888 KB | 781 KB |
| Same, metadata derived instead of shipped | 799 KB | 696 KB |
| All MARF proofs as one multiproof | 143 KB | 143 KB |
| Same, compact (no rebuildable child hashes) | 83 KB | 82 KB |
| Verify | 6.8 ms | 6.4 ms |
| Verify without metadata re-derivation | 0.68 ms | 0.59 ms |
| Re-execute | 1.6 ms | 2.0 ms |

- **Per-entry MARF proofs are big: about 26 KB each.** Every trie a walk visits adds its root Node256 step: 255 sibling hashes (8 KB) plus 256 pointers with 32-byte `back_block` ids (8.7 KB). A read that crosses back-pointers visits several tries.
- **The tries are shared across entries.** One multiproof ships each node once and is 5.5x smaller. It can also drop child hashes the verifier rebuilds (empty slots, and back-pointers whose hash is their `back_block`), for another 1.7x. Interning `back_block` ids in a per-proof table would shrink root pointers further (not measured).
- **Metadata no longer has to ship.** It was 95% of the phase-1 witness, and the verifier now re-derives it from sources. Those sources are tiny next to the proofs.
- **Verify is dominated by re-deriving 4 contracts.** Without that it costs less than re-execution.

## Remaining gaps

1. **Environment classes (c) and (d)** (table above). A block that reads them is rejected, not accepted.
2. **Burn view recency.** The verifier checks that the tenure change is in this tenure, not that no later extend happened before the block. A client verifying blocks in order has every tx list and can check it. A one-block client needs every intermediate block's tx list.
3. **Nested `at-block`.** Ancestry is checked against the parent, not the enclosing `at-block` target.
4. ~~**Contracts whose initialization reads chain state** need the deploy block's own witness (recursive).~~ Store reads: deploy witness (phase 2c), with the limits listed there. Environment lookups at deploy: still rejected. Boot contracts not in the table are rejected.
5. **Block-level writes** (setup and teardown, coinbase-attached events) are still inputs. Not covered.
6. **Epoch 2.x and microblocks**: no tests.
7. **Signer signatures and Bitcoin PoW** are assumed checked by whoever builds `HeaderChain` / `BitcoinChain`.
8. ~~No wire format.~~ Done in phase 2b (`witness_wire.rs`), v2 in phase 2c.

# Phase 2b prep: serve, ship and check a witness

```
client                                       node (this branch)
GET /v3/blocks/<id> ───────────────────────► staging block bytes
GET /v3/blocks/replay/<id>?read_witness=1 ─► replay (same collectors as live)
      &vm_events=1, Authorization: <token>     └► serve_witness: MARF proofs, contract
                                                  evidence, burn preimages, headers,
                                                  Bitcoin headers, write proofs
◄──────────── RPCReplayedBlock + read_witness (WitnessEnvelope v1, JSON)
hash headers → HeaderChain (+ pinned genesis root)
fill metadata by re-derivation → check every entry → re-execute from the witness
→ compare tx writes, prove final writes at the block root, compare events / vm_events
```

| Piece | Where |
|---|---|
| Replay flag, burn-view fix, `block_vm_events` / `receipt_events` | `stackslib/src/net/api/blockreplay.rs` |
| Node side: gather proofs and headers (`serve_witness`) | `stackslib/src/clarity_vm/witness_serve.rs` |
| Wire format (v1 here, v2 since phase 2c) (`ServedWitness` <-> `WitnessEnvelope`) | `stackslib/src/clarity_vm/witness_wire.rs` |
| Client checks (`check_replayed_block`, `ClientParams::mainnet`) | `stackslib/src/clarity_vm/witness_client.rs` |
| CLI | `contrib/reexec-verify` |
| Tests | `net/api/tests/blockreplay_witness.rs` (HTTP), `proven_witness.rs` (round trip), `stateless_reexec.rs` (burn view), `witness_proof.rs` (mainnet boot sources) |

## Endpoint

`GET /v3/blocks/replay/<id>?read_witness=1` (auth: `connection_options.auth_token` as `Authorization`). Same collector path as live processing (`ClarityInstance::set_collect_read_witness`), switched on only for that replay. Zero cost when off: the store wrapper and env tap are only installed when the flag is set.

- `read_witness=1` implies `state_writes=1`: the client needs the block-level writes to re-execute, and the node proves each written key's final value.
- Adds `read_witness` (the envelope) to the usual response. `transactions[].events`, `vm_events` (with `vm_events=1`) and `state_writes` are what the client compares against.
- Proving can fail (e.g. a missing deploy block): the replay then answers 500 with the reason.
- **Burn view fix.** Replay used `index_handle_at_block(parent)` (the parent's burn view). It now uses `get_block_burn_view` (the block's own tenure change, else the parent's), as `process_next_nakamoto_block` does. For a tenure-start block the old code printed `burn-block-height` one lower (`u42` vs `u43` in the test), and the client caught it from the proofs alone: `tip_burn_block_height() answered 52, proven 53`.

## Wire format v1 (`WitnessEnvelope`)

Replaced by v2 in phase 2c (per-entry proofs became two shared proofs; see
there). Kept for the record.

JSON. Binary as lowercase hex, no `0x`. Ids and hashes: their bytes. Proofs, transactions, headers, addresses: consensus encoding. Store values: the side-store string as is.

| Field | Content | How the client checks it |
|---|---|---|
| `version` | `1` | Rejects anything else |
| `network` | `{mainnet, chain_id}` | Must equal the client's pinned network |
| `witness.open_tip`, `open_height` | Miner placeholder id, parent height + 1 | Exact |
| `witness.epoch` | `{epoch_id, start_height, end_height, block_limit, network_epoch}` | Equals the pinned epoch at the parent's burn height |
| `witness.store[]` | `{query: {kind: data\|path\|block_at_height\|current_height\|at_block\|metadata, ...}, value, proof}` | Per proof kind, below |
| `witness.env[]` | `{query: {method: <snake_case EnvQuery>, ...args}, answer}` | Per class, below. Answer: hex, number, decimal string (`u128`), `null`, epoch object, or `{addrs: [clarity hex], payout}` |
| `contracts[]` | `{contract, block, source: "boot" \| {tx: {block, tx, merkle_path}}, commitment, commitment_proof, epoch_key, epoch_key_proof, ancestry: [h2h, h2b] \| null}` | Deploy block is an ancestor of the parent (MARF `__MARF_BLOCK_HASH_TO_HEIGHT` / `HEIGHT_TO_HASH` at the parent root; replaces 2a's header walk, which needed every header back to the deploy); commitment and epoch proven at the deploy block's root; source hashes to the commitment; then re-derived |
| `burn[]` | `{burn_header_hash, ops_hash, total_burn, pox_id: "1101…", prev_consensus_hashes}` | Hashes to the consensus hash it stands for |
| `burn_view`, `coinbases[]` | `{block, tx, merkle_path: [[left\|right, hash]]}` | Merkle path to the named block's tx root |
| `headers[]` | `{consensus_hash, nakamoto: hex}` or `{consensus_hash, epoch2: hex}` | Hashed to a block id; only ids reached that way exist for the client. Signer signatures stripped (the block hash does not commit to them) |
| `bitcoin[]` | `{height, hash, parent, time}` | Must link by parent hash; heights trusted (SPV composes upstream) |
| `writes[]` | `{key, proof}` | Inclusion of the re-executed final value at the block's own root |
| `unproven_contracts[]` | `[contract, reason]` | Diagnostic only |

Store proof kinds: `{"marf": {"present"\|"absent": hex}}` (inclusion or absence at the parent, or at the `at-block` target), `{"ancestor": [p, p]}`, `"open_block"` (deterministic), `"rederived"` (value left out, client fills it from re-derivation), `"served"` (value shipped as is, rejected: the contract cannot be re-derived from its deploy alone).

Headers the node ships: the parent, `at-block` targets, every block an env lookup names, deploy blocks, the tenure-start blocks of coinbases, every block walked back to the burn-view tenure change, and every trie a MARF proof crosses (on-path back-pointer targets, `MarfProof::crossed_blocks`). Genesis is never shipped: its header has a zero root, so the client pins it (`MAINNET_2_0_GENESIS_ROOT_HASH`, the root every mainnet node asserts at boot, `9653c92b…52af`; recomputed from `stx-genesis` in 4.6 s to confirm).

## Client (`check_replayed_block`, `contrib/reexec-verify`)

```
reexec-verify <block id> --node http://127.0.0.1:30443 --auth $TOKEN
reexec-verify <block id> --chainstate /copy/of/working_dir/mainnet 
```

`--chainstate` runs the same replay handler in process on a stopped node's directory, then round-trips the response through JSON: no node, ports or bitcoind. Exit 0 only if every check passes. A rejected entry fails the run, but re-execution and the comparisons still run on the served values, so one run shows everything. Output (abridged), for the 7-tx history fixture over HTTP:

```
witness entries verified:
  at-block ancestry 1, at-block inclusion 2, parent inclusion 16, parent absence 5,
  open-block 1, metadata (re-derived) 10, contract (boot source) 2, contract (deploy tx) 2,
  env (a) header 4, env (b) burn 6, env constant 4
ok   headers        17 Stacks (hashed to their ids, genesis root pinned), 2 Bitcoin (heights trusted)
ok   witness        35 store entries, 14 lookups, 4 contracts, 1 burn preimages
ok   re-execute     7 receipts, 26 writes
ok   writes         25 tx writes = replay state_writes
ok   write proofs   10 final values proven at the block's state root
ok   events         10 events (6 prints) and results = replay receipts
ok   vm_events      4 = replay vm_events
VERIFIED
```

What each comparison means:

- **writes**: the transactions' re-executed writes equal the replay's `state_writes`, in order. This compares against the node's claim.
- **write proofs**: each written key's final value (re-executed, plus setup and teardown) is proven at the block's own `state_index_root`. This is against the header. It does not prove completeness (a trie leaf re-execution did not write); listing the block trie's leaves would.
- **events**: per tx, `events` and `result` equal the replay's. Replay's equal live `/new_block` (asserted in the HTTP test). Events are then as trustworthy as the witness entries: every input re-execution read is proven.

## Results

| Test | Shows |
|---|---|
| `served_witness_verifies_and_reexecutes_over_http` | History fixture through the RPC server: `VERIFIED`, every entry kind present, replay receipts equal live |
| `served_witness_verifies_a_tenure_start_block_over_http` | Tenure-start block (own tenure change, new burn view): `VERIFIED`. Fails without the burn-view fix |
| `tampered_witness_byte_fails_naming_the_entry` | One hex digit of the `note` value in transit: `vm::…::1::note: MARF proof fails`. One digit of its proof, and a block-time answer +1: rejected, named |
| `unprovable_metadata_is_served_and_rejected_but_reexecution_still_runs` | A contract whose `define-data-var` reads `burn-block-height`: its 3 metadata entries are served and rejected (`its deploy reads chain state: ["tip_burn_block_height()"]`); writes, write proofs and events still pass |
| `served_witness_round_trips_through_json` | Envelope → JSON → envelope → `ServedWitness` → envelope is identical; decoded witness = live witness minus metadata values; a future version is refused |
| `block_replay_uses_the_tenure_change_burn_view` | Replay result and events equal live for a tenure-start block (`u42` before the fix) |
| `mainnet_boot_contracts_rederive_from_bundled_sources` | 40 of the 42 mainnet boot contracts re-derive from bundled sources in their transition epoch, except `signers-voting` (constant `pox-info` reads `pox-4` state, incl. `ustx_liquid_supply`) and `pox-5` (needs the user-deployed `sbtc-token` first) |

Plus all phase 1/2a tests (40 witness, replay and absence tests pass). Fix found on the way: an epoch-2.0 deploy (genesis boot contracts, `vm-epoch::epoch-version` never set) failed re-derivation because the unset key read was missing; it now answers none.

Size: the history fixture's envelope is 2.4 MB of JSON (35 entries, 10 write proofs, per-entry proofs, hex). Per-entry MARF proofs dominate (phase 2a: ~26 KB each, 5.5x smaller as a multiproof). A mainnet block with hundreds of entries and deeper tries will likely be tens of MB. Fine for a scratch run; the multiproof is the fix.

## Proving cost (lookup memo)

Per-read proofs and their shunts are gone since phase 2c; the memo now only
serves each trie's skip-list (its ancestor roots), once per distinct trie.

First mainnet run (block 1,113,075, `sbtc-yield-rewards-v3`, 1,239 store entries, 408 write proofs): VERIFIED, but replay plus proving took 1,413 s. Replay itself is ~50 s; the rest was proving.

- **Why.** Every back-pointer a proof's walk crosses gets a shunt proof. Each hop of a shunt recomputes that trie's skip-list ancestor hashes: ~20 `block at height` lookups, each 2 MARF walks on disk. Nothing was reused across keys.
- **Fix.** An opt-in `LookupMemo` on the trie storage (`index/storage.rs`). It memoizes ancestor hashes per trie, block heights, and blocks at a height. All of these are pure functions of committed tries. It is consulted only while no trie is being extended, so the node's own processing never sees it. `serve_witness` turns it on for one call and drops it afterwards.
- **Anchor.** With an anchor tip (`serve_witness` anchors at the block), a block B on the anchor's chain answers "block at height h < height(B)" with the anchor's answer. Both tries map h to the same ancestor. Lookups from different tries then share one entry per height. Whether B is on the chain is itself a MARF lookup at the anchor; blocks off it take the plain path.
- **Proof bytes are unchanged.** Same proofs, same wire format, same verifier. The response is the same size.

| Proving (`index/test/proof_memo.rs`, `proven_witness.rs`) | Node reads: plain / memo / anchored | Time: plain / memo / anchored |
|---|---|---|
| History fixture: 35 store entries + 10 write proofs | 1,147 / 369 / 309 | 8.8 / 4.4 / 3.9 ms |
| Synthetic 300 blocks, 500 proofs | 159,368 / 12,305 / 8,573 | 395 / 121 / 114 ms |
| Synthetic 32,768 blocks, 3,500 proofs (file-backed) | 5,474,102 / 817,751 / 263,406 | 25.4 / 5.9 / 3.4 s |

Both tests assert that every proof is byte-identical with the memo off, on, and anchored. The 32k case is `--ignored` (it takes ~4 min to build its chain).

**Still to expect on mainnet.** Lookups now scale with distinct tries and distinct heights, not with keys times hops. A 1.1M-block chain has longer shunts (~20-bit distances), so expect more distinct heights per proof than the 32k test. The response size is unchanged: per-entry proofs, 427 MB of JSON for 1,113,075. The multiproof is the next fix, for size and for the time spent hashing and serializing.

**Progress.** `serve_witness` logs each phase on stderr (`Witness: ...`): store entries (every 1,000), contracts, final writes, and the memo's size. The client logs verify, re-execute and compare (`Client: ...`), and `reexec-verify` brackets replay and fetch.

**`--events-out <file.jsonl>`.** Writes one line per re-executed, committed event: `txid`, `event_index`, `type`, `contract_id` (the emitter, or the asset's contract for FT/NFT), `topic`, `value_hex` (consensus, `0x`), `value_repr` (Clarity), and `event` as `/new_block` serializes it. Use it to diff against an indexer's events. The HTTP test checks that the rows match the replay's events and that each print's hex equals its `raw_value`.

## Scratch node: build and run

Build (linux x86_64). The repo's `Dockerfile` builds the workspace in release (fat LTO) on `rust:bookworm`; `rust-toolchain.toml` pins 1.98.0, which rustup installs inside the build. The fork's CI (`.github/workflows/docker-image.yml`) runs `cargo build --features monitoring_prom,slog_json --profile release --workspace`. Build natively on an x86_64 box (QEMU emulation from Apple silicon is very slow):

```
docker build -t stacks-node:reexec-$(git rev-parse --short HEAD) \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) .
# or without Docker: cargo build --release --features monitoring_prom,slog_json -p stacks-node -p reexec-verify
# (--profile release-lite: thin LTO, much less RAM and time)
```

Fat-LTO release builds of stackslib need a lot of RAM (plan for well over 8 GB); `release-lite` is the safer choice on a smaller box. `reexec-verify` builds anywhere (also macOS) and talks plain HTTP.

Run, preferred first: no node at all. Stop nothing in production. Copy a stopped (or snapshotted) mainnet `working_dir` to scratch disk, then:

```
reexec-verify <block id> --chainstate /scratch/working_dir/mainnet
```

Run as a node (when RPC is wanted), on a **copy** of the chainstate: this branch may migrate DB schemas, and replay opens the chainstate read-write (it rolls back). Config:

```toml
[node]
working_dir = "/scratch/reexec"     # copy of a mainnet working_dir
rpc_bind = "127.0.0.1:30443"        # own ports, not the prod node's
p2p_bind = "127.0.0.1:30444"
miner = false
stacker = false

[burnchain]
mode = "mainnet"
peer_host = "<bitcoind host>"       # the run loop connects to the burnchain at start
username = "..."
password = "..."

[connection_options]
auth_token = "<random secret>"      # enables /v3/blocks/replay
```

`stacks-node start --config reexec.toml`, wait for RPC (`/v2/info`), then `reexec-verify <id> --node http://127.0.0.1:30443 --auth <secret>`.

Memory: plan for a normal mainnet follower (8 GB+). Replay with `read_witness=1` adds the proofs and their JSON (tens of MB for a large block) plus metadata re-derivation of each contract read (milliseconds each). The client holds one block's witness and re-executes in milliseconds (phase 2a numbers).

## Still blocking or untested for a mainnet run

1. **Contracts whose initialization reads chain state** (gap 4). Store reads: deploy witness since phase 2c (limits there). Environment lookups at deploy: their metadata is served and rejected; the run still re-executes and compares.
2. **Env classes (c)/(d)** (miner address, block rewards, burn spends, PoX payouts, Clarity 1/2 `block-height` on Nakamoto) are rejected.
3. **Never run on mainnet data.** In particular: the bundled `sip-031` and `pox-5` bodies must hash to mainnet's commitments byte for byte; mainnet MARF proofs must find full tries (a squashed or pruned chainstate breaks proofs into old tries; `marf-squash` output is not usable); `--chainstate` mode is only exercised through the shared handler code, not on a real directory.
4. **Header and Bitcoin authenticity** are not checked here: headers by id hash only, Bitcoin heights from the node. `@secondlayer/verify` (signer signatures, canonical fork) and an SPV header chain compose on top by checking the same ids and hashes.
5. **Burn-view recency** (gap 2) and **nested `at-block`** (gap 3) as in 2a.
6. **Epoch 2.x**: a parent or `at-block` target in 2.x is shipped as an epoch-2 header (its parent id unknown, zero); untested. First Nakamoto blocks (2.x parent) untested.
7. ~~**Response size** (per-entry proofs).~~ Shared proofs since phase 2c; still untested on mainnet.

First target is still the `sbtc-yield-rewards-v3` block: run it and read which entries are rejected and why.

# Phase 2c: deploy witness and shared proofs

Mainnet run before this phase (12 DeFi blocks, `reexec-verify <id>
--chainstate`): every one of 4,421 re-executed events equals the canonical
event byte for byte, and 10 of 12 blocks are VERIFIED. The other two fail only
on the metadata of contracts whose deploy reads chain state: 1,170,254
(`SP001SFSMC2ZY76PD4M68P3WGX154XCH7NE3TYMX.pox4-pools`, reads
`_stx-data::ustx_liquid_supply`) and 1,230,200 (`kiki-token`, which mints at
deploy, and `token-wkiki`, which depends on it). Serving cost: per-read proofs
made the response ~430 MB and took 341 to 1,534 s per block.

## Deploy witness

A contract whose deploy reads chain state is re-derived by re-running its
deploy with those reads, each proven the way a block's own reads are.

```
prover (C deployed in D, D's parent P)
  re-derive C from its deploy, with the contracts it depends on
  ├─ reads a commitment of contract X → re-derive X first (≤ 16 deep, X may carry its own deploy witness)
  ├─ reads chain state K            → answer K at P from the MARF, add (K, answer), re-derive again (≤ 256 rounds)
  └─ makes an environment lookup    → unprovable ("not provable yet", lookup named)
client
  P = __MARF_BLOCK_HEIGHT_TO_HASH::(h(D) - 1) at D's root (the child trie rewrites it with the real id;
      must equal the header's parent for a Nakamoto D, and also works for an epoch 2.x D)
  each deploy read: checked like a block read, at P (or its `at-block` target), open height h(D)
  re-run the deploy with those reads → metadata → compare with the block's metadata entries
```

| Piece | Where |
|---|---|
| Deploy reads in a re-derivation (`ContractDeployment::reads`, typed misses `DeriveError::Missing`) | `stateless.rs::derive_contract_metadata` |
| Prover (`resolve_contract`, `answer_store_query`, `prove_contract_facts`) | `witness_proof.rs` |
| Verifier (`verify_deploy_reads`) | `witness_proof.rs` |
| Wire: `contracts[].deploy_reads` | `witness_wire.rs` |

What a deploy read proves, and what it cannot:

- **The value at P.** The deploy saw P's value unless something earlier in D wrote the key: block setup, an earlier transaction, or the deploy transaction's own fee. Roots cannot show order within a block.
- **So each read is also classified at D's root.** The client walks every key read outside the contract's own storage (`vm::<C>::…` cannot exist before C) at D's root too. Not written in D: settled. Written in D: counted as `deploy read (block also wrote key; assumed after)` in the report. The run is still VERIFIED, but the report shows how many reads rest on that assumption.
- **`_stx-data::ustx_liquid_supply` always lands in "assumed after".** Every block's teardown rewrites it after its transactions (`finish_block` adds unlocks and matured rewards, even 0). So the value at P is what a deploy sees, unless an earlier transaction in D burned STX.
- **Closing it** needs D's own read witness up to the deploy transaction (re-execute D's prefix). Not done.
- **Same-block dependencies.** If X was deployed earlier in D and C's deploy reads X's state, P has none of it. The read is flagged "assumed after" and the metadata will not match (rejected). Analysis-only dependencies are fine: `ledger` and `relay` in the history fixture share a block.
- **Environment lookups at deploy** (`burn-block-height`, `block-height` for Clarity 1/2 on Nakamoto, `get-*-info?`) need D's burn view. Not provable in a deploy yet: the contract is served unproven, naming the lookup (`born` test).
- **Epoch 2.x deploys in a microblock** are not in D's anchored tx list: unprovable (deploy tx not found).

## Shared proofs

One proof for every read, at every root, instead of one proof per read
(`stackslib/src/chainstate/stacks/index/multiproof.rs`):

```
reads ─► MultiproofBuilder::walk(root, path)   per trie: the nodes walks touched
                                                (others: their hash; back-pointers: the ancestor's block id)
       ─► encode                                 + each trie's skip-list (ancestor roots), deduplicated
client ─► Multiproof::open(bytes, header roots)  every trie hashes to its header's root
       ─► get(root, path) per claim              walk exactly as the MARF does
       ─► unvisited() == 0                       no node no claim reaches
```

- **No shunt proofs.** A back-pointer child hashes as the id of the block it points into, and that block's trie is pinned by its header's root. The client already needed a header for every crossed trie, so the skip-list hash chains between tries (shunt proofs) are redundant. They were the expensive part of proving: ~20 block-at-height lookups per hop, per read. Each trie still ships its own skip-list (≤ log2 height hashes) to recompute its root.
- **Strict verifier.** The bytes must parse exactly, with no trailing bytes and every block and ancestor hash in the tables used. Every trie must hash to its block header's root (genesis: pinned). A claim whose walk needs a node the proof left out fails. After every claim is checked, a node no claim reached fails the witness ("extra nodes"). A trie that does not hash fails exactly the walks that reach it, so the report still names entries.
- **Two proofs per served witness.** The read proof covers every store entry and every contract fact. Its claims are at the parent, at `at-block` targets, and at deploy blocks (commitment, epoch key, parent entry, the "written in D?" walks). Deploy reads are at the deploy blocks' parents. A trie reached from several roots ships once. The final-write proof is at the block's own root, checked after re-execution.
- **Proving** walks each read once (node reads ∝ distinct nodes), computes one skip-list per distinct trie (lookup memo, anchored at the block), and encodes. Contract facts are walked only for evidence that is served, so a contract that fails re-derivation leaves no extra nodes.

## Wire format v2 (`WitnessEnvelope`)

JSON, binary as lowercase hex without `0x`. Changes from v1: every `proof`
of an entry is now a tag, MARF bytes live in `marf` and `writes.proof`,
contracts lost their proof fields and gained `deploy_reads`.

| Field | Content | How the client checks it |
|---|---|---|
| `version` | `2` | Rejects anything else |
| `network` | `{mainnet, chain_id}` | Must equal the client's pinned network |
| `witness.open_tip`, `open_height`, `epoch`, `env[]` | As v1 | As v1 |
| `witness.store[]` | `{query, value, proof}`, `proof` one of `"marf"`, `"ancestor"`, `"open_block"`, `"rederived"`, `"served"` | `marf`: walk at the root the query names (parent, or `at-block` target) gives `value` (`null`: absent). `ancestor`: walks of `__MARF_BLOCK_HASH_TO_HEIGHT::X` and back at the parent. `open_block`: deterministic. `rederived`: value left out, filled by re-derivation. `served`: rejected |
| `contracts[]` | `{contract, block, source: "boot" \| {tx}, commitment, epoch_key, deploy_reads: [store entry]}` | Commitment and epoch key: walks at the deploy block's root. Ancestry: walks at the parent's root. Source hashes to the commitment. `deploy_reads`: as above, then re-derived with them |
| `marf` | Shared read proof (format below) | Opened against the headers; strict (every node reached) |
| `burn[]`, `burn_view`, `coinbases[]`, `bitcoin[]` | As v1 | As v1 |
| `headers[]` | As v1; now: every trie either proof holds, plus deploy blocks, env-named blocks, the burn-view walk, coinbase blocks | Hashed to ids; each trie's root must equal its header's |
| `writes` | `{keys: [key], proof}`: keys the block wrote, shared proof at the block's own root | Keys = re-executed final keys; each final value = walk; strict |
| `unproven_contracts[]` | `[contract, reason]` | Diagnostic only |

Shared proof (big-endian):

```
proof := u8 version=1 | u32 n_blocks | [32]*n_blocks | u32 n_hashes | [32]*n_hashes | u32 n_tries | trie*
trie  := u32 block index | u8 n_anc | u32*n_anc hash index | node            (root: Node256)
node  := u8 id | u8 path_len | path | leaf: [40] value | interior: ptr*(4/16/48/256) | child*
ptr   := u8 tag | (tag != 0: u8 chr) | (0x80 back-pointer: u32 block index) | (0x40 pruned: [32] hash)
```

A ptr tag is 0 (empty), or a node id 1..=5 plus at most one flag. Expanded
children follow their node in preorder. Like marf-witness v3 (u32 tables, one
32-byte id per distinct ancestor block), but many tries per proof, pruned
children, and a shared ancestor-hash table.

## Results

| Test | Shows |
|---|---|
| `contracts_whose_deploy_reads_chain_state_rederive_from_a_deploy_witness` (HTTP) | `kiki-token` keeps `stx-liquid-supply` in a constant and mints at deploy; `kiki-wrapper` (next block) keeps what it reads from `kiki-token` at deploy. Both carry deploy witnesses (3 reads: 2 settled, `ustx_liquid_supply` "assumed after"), re-derive, and the calling block is VERIFIED. One deploy-read value changed in transit: rejected, `deploy read Data { …ustx_liquid_supply }: MARF proof fails` |
| `unprovable_metadata_is_served_and_rejected_but_reexecution_still_runs` | Unchanged outcome: a deploy reading `burn-block-height` is served unproven, naming the lookup |
| `tampered_witness_byte_fails_naming_the_entry` | A flipped bit in the shared proof's ancestor table: the trie no longer hashes, every entry read through it is rejected by name (incl. `note`); re-execution is skipped (metadata did not re-derive). A flipped bit in the final-write proof fails `write proofs` |
| `absent_and_present_reads_verify_from_one_shared_proof` | 300 absent + 320 present keys at the tip, absent walks ending in the tip trie and through back-pointers in older ones; a present key is never absent from it and vice versa |
| `tampering_with_any_byte_of_a_shared_proof_breaks_it` | Bits 0x01 and 0x80 of every byte of a 5-read, multi-trie proof, plus truncation and a trailing byte: each is caught |
| `a_shared_proof_holds_its_reads_and_no_others` | Verifying half the reads leaves extra nodes (rejected); a read the proof was not made for needs a pruned node (fails) |
| `absence_holds_until_the_block_that_writes_the_key`, `near_miss_…` | Ported from the absence-proof tests |
| `memoized_lookups_produce_a_byte_identical_shared_proof`, `lookup_memo_proves_the_fixture_witness_byte_identically` | Same proof bytes with the memo off, on and anchored |

All witness, replay, stateless, state-writes and index tests pass.

## Measurements (optimized + debuginfo, Apple silicon)

| | per-read (v1, `ba75388`) | shared (v2) |
|---|---|---|
| History fixture: all evidence (MARF + contracts + env) | 1,036,610 B (store proofs 654,161) | 18,097 B (shared proof 14,183): **57x** |
| State-writes fixture: all evidence | 847,627 B | 16,278 B (shared proof 13,455): **52x** |
| History fixture envelope (JSON) | 2,436,295 B | 56,070 B: **43x** |
| History fixture proving, 35 entries + 10 writes: plain / memo / anchored | 6.4 / 3.2 / 2.9 ms (1,146 / 368 / 308 node reads) | 1.36 / 1.13 / 1.03 ms (305 / 249 / 219): **~3–5x** |
| Synthetic, 300 blocks, 400 present + 100 absent reads: bytes, plain / memo / anchored | 22.9 MB, 390 / 123 / 113 ms | 361 KB (**64x**), 23.6 / 18.0 / 13.2 ms (**~9–17x**) |
| Synthetic, 8 blocks, 620 reads at the tip | 10.8 MB (inclusion proofs of the 320 present keys alone) | 35 KB (8 tries, 474 nodes): **309x** |
| History fixture verify (without metadata re-derivation) | 6.5 ms (0.65 ms) | 5.7 ms (0.21 ms) |
| HTTP test blocks, whole replay body | not measured | 94 to 148 KB (read proof 33 to 43 KB, write proof 5 to 6 KB) |

The HTTP chain is longer than the `proven_witness` one, so its tries' root
nodes and skip-lists are bigger. Root `Node256`s dominate: 256 ptr tags, 6
bytes per back-pointer, 34 per pruned child.

## Still to expect on mainnet

- **Deploy witnesses.** Both mainnet failures should move: `pox4-pools` reads `ustx_liquid_supply` (shown as "assumed after"), and `kiki-token` reads and writes its own FT keys (settled). Blockers that would still reject them: an environment lookup at deploy (`block-height` in Clarity 1/2 on Nakamoto is class (c)), a deploy in an epoch 2.x microblock, or `token-wkiki` reading `kiki-token` state at deploy when both were deployed in the same block. Never run on mainnet.
- **Size and time.** Both now scale with distinct tries and nodes. A mainnet block crosses many more tries (1,113,075 had 1,239 entries + 408 writes). Each distinct trie costs its root node (~0.3–1.5 KB in this format), its skip-list references, one skip-list computation (memoized), and a header in the response. Expect single-digit MB and seconds, not 430 MB and 20 minutes. Unmeasured.
