# Stateless re-execution spike

Phase 1 (below, through "Why replay diverged"): re-execute a block from a
read witness. Phase 2a (after it): make every witness entry provable and
verify it. Phase 2b: a mainnet block.

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

**Boot table.** `pox`, `lockup`, `costs`, `cost-voting`, `bns`, `genesis`, `costs-2`, `pox-2`, `costs-3`, `pox-3`, `pox-4`, `signers`, `signers-voting` and `costs-4`, each with the Clarity version its transition pins. Not covered yet: `signers-stackerdb` (generated), `sip-031` (generated body), `pox-5`. In the fixtures, `lockup` and `costs-3` are read every block. Both re-derive.

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
4. **Contracts whose initialization reads chain state** need the deploy block's own witness (recursive). Boot contracts not in the table are rejected.
5. **Block-level writes** (setup and teardown, coinbase-attached events) are still inputs. Not covered.
6. **Epoch 2.x and microblocks**: no tests.
7. **Signer signatures and Bitcoin PoW** are assumed checked by whoever builds `HeaderChain` / `BitcoinChain`.
8. **No wire format.** Evidence types are in-memory Rust. `TrieMerkleProof` and transactions have consensus codecs; `TrieAbsenceProof`, `ContractEvidence` and the typed env answers do not.

# Phase 2b: a mainnet block on a scratch node

What it needs, in order:

1. **Build a scratch node from this branch** (it carries `f0f9d6b`, or replay witnesses are wrong for `at-block`). Fix replay's burn view to the tenure-change burn view, not `index_handle_at_block(parent)`.
2. **Add a replay flag returning the proof-carrying witness.** For example `/v3/blocks/replay/{id}?read_witness=1&proofs=1`. The node already holds everything the prover needs:
   - the MARF, for `prove_store_reads` and the contract commitment and epoch proofs;
   - Nakamoto staging blocks and the 2.x block store, for `find_deploy` (deploy txs, tenure changes, coinbases) and their Merkle paths;
   - the sortition DB, for consensus-hash preimages (reuse marf-witness `burn`).
3. **Wire format v1**, one JSON envelope:
   - `witness`: `{open_tip, open_height, epoch, store: [{kind, at, key | path | height | target | contract+key, value_hex | null}], env: [{query: EnvQuery, answer}]}`. `EnvQuery` is now typed, so serde derives work. Answers need serde for `StacksEpoch`, `TupleData` and `VRFSeed`;
   - `store_proofs`: per entry `{marf: inclusion | absence, hex} | {ancestor: [hex, hex]} | open_block | rederived`. Inclusion proofs use the existing consensus codec; add one for `TrieAbsenceProof`. Then a multiproof (dedupe nodes, drop rebuildable hashes, intern block ids) once the per-entry format works;
   - `contracts`: `{contract, block, source: {tx_hex, merkle_path} | boot, commitment, commitment_proof, epoch_key, epoch_key_proof}`;
   - `burn`: preimages as marf-witness `burn` serves them, plus pox_id length so the client can split them;
   - `burn_view`, `coinbases`: `{block, tx_hex, merkle_path}`.
   - Leave out metadata values: the client re-derives them.
4. **Client inputs**:
   - signer-verified header chain from genesis to the block (state roots, tx roots, timestamps);
   - Bitcoin headers (the marf-witness sidecar's `/headers`);
   - mainnet network constants: epochs, PoX constants, genesis MARF root;
   - mainnet boot sources (add `pox-5`, `sip-031`, `signers-stackerdb`);
   - a re-derivation cache keyed by source hash.
5. **First target: the `sbtc-yield-rewards-v3` block.**
   - Replay with proofs, verify offline, re-execute.
   - Compare the writes with marf-witness's state diff and the prints with live `/new_block`.
   - Record which class (c)/(d) lookups mainnet blocks hit, and how many tries a mainnet read crosses (proof size scales with it).
