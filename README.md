# rs-sdk

Native Rust SDK for the Curvy PIX profiles, driven entirely through Blokli.

It covers four operations end to end:

1. **deposit** through a deterministic shield portal;
2. **commit** pending notes into the global depth-30 tree;
3. **aggregate** up to two input notes into nine regular outputs plus one fee output;
4. **withdraw** up to ten notes held by unrelated BabyJubJub scalars in a single proof.

There are two entry points. [`CurvyClient`](curvy-sdk/src/client.rs) is the direct
API. [`CurvyDepositPool`](curvy-deposit-pool/src/pool.rs) implements
`hopr_api::chain::DepositPool`, so a HOPR node can substitute it for
`NonAnonymousDepositPool` at the construction site and change nothing else.

## Prerequisites

| what | where | why |
|---|---|---|
| `rs-core` checked out beside this repo | `../rs-core` | Poseidon, BabyJubJub, note commitments, indexed IMT, Groth16 prover |
| Proving keys | `CURVY_ZK_KEYS_DIR` | too large to commit; hash-checked before parsing |
| A Curvy-enabled Blokli + Anvil stack | `BLOKLI_URL` | the only backend this SDK talks to |

The proving keys are **evaluation setups**, adequate for local work and not
production trusted-setup artifacts.

## Getting a run out of it

```bash
export BLOKLI_URL=http://127.0.0.1:8080
export CURVY_ADDRESSES=/absolute/path/to/curvy_deployed_addresses.json
export CURVY_ZK_KEYS_DIR=/absolute/path/to/zk-keys/v2

cargo run --release -p curvy-e2e
```

The stack must deploy verifier profiles `(2,9)` and `(10)`. Thirteen phases run:
deposit, two aggregation fan-outs, a ten-owner withdrawal, then the four
`DepositPool` methods. Each prints as it completes, and the summary lists every
transaction with its label, backend and hash.

Set `CURVY_E2E_SALT=<u64>` to reproduce a specific run against a fresh chain.
Without it each run salts its own note commitments, which is what makes the flow
re-runnable against a long-lived stack - a fixed shared secret would replay
identical commitments and the second run would revert on spent nullifiers.

## Workspace

| crate | responsibility |
|---|---|
| `curvy-sdk` | deposit, pending-note commit, PIX aggregation, PIX withdrawal, note sync |
| `curvy-deposit-pool` | `hopr_api::chain::DepositPool` over `CurvyClient`, with batching and persistence |
| `curvy-witnesscalc` | PIX input ABI, authenticated artifact selection, witness calculation, Groth16 proving |
| `curvy-chain-blokli` | Blokli GraphQL index and `sendTransactionSync` submission |
| `curvy-chain-rpc` | direct on-chain reads and plain-transfer fallback; not on the acceptance path |
| `curvy-chain-api`, `curvy-types` | backend-neutral seams and data types |
| `curvy-abi` | v2 ABI bindings, raw-transaction signing, Groth16 calldata conversion |
| `curvy-e2e` | the runnable acceptance flow |

No cryptography lives here. The PIX witness modules do circuit-version assembly
only; everything else comes from `../rs-core`.

## Things that will bite you

**`deposit_funds_to` returns on enqueue, not on settlement.** Curvy's aggregation
circuit takes 2 inputs and 9 regular outputs, so one proof serves seven recipients
plus change plus a relayer note. Batching is what makes that affordable, and
`notify_deposit` is the only honest signal that funds exist. This differs from
`NonAnonymousDepositPool`, which awaits its transfer inline.

**Partial withdrawal delivers whole notes.** Curvy notes are atomic; splitting one
needs an extra aggregation proof authorised by the depositor's key. Ask for an
amount no subset matches exactly and you get the smallest total that still covers
it, with the excess landing at the same destination. Only a genuinely insufficient
balance fails.

**The pool must be funded before the first `deposit_funds_to`.** It spends
committed notes it already owns and the trait has no funding hook, so something has
to seed it. A long-running node wants a replenishment policy.

**Recovery from a crash mid-proof is deliberately manual.** Auto-recovery risks
re-spending a note that already landed, so the pool surfaces the condition instead
of guessing.

## Output shape

`VerifyPixAggregation(2, 9, 30, 6)` emits `maxOutputs + 1` notes - nine regular
outputs plus the protocol fee note in its own constrained slot:

| slot | note | constrained by the circuit? |
|---|---|---|
| 1–7 | allocations to PIX owners | no |
| 8 | change back to the spender | no |
| 9 | relayer gas reimbursement | no |
| 10 | protocol fee note | yes - owner is `feeNotePublicKey`, amount is `gasFee + protocolFeeQ` |

Only the fee note is constrained. The relayer note is an ordinary output, exactly
as in production: the relayer trial-decrypts an aggregation's outputs, refuses to
submit when none is addressed to it, and refuses again when the amount is below its
live gas quote plus tolerance. That check is what makes the payment safe, not the
proof.

The circuit charges the protocol fee on every output the spender does *not* own, so
the relayer note is fee-bearing and `curvy-sdk` sizes the fee note accordingly - see
`pix_value_split`.

## Blokli is the only backend

There is no `RPC_URL`. Every seam is served by `BlokliChain`, and the integration
test asserts no transaction reports another backend.

| seam | blokli query |
|---|---|
| `TxSubmitter` | `sendTransactionSync` |
| `NoteIndexSource` | `curvySyncCheckpoint` + `curvySyncNotes`, `curvyPendingNotes`, `curvyCommittedNullifiers` |
| `RootAnchor` | `curvyAggregatorState`, `curvyValidNotesRoot`, `curvyNoteStatus` |
| `FeeConfigSource` | `curvyVaultFees`, `curvyAggregatorFees`, `curvyVaultTokenCount` + `curvyVaultToken` |
| `BalanceReader` | `nativeBalance`, `transactionCount`, `chainInfo` |
| `PortalDirectory` | `curvyEntryPortalAddress`, `curvyPortalRegistered` |

This does not weaken the trust model: blokli's `curvy*` resolvers are direct
contract reads, not indexed state, so the aggregator's notes root is still a chain
read - merely proxied - and `sync()` reconciles the locally rebuilt tree against it
before anything is spent.

`curvy-chain-blokli` targets the `curvy-events-finalized` schema: union-wrapped
`curvy*` queries, `Hex32` note ids converted to decimal at the adapter, and
exclusive `after`-cursor pagination followed to exhaustion. Blokli caps `first` at
1000, so a single unpaged read silently truncates a busy chain and yields a wrong
root.

### Rebuilding the notes tree

`sync()` prefers a **checkpoint-pinned snapshot**: `curvySyncCheckpoint` yields an
immutable `(blockHash, noteCount, notesRoot)` and `curvySyncNotes` pages leaves
against it, each carrying its authoritative `leafIndex`. Pages cannot straddle a
commit, and the adapter asserts every leaf lands where it claims.

`leaves_from_events` is the fallback for backends that cannot serve a snapshot - a
plain `eth_getLogs` reader has no tree frontier to derive positions from. It is the
weaker path: it reproduces the on-chain tree only while the index reports events in
chain order, an assumption the event log never states, and a wrong order yields a
wrong root rather than an error.

Both reconcile against the aggregator's on-chain root before anything is spent.

## Artifacts

Witness graphs for pending `(5,30)`, PIX aggregation `(2,9,30,6)`, PIX withdrawal
`(10,30)`, and the two legacy profiles live under `artifacts/cvywit` and are
authenticated against pinned SHA-256 digests before decoding. Proving keys are
resolved under `CURVY_ZK_KEYS_DIR` and hash-checked before the unchecked point
parser sees them. Wrong or stale files fail closed.

See [artifacts/README.md](artifacts/README.md) for the digest table and for why
`artifacts/graphs` exists.

## Local checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

The default suite calculates both full PIX witnesses from unrelated scalar keys and
checks every bundled graph pin. To additionally prove and self-verify every PIX-flow
profile against the real evaluation keys:

```bash
CURVY_ZK_KEYS_DIR=/absolute/path/to/zk-keys/v2 \
  cargo test --release -p curvy-witnesscalc -- --ignored --nocapture
```

`cargo test` needs a C toolchain because `circom-witnesscalc` is a dev-dependency -
it is the independent reference the graph-equivalence tests compare against.
`cargo build` and `cargo run` never touch it.

## Not implemented, deliberately

`PixSettlement` does not exist in `hopr-api`, and idempotency by `PixAddressId`
lives in HOPR's own strategy, which caches and tests it - `DepositPool` never
receives an id to key on.
