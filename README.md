# rs-sdk

Native Rust SDK for Curvy, driven through Blokli.

It covers four operations end to end:

1. **deposit** through a deterministic shield portal;
2. **commit** pending notes into the global depth-30 tree;
3. **aggregate** up to two input notes into nine regular outputs plus one fee output;
4. **withdraw** up to ten notes held by unrelated BabyJubJub scalars in a single proof.

[`CurvyClient`](curvy-sdk/src/client.rs) is the direct API. The HOPR
`DepositPool` implementation lives in
[`hopr-impls`](https://github.com/hoprnet/hopr-impls), and
[`hopr-strategy`](https://github.com/hoprnet/hopr-strategy) injects it into its
generic strategy. This SDK stays independent of HOPR's protocol lifecycle and
allocation identifiers.

## Prerequisites

| what | where | why |
|---|---|---|
| Rust 1.94 | `rust-toolchain.toml` | pinned; rustup installs it on first build |
| A C compiler | `cc` on PATH | native cryptography dependencies need it |
| Proving keys | `zk-keys/v2` in this repo | 249 MB, gitignored; fetched and digest-checked automatically by any recipe that needs them |
| A Curvy-enabled Blokli + Anvil stack | `BLOKLI_URL` | the only backend this SDK talks to |

The cryptography comes from the `curvy-core`, `curvy-prover` and `curvy-witness`
crates, pinned to `=0.1.0-rc.3`.

The proving keys are **evaluation setups**, adequate for local work and not
production trusted-setup artifacts.

## Getting a run out of it

```bash
export BLOKLI_URL=http://127.0.0.1:8080
export CURVY_ADDRESSES=/absolute/path/to/curvy_deployed_addresses.json

just e2e
```

Proving keys are fetched on demand into `zk-keys/v2` inside the repo, and `just` points
`CURVY_ZK_KEYS_DIR` there, so there is no path to configure. Driving cargo directly still
works, and then `CURVY_ZK_KEYS_DIR` is yours to set.

The stack must deploy verifier profiles `(2,9)` and `(10)`. Nine phases exercise
deposit, two aggregation fan-outs, a ten-owner withdrawal, commitment, and indexed
nullifier verification. Each prints as it completes, and the summary lists every
transaction with its label, backend and hash.

See [TESTING.md](TESTING.md) for stack requirements and validation commands.

`curvy-e2e --preflight` checks the artifacts, the proving keys, the address manifest
and Blokli, submits nothing, and exits. Run it first on a machine you have not proved
on before.

Set `CURVY_E2E_SALT=<u64>` to reproduce a specific run against a fresh chain.
Without it each run generates a unique note salt.

## Workspace

| crate | responsibility |
|---|---|
| `curvy-sdk` | deposit, pending-note commit, aggregation, withdrawal, note sync |
| `curvy-witnesscalc` | circuit input assembly, artifact selection, witness calculation, Groth16 proving |
| `curvy-chain-blokli` | Blokli GraphQL index and `sendTransactionSync` submission |
| `curvy-chain-rpc` | direct on-chain reads and plain-transfer fallback; not on the acceptance path |
| `curvy-chain-api`, `curvy-types` | backend-neutral seams and data types |
| `curvy-abi` | v2 ABI bindings, raw-transaction signing, Groth16 calldata conversion |
| `curvy-e2e` | the runnable acceptance flow |

Cryptographic primitives and proving are provided by the `curvy-*` crates. This
workspace assembles circuit inputs and coordinates chain operations.

## Scanning an already-indexed note

Code that already has a pending note does not need to construct a `CurvyClient`
or provide chain and transaction adapters. Normalize the indexer result to a
`PendingNote`, then use the pure scanner:

```rust
use curvy_sdk::{Account, PendingNote, scan_pending_note};

if let Some(discovered) = scan_pending_note(&account, &pending_note)? {
    persist_until_commit(discovered.into_owned_note())?;
}
```

Contract `PendingNotes` events contain parallel arrays and may hold multiple
notes. `PendingNotesEvent::notes()` validates and normalizes those arrays;
`scan_pending_event` scans the complete event and returns every owned note. A
successful discovery contains the complete `OwnedNote` required for durable
pending-to-committed correlation and later spending. The existing
`CurvyClient::scan` remains available when the SDK itself should query all indexed
events.

## Output shape

`VerifyPixAggregation(2, 9, 30, 6)` emits `maxOutputs + 1` notes: nine regular
outputs plus the protocol fee note in its own constrained slot:

| slot | note | constrained by the circuit? |
|---|---|---|
| 1-7 | allocations to note owners | no |
| 8 | change back to the spender | no |
| 9 | relayer gas reimbursement | no |
| 10 | protocol fee note | yes; owner is `feeNotePublicKey`, amount is `gasFee + protocolFeeQ` |

Only the fee note is constrained. A relayer must verify that an output is addressed
to it and covers its live gas quote before submitting the transaction.

The protocol fee applies to every output the spender does not own, including the
relayer note.

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

Blokli's `curvy*` resolvers perform direct contract reads. `sync()` reconciles the
locally rebuilt tree against the on-chain root before spending notes.

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

`leaves_from_events` is the fallback for backends without snapshots. It requires
events in chain order.

Both reconcile against the aggregator's on-chain root before anything is spent.

## Artifacts

Every circuit needs a witness graph and a proving key at runtime. Both are resolved the
same way: a circuit-specific variable (`CURVY_<CIRCUIT>_GRAPH`, `CURVY_<CIRCUIT>_ZKEY`)
wins, otherwise the file is looked up flat under `CURVY_ZK_KEYS_DIR`. Both are
authenticated against SHA-256 digests pinned in `curvy-witnesscalc` before decompression,
decoding, or the unchecked point parser sees them. Wrong or stale files fail closed.

The artifacts are **not** part of the published crates. They ship with this repository's
GitHub releases; a consumer downloads the release's graphs and keys into one directory
and points `CURVY_ZK_KEYS_DIR` at it. `scripts/fetch-keys.sh` does exactly that for this
checkout, and copies the graphs from `artifacts/signet` alongside.

The graphs for pending `(5,30)`, aggregation `(2,9,30,6)`, withdrawal `(10,30)`, and two
compatibility profiles are checked in under `artifacts/signet`: `SIGNET01` version-1
bodies inside zstd frames, 9.5 MB in total, readable by a stock `curvy-witness` with no
feature flags. The `bundled-graphs` feature of `curvy-witnesscalc` falls back to that
directory and exists for this repository's own tests and acceptance flow only.

See [artifacts/README.md](artifacts/README.md) for digests and test fixtures.

## Local checks

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

The default suite calculates the full aggregation and withdrawal witnesses and checks
every bundled graph pin. To prove and self-verify every profile against the evaluation
keys:

```bash
just test-proving
```

`cargo test` needs `libclang` for the graph-equivalence tests. Builds also need a C
compiler for `secp256k1-sys`.

For the acceptance flow on a separate Linux box, see [TESTING.md](TESTING.md).
Check a machine before proving anything on it:

```bash
./scripts/preflight.sh
```
