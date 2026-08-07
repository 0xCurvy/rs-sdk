# Testing Guide

The workspace has unit tests, artifact compatibility tests, and a live acceptance
flow against a Curvy-enabled Blokli stack.

## Commands

```bash
# Format, lint, and type-check the workspace
just quick

# Run self-contained tests
just test

# Run one package
just test-package curvy-witnesscalc

# Run tests serially with output
just test-debug

# Prove and verify every bundled profile
just test-proving

# Validate artifacts and the live stack without submitting transactions
just preflight

# Run the live acceptance flow
just e2e

# Replay a run with a fixed salt against a fresh chain
just e2e 123456
```

`curvy-e2e` is excluded from `just test` because it requires live infrastructure.
The proving tests are ignored by default because they require the evaluation keys.

## Proving keys

`just fetch-keys` populates the gitignored `zk-keys/v2` directory. Each file is
authenticated against the digest in `curvy-witnesscalc/src/lib.rs`.

To copy keys from an existing directory:

```bash
CURVY_KEYS_SRC=/path/to/zk-keys/v2 just fetch-keys
```

`CURVY_KEYS_URL` can provide a download base URL. Direct Cargo commands must set
`CURVY_ZK_KEYS_DIR` or a circuit-specific key variable.

## Live acceptance flow

The flow requires:

- a Blokli endpoint with Curvy indexing enabled;
- a deployment address manifest;
- the authenticated proving keys; and
- chain ID `31337`.

### Bringing up the stack

One container carries anvil, the deployed Curvy suite, and Blokli with Curvy indexing
enabled. It deploys unconditionally, so there is no flag to set.

```bash
cd ~/Projects/blokli && git add -N . && nix build -L .#docker-bloklid-anvil-curvy-x86_64-linux --out-link result-curvy-image
```

```bash
cd ~/Projects/blokli && docker load < result-curvy-image
```

```bash
mkdir -p /tmp/blokli-curvy-data && docker run --rm --name bloklid-anvil-curvy -e ANVIL_HOST=0.0.0.0 -p 8545:8545 -p 8080:8080 -v /tmp/blokli-curvy-data:/data bloklid-anvil-curvy:latest
```

The manifest lands at `/tmp/blokli-curvy-data/curvy_deployed_addresses.json`. Nix
flakes copy tracked files only, so `git add -N` stages any new file for the build.

### Running it

Set the runtime paths before starting:

```bash
export BLOKLI_URL=http://127.0.0.1:8080
export CURVY_ADDRESSES=/tmp/blokli-curvy-data/curvy_deployed_addresses.json
export CURVY_ZK_KEYS_DIR="$PWD/zk-keys/v2"
```

Confirm the deploy registered both PIX verifiers before proving anything:

```bash
jq 'keys' "$CURVY_ADDRESSES"
```

`CurvyAggregator#CurvyPixAggregationVerifier`,
`CurvyAggregator#CurvyPixMultiOwnerWithdrawalVerifier` and
`PortalFactoryV2#PortalFactory` must all be present.

Check readiness and the required GraphQL fields:

```bash
curl -s "$BLOKLI_URL/readyz"
curl -s "$BLOKLI_URL/graphql" \
  -H 'content-type: application/json' \
  --data '{"query":"{ curvyAggregatorFees { __typename ... on CurvyAggregatorFees { protocolFeePerThousand commitmentFeeRoot feeNotePublicKey } } curvyVaultTokenCount { __typename ... on CurvyVaultTokenCount { count } } }"}'
```

Then validate and run:

```bash
just preflight
just e2e
```

The flow covers deposit funding and shielding, note commitment, two aggregation
proofs, relayer-note discovery, multi-owner withdrawal, indexed nullifiers, and the
`DepositPool` interface. Protocol transactions must report Blokli as their backend.

## Test organization

### Unit tests

Unit tests are colocated with their modules. They cover field conversion, note
construction, value splitting, persistence, state transitions, response decoding,
and error classification without requiring a chain.

### Artifact compatibility tests

`curvy-witnesscalc/tests/pix_profiles.rs` compares assignments from the bundled
SIGNET graphs with pinned iden3 reference graphs. It also checks graph digests,
optional evaluator modes, and proof verification when keys are available.

The reference evaluator is a development dependency and requires `libclang`.
Building or running the SDK does not compile it.

### Live acceptance test

`curvy-e2e/tests/e2e.rs` runs the complete flow against Blokli. It is ignored by
default and is available through `just test-e2e` or `just e2e`.

The suite does not simulate index lag, reorganization, RPC outages, or a disk-backed
restart during the live flow. Those cases require dedicated infrastructure tests.

## Adding tests

- Use deterministic inputs unless randomness is the behavior under test.
- Pin every artifact by SHA-256.
- Compare circuit assignments with an independent evaluator when possible.
- Name tests after the invariant they establish.
- Mark tests requiring external state with `#[ignore = "reason"]`.
- Keep adapter fixtures aligned with the public Blokli schema.

Run the full local gate before committing:

```bash
just fmt-check
just clippy-all
just test
just doc-check
```

## Troubleshooting

| Symptom | Check |
|---|---|
| `graph sha256 mismatch` | Replace the stale or truncated graph. |
| `zkey sha256 mismatch` | Replace the key and rerun `just fetch-keys`. |
| `proving key location is not configured` | Set `CURVY_ZK_KEYS_DIR` or use `just`. |
| `Blokli is not ready` | Check the daemon and `BLOKLI_URL`. |
| `unexpected chain id` | Point the SDK at the local test chain. |
| GraphQL `Unknown type` | Use a Blokli build with the Curvy schema enabled. |
| `sync` root mismatch | Verify the configured aggregator address and rebuild the index. |
| transaction bypassed Blokli | Treat it as an adapter or routing defect. |
| linker or `cc` failure | Install a C compiler for `secp256k1-sys`. |
| `libclang` failure | Install libclang for witness compatibility tests. |

`alloy` is configured for plain HTTP. HTTPS and WebSocket endpoints are not
supported by this workspace build.
