#!/usr/bin/env bash
set -euo pipefail

POC_DIR="${POC_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
REPOSITORY_ROOT="$(cd "$POC_DIR/../../.." && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/curvy-witness-graph.XXXXXX")"
UPSTREAM_REV="38553d2e71059c8635651a81a397603c75fb9d8a"
CIRCUIT_RELATIVE_PATH="${1:-v2/instances/verifySingleWithdrawalNoHashing_2_30.circom}"
OUTPUT_PATH="${2:-$POC_DIR/artifacts/withdrawal-2-30.graph.bin}"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

git clone --quiet https://github.com/philsippl/circom-witness-rs.git "$WORK_DIR/circom-witness-rs"
git -C "$WORK_DIR/circom-witness-rs" checkout --quiet "$UPSTREAM_REV"
git -C "$WORK_DIR/circom-witness-rs" apply --unidiff-zero "$POC_DIR/patches/circom-witness-rs-v0.2.3.patch"

mkdir -p "$WORK_DIR/zk-circuits/node_modules"
cp -R "$REPOSITORY_ROOT/packages/zk-circuits/circuits" "$WORK_DIR/zk-circuits/circuits"
cp -RL "$REPOSITORY_ROOT/packages/zk-circuits/node_modules/circomlib" "$WORK_DIR/zk-circuits/node_modules/circomlib"
patch --quiet -d "$WORK_DIR/zk-circuits" -p1 < "$POC_DIR/patches/circomlib-iszero-bbf.patch"
# Circom debug logs do not affect constraints, but their generated C++ calls an
# unsupported formatting helper. Strip them only in the disposable graph copy;
# the R1CS equality check below proves the circuit itself is unchanged.

ORIGINAL_CIRCUIT="$REPOSITORY_ROOT/packages/zk-circuits/circuits/$CIRCUIT_RELATIVE_PATH"
PATCHED_CIRCUIT="$WORK_DIR/zk-circuits/circuits/$CIRCUIT_RELATIVE_PATH"
CIRCUIT_NAME="$(basename "$CIRCUIT_RELATIVE_PATH" .circom)"
mkdir -p "$WORK_DIR/original-r1cs" "$WORK_DIR/patched-r1cs"
circom "$ORIGINAL_CIRCUIT" --r1cs --O2 -o "$WORK_DIR/original-r1cs"
circom "$PATCHED_CIRCUIT" --r1cs --O2 -o "$WORK_DIR/patched-r1cs"
cmp \
  "$WORK_DIR/original-r1cs/$CIRCUIT_NAME.r1cs" \
  "$WORK_DIR/patched-r1cs/$CIRCUIT_NAME.r1cs"

(
  cd "$WORK_DIR/circom-witness-rs"
  WITNESS_CPP="$PATCHED_CIRCUIT" cargo run --release --features build-witness --bin build_graph
)
mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$WORK_DIR/circom-witness-rs/graph.bin" "$OUTPUT_PATH"
shasum -a 256 "$WORK_DIR/original-r1cs/$CIRCUIT_NAME.r1cs"
