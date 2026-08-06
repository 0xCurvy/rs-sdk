#!/usr/bin/env bash
# Validate host tools, artifacts, keys, and Blokli without submitting transactions.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

BLOKLI_URL="${BLOKLI_URL:-http://127.0.0.1:8080}"
failures=0

say()  { printf '  %-28s %s\n' "$1" "$2"; }
ok()   { say "$1" "ok: $2"; }
bad()  { say "$1" "FAIL: $2"; failures=$((failures + 1)); }

echo "== toolchain"

if command -v cargo >/dev/null 2>&1; then
  ok cargo "$(cargo --version)"
else
  bad cargo "not on PATH; install rustup from https://rustup.rs"
fi

# Check the pinned Rust series.
pinned="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [ -n "$pinned" ]; then
  actual="$(cargo --version 2>/dev/null | awk '{print $2}')"
  # Accept any patch release in the pinned series.
  case "$actual" in
    "$pinned" | "$pinned".*) ok "rust $pinned" "active as $actual" ;;
    *) say "rust $pinned" "note: cargo reports $actual; rustup will fetch the pinned one" ;;
  esac
fi

# `secp256k1-sys` requires a C compiler.
if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; then
  ok "C compiler" "$(command -v cc || command -v gcc || command -v clang)"
else
  bad "C compiler" "secp256k1-sys needs one (apt install build-essential)"
fi

echo
echo "== bundled artifacts"

# Read graph digests from the circuit definitions.
if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  digest() { echo "no-sha256-tool"; }
fi

pins="$(sed -n 's/.*graph_default: "\([^"]*\)".*/\1/p;s/.*graph_sha256: "\([^"]*\)".*/\1/p' \
  curvy-witnesscalc/src/lib.rs | paste - -)"
if [ -z "$pins" ]; then
  bad artifacts "could not read the pin table out of curvy-witnesscalc/src/lib.rs"
else
  while IFS=$'\t' read -r name expected; do
    path="artifacts/signet/$name"
    if [ ! -f "$path" ]; then
      bad "$name" "missing"
    elif [ "$(digest "$path")" = "$expected" ]; then
      ok "$name" "$(wc -c < "$path" | tr -d ' ') bytes"
    else
      bad "$name" "sha256 mismatch, incomplete or stale copy"
    fi
  done <<< "$pins"
fi

echo
echo "== proving keys"

# Match the justfile key directory.
KEYS_DIR="${CURVY_ZK_KEYS_DIR:-$HERE/zk-keys/v2}"
if [ -d "$KEYS_DIR" ]; then
  ok CURVY_ZK_KEYS_DIR "$KEYS_DIR"
else
  bad CURVY_ZK_KEYS_DIR "$KEYS_DIR does not exist; run scripts/fetch-keys.sh"
fi

echo
echo "== blokli"

if [ -n "${CURVY_ADDRESSES:-}" ] && [ -f "${CURVY_ADDRESSES:-}" ]; then
  ok CURVY_ADDRESSES "$CURVY_ADDRESSES"
elif [ -n "${CURVY_ADDRESSES:-}" ]; then
  bad CURVY_ADDRESSES "$CURVY_ADDRESSES does not exist"
else
  bad CURVY_ADDRESSES "unset; point it at the stack's curvy_deployed_addresses.json"
fi

if command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 5 "$BLOKLI_URL/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
    ok "$BLOKLI_URL/readyz" "ready"
  else
    bad "$BLOKLI_URL/readyz" "not ready; is the stack up, and is the port forwarded?"
  fi
else
  say curl "note: absent, skipping the readiness probe"
fi

echo
if [ "$failures" -ne 0 ]; then
  echo "preflight: $failures problem(s) above. Not building."
  exit 1
fi

echo "== build and full preflight"
cargo build --release -p curvy-e2e
./target/release/curvy-e2e --preflight
