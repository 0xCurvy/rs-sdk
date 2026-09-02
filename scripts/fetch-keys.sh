#!/usr/bin/env bash
# Fetch and authenticate evaluation proving keys, and place the witness graphs from
# artifacts/signet next to them, so zk-keys/v2 has the flat layout consumers point
# CURVY_ZK_KEYS_DIR at.
#
# Sources, in priority order:
#   1. $CURVY_KEYS_URL   a base URL serving the files at their relative paths
#   2. DEFAULT_KEYS_URL below
#   3. $CURVY_KEYS_SRC   a local zk-keys/v2 directory to copy from, for seeding

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

# Optional release asset base URL.
# https://github.com/0xCurvy/rs-sdk/releases/download/<tag>
DEFAULT_KEYS_URL="https://github.com/0xCurvy/rs-sdk/releases/download/v0.1.0"

KEYS_DIR="$HERE/zk-keys/v2"

if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  digest() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "need sha256sum or shasum" >&2
  exit 1
fi

# Read key names and digests from the circuit definitions.
pins="$(sed -n 's/.*zkey_file: "\([^"]*\)".*/\1/p;s/.*zkey_sha256: "\([^"]*\)".*/\1/p' \
  curvy-witnesscalc/src/lib.rs | paste - -)"
if [ -z "$pins" ]; then
  echo "could not read the proving-key pins out of curvy-witnesscalc/src/lib.rs" >&2
  exit 1
fi

missing=0
while IFS=$'\t' read -r name expected; do
  target="$KEYS_DIR/$name"
  if [ ! -f "$target" ] || [ "$(digest "$target")" != "$expected" ]; then
    missing=$((missing + 1))
  fi
done <<< "$pins"

if [ "$missing" -eq 0 ]; then
  echo "proving keys: all pins verified at zk-keys/v2"
  fetched=0
  failures=0
fi

# Resolve a source for missing keys.
KEYS_URL="${CURVY_KEYS_URL:-$DEFAULT_KEYS_URL}"
KEYS_SRC="${CURVY_KEYS_SRC:-}"

if [ -z "$KEYS_URL" ] && [ -z "$KEYS_SRC" ]; then
  cat >&2 <<MSG
proving keys: $missing of 5 missing from zk-keys/v2, and there is nowhere to get them.

No default source is compiled in yet. Set one:
  CURVY_KEYS_URL=https://.../          download from a base URL
  CURVY_KEYS_SRC=/path/to/zk-keys/v2   copy from a local checkout, to seed a release

Once the keys are published, set DEFAULT_KEYS_URL in this script and neither is
needed again.
MSG
  exit 1
fi

mkdir -p "$KEYS_DIR"
if [ "$missing" -ne 0 ]; then
echo "proving keys: fetching $missing of 5 into zk-keys/v2"
failures=0
fetched=0

while IFS=$'\t' read -r name expected; do
  target="$KEYS_DIR/$name"
  if [ -f "$target" ] && [ "$(digest "$target")" = "$expected" ]; then
    continue
  fi

  if [ -n "$KEYS_URL" ]; then
    curl -fsSL --retry 3 -o "$target" "${KEYS_URL%/}/$name" || {
      printf '  %-58s DOWNLOAD FAILED\n' "$name"
      failures=$((failures + 1))
      continue
    }
  else
    # Locate nested source files by name.
    source_file="$(find "$KEYS_SRC" -name "$name" -type f -print -quit 2>/dev/null || true)"
    if [ -z "$source_file" ]; then
      printf '  %-58s MISSING at source\n' "$name"
      failures=$((failures + 1))
      continue
    fi
    cp "$source_file" "$target"
  fi

  got="$(digest "$target")"
  if [ "$got" = "$expected" ]; then
    printf '  %-58s ok (%s bytes)\n' "$name" "$(wc -c < "$target" | tr -d ' ')"
    fetched=$((fetched + 1))
  else
    # Remove invalid downloads.
    printf '  %-58s SHA-256 MISMATCH\n' "$name"
    printf '    expected %s\n    got      %s\n' "$expected" "$got"
    rm -f "$target"
    failures=$((failures + 1))
  fi
done <<< "$pins"

if [ "$failures" -ne 0 ]; then
  echo
  echo "proving keys: $failures could not be fetched or did not verify."
  exit 1
fi

echo "proving keys: $fetched fetched, all pins verified at zk-keys/v2"
fi

# Witness graphs: copied from the checkout, digest-checked like the keys.
graph_pins="$(sed -n 's/.*graph_file: "\([^"]*\)".*/\1/p;s/.*graph_sha256: "\([^"]*\)".*/\1/p' \
  curvy-witnesscalc/src/lib.rs | paste - -)"
while IFS=$'\t' read -r name expected; do
  target="$KEYS_DIR/$name"
  if [ -f "$target" ] && [ "$(digest "$target")" = "$expected" ]; then
    continue
  fi
  cp "artifacts/signet/$name" "$target"
  if [ "$(digest "$target")" != "$expected" ]; then
    printf '  %-58s SHA-256 MISMATCH (stale checkout?)\n' "$name"
    rm -f "$target"
    exit 1
  fi
  printf '  %-58s ok (%s bytes)\n' "$name" "$(wc -c < "$target" | tr -d ' ')"
done <<< "$graph_pins"
echo "witness graphs: all pins verified at zk-keys/v2"
