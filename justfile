# Repository commands.

# Proving keys fetched by `fetch-keys`.
export CURVY_ZK_KEYS_DIR := justfile_directory() / "zk-keys/v2"

# ============================================================================
# Default Command
# ============================================================================

# Show available commands
default:
    @just --list

# ============================================================================
# Quick Workflows
# ============================================================================

# Quick check - format, clippy, and check
quick: fmt clippy check

# Development build and test cycle - format, check, and test
dev: fmt check test

# ============================================================================
# Build Commands
# ============================================================================

# Build all workspace packages in debug mode
build:
    cargo build --workspace

# Build all workspace packages in release mode with full optimizations
build-release:
    cargo build --workspace --release

# Check all workspace code without building binaries
check:
    cargo check --workspace

# Clean all build artifacts
clean:
    cargo clean

# ============================================================================
# Test Commands
# ============================================================================

# The E2E suite requires a live Blokli stack.

# Run all tests in workspace
test:
    cargo test --workspace --exclude curvy-e2e --no-fail-fast

# Run tests for a specific package
test-package package:
    cargo test -p {{ package }} --no-fail-fast

# Run tests in single thread mode with output (useful for debugging)
test-debug:
    cargo test --workspace --exclude curvy-e2e -- --test-threads=1 --nocapture

# Run all tests in workspace using nextest
nextest:
    cargo nextest run --workspace --exclude curvy-e2e

# Run tests for a specific package using nextest
nextest-package package:
    cargo nextest run -p {{ package }}

# Prove and verify every bundled profile.
test-proving: fetch-keys
    cargo test --release -p curvy-witnesscalc -- --include-ignored --nocapture

# Optional salt, as in `just test-e2e 123456`, replays one specific run and is only
# meaningful against a fresh chain.

# Run the acceptance flow as a test (requires a live Blokli stack)
test-e2e salt="": fetch-keys
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{ salt }}" ]; then
      export CURVY_E2E_SALT="{{ salt }}"
      echo "replaying run salt {{ salt }}"
    fi
    cargo test --release -p curvy-e2e --test e2e -- --include-ignored --nocapture

# ============================================================================
# Code Quality
# ============================================================================

# Format all code
fmt:
    cargo fmt --all

# Run clippy lints with warnings as errors
clippy:
    cargo clippy --workspace -- -D warnings

# Run clippy on all targets (lib, bin, tests, benches, examples)
clippy-all:
    cargo clippy --workspace --all-targets -- -D warnings

# Automatically fix clippy warnings
clippy-fix:
    cargo clippy --workspace --fix --allow-dirty --allow-staged

# Verify formatting without writing (what CI would run)
fmt-check:
    cargo fmt --all --check

# ============================================================================
# Run Commands - acceptance flow
# ============================================================================

# Fetch the evaluation proving keys into ./zk-keys/v2 if absent, and verify every pin
fetch-keys:
    ./scripts/fetch-keys.sh

# Check artifacts, proving keys, the address manifest and Blokli, and submit nothing
preflight: fetch-keys
    ./scripts/preflight.sh

# Check the same things through the SDK's own pins, without the host checks
preflight-sdk: fetch-keys
    cargo run --release -p curvy-e2e -- --preflight

# Pass a salt to replay a run against a fresh chain.

# Run the nine-phase acceptance flow against a live Blokli stack
e2e salt="": fetch-keys
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{ salt }}" ]; then
      export CURVY_E2E_SALT="{{ salt }}"
      echo "replaying run salt {{ salt }}"
    fi
    cargo run --release -p curvy-e2e

# ============================================================================
# Artifacts
# ============================================================================

# Re-check every bundled graph and proving key against its pinned digest
verify-artifacts: preflight-sdk

# ============================================================================
# Documentation
# ============================================================================

# Build and open the workspace documentation
doc:
    cargo doc --workspace --no-deps --open

# Build documentation with warnings as errors
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
