#!/bin/bash
# Script to compare Poseidon outputs between Zig and Rust

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/.."
ZIG_TOOL="$REPO_ROOT/zig-out/bin/compare-poseidon-direct"
RUST_TOOL="$REPO_ROOT/benchmark/rust_benchmark/target/release/remote_hashsig_tool"

PK_JSON="${1:-/tmp/rust_public_2pow8.key.json}"
SIG_BIN="${2:-/tmp/rust_signature_2pow8.bin}"
MESSAGE="${3:-Cross-language benchmark message}"
EPOCH="${4:-0}"
LIFETIME="${5:-2^8}"

echo "=== Poseidon Output Comparison ==="
echo "Public Key: $PK_JSON"
echo "Signature: $SIG_BIN"
echo "Message: $MESSAGE"
echo "Epoch: $EPOCH"
echo "Lifetime: $LIFETIME"
echo ""

echo "=== Zig Output ==="
ZIG_OUTPUT=$("$ZIG_TOOL" "$PK_JSON" "$SIG_BIN" "$MESSAGE" "$EPOCH" "$LIFETIME" 2>&1)
echo "$ZIG_OUTPUT" | grep "ZIG_COMPARE_OUTPUT" | head -3

echo ""
echo "=== Extracting Values ==="
ZIG_VALUES=$(echo "$ZIG_OUTPUT" | grep "ZIG_COMPARE_OUTPUT" | grep -oE '0x[0-9a-f]{8}' | head -15)
echo "Zig values:"
echo "$ZIG_VALUES" | nl -v 0 -w 2

echo ""
echo "=== Note ==="
echo "Rust output extraction requires fixing the debug code in remote_hashsig_tool.rs"
echo "The RUST_POSEIDON_OUTPUT is only printed under certain conditions that"
echo "may not be met when reading binary signatures."

