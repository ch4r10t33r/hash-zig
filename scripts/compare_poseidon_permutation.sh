#!/bin/bash
# Script to compare Rust and Zig Poseidon permutation implementations
# This extracts input from a real signature and tests both variants

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$SCRIPT_DIR/../benchmark"
RUST_BENCHMARK_DIR="$BENCHMARK_DIR/rust_benchmark"
ZIG_BENCHMARK_DIR="$BENCHMARK_DIR/zig_benchmark"

echo "=== Poseidon Permutation Comparison Tool ==="
echo ""

# Check if we have test files
if [ ! -f "$RUST_BENCHMARK_DIR/test_data/public_key.json" ] || [ ! -f "$RUST_BENCHMARK_DIR/test_data/signature.bin" ]; then
    echo "Creating test data..."
    cd "$RUST_BENCHMARK_DIR"
    
    # Generate a test signature if needed
    if [ ! -f "test_data/public_key.json" ]; then
        mkdir -p test_data
        cargo run --release --bin sign_message -- "Test message for Poseidon comparison" test_data/public_key.json test_data/signature.bin 2>/dev/null || {
            echo "Error: Could not generate test data. Please run manually:"
            echo "  cd $RUST_BENCHMARK_DIR"
            echo "  cargo run --release --bin sign_message -- 'Test message' test_data/public_key.json test_data/signature.bin"
            exit 1
        }
    fi
fi

echo "Step 1: Extracting Poseidon input from signature..."
cd "$RUST_BENCHMARK_DIR"

# Use the poseidon_debug tool to extract inputs
RUST_OUTPUT=$(cargo run --release --bin poseidon_debug -- test_data/public_key.json test_data/signature.bin 0 "Test message" 2>&1)

# Extract parameter and rho values
PARAM_VALUES=$(echo "$RUST_OUTPUT" | grep "param\[" | sed 's/.*= \([0-9]*\).*/\1/' | tr '\n' ' ')
RHO_VALUES=$(echo "$RUST_OUTPUT" | grep "rho\[" | sed 's/.*= \([0-9]*\).*/\1/' | tr '\n' ' ')

echo "Parameter values: $PARAM_VALUES"
echo "Rho values: $RHO_VALUES"

# Create JSON input file for permutation test
# Format: rho (7) + parameter (5) + epoch (2) + message (9) + iteration_index (1) = 24 elements
# For now, let's create a simple test input
cat > /tmp/poseidon_input.json <<EOF
{
  "input": [
    $(echo "$RHO_VALUES" | awk '{for(i=1;i<=7;i++) printf "%s%s", $i, (i<7?", ":"")}')
    $(echo "$PARAM_VALUES" | awk '{for(i=1;i<=5;i++) printf ", %s", $i}')
    , 0, 0
    , 84, 101, 115, 116, 32, 109, 101, 115, 115
    , 0
  ]
}
EOF

echo ""
echo "Step 2: Testing Rust permutation..."
cd "$RUST_BENCHMARK_DIR"
cargo build --release --bin debug_poseidon_step_by_step --features debug-tools 2>/dev/null || {
    echo "Building Rust tool..."
    cargo build --release --bin debug_poseidon_step_by_step --features debug-tools
}

RUST_RESULT=$(cargo run --release --bin debug_poseidon_step_by_step --features debug-tools -- /tmp/poseidon_input.json 2>&1)
echo "$RUST_RESULT" | grep -A 30 "RUST_PERM_RESULT" || echo "$RUST_RESULT"

echo ""
echo "Step 3: Testing Zig permutation (WITH MDS light)..."
cd "$ZIG_BENCHMARK_DIR"
zig build debug_poseidon_mds_light_test 2>/dev/null || {
    echo "Building Zig tool..."
    zig build debug_poseidon_mds_light_test
}

ZIG_RESULT=$(./zig-out/bin/debug_poseidon_mds_light_test /tmp/poseidon_input.json 2>&1)
echo "$ZIG_RESULT" | grep -A 30 "ZIG_TEST_VARIANT1_RESULT" || echo "$ZIG_RESULT"

echo ""
echo "Step 4: Comparing results..."
echo "Check the outputs above to see which Zig variant matches Rust."

