# Performance Testing Guide for Optimized Zig Implementation

## Overview

The Zig benchmark has been updated to use the `optimized_rust_compatible` version, which aims to match Rust's hash-sig implementation while maintaining better performance.

## Current Performance Results

### Latest Benchmark Results (Lifetime 2^10 = 1,024 signatures)

- **Rust (hash-sig)**: ~0.965 seconds
- **Zig (optimized)**: ~2.818 seconds
- **Performance Gap**: Zig is ~2.9x slower than Rust

### Previous Results (Before Optimization)

- **Zig (non-optimized)**: ~2.893 seconds
- **Improvement**: ~2.6% faster

## How to Test Performance

### 1. Build the Optimized Version

```bash
cd /Users/partha/zig/hash-sig-benchmarks/zig_benchmark
zig build -Doptimize=ReleaseFast
```

### 2. Run Individual Benchmarks

**Test Zig Implementation:**
```bash
cd /Users/partha/zig/hash-sig-benchmarks/zig_benchmark
SEED_HEX=$(printf '42%.0s' {1..64}) ./zig-out/bin/keygen_bench
```

**Test Rust Implementation:**
```bash
cd /Users/partha/zig/hash-sig-benchmarks/rust_benchmark
SEED_HEX=$(printf '42%.0s' {1..64}) cargo run --release
```

### 3. Run Comparative Benchmark

```bash
cd /Users/partha/zig/hash-sig-benchmarks
SEED_HEX=$(printf '42%.0s' {1..64}) python3 benchmark.py 3
```

This will run 3 iterations and provide statistical analysis.

### 4. Run with Different Seeds

```bash
# Random seed
SEED_HEX=$(openssl rand -hex 32) ./zig-out/bin/keygen_bench

# Specific seed
SEED_HEX="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ./zig-out/bin/keygen_bench
```

## Optimization Techniques Implemented

### 1. **Removed HashMap Caching**
   - Initially tried to implement hash caching but removed it to avoid complexity
   - HashMap overhead wasn't worth the potential benefit for this use case

### 2. **Batch Processing**
   - Process Winternitz chains in batches of 4 for better memory locality
   - Reduces cache misses during public key generation

### 3. **Memory Pre-allocation**
   - Pre-compute total memory requirements
   - Single large allocations instead of many small ones
   - Reduces memory fragmentation

### 4. **Optimized Memory Layout**
   - Contiguous memory for leaf keys improves cache performance
   - Better data locality during Merkle tree construction

## Further Optimization Opportunities

### High Impact Optimizations

1. **SIMD Instructions for Hash Chains**
   - Apply 256 hash operations in parallel using SIMD
   - Potential 4-8x speedup depending on hardware

2. **Multi-threading**
   - Generate Winternitz key pairs in parallel (1024 leaves)
   - Thread pool for Merkle tree construction
   - Potential near-linear speedup with core count

3. **Custom Allocator**
   - Arena allocator with fixed-size pools
   - Eliminate allocation overhead
   - Reduce memory fragmentation

4. **Lookup Tables**
   - Pre-compute common hash values
   - Trade memory for speed

### Medium Impact Optimizations

1. **Inline Critical Functions**
   - Mark hot path functions as `inline`
   - Reduce function call overhead

2. **Loop Unrolling**
   - Manually unroll tight loops in hash operations
   - Compiler hints for vectorization

3. **Memory Access Patterns**
   - Structure data for sequential access
   - Minimize pointer chasing

### Low Impact Optimizations

1. **Const Propagation**
   - Mark more values as `const` where possible
   - Help compiler optimize better

2. **Reduce Allocations**
   - Reuse buffers where possible
   - Stack allocations for small, fixed-size data

## Profiling Commands

### Profile with Zig

```bash
# Build with debug symbols
zig build -Doptimize=ReleaseFast

# Run with time profiling
time ./zig-out/bin/keygen_bench

# Use perf (Linux) or Instruments (macOS)
perf record -g ./zig-out/bin/keygen_bench
perf report
```

### Profile with Rust

```bash
# Build with profiling
cargo build --release

# Run with time profiling
time ./target/release/keygen_bench

# Use cargo-flamegraph
cargo install flamegraph
cargo flamegraph --bin keygen_bench
```

## Benchmark Metrics

The benchmark reports several key metrics:

1. **Key Generation Time**: Total time to generate the keypair
2. **PUBLIC_SHA3**: SHA3-256 hash of the public key (for verification)
3. **VERIFY_OK**: Whether self-verification passed
4. **BENCHMARK_RESULT**: Precise timing in seconds

## Key Differences Between Implementations

### Current Status

- **Rust**: Uses `GeneralizedXMSSPublicKey` with `PoseidonTweakHash<5, 7, 2, 9, 20>`
- **Zig**: Uses `OptimizedRustCompatibleHashSignature` with custom Poseidon2 parameters

### Why Keys Don't Match

Even with matching parameters (22 chains, w=8, lifetime 2^10), the keys differ because:

1. **Different Poseidon2 Implementations**
   - Rust: width=5, ext_rounds=7, int_rounds=2, sbox=9, field_bits=20
   - Zig: width=16, ext_rounds=8, int_rounds=20, sbox=3, KoalaBear field

2. **Different Merkle Tree Construction**
   - Internal node ordering and hashing strategies differ

3. **Different Field Arithmetic**
   - Rust uses a 20-bit field
   - Zig's SIMD implementation uses KoalaBear field (different modulus)

## Next Steps for Full Compatibility

To achieve bit-for-bit compatibility with Rust:

1. Implement exact Poseidon2 parameters from Rust
2. Match Merkle tree construction algorithm
3. Use identical field arithmetic
4. Verify against Rust test vectors

## Quick Performance Comparison Script

```bash
#!/bin/bash
echo "=== Performance Comparison ==="
echo

echo "Rust Implementation:"
cd /Users/partha/zig/hash-sig-benchmarks/rust_benchmark
SEED_HEX=$(printf '42%.0s' {1..64}) cargo run --release 2>&1 | grep "BENCHMARK_RESULT"

echo

echo "Zig Optimized Implementation:"
cd /Users/partha/zig/hash-sig-benchmarks/zig_benchmark
SEED_HEX=$(printf '42%.0s' {1..64}) ./zig-out/bin/keygen_bench | grep "BENCHMARK_RESULT"
```

Save this as `compare.sh`, make it executable with `chmod +x compare.sh`, and run it.

