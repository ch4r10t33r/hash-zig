# Performance Testing Guide

## Overview

`benchmark/benchmark.py` records wall-clock timings for key generation and verification while exercising both implementations. Use it for quick comparisons, or drive the helper binaries directly for targeted profiling.

## Running the built-in benchmark

```bash
python3 benchmark/benchmark.py
```

The summary table includes per-operation durations (ms) for the two supported lifetimes. A typical run (ReleaseFast Zig build, Rust release binary) produces numbers in the low-millisecond range for verification and single-digit seconds for Zig key generation:

```
Lifetime 2^18:
  Rust sign (keygen)             0.028s
  Rust sign → Zig verify         0.037s
  Zig sign (keygen)              6.847s
  Zig sign → Rust verify         0.007s
```

Use these as relative indicators; rerun on your hardware after major changes.

## Manual micro-benchmarking

When you need isolated numbers without verification overhead:

```bash
# Build helpers once (ReleaseFast for Zig)
zig build zig-remote-hash-tool -Doptimize=ReleaseFast
cargo build --manifest-path benchmark/rust_benchmark/Cargo.toml --release --bin remote_hashsig_tool

# Time Rust signing only
/usr/bin/time -f "%E" benchmark/rust_benchmark/target/release/remote_hashsig_tool \
  sign "bench" /tmp/rust_public.key.json /tmp/rust_signature.bin \
  4242…4242 0 256 0 2^18

# Time Zig signing only
/usr/bin/time -f "%E" zig-out/bin/zig-remote-hash-tool \
  sign "bench" /tmp/zig_public.key.json /tmp/zig_signature.bin \
  4242…4242 0 256 0 2^18
```

Swap in custom seeds or lifetimes as required. The helpers reuse the same deterministic message truncation logic as the benchmark script.

## Profiling tips

- **Linux**: `perf record -g zig-out/bin/zig-remote-hash-tool …` followed by `perf report`
- **macOS**: Use Instruments or `sample` to capture call stacks while the helper runs
- **Windows**: Run under Windows Performance Recorder or use WSL for perf-based profiling

Always build Zig artefacts with `-Doptimize=ReleaseFast` and Rust artefacts with `--release` when measuring.

## Tracking regressions

- Capture benchmark output before and after a change; commit the console logs or record the summary numbers in your PR description.
- For significant performance work, add an extra scenario in `benchmark.py` (e.g. different lifetime) so CI can flag regressions automatically.
- If verification times change materially, re-run `benchmark.py` locally to ensure cross-language compatibility still passes.

