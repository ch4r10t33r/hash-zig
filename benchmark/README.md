# Cross-Language Benchmark Suite

This directory contains the tooling that exercises both the Zig and Rust implementations of Generalized XMSS and reports timing/compatibility results. The current flow is centered around the convenience script `benchmark.py`, which mirrors what CI runs.

## What the script does

Running `python3 benchmark.py` will:

- Build the helper binaries
  - `zig-remote-hash-tool` via `zig build zig-remote-hash-tool -Doptimize=ReleaseFast`
  - `remote_hashsig_tool` via `cargo build --release --bin remote_hashsig_tool`
- Generate deterministic key pairs for lifetimes `2^8` and `2^18` (256 active epochs)
- Sign with both implementations and verify in all four directions (Zig→Zig, Zig→Rust, Rust→Rust, Rust→Zig)
- Print a per-operation timing table and the locations of the generated artifacts under `/tmp`

You can run the exact same flow locally as the CI job “Run cross-language compatibility suite”.

## Prerequisites

- Python 3.8+
- Rust toolchain 1.87.0 (matches CI)
- Zig 0.14.1

Check with:

```bash
python3 --version
rustc --version
zig version
```

## Quick start

From the repository root:

```bash
python3 benchmark/benchmark.py
```

Example output (abridged):

```
=== Scenario: Lifetime 2^18 ===
  Rust sign (keygen)             PASS  (0.028s)
  Rust sign → Zig verify         PASS  (0.037s)
  Zig sign (keygen)              PASS  (6.847s)
  Zig sign → Rust verify         PASS  (0.007s)
  Rust public key: /tmp/rust_public_2pow18.key.json
  Zig public key : /tmp/zig_public_2pow18.key.json
```

The script stores the public keys and signatures for each scenario under `/tmp` so you can inspect them or reuse them with the helper binaries.

## Manual helper usage

If you want to drive the helpers yourself:

```bash
# Build everything once
zig build zig-remote-hash-tool -Doptimize=ReleaseFast
cargo build --manifest-path benchmark/rust_benchmark/Cargo.toml --release --bin remote_hashsig_tool

# Rust: sign (writes JSON public key + bincode signature)
benchmark/rust_benchmark/target/release/remote_hashsig_tool \
  sign "message" /tmp/rust_public.key.json /tmp/rust_signature.bin \
  4242…4242 0 256 0 2^18

# Zig: verify the Rust artefacts
zig-out/bin/zig-remote-hash-tool verify "message" \
  /tmp/rust_public.key.json /tmp/rust_signature.bin 0 2^18
```

Swap the commands to sign with Zig and verify with Rust. The helpers accept the lifetime (`2^8` or `2^18`), the seed (`SEED_HEX` argument), the starting epoch, and the active window so they line up with the benchmark script.

## Updating or extending benchmarks

- Adjust the lifetimes or scenarios by editing the `SCENARIOS` list in `benchmark.py`.
- The helper binaries already support custom seeds, start epochs, and active epochs; expose more scenarios by wiring them into the script.
- If you need raw timing without verification, call the helpers directly or wrap them in your own driver script.

## Troubleshooting

- **Missing toolchains**: make sure `rustup` installed 1.87.0 and `zig` 0.14.1 is on PATH.
- **Failed build**: inspect the cargo/zig output printed by the script; it bubbles up errors before running the checks.
- **Different results from CI**: ensure you are running the script from a clean worktree and that you have not modified the helper binaries locally.

## Related documents

- `COMPATIBILITY_TEST.md` – summary of interoperability expectations and how we measure them.
- `PERFORMANCE_TESTING.md` – guidance for capturing timing breakdowns beyond the default script.
