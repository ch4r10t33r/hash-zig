# Cross-Language Benchmark Suite

This directory contains the tooling that exercises both the Zig and Rust implementations of Generalized XMSS and reports timing/compatibility results. The current flow is centered around the convenience script `benchmark.py`, which mirrors what CI runs.

## What the script does

Running `python3 benchmark.py` will:

- Build the helper binaries
  - `cross-lang-zig-tool` via `zig build install -Doptimize=ReleaseFast`
  - `cross_lang_rust_tool` via `cargo build --release --bin cross_lang_rust_tool`
- Generate deterministic key pairs for lifetime `2^8` (256 active epochs)
- Sign with both implementations and verify in all four directions (Zig→Zig, Zig→Rust, Rust→Rust, Rust→Zig)
- Print a per-operation timing table and the locations of the generated artifacts under `/tmp`
- Ensure signatures are in leanSpec-compatible format (3116 bytes, canonical form)

You can run the exact same flow locally as the CI job "Run cross-language compatibility suite".

**Note:** The cross-language tools (`cross-lang-zig-tool` and `cross_lang_rust_tool`) are specifically designed for cross-language compatibility testing and ensure signatures conform to the [leanSpec signature format](https://github.com/leanEthereum/leanSpec/blob/main/src/lean_spec/subspecs/containers/signature.py) (3116 bytes).

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
=== Scenario: Lifetime 2^8 ===
  Rust sign (keygen)             PASS  (0.013s)
  Rust sign → Rust verify        PASS  (0.003s)
  Rust sign → Zig verify         PASS  (0.318s)
  Zig sign (keygen)              PASS  (1.245s)
  Zig sign → Zig verify          PASS  (0.006s)
  Zig sign → Rust verify         PASS  (0.003s)
  Rust public key: /tmp/rust_public_2pow8.key.json
  Zig public key : /tmp/zig_public_2pow8.key.json
```

The script stores the public keys and signatures for each scenario under `/tmp` so you can inspect them or reuse them with the helper binaries.

## Manual helper usage

The cross-language tools use a simpler interface designed for compatibility testing:

```bash
# Build everything once
zig build install -Doptimize=ReleaseFast
cargo build --manifest-path benchmark/rust_benchmark/Cargo.toml --release --bin cross_lang_rust_tool

# Rust: generate keypair (saves to tmp/rust_sk.json and tmp/rust_pk.json)
cd benchmark/rust_benchmark
target/release/cross_lang_rust_tool keygen 4242424242424242424242424242424242424242424242424242424242424242

# Rust: sign message (reads from tmp/rust_sk.json, writes to tmp/rust_sig.bin)
target/release/cross_lang_rust_tool sign "message" 0

# Zig: verify the Rust signature
cd ../..
zig-out/bin/cross-lang-zig-tool verify tmp/rust_sig.bin tmp/rust_pk.json "message" 0

# Zig: generate keypair (saves to tmp/zig_sk.json and tmp/zig_pk.json)
zig-out/bin/cross-lang-zig-tool keygen 4242424242424242424242424242424242424242424242424242424242424242

# Zig: sign message (reads from tmp/zig_sk.json, writes to tmp/zig_sig.bin)
zig-out/bin/cross-lang-zig-tool sign "message" 0

# Rust: verify the Zig signature
cd benchmark/rust_benchmark
target/release/cross_lang_rust_tool verify ../tmp/zig_sig.bin ../tmp/zig_pk.json "message" 0
```

**Key features:**
- All tools use `tmp/` directory (relative to project root) for key and signature files
- Signatures are automatically padded to exactly 3116 bytes (leanSpec format)
- Field elements are serialized in canonical form (matching Rust's `bincode::serialize`)
- Currently supports lifetime `2^8` only (hardcoded in the tools)

**Signature format:**
- Binary format (bincode) with canonical field element representation
- Exactly 3116 bytes (padded with zeros if needed)
- Compatible with [leanSpec signature container](https://github.com/leanEthereum/leanSpec/blob/main/src/lean_spec/subspecs/containers/signature.py)

## Updating or extending benchmarks

- Adjust the lifetimes or scenarios by editing the `build_scenarios` function in `benchmark.py`.
- The cross-language tools currently support lifetime `2^8` only. To add support for other lifetimes, modify the tools to accept a lifetime parameter.
- The tools support custom seeds via the `keygen` command. The benchmark script uses a deterministic seed for reproducibility.
- If you need raw timing without verification, call the helpers directly or wrap them in your own driver script.

## Tools Overview

### `cross-lang-zig-tool` (Zig)
- **Location:** `zig-out/bin/cross-lang-zig-tool`
- **Commands:**
  - `keygen [seed_hex]` - Generate keypair (saves to `tmp/zig_sk.json` and `tmp/zig_pk.json`)
  - `sign <message> <epoch>` - Sign message (reads from `tmp/zig_sk.json`, writes to `tmp/zig_sig.bin`)
  - `verify <sig_path> <pk_path> <message> <epoch>` - Verify signature

### `cross_lang_rust_tool` (Rust)
- **Location:** `benchmark/rust_benchmark/target/release/cross_lang_rust_tool`
- **Commands:**
  - `keygen [seed_hex]` - Generate keypair (saves to `tmp/rust_sk.json` and `tmp/rust_pk.json`)
  - `sign <message> <epoch>` - Sign message (reads from `tmp/rust_sk.json`, writes to `tmp/rust_sig.bin`)
  - `verify <sig_path> <pk_path> <message> <epoch>` - Verify signature

## Troubleshooting

- **Missing toolchains**: make sure `rustup` installed 1.87.0 and `zig` 0.14.1 is on PATH.
- **Failed build**: inspect the cargo/zig output printed by the script; it bubbles up errors before running the checks.
- **Different results from CI**: ensure you are running the script from a clean worktree and that you have not modified the helper binaries locally.
- **File not found errors**: The tools use `tmp/` directory relative to the project root. Make sure you're running commands from the correct directory.
- **Verification failures**: Check that signatures are exactly 3116 bytes and that field elements are in canonical form. The tools handle this automatically, but manual signature manipulation may cause issues.

## Related documents

- `docs/CROSS_LANGUAGE_COMPAT_TOOL.md` – documentation for the cross-language compatibility tools
- `docs/CROSS_LANGUAGE_VERIFICATION_FIX.md` – details on cross-language verification fixes
- `docs/ENCODING_SUM_FIX.md` – investigation and fixes for encoding sum mismatches
