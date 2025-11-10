# Rust Compatibility Guide

## Overview

The `hash-zig` implementation is designed to be **100% compatible** with the Rust `hash-sig` reference implementation (https://github.com/b-wagn/hash-sig/). The primary `HashSignature` implementation is now Rust-compatible by default. This document outlines the requirements and tests that enforce this compatibility.

## ⚠️ CRITICAL: Rust Compatibility is MANDATORY

**ALL changes to this codebase MUST maintain compatibility with the Rust implementation.**

- ❌ DO NOT change the Poseidon2 parameters
- ❌ DO NOT change the MDS matrix implementation  
- ❌ DO NOT change the Winternitz parameters (w=8, 22 chains, chain_length=256)
- ❌ DO NOT change the hash function from Poseidon2
- ✅ ALL tests MUST pass before merge
- ✅ Signature verification MUST work

## Required Parameters

### Poseidon2 Configuration (KoalaBear Field)
```zig
- Field: KoalaBear (p = 0x7f000001 = 2^31 - 2^24 + 1)
- Width: 16
- External rounds: 8
- Internal rounds: 20
- S-Box degree: 3 (x^3)
- Hash output: 32 bytes (8 field elements × 4 bytes)
```

### Winternitz OTS Parameters
```zig
- w: 8 (chain length = 2^8 = 256)
- Number of chains: 22
- Hash function: Poseidon2 (as above)
- Encoding: Binary (Incomparable)
```

### Merkle Tree Parameters
```zig
- Tree height: 10 (for 2^10 = 1,024 signatures)
- Hash function: Poseidon2 (as above)
```

## Tests That Enforce Compatibility

### 1. Rust Compatibility Tests (`test/rust_compatibility_test.zig`)

These are **CRITICAL** tests that MUST pass:

- **`poseidon2 parameters are correct`**: Verifies all parameters match Rust
- **`signature verification must succeed`**: THE most important test - if this fails, DO NOT MERGE
- **`public key has no repeating patterns`**: Catches MDS matrix bugs
- **`hash function produces diverse outputs`**: Verifies Poseidon2 correctness
- **`default parameters use poseidon2`**: Ensures we never accidentally switch hash functions
- **`chain length is 256 for w=8`**: Verifies Winternitz parameter calculation
- **`deterministic key generation`**: Same seed must produce same keys

### 2. Poseidon2 Tests (`test/poseidon2_test.zig`)

- Verifies no repeating patterns in hash output
- Tests entropy and randomness
- Validates different inputs/tweaks produce different outputs

### 3. Integration Tests (`test/integration_test.zig`)

- Full signature workflow with verification
- Multiple message signing
- Public key pattern detection

## GitHub Workflow Enforcement

The `.github/workflows/ci.yml` workflow includes a **mandatory** `rust-compatibility` job that:

1. Runs all Rust compatibility tests
2. **Blocks merging** if any test fails
3. Runs on every PR and push to main/master
4. Cannot be bypassed

## Bug That Was Fixed

### The MDS Matrix Bug

**Symptom**: Public keys showed repeating 4-byte patterns (e.g., `87240402` repeated 8 times)

**Root Cause**: The MDS matrix multiplication in `generic_poseidon2.zig` was incorrectly implemented:

```zig
// WRONG (before fix):
for (0..width) |i| {
    for (0..width) |j| {
        sum += state[j] * diagonal[j];  // ← Bug: Uses diagonal[j] for all i
    }
    new_state[i] = sum;  // ← All elements get the SAME sum!
}
```

**Fix**: Use circulant indexing for the diagonal:

```zig
// CORRECT (after fix):
for (0..width) |i| {
    for (0..width) |j| {
        const diag_idx = (width + j - i) % width;  // ← Circulant indexing
        sum += state[j] * diagonal[diag_idx];
    }
    new_state[i] = sum;
}
```

This bug caused:
- All state elements after permutation to be identical
- Public keys to be repeating patterns
- Signature verification to fail

## How to Verify Compatibility

### Before Committing Changes

```bash
# Run all tests (includes Rust compatibility tests)
zig build test

# If any test fails, DO NOT commit
# Fix the issue and rerun tests
```

### Expected Test Output

All tests should pass with output like:
```
All 12 tests passed.
```

If you see:
```
🚨 CRITICAL FAILURE: SIGNATURE VERIFICATION FAILED 🚨
```

**STOP**. Do not merge. The implementation is broken.

## References

- Rust reference implementation: https://github.com/b-wagn/hash-sig/
- Poseidon2 specification: https://eprint.iacr.org/2023/323
- XMSS RFC: https://datatracker.ietf.org/doc/html/rfc8391
- Parameter selection: https://github.com/b-wagn/hashsig-parameters

## Maintainer Notes

When reviewing PRs:

1. ✅ Verify `zig build test` passes
2. ✅ Check GitHub Actions CI status
3. ✅ Ensure `rust-compatibility` job passed
4. ✅ Look for any changes to Poseidon2 parameters
5. ✅ Verify no changes to MDS matrix implementation
6. ❌ REJECT if signature verification fails
7. ❌ REJECT if public keys show repeating patterns

## Contact

For questions about Rust compatibility, refer to:
- This document
- `test/rust_compatibility_test.zig` (the tests themselves)
- The Rust reference implementation

**Remember**: Compatibility is not optional. It's mandatory.

