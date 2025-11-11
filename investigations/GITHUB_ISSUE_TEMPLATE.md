# GitHub Issue: Hash-Based Signature Scheme Compatibility Investigation

## Title
**CRITICAL: Zig implementation produces different public key roots than Rust reference despite identical foundational components**

## Labels
- `bug`
- `critical`
- `compatibility`
- `investigation`

## Description

The Zig implementation of the hash-based signature scheme produces different final public key roots compared to the Rust reference implementation, despite having identical foundational components (parameters, PRF keys, and RNG state synchronization).

## Current Status

### ✅ **RESOLVED ISSUES:**

1. **RNG State Synchronization** - Fixed shared RNG state bug between multiple scheme instances
2. **Parameter Generation** - Both implementations now produce identical parameters: `[1128497561, 1847509114, 1994249188, 1874424621, 1302548296]`
3. **PRF Key Generation** - Both implementations now produce identical PRF keys: `32038786f4803ddcc9a7bbed5ae672df919e469b7e26e9c388d12be81790ccc9`
4. **Tweak Level Calculation** - Fixed Zig to use `level + 1` to match Rust's `(level as u8) + 1`
5. **Hash Function Input Structure** - Fixed Zig to process left and right components separately like Rust, instead of concatenating them first
6. **Bottom Tree Generation** - Fixed to use 16 leaves per tree and correct depth (4 layers)
7. **RNG Consumption in Padding** - Fixed Zig to consume RNG during tree building like Rust

### ❌ **REMAINING ISSUE:**

**Final public key roots are still completely different:**
- **Rust Root:** `[272571317, 816959513, 1641229267, 1432426756, 1894915310, 1536602969, 679245493, 946325787]`
- **Zig Root:** `[1292801901, 1821755911, 1418359130, 702260904, 1875345344, 923761677, 2118579969, 1204694192]`

## Probable Causes

### 1. **Hash Function Application Differences**
- **Issue**: Despite fixing input structure, there may be subtle differences in how Poseidon2 is applied
- **Evidence**: Tweak levels match exactly, but final results differ
- **Investigation**: Compare intermediate hash results during tree building

### 2. **Tree Building Algorithm Implementation**
- **Issue**: Different tree construction logic between Rust and Zig
- **Evidence**: Both implementations build 16 bottom trees and top tree, but results differ
- **Investigation**: Step-by-step comparison of tree building process

### 3. **Padding Logic Differences**
- **Issue**: Different padding behavior during tree construction
- **Evidence**: RNG consumption patterns may differ
- **Investigation**: Compare padding node generation between implementations

### 4. **Field Element Conversion**
- **Issue**: Different field element representation or conversion
- **Evidence**: All foundational components match, but tree building differs
- **Investigation**: Verify field element handling in hash function calls

### 5. **Memory Layout or Endianness**
- **Issue**: Different memory layout affecting hash function input
- **Evidence**: Identical data but different final results
- **Investigation**: Compare exact byte representation of inputs

## Technical Details

### Tree Building Process
1. **Bottom Trees**: 16 trees, each with 16 leaves, 4 layers deep
2. **Top Tree**: Built from 16 bottom tree roots, 4 layers deep
3. **Final Root**: 8-element array representing the public key

### Hash Function Application
- **Function**: Poseidon2-24 for tree hashing
- **Input Structure**: `parameter + tweak + left + right`
- **Tweak Encoding**: `((level + 1) << 40) | (pos_in_level << 8) | 0x01`

### Current Implementation Status
- **Parameters**: ✅ Match exactly
- **PRF Keys**: ✅ Match exactly  
- **RNG State**: ✅ Synchronized
- **Tweak Levels**: ✅ Match exactly
- **Hash Input Structure**: ✅ Fixed to match Rust
- **Final Roots**: ❌ Still different

## Next Investigation Steps

1. **Compare Intermediate Hash Results**: Log and compare hash function outputs at each tree building step
2. **Verify Padding Logic**: Ensure padding node generation matches Rust exactly
3. **Check Field Element Handling**: Verify field element conversion and representation
4. **Memory Layout Analysis**: Compare exact byte representation of inputs
5. **Tree Building Algorithm**: Step-by-step comparison of tree construction logic

## Files Modified

- `src/signature/signature_native.zig` - Fixed tweak level calculation and hash function input structure
- `benchmark/rust_hash_sig_debug/` - Removed RNG-consuming debug output
- Various debug files created for investigation

## Test Cases

- **Seed**: `[0x42] * 32` (fixed seed for deterministic testing)
- **Lifetime**: `lifetime_2_8`
- **Expected Parameters**: `[1128497561, 1847509114, 1994249188, 1874424621, 1302548296]`
- **Expected PRF Key**: `32038786f4803ddcc9a7bbed5ae672df919e469b7e26e9c388d12be81790ccc9`
- **Expected Root**: `[272571317, 816959513, 1641229267, 1432426756, 1894915310, 1536602969, 679245493, 946325787]`

## Priority

**HIGH** - This is blocking the completion of the Zig implementation. The signature scheme must produce identical public keys to the Rust reference implementation for the same seed and lifetime parameters.

## Reproduction Steps

1. Run the Zig implementation with seed `[0x42] * 32`
2. Run the Rust implementation with the same seed
3. Compare the final public key roots
4. Observe that they are completely different despite identical foundational components

## Expected Behavior

Both implementations should produce identical public key roots for the same seed and lifetime parameters.

## Actual Behavior

The implementations produce different final roots despite having identical parameters, PRF keys, and RNG state synchronization.

## Environment

- **Zig Version**: Latest
- **Rust Version**: Latest
- **OS**: macOS
- **Architecture**: x86_64

## Additional Context

This investigation has been ongoing and has resolved many compatibility issues. The remaining issue appears to be in the tree building algorithm itself, specifically in how the hash function is applied or how the tree structure is constructed.

## Related Files

- `INVESTIGATION_STATUS.md` - Detailed investigation status
- `context.md` - Investigation context and progress
- `debug_tree_building_detailed_comparison.zig` - Debug program for tree building analysis
- `benchmark/rust_hash_sig_debug/` - Rust debug implementation
