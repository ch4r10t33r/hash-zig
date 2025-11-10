# Hash-Zig Investigation Status

## ✅ **RESOLVED ISSUES:**

### 1. **Poseidon2 Compatibility** ✅
- **Status**: Fully resolved
- **Fix**: Implemented correct internal layer logic matching Plonky3 Rust implementation
- **Verification**: All Poseidon2 tests pass with identical outputs

### 2. **Shared RNG State Bug** ✅
- **Status**: Fully resolved
- **Root Cause**: `getRngState()` function was consuming RNG state instead of just reading it
- **Fix**: Modified `getRngState()` to create a copy of the RNG for state checking
- **Verification**: Schemes are now truly independent with proper RNG synchronization

### 3. **Parameter Generation** ✅
- **Status**: Fully resolved
- **Root Cause**: Missing right-shift by 1 when converting u32 to field elements
- **Fix**: Added `>> 1` operation to ensure 31-bit values compatible with field modulus
- **Verification**: Parameters now match Rust exactly: `[1128497561, 1847509114, 1994249188, 1874424621, 1302548296]`

### 4. **PRF Key Generation** ✅
- **Status**: Fully resolved
- **Verification**: PRF keys now match Rust exactly: `32038786f4803ddcc9a7bbed5ae672df919e469b7e26e9c388d12be81790ccc9`

### 5. **Benchmark Seed Initialization** ✅
- **Status**: Fully resolved
- **Root Cause**: Benchmark was using `init()` which generates random seed from timestamp
- **Fix**: Changed to use `initWithSeed()` with fixed seed `0x42`
- **Verification**: Parameters and PRF keys now consistent across runs

### 6. **Tweak Level Calculation** ✅
- **Status**: Fully resolved
- **Root Cause**: Zig was using `level` directly in tweak calculation, while Rust uses `(level as u8) + 1`
- **Fix**: Modified Zig tweak calculation to match Rust: `const tweak_level = level + 1;`
- **Verification**: Tweak levels now match exactly between Rust and Zig

### 7. **Hash Function Input Structure** ✅
- **Status**: Fully resolved
- **Root Cause**: Zig was concatenating left and right child nodes before passing to hash function, while Rust processes them as separate iterators
- **Fix**: Created `applyPoseidonTreeTweakHashWithSeparateInputs` function that takes left and right separately and constructs input as `parameter + tweak + left + right`
- **Verification**: Hash function input structure now matches Rust exactly

### 8. **Truncation Logic** ✅
- **Status**: Fully resolved
- **Root Cause**: Zig was building 4-layer bottom trees directly, while Rust builds 8-layer trees and truncates to 4 layers
- **Fix**: Modified `buildBottomTree` to build full 8-layer trees (0->8) and then truncate to 4 layers (0->4), returning the root from layer 4
- **Verification**: Truncation logic now works correctly with proper layer storage and access

## 🚨 **CRITICAL DISCOVERY: Final Roots Are Completely Different**

### **Current Status:**
- ✅ **Parameters match exactly**: `[1128497561, 1847509114, 1994249188, 1874424621, 1302548296]`
- ✅ **PRF keys match exactly**: `32038786f4803ddcc9a7bbed5ae672df919e469b7e26e9c388d12be81790ccc9`
- ✅ **Tweak levels match exactly**: Both use identical tweak level calculation (`tweak_level = level + 1`)
- ✅ **Hash function input structure matches exactly**: Both process left and right child nodes separately
- ✅ **Truncation logic works correctly**: 8-layer trees are built and truncated to 4 layers, returning root from layer 4
- ❌ **Final roots are completely different**: Despite matching all foundational components and algorithm details

### **Current Results:**
- **Zig Final Root**: `[20459627, 418629744, 877260828, 1984151126, 856286975, 1841460741, 716000703, 1759124702]`
- **Expected Rust Root**: `[1802260327, 844516806, 1680631913, 1711930483, 1951233105, 425088255, 715789386, 1649882860]`

**CRITICAL DISCOVERY**: Despite all foundational components matching perfectly (parameters, PRF keys, truncation logic, tweak levels, hash function input structure), the final roots are completely different. This indicates a fundamental difference in the tree building algorithm itself.

**ANALYSIS**: The issue is now definitively within the tree building algorithm. The most likely candidates are:

1. **Tree topology differences** - The order of node pairing might be different between implementations
2. **Padding node generation** - The padding nodes might be generated differently
3. **RNG state synchronization** - There might be subtle differences in RNG state at different points
4. **Subtle differences in hash function application** - There might be minor differences in how the hash function is applied

**NEXT INVESTIGATION**: Create a focused investigation to compare the exact tree building process between Rust and Zig implementations.

## 🎯 **Goal:**
Both Rust and Zig implementations should generate the **same public key** for a given seed and lifetime.
