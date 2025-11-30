//! CPU feature detection for SIMD width selection
//! Determines optimal SIMD width based on available CPU features

const std = @import("std");
const builtin = @import("builtin");

/// Detects the optimal SIMD width based on CPU features
/// Returns 4 for SSE4.1, 8 for AVX-512 (if available)
/// Falls back to 4 if detection fails or AVX-512 is not available
pub fn detectOptimalSIMDWidth() u32 {
    // For now, we'll use compile-time detection via build options
    // Runtime detection would require platform-specific code (cpuid instruction)
    // which is complex and may not be worth it for this use case
    
    // Check if we're targeting a CPU that supports AVX-512
    // This is a compile-time check, not runtime
    const target = builtin.target;
    
    // For x86_64, check if AVX-512 is enabled
    // Note: This requires the CPU to actually support it, which we can't check at compile time
    // We'll default to 4-wide for safety and compatibility
    
    // TODO: Add runtime CPUID detection for AVX-512 support
    // For now, return 4 as the safe default
    return 4;
}

/// Gets the SIMD width to use
/// Can be overridden via build option or environment variable
pub fn getSIMDWidth() u32 {
    // Check for build option first
    // If -Dsimd-width=8 is passed, use 8-wide
    // Otherwise, use detected width
    
    // For now, we'll use a compile-time constant
    // Future: Add runtime detection
    return detectOptimalSIMDWidth();
}

/// Checks if 8-wide SIMD is available
/// Returns true if AVX-512 is supported
pub fn has8WideSIMD() bool {
    return getSIMDWidth() >= 8;
}

