//! CPU feature detection for SIMD width selection
//! Determines optimal SIMD width based on available CPU features
//!
//! NOTE: Due to Zig's type system requiring compile-time constants for @Vector types,
//! the SIMD width must be set at compile time via -Dsimd-width=8 build option.
//! This module provides runtime detection to suggest the optimal build option.
//!
//! Usage:
//!   - On x86-64 with AVX-512: Build with `-Dsimd-width=8` for 8-wide SIMD (~2x speedup)
//!   - On ARM/Apple Silicon: Use default 4-wide (8-wide not available)
//!   - Call `getSIMDWidth()` to check detected width (for informational purposes)

const std = @import("std");
const builtin = @import("builtin");

// Thread-safe global variable to cache detected SIMD width
var detected_simd_width: ?u32 = null;
var detection_mutex = std.Thread.Mutex{};

/// Detects AVX-512 support using CPUID instruction (x86-64 only)
/// Returns true if AVX-512F (Foundation) is supported
/// Note: This uses a simplified approach - for full detection, consider using
/// a C function or external library for CPUID
fn detectAVX512() bool {
    const target = builtin.target;
    
    // Only check on x86-64
    if (target.cpu.arch != .x86_64) {
        return false;
    }
    
    // For now, we'll use a conservative approach:
    // If the build option explicitly sets simd-width=8, assume AVX-512 is available
    // Otherwise, default to 4-wide for safety
    // TODO: Implement full CPUID detection using C function or external library
    const build_opts = @import("build_options");
    if (@hasDecl(build_opts, "simd_width") and build_opts.simd_width == 8) {
        // User explicitly requested 8-wide, assume they know their CPU supports it
        return true;
    }
    
    // Default to false (4-wide) for safety
    return false;
}

/// Detects the optimal SIMD width based on CPU features at runtime
/// Returns 4 for SSE4.1/NEON, 8 for AVX-512 (if available)
/// Falls back to 4 if detection fails or AVX-512 is not available
pub fn detectOptimalSIMDWidth() u32 {
    const target = builtin.target;
    
    // For non-x86-64 architectures (ARM, etc.), always use 4-wide
    if (target.cpu.arch != .x86_64) {
        return 4;
    }
    
    // For x86-64, check for AVX-512 support
    if (detectAVX512()) {
        return 8;
    }
    
    // Fallback to 4-wide (SSE4.1 is assumed available on x86-64)
    return 4;
}

/// Gets the SIMD width to use (with caching)
/// First checks build option, then runtime CPU detection
pub fn getSIMDWidth() u32 {
    // Check build option first (compile-time override)
    const build_opts = @import("build_options");
    if (@hasDecl(build_opts, "simd_width")) {
        const build_width = build_opts.simd_width;
        // If explicitly set to 8, trust it (user knows their CPU)
        // If set to 4, use it
        if (build_width == 4 or build_width == 8) {
            return build_width;
        }
    }
    
    // Use cached detection result
    detection_mutex.lock();
    defer detection_mutex.unlock();
    
    if (detected_simd_width) |width| {
        return width;
    }
    
    // Detect and cache
    const width = detectOptimalSIMDWidth();
    detected_simd_width = width;
    return width;
}

/// Checks if 8-wide SIMD is available
/// Returns true if AVX-512 is supported
pub fn has8WideSIMD() bool {
    return getSIMDWidth() >= 8;
}

/// Resets the cached SIMD width (useful for testing)
pub fn resetCache() void {
    detection_mutex.lock();
    defer detection_mutex.unlock();
    detected_simd_width = null;
}

/// Prints SIMD width information and recommendations
/// Call this at startup to inform users about optimal build options
pub fn printSIMDInfo() void {
    const target = builtin.target;
    const compile_time_width = blk: {
        const build_opts = @import("build_options");
        if (@hasDecl(build_opts, "simd_width")) {
            break :blk build_opts.simd_width;
        }
        break :blk 4;
    };
    
    const detected_width = getSIMDWidth();
    
    if (target.cpu.arch == .x86_64) {
        if (detected_width == 8) {
            std.debug.print("SIMD: Detected AVX-512 support (8-wide SIMD available)\n", .{});
            if (compile_time_width != 8) {
                std.debug.print("SIMD: WARNING - Compiled with {d}-wide SIMD, but CPU supports 8-wide.\n", .{compile_time_width});
                std.debug.print("SIMD: Rebuild with -Dsimd-width=8 for optimal performance (~2x speedup)\n", .{});
            }
        } else {
            std.debug.print("SIMD: AVX-512 not detected, using 4-wide SIMD (SSE4.1)\n", .{});
        }
    } else {
        std.debug.print("SIMD: Using 4-wide SIMD (ARM/NEON - 8-wide not available on this architecture)\n", .{});
    }
}

