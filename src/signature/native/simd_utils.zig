//! SIMD utilities for optimized field element operations
//! Based on leanSig PR #5: simd: apply packing for tree leaves
//!
//! This module provides SIMD-optimized operations for processing multiple
//! field elements in parallel, matching the Rust implementation's use of
//! Plonky3's Packing trait.

const std = @import("std");
const FieldElement = @import("../../core/field.zig").FieldElement;

// SIMD width constant (compile-time, for type system)
// Can be overridden via build option -Dsimd-width=8 for AVX-512 support
pub const SIMD_WIDTH = blk: {
    const build_opts = @import("build_options");
    if (@hasDecl(build_opts, "simd_width")) {
        break :blk build_opts.simd_width;
    }
    break :blk 4; // Default to 4-wide for compatibility
};

// Runtime-effective SIMD width (detected from CPU features)
// This is the actual width we can use at runtime, which may differ from SIMD_WIDTH
// if the CPU doesn't support the compile-time width
const simd_cpu = @import("simd_cpu.zig");

/// Gets the effective SIMD width to use at runtime
/// This detects CPU features and returns the optimal width (4 or 8)
/// Falls back to compile-time SIMD_WIDTH if detection fails
pub fn getEffectiveSIMDWidth() u32 {
    const detected = simd_cpu.getSIMDWidth();
    // Use the minimum of detected width and compile-time width
    // This ensures we don't try to use 8-wide if we compiled for 4-wide
    return @min(detected, SIMD_WIDTH);
}

// 4-wide PackedF for SSE4.1 (128-bit vectors)
pub const PackedF4 = struct {
    values: @Vector(4, u32),

    pub fn init(elements: [4]FieldElement) PackedF4 {
        return .{
            .values = .{
                elements[0].value,
                elements[1].value,
                elements[2].value,
                elements[3].value,
            },
        };
    }

    pub fn initFromSlice(elements: []const FieldElement) PackedF4 {
        var values: [4]u32 = undefined;
        for (0..4) |i| {
            values[i] = if (i < elements.len) elements[i].value else 0;
        }
        return .{ .values = values };
    }

    pub fn toArray(self: PackedF4) [4]FieldElement {
        return .{
            FieldElement.fromMontgomery(self.values[0]),
            FieldElement.fromMontgomery(self.values[1]),
            FieldElement.fromMontgomery(self.values[2]),
            FieldElement.fromMontgomery(self.values[3]),
        };
    }

    // SIMD operations on packed field elements
    pub fn add(self: PackedF4, other: PackedF4) PackedF4 {
        return .{ .values = self.values + other.values };
    }

    pub fn mul(self: PackedF4, other: PackedF4) PackedF4 {
        // Note: This is element-wise multiplication, not field multiplication
        return .{ .values = self.values * other.values };
    }

    // SIMD-aware field addition (element-wise, assumes values are in Montgomery form)
    pub fn addField(self: PackedF4, other: PackedF4) PackedF4 {
        return .{ .values = self.values +% other.values };
    }

    // Broadcast a single field element to all lanes
    pub fn broadcast(fe: FieldElement) PackedF4 {
        return .{ .values = @splat(fe.value) };
    }
};

// 8-wide PackedF for AVX-512 (512-bit vectors)
pub const PackedF8 = struct {
    values: @Vector(8, u32),

    pub fn init(elements: [8]FieldElement) PackedF8 {
        var values: [8]u32 = undefined;
        for (0..8) |i| {
            values[i] = elements[i].value;
        }
        return .{ .values = values };
    }

    pub fn initFromSlice(elements: []const FieldElement) PackedF8 {
        var values: [8]u32 = undefined;
        for (0..8) |i| {
            values[i] = if (i < elements.len) elements[i].value else 0;
        }
        return .{ .values = values };
    }

    pub fn toArray(self: PackedF8) [8]FieldElement {
        var result: [8]FieldElement = undefined;
        for (0..8) |i| {
            result[i] = FieldElement.fromMontgomery(self.values[i]);
        }
        return result;
    }

    // SIMD operations on packed field elements
    pub fn add(self: PackedF8, other: PackedF8) PackedF8 {
        return .{ .values = self.values + other.values };
    }

    pub fn mul(self: PackedF8, other: PackedF8) PackedF8 {
        return .{ .values = self.values * other.values };
    }

    // SIMD-aware field addition (element-wise, assumes values are in Montgomery form)
    pub fn addField(self: PackedF8, other: PackedF8) PackedF8 {
        return .{ .values = self.values +% other.values };
    }

    // Broadcast a single field element to all lanes
    pub fn broadcast(fe: FieldElement) PackedF8 {
        return .{ .values = @splat(fe.value) };
    }
};

// Type alias: Select PackedF based on SIMD_WIDTH
// This allows the rest of the code to use PackedF without knowing the width
pub const PackedF = blk: {
    if (SIMD_WIDTH == 8) {
        break :blk PackedF8;
    } else {
        break :blk PackedF4;
    }
};

// Note: PackedF8Compat removed - not used in codebase
// For 8-wide SIMD, use PackedF directly (which is PackedF8 when SIMD_WIDTH == 8)

// SIMD-optimized batch processing of field element arrays
// Processes multiple field elements in parallel using @Vector operations
pub fn batchProcessFieldElementsSIMD(
    elements: []const FieldElement,
    batch_size: usize,
) []const FieldElement {
    _ = batch_size; // For future use
    // For now, return as-is - SIMD operations will be applied at call sites
    return elements;
}

// SIMD-optimized field element array operations
// Uses @Vector for parallel operations on multiple field elements
pub fn simdAddFieldElements(a: []const FieldElement, b: []const FieldElement, result: []FieldElement) void {
    const simd_width = SIMD_WIDTH;
    var i: usize = 0;
    while (i + simd_width <= a.len and i + simd_width <= b.len and i + simd_width <= result.len) : (i += simd_width) {
        // For now, handle 4-wide. 8-wide would require different logic
        if (simd_width == 4) {
            const a_vec: @Vector(4, u32) = .{ a[i].value, a[i + 1].value, a[i + 2].value, a[i + 3].value };
            const b_vec: @Vector(4, u32) = .{ b[i].value, b[i + 1].value, b[i + 2].value, b[i + 3].value };
            const sum_vec = a_vec + b_vec;
            result[i] = FieldElement.fromMontgomery(sum_vec[0]);
            result[i + 1] = FieldElement.fromMontgomery(sum_vec[1]);
            result[i + 2] = FieldElement.fromMontgomery(sum_vec[2]);
            result[i + 3] = FieldElement.fromMontgomery(sum_vec[3]);
        } else {
            // For 8-wide, would need different implementation
            // TODO: Implement 8-wide SIMD operations
            for (0..simd_width) |j| {
                result[i + j] = FieldElement.fromMontgomery(a[i + j].value +% b[i + j].value);
            }
        }
    }
    // Handle remaining elements sequentially
    while (i < a.len and i < b.len and i < result.len) : (i += 1) {
        // Note: This is element-wise addition, not field addition
        // For proper field addition, we'd need to use FieldElement operations
        result[i] = FieldElement.fromMontgomery(a[i].value +% b[i].value);
    }
}

// Batch process multiple epochs/chains using SIMD where possible
// This matches the Rust implementation's compute_tree_leaves optimization
pub fn computeTreeLeavesBatched(
    allocator: std.mem.Allocator,
    epochs: []const u32,
    num_chains: usize,
    chain_length: usize,
    prf_fn: *const fn ([32]u8, u32, u64) [8]u32,
    chain_fn: *const fn ([8]u32, u32, u8, [5]FieldElement) anyerror![8]FieldElement,
    reduce_fn: *const fn ([][8]FieldElement, [5]FieldElement, u32) anyerror![]FieldElement,
    prf_key: [32]u8,
    parameter: [5]FieldElement,
) ![]FieldElement {
    _ = chain_length; // Reserved for future SIMD optimizations
    // Allocate result array
    var leaf_domains = try allocator.alloc([8]FieldElement, epochs.len);
    errdefer allocator.free(leaf_domains);

    // Process epochs in batches for potential SIMD optimization
    // For now, process sequentially but structure allows for SIMD optimization
    for (epochs, 0..) |epoch, epoch_idx| {
        // Generate chain end domains for this epoch
        var chain_domains = try allocator.alloc([8]FieldElement, num_chains);
        defer allocator.free(chain_domains);

        // Process chains - this could be optimized with SIMD packing
        for (0..num_chains) |chain_index| {
            // Get chain start using PRF
            const domain_elements = prf_fn(prf_key, epoch, @as(u64, @intCast(chain_index)));

            // Walk the chain to get the final domain
            chain_domains[chain_index] = try chain_fn(domain_elements, epoch, @as(u8, @intCast(chain_index)), parameter);
        }

        // Reduce chain domains to a single leaf domain
        const leaf_domain_slice = try reduce_fn(chain_domains, parameter, epoch);
        defer allocator.free(leaf_domain_slice);

        // Convert to fixed-size array
        const hash_len = if (epochs.len > 256) 7 else 8; // 7 for 2^18, 8 for 2^8
        for (0..hash_len) |i| {
            leaf_domains[epoch_idx][i] = leaf_domain_slice[i];
        }
        for (hash_len..8) |i| {
            leaf_domains[epoch_idx][i] = FieldElement.zero();
        }
    }

    return leaf_domains;
}

// SIMD-optimized batch processing of field element arrays
// This can be used to process multiple field operations in parallel
pub fn batchProcessFieldElements(
    elements: []const FieldElement,
    batch_size: usize,
    process_fn: *const fn ([]const FieldElement) anyerror![]FieldElement,
) ![]FieldElement {
    var results = std.ArrayList(FieldElement).init(std.heap.page_allocator);
    defer results.deinit();

    var i: usize = 0;
    while (i < elements.len) {
        const end = @min(i + batch_size, elements.len);
        const batch = elements[i..end];
        const batch_results = try process_fn(batch);
        defer std.heap.page_allocator.free(batch_results);
        try results.appendSlice(batch_results);
        i = end;
    }

    return results.toOwnedSlice();
}

// Note: SIMD_WIDTH is now defined above with PackedF

// Vertical packing: transpose from [epoch][chain] to [chain][epoch] for SIMD processing
// This matches Rust's pack_array function from simd_utils.rs
pub fn packEpochsVertically(
    allocator: std.mem.Allocator,
    epochs: []const u32,
    num_chains: usize,
    hash_len: usize,
    prf_fn: *const fn (*const anyopaque, u32, u64) [8]u32,
    scheme_ptr: *const anyopaque,
) ![][]PackedF {
    // Allocate packed chains: [num_chains][hash_len]PackedF
    const packed_chains = try allocator.alloc([]PackedF, num_chains);
    errdefer {
        for (packed_chains) |chain| allocator.free(chain);
        allocator.free(packed_chains);
    }

    // For each chain, pack starting points across all epochs in batch
    for (0..num_chains) |chain_idx| {
        const packed_chain = try allocator.alloc(PackedF, hash_len);
        errdefer allocator.free(packed_chain);

        // Generate starting points for this chain across all epochs
        var starts: [SIMD_WIDTH][8]u32 = undefined;
        for (0..SIMD_WIDTH) |lane| {
            if (lane < epochs.len) {
                starts[lane] = prf_fn(scheme_ptr, epochs[lane], @as(u64, @intCast(chain_idx)));
            } else {
                // Pad with zeros if batch is incomplete
                @memset(&starts[lane], 0);
            }
        }

        // Transpose: [lane][element] -> [element][lane]
        // Each PackedF contains SIMD_WIDTH epochs for one hash element position
        for (0..hash_len) |h| {
            var values: [SIMD_WIDTH]u32 = undefined;
            for (0..SIMD_WIDTH) |lane| {
                values[lane] = starts[lane][h];
            }
            packed_chain[h] = PackedF{ .values = values };
        }

        packed_chains[chain_idx] = packed_chain;
    }

    return packed_chains;
}

// Unpack SIMD-packed chains back to scalar representation
pub fn unpackChainsFromSIMD(
    allocator: std.mem.Allocator,
    packed_chains: [][]PackedF,
    num_chains: usize,
    hash_len: usize,
    simd_width: usize,
) ![][]FieldElement {
    // Allocate unpacked chains: [simd_width][num_chains][hash_len]FieldElement
    const unpacked = try allocator.alloc([]FieldElement, simd_width);
    errdefer {
        for (unpacked) |chain_domains| allocator.free(chain_domains);
        allocator.free(unpacked);
    }

    for (0..simd_width) |lane| {
        const chain_domains = try allocator.alloc([8]FieldElement, num_chains);
        errdefer allocator.free(chain_domains);

        for (0..num_chains) |chain_idx| {
            // Unpack this chain for this lane
            for (0..hash_len) |h| {
                const unpacked_array = packed_chains[chain_idx][h].toArray();
                chain_domains[chain_idx][h] = unpacked_array[lane];
            }
            // Zero pad remaining elements
            for (hash_len..8) |h| {
                chain_domains[chain_idx][h] = FieldElement.zero();
            }
        }

        unpacked[lane] = chain_domains;
    }

    return unpacked;
}
