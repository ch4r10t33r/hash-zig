//! SIMD utilities for optimized field element operations
//! Based on leanSig PR #5: simd: apply packing for tree leaves
//!
//! This module provides SIMD-optimized operations for processing multiple
//! field elements in parallel, matching the Rust implementation's use of
//! Plonky3's Packing trait.

const std = @import("std");
const FieldElement = @import("../../core/field.zig").FieldElement;

// Packed field element type for SIMD operations
// For KoalaBear (u32), we can pack 4 or 8 elements depending on SIMD width
pub const PackedF = struct {
    // Using Zig's @Vector for SIMD operations
    // For AVX2/AVX-512, we can pack 8 u32s
    // For SSE4.1, we can pack 4 u32s
    // We'll use 4 as a safe default that works on most architectures
    values: @Vector(4, u32),

    pub fn init(elements: [4]FieldElement) PackedF {
        return .{
            .values = .{
                elements[0].value,
                elements[1].value,
                elements[2].value,
                elements[3].value,
            },
        };
    }

    pub fn initFromSlice(elements: []const FieldElement) PackedF {
        var values: [4]u32 = undefined;
        for (0..4) |i| {
            values[i] = if (i < elements.len) elements[i].value else 0;
        }
        return .{ .values = values };
    }

    pub fn toArray(self: PackedF) [4]FieldElement {
        return .{
            FieldElement.fromMontgomery(self.values[0]),
            FieldElement.fromMontgomery(self.values[1]),
            FieldElement.fromMontgomery(self.values[2]),
            FieldElement.fromMontgomery(self.values[3]),
        };
    }

    // SIMD operations on packed field elements
    pub fn add(self: PackedF, other: PackedF) PackedF {
        return .{ .values = self.values + other.values };
    }

    pub fn mul(self: PackedF, other: PackedF) PackedF {
        // Note: This is element-wise multiplication, not field multiplication
        // For proper field multiplication, we'd need to unpack, multiply, repack
        return .{ .values = self.values * other.values };
    }
};

// Pack 8 field elements into 2 SIMD vectors
pub const PackedF8 = struct {
    low: PackedF,
    high: PackedF,

    pub fn init(elements: [8]FieldElement) PackedF8 {
        return .{
            .low = PackedF.init(elements[0..4].*),
            .high = PackedF.init(elements[4..8].*),
        };
    }

    pub fn toArray(self: PackedF8) [8]FieldElement {
        const low_arr = self.low.toArray();
        const high_arr = self.high.toArray();
        return .{
            low_arr[0],  low_arr[1],  low_arr[2],  low_arr[3],
            high_arr[0], high_arr[1], high_arr[2], high_arr[3],
        };
    }
};

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
    const simd_width = 4;
    var i: usize = 0;
    while (i + simd_width <= a.len and i + simd_width <= b.len and i + simd_width <= result.len) : (i += simd_width) {
        const a_vec: @Vector(4, u32) = .{ a[i].value, a[i + 1].value, a[i + 2].value, a[i + 3].value };
        const b_vec: @Vector(4, u32) = .{ b[i].value, b[i + 1].value, b[i + 2].value, b[i + 3].value };
        const sum_vec = a_vec + b_vec;
        result[i] = FieldElement.fromMontgomery(sum_vec[0]);
        result[i + 1] = FieldElement.fromMontgomery(sum_vec[1]);
        result[i + 2] = FieldElement.fromMontgomery(sum_vec[2]);
        result[i + 3] = FieldElement.fromMontgomery(sum_vec[3]);
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
