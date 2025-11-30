//! Direct benchmark of Poseidon2 hash function performance
//! This isolates hash function performance from keygen overhead

const std = @import("std");
const hash_zig = @import("hash-zig");
const Allocator = std.mem.Allocator;
const FieldElement = hash_zig.FieldElement;
const Poseidon2RustCompat = hash_zig.Poseidon2RustCompat;
const poseidon2_simd = @import("../src/hash/poseidon2_hash_simd.zig");
const simd_utils = @import("../src/signature/native/simd_utils.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Poseidon2 Hash Function Benchmark ===\n\n", .{});

    // Initialize Poseidon2
    var poseidon2 = try Poseidon2RustCompat.init(allocator);
    defer poseidon2.deinit();

    var simd_poseidon2 = poseidon2_simd.Poseidon2SIMD.init(allocator, &poseidon2);

    // Test parameters
    const num_iterations = 10000;
    const hash_len = 8; // HASH_LEN_FE
    const SIMD_WIDTH = simd_utils.SIMD_WIDTH;

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  SIMD Width: {}\n", .{SIMD_WIDTH});
    std.debug.print("  Hash Length: {}\n", .{hash_len});
    std.debug.print("  Iterations: {}\n\n", .{num_iterations});

    // Benchmark: compress16SIMD with SIMD-packed input
    var packed_input: [16]simd_utils.PackedF = undefined;
    
    // Initialize with test data
    for (0..16) |i| {
        var values: [SIMD_WIDTH]u32 = undefined;
        for (0..SIMD_WIDTH) |lane| {
            values[lane] = @as(u32, @intCast((i * 1000) + lane));
        }
        packed_input[i] = simd_utils.PackedF{ .values = values };
    }

    // Warmup
    var output_stack: [8]simd_utils.PackedF = undefined;
    for (0..100) |_| {
        _ = try simd_poseidon2.compress16SIMD(&packed_input, hash_len, output_stack[0..hash_len]);
    }

    // Benchmark
    const start = std.time.nanoTimestamp();
    for (0..num_iterations) |_| {
        _ = try simd_poseidon2.compress16SIMD(&packed_input, hash_len, output_stack[0..hash_len]);
    }
    const end = std.time.nanoTimestamp();
    const elapsed_ns = @as(f64, @floatFromInt(end - start));
    const elapsed_ms = elapsed_ns / 1_000_000.0;
    const avg_us = elapsed_ns / @as(f64, @floatFromInt(num_iterations)) / 1000.0;

    std.debug.print("Results:\n", .{});
    std.debug.print("  Total time: {d:.2} ms\n", .{elapsed_ms});
    std.debug.print("  Average per hash: {d:.3} μs\n", .{avg_us});
    std.debug.print("  Throughput: {d:.2} hashes/sec\n\n", .{1_000_000.0 / avg_us});

    // Estimate for 2^32 with 1024 epochs
    // Each epoch: 64 chains × 7 steps = 448 hash operations
    // Total: 1024 epochs × 448 = 458,752 hash operations
    const hash_ops_per_epoch = 64 * 7; // chains × chain_length
    const total_hash_ops = 1024 * hash_ops_per_epoch;
    const estimated_time_s = (avg_us * @as(f64, @floatFromInt(total_hash_ops))) / 1_000_000.0;

    std.debug.print("Estimated time for 2^32 (1024 epochs):\n", .{});
    std.debug.print("  Hash operations: {}\n", .{total_hash_ops});
    std.debug.print("  Estimated time: {d:.2} seconds\n", .{estimated_time_s});
    std.debug.print("  Actual keygen time: ~868 seconds\n", .{});
    std.debug.print("  Overhead factor: {d:.2}x\n\n", .{868.0 / estimated_time_s});
}

