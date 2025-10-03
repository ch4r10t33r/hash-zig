const std = @import("std");
const simd_signature = @import("simd_signature");
const hash_zig = @import("hash-zig");

// Simplified SIMD Performance Benchmark
// Tests key generation for lifetime_2_10 and lifetime_2_16

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("SIMD Performance Benchmark\n", .{});
    std.debug.print("==========================\n", .{});
    std.debug.print("Testing SIMD-optimized hash-based signatures\n\n", .{});

    // Fixed seed for all operations
    const seed: [32]u8 = .{42} ** 32;
    std.debug.print("Using fixed seed: {any}\n\n", .{seed});

    // Test lifetime_2_10
    std.debug.print("Testing lifetime: 2^10 (1,024 signatures)\n", .{});
    std.debug.print("==========================================\n", .{});

    var sig_scheme_10 = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(.lifetime_2_10));
    defer sig_scheme_10.deinit();

    const keygen_start_10 = std.time.nanoTimestamp();
    var keypair_10 = try sig_scheme_10.generateKeyPair(allocator, &seed);
    const keygen_end_10 = std.time.nanoTimestamp();
    defer keypair_10.deinit();

    const keygen_duration_10 = @as(f64, @floatFromInt(keygen_end_10 - keygen_start_10)) / 1_000_000_000.0;

    // Print keypair information for 2^10
    std.debug.print("Keypair 2^10:\n", .{});
    const secret_key_size_10 = keypair_10.secret_key.chains.len * @sizeOf(@TypeOf(keypair_10.secret_key.chains[0]));
    const public_key_size_10 = keypair_10.public_key.chains.len * @sizeOf(@TypeOf(keypair_10.public_key.chains[0]));
    std.debug.print("  Secret key length: {d} bytes\n", .{secret_key_size_10});
    std.debug.print("  Public key length: {d} bytes\n", .{public_key_size_10});
    std.debug.print("  Key generation time: {d:.3}s\n", .{keygen_duration_10});

    // Display secret key as hex
    std.debug.print("  Secret key (hex): ", .{});
    for (keypair_10.secret_key.chains) |chain| {
        for (0..8) |i| {
            std.debug.print("{x:0>8}", .{chain[i]});
        }
    }
    std.debug.print("\n", .{});

    // Display public key as hex
    std.debug.print("  Public key (hex): ", .{});
    for (keypair_10.public_key.chains) |chain| {
        for (0..8) |i| {
            std.debug.print("{x:0>8}", .{chain[i]});
        }
    }
    std.debug.print("\n", .{});

    // Test lifetime_2_16
    std.debug.print("\nTesting lifetime: 2^16 (65,536 signatures)\n", .{});
    std.debug.print("==========================================\n", .{});

    var sig_scheme_16 = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(.lifetime_2_16));
    defer sig_scheme_16.deinit();

    const keygen_start_16 = std.time.nanoTimestamp();
    var keypair_16 = try sig_scheme_16.generateKeyPair(allocator, &seed);
    const keygen_end_16 = std.time.nanoTimestamp();
    defer keypair_16.deinit();

    const keygen_duration_16 = @as(f64, @floatFromInt(keygen_end_16 - keygen_start_16)) / 1_000_000_000.0;

    // Print keypair information for 2^16
    std.debug.print("Keypair 2^16:\n", .{});
    const secret_key_size_16 = keypair_16.secret_key.chains.len * @sizeOf(@TypeOf(keypair_16.secret_key.chains[0]));
    const public_key_size_16 = keypair_16.public_key.chains.len * @sizeOf(@TypeOf(keypair_16.public_key.chains[0]));
    std.debug.print("  Secret key length: {d} bytes\n", .{secret_key_size_16});
    std.debug.print("  Public key length: {d} bytes\n", .{public_key_size_16});
    std.debug.print("  Key generation time: {d:.3}s\n", .{keygen_duration_16});

    // Display secret key as hex
    std.debug.print("  Secret key (hex): ", .{});
    for (keypair_16.secret_key.chains) |chain| {
        for (0..8) |i| {
            std.debug.print("{x:0>8}", .{chain[i]});
        }
    }
    std.debug.print("\n", .{});

    // Display public key as hex
    std.debug.print("  Public key (hex): ", .{});
    for (keypair_16.public_key.chains) |chain| {
        for (0..8) |i| {
            std.debug.print("{x:0>8}", .{chain[i]});
        }
    }
    std.debug.print("\n", .{});

    // Summary
    std.debug.print("\n📊 SUMMARY:\n", .{});
    std.debug.print("2^10 key generation: {d:.3}s\n", .{keygen_duration_10});
    std.debug.print("2^16 key generation: {d:.3}s\n", .{keygen_duration_16});
    std.debug.print("Performance ratio: {d:.2}x\n", .{keygen_duration_16 / keygen_duration_10});

    // Output for CI
    std.debug.print("\nBENCHMARK_RESULT: 2^10:keygen:{d:.6}\n", .{keygen_duration_10});
    std.debug.print("BENCHMARK_RESULT: 2^16:keygen:{d:.6}\n", .{keygen_duration_16});

    std.debug.print("\n✅ SIMD Benchmark completed successfully!\n", .{});
}
