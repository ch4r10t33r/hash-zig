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

    // Seed: read from SEED_HEX env var if provided, else default to 0x2a repeated
    const seed_env = std.process.getEnvVarOwned(std.heap.page_allocator, "SEED_HEX") catch null;
    defer if (seed_env) |s| std.heap.page_allocator.free(s);

    var seed: [32]u8 = .{42} ** 32;
    if (seed_env) |hex| {
        // Parse up to 64 hex chars into 32 bytes
        const n = @min(hex.len, 64);
        var i: usize = 0;
        while (i < n) : (i += 2) {
            const high_nibble = std.fmt.charToDigit(hex[i], 16) catch 0;
            const low_nibble = if (i + 1 < n) std.fmt.charToDigit(hex[i + 1], 16) catch 0 else 0;
            seed[i / 2] = @as(u8, @intCast((high_nibble << 4) | low_nibble));
        }
    }
    std.debug.print("Using seed (hex): ", .{});
    for (seed) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // Test lifetime_2_10
    std.debug.print("Testing lifetime: 2^10 (1,024 signatures)\n", .{});
    std.debug.print("==========================================\n", .{});

    var sig_scheme_10 = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(.lifetime_2_10));
    defer sig_scheme_10.deinit();

    const keygen_start_10 = std.time.nanoTimestamp();
    var keypair_10 = try sig_scheme_10.generateKeyPair(allocator, &seed);
    const keygen_end_10 = std.time.nanoTimestamp();
    defer keypair_10.deinit(allocator);

    const keygen_duration_10 = @as(f64, @floatFromInt(keygen_end_10 - keygen_start_10)) / 1_000_000_000.0;

    // Print keypair information for 2^10
    std.debug.print("Keypair 2^10:\n", .{});
    const secret_key_size_10 = keypair_10.secret_key.chains.len * @sizeOf(@TypeOf(keypair_10.secret_key.chains[0]));
    const public_key_size_10 = keypair_10.public_key.chains.len * @sizeOf(@TypeOf(keypair_10.public_key.chains[0]));
    std.debug.print("  Secret key length: {d} bytes\n", .{secret_key_size_10});
    std.debug.print("  Public key length: {d} bytes\n", .{public_key_size_10});
    std.debug.print("  Key generation time: {d:.3}s\n", .{keygen_duration_10});

    // Test lifetime_2_16
    std.debug.print("\nTesting lifetime: 2^16 (65,536 signatures)\n", .{});
    std.debug.print("==========================================\n", .{});

    var sig_scheme_16 = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(.lifetime_2_16));
    defer sig_scheme_16.deinit();

    const keygen_start_16 = std.time.nanoTimestamp();
    var keypair_16 = try sig_scheme_16.generateKeyPair(allocator, &seed);
    const keygen_end_16 = std.time.nanoTimestamp();
    defer keypair_16.deinit(allocator);

    const keygen_duration_16 = @as(f64, @floatFromInt(keygen_end_16 - keygen_start_16)) / 1_000_000_000.0;

    // Print keypair information for 2^16
    std.debug.print("Keypair 2^16:\n", .{});
    const secret_key_size_16 = keypair_16.secret_key.chains.len * @sizeOf(@TypeOf(keypair_16.secret_key.chains[0]));
    const public_key_size_16 = keypair_16.public_key.chains.len * @sizeOf(@TypeOf(keypair_16.public_key.chains[0]));
    std.debug.print("  Secret key length: {d} bytes\n", .{secret_key_size_16});
    std.debug.print("  Public key length: {d} bytes\n", .{public_key_size_16});
    std.debug.print("  Key generation time: {d:.3}s\n", .{keygen_duration_16});

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
