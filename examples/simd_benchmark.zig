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

    // Test multiple lifetimes with the same seed for consistent comparison
    const lifetimes = [_]struct { name: []const u8, lifetime: hash_zig.params.KeyLifetime, expected_sigs: u32 }{
        .{ .name = "2^10", .lifetime = .lifetime_2_10, .expected_sigs = 1024 },
        .{ .name = "2^16", .lifetime = .lifetime_2_16, .expected_sigs = 65536 },
    };

    var results: [lifetimes.len]struct { duration: f64, secret_key_size: usize, public_key_size: usize } = undefined;

    for (lifetimes, 0..) |config, i| {
        std.debug.print("Testing lifetime: {s} ({d} signatures)\n", .{ config.name, config.expected_sigs });
        std.debug.print("==========================================\n", .{});

        var sig_scheme = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(config.lifetime));
        defer sig_scheme.deinit();

        const keygen_start = std.time.nanoTimestamp();
        var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
        const keygen_end = std.time.nanoTimestamp();
        defer keypair.deinit(allocator);

        const keygen_duration = @as(f64, @floatFromInt(keygen_end - keygen_start)) / 1_000_000_000.0;

        // Calculate key sizes
        const secret_key_size = keypair.secret_key.chains.len * @sizeOf(@TypeOf(keypair.secret_key.chains[0]));
        const public_key_size = keypair.public_key.chains.len * @sizeOf(@TypeOf(keypair.public_key.chains[0]));

        // Store results
        results[i] = .{
            .duration = keygen_duration,
            .secret_key_size = secret_key_size,
            .public_key_size = public_key_size,
        };

        // Print keypair information
        std.debug.print("Keypair {s}:\n", .{config.name});
        std.debug.print("  Secret key length: {d} bytes\n", .{secret_key_size});
        std.debug.print("  Public key length: {d} bytes\n", .{public_key_size});
        std.debug.print("  Key generation time: {d:.3}s\n", .{keygen_duration});
        std.debug.print("\n", .{});
    }

    // Summary
    std.debug.print("\n📊 SUMMARY:\n", .{});
    for (lifetimes, results) |config, result| {
        std.debug.print("{s} key generation: {d:.3}s\n", .{ config.name, result.duration });
    }

    if (results.len >= 2) {
        const performance_ratio = results[1].duration / results[0].duration;
        std.debug.print("Performance ratio: {d:.2}x\n", .{performance_ratio});
    }

    // Output for CI
    std.debug.print("\n", .{});
    for (lifetimes, results) |config, result| {
        std.debug.print("BENCHMARK_RESULT: {s}:keygen:{d:.6}\n", .{ config.name, result.duration });
    }

    std.debug.print("\n✅ SIMD Benchmark completed successfully!\n", .{});
}
