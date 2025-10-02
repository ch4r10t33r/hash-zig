const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Hash-Zig Performance Benchmark\n", .{});
    std.debug.print("==============================\n", .{});
    std.debug.print("Focus: Key Generation Performance for Lifetime 2^10\n", .{});
    std.debug.print("Target: Measure improvements from optimizations\n\n", .{});

    // Test different lifetimes - focus on 2^10 for detailed analysis
    const lifetimes = [_]struct { name: []const u8, lifetime: hash_zig.params.KeyLifetime, expected_time_sec: f64, description: []const u8 }{
        .{ .name = "2^10", .lifetime = .lifetime_2_10, .expected_time_sec = 30.0, .description = "1,024 signatures - Quick test" },
        .{ .name = "2^16", .lifetime = .lifetime_2_16, .expected_time_sec = 300.0, .description = "65,536 signatures - Full benchmark" },
    };

    for (lifetimes) |config| {
        std.debug.print("\nTesting lifetime: {s} ({s})\n", .{ config.name, config.description });
        std.debug.print("Expected time: ~{d:.1}s\n", .{config.expected_time_sec});
        std.debug.print("-------------------\n", .{});

        const params = hash_zig.Parameters.init(config.lifetime);
        var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
        defer sig_scheme.deinit();

        const seed: [32]u8 = .{42} ** 32;

        // Key generation benchmark - this is the main focus
        std.debug.print("Starting key generation...\n", .{});
        const keygen_start = std.time.nanoTimestamp();
        var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
        const keygen_end = std.time.nanoTimestamp();
        defer keypair.deinit(allocator);

        const keygen_duration_ns = keygen_end - keygen_start;
        const keygen_duration_sec = @as(f64, @floatFromInt(keygen_duration_ns)) / 1_000_000_000.0;

        // Calculate performance metrics
        const num_signatures = @as(usize, 1) << @intCast(@intFromEnum(config.lifetime));
        const signatures_per_sec = @as(f64, @floatFromInt(num_signatures)) / keygen_duration_sec;
        const time_per_signature_ms = (keygen_duration_sec * 1000.0) / @as(f64, @floatFromInt(num_signatures));

        // Performance assessment
        const performance_ratio = keygen_duration_sec / config.expected_time_sec;
        const performance_status = if (performance_ratio < 0.8) "🚀 Excellent" else if (performance_ratio < 1.2) "✅ Good" else if (performance_ratio < 2.0) "⚠️  Slow" else "🐌 Very Slow";

        // Sign benchmark
        const message = "Performance test message";
        const sign_start = std.time.nanoTimestamp();
        var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
        const sign_end = std.time.nanoTimestamp();
        defer signature.deinit(allocator);

        const sign_duration_ns = sign_end - sign_start;
        const sign_duration_sec = @as(f64, @floatFromInt(sign_duration_ns)) / 1_000_000_000.0;

        // Verify benchmark
        const verify_start = std.time.nanoTimestamp();
        const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);
        const verify_end = std.time.nanoTimestamp();

        const verify_duration_ns = verify_end - verify_start;
        const verify_duration_sec = @as(f64, @floatFromInt(verify_duration_ns)) / 1_000_000_000.0;

        // Display detailed key generation results
        std.debug.print("\n📊 KEY GENERATION RESULTS:\n", .{});
        std.debug.print("  Duration: {d:.3}s {s}\n", .{ keygen_duration_sec, performance_status });
        std.debug.print("  Signatures: {d} (2^{d})\n", .{ num_signatures, @intFromEnum(config.lifetime) });
        std.debug.print("  Throughput: {d:.1} signatures/sec\n", .{signatures_per_sec});
        std.debug.print("  Time per signature: {d:.3}ms\n", .{time_per_signature_ms});
        std.debug.print("  Expected: ~{d:.1}s (ratio: {d:.2f}x)\n", .{ config.expected_time_sec, performance_ratio });

        // Display sign/verify results
        std.debug.print("\n🔐 SIGN/VERIFY RESULTS:\n", .{});
        std.debug.print("  Sign: {d:.3}ms\n", .{sign_duration_sec * 1000});
        std.debug.print("  Verify: {d:.3}ms\n", .{verify_duration_sec * 1000});
        std.debug.print("  Valid: {}\n", .{is_valid});

        // Output results in a format that can be captured by CI
        std.debug.print("\n📈 CI BENCHMARK DATA:\n", .{});
        std.debug.print("BENCHMARK_RESULT: {s}:keygen:{d:.6}\n", .{ config.name, keygen_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:sign:{d:.6}\n", .{ config.name, sign_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:verify:{d:.6}\n", .{ config.name, verify_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:throughput:{d:.1}\n", .{ config.name, signatures_per_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:performance_ratio:{d:.2f}\n", .{ config.name, performance_ratio });
    }

    std.debug.print("\nBenchmark completed successfully!\n", .{});
}
