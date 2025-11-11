const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Removed debug prints for performance

    var lifetime_power: u8 = 18; // Default to 2^18 for performance testing
    if (args.len > 1) {
        lifetime_power = std.fmt.parseInt(u8, args[1], 10) catch 18;
        // Removed debug print for performance
    } else {
        // Removed debug print for performance
    }

    log.print("Hash-Zig Performance Benchmark\n", .{});
    log.print("==============================\n", .{});
    log.print("Focus: Key Generation Performance for Lifetime 2^{d}\n", .{lifetime_power});
    log.print("Parameters: Winternitz (22 chains × 256, w=8)\n", .{});
    log.print("Target: Measure improvements from optimizations\n\n", .{});

    // Determine lifetime based on power (only support available lifetimes)
    const lifetime: hash_zig.KeyLifetimeRustCompat = switch (lifetime_power) {
        8 => .lifetime_2_8,
        18 => .lifetime_2_18,
        32 => .lifetime_2_32,
        else => .lifetime_2_8, // Default to 2^8 if unsupported
    };

    const num_signatures = @as(usize, 1) << @intCast(lifetime_power);
    const expected_time_sec = @as(f64, @floatFromInt(num_signatures)) / 100.0; // More realistic estimate for optimized implementation

    const lifetimes = [_]struct { name: []const u8, lifetime: hash_zig.KeyLifetimeRustCompat, expected_time_sec: f64, description: []const u8 }{
        .{ .name = std.fmt.allocPrint(allocator, "2^{d}", .{lifetime_power}) catch "2^8", .lifetime = lifetime, .expected_time_sec = expected_time_sec, .description = std.fmt.allocPrint(allocator, "{d} signatures", .{num_signatures}) catch "256 signatures" },
    };

    for (lifetimes) |config| {
        log.print("\nTesting lifetime: {s} ({s})\n", .{ config.name, config.description });
        log.print("Expected time: ~{d:.1}s\n", .{config.expected_time_sec});
        log.print("-------------------\n", .{});

        var sig_scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, config.lifetime);
        defer sig_scheme.deinit();

        // Key generation benchmark - this is the main focus
        log.print("Starting key generation...\n", .{});
        const keygen_start = std.time.nanoTimestamp();
        var keypair = try sig_scheme.keyGen(0, @intCast(num_signatures));
        const keygen_end = std.time.nanoTimestamp();
        defer keypair.secret_key.deinit();

        const keygen_duration_ns = keygen_end - keygen_start;
        const keygen_duration_sec = @as(f64, @floatFromInt(keygen_duration_ns)) / 1_000_000_000.0;

        // Calculate performance metrics
        const total_signatures = num_signatures;
        const signatures_per_sec = @as(f64, @floatFromInt(total_signatures)) / keygen_duration_sec;
        const time_per_signature_ms = (keygen_duration_sec * 1000.0) / @as(f64, @floatFromInt(total_signatures));

        // Performance assessment
        const performance_ratio = keygen_duration_sec / config.expected_time_sec;
        const performance_status = if (performance_ratio < 0.8) "🚀 Excellent" else if (performance_ratio < 1.2) "✅ Good" else if (performance_ratio < 2.0) "⚠️  Slow" else "🐌 Very Slow";

        // Sign benchmark
        const message = [_]u8{ 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65 } ++ [_]u8{0x00} ** 21; // "Performance" + padding
        const sign_start = std.time.nanoTimestamp();
        var signature = try sig_scheme.sign(keypair.secret_key, 0, message);
        const sign_end = std.time.nanoTimestamp();
        defer signature.deinit();

        const sign_duration_ns = sign_end - sign_start;
        const sign_duration_sec = @as(f64, @floatFromInt(sign_duration_ns)) / 1_000_000_000.0;

        // Verify benchmark
        const verify_start = std.time.nanoTimestamp();
        const is_valid = try sig_scheme.verify(&keypair.public_key, 0, message, signature);
        const verify_end = std.time.nanoTimestamp();

        const verify_duration_ns = verify_end - verify_start;
        const verify_duration_sec = @as(f64, @floatFromInt(verify_duration_ns)) / 1_000_000_000.0;

        // Display detailed key generation results
        log.print("\n📊 KEY GENERATION RESULTS:\n", .{});
        log.print("  Duration: {d:.3}s {s}\n", .{ keygen_duration_sec, performance_status });
        log.print("  Signatures: {d}\n", .{total_signatures});
        log.print("  Throughput: {d:.1} signatures/sec\n", .{signatures_per_sec});
        log.print("  Time per signature: {d:.3}ms\n", .{time_per_signature_ms});
        log.print("  Expected: ~{d:.1}s (ratio: {d:.2}x)\n", .{ config.expected_time_sec, performance_ratio });

        // Display sign/verify results
        log.print("\n🔐 SIGN/VERIFY RESULTS:\n", .{});
        log.print("  Sign: {d:.3}ms\n", .{sign_duration_sec * 1000});
        log.print("  Verify: {d:.3}ms\n", .{verify_duration_sec * 1000});
        log.print("  Valid: {}\n", .{is_valid});

        // Output results in a format that can be captured by CI
        log.print("\n📈 CI BENCHMARK DATA:\n", .{});
        log.print("BENCHMARK_RESULT: {s}:keygen:{d:.6}\n", .{ config.name, keygen_duration_sec });
        log.print("BENCHMARK_RESULT: {s}:sign:{d:.6}\n", .{ config.name, sign_duration_sec });
        log.print("BENCHMARK_RESULT: {s}:verify:{d:.6}\n", .{ config.name, verify_duration_sec });
        log.print("BENCHMARK_RESULT: {s}:throughput:{d:.1}\n", .{ config.name, signatures_per_sec });
        log.print("BENCHMARK_RESULT: {s}:performance_ratio:{d:.2}\n", .{ config.name, performance_ratio });
    }

    log.print("\nBenchmark completed successfully!\n", .{});
}
