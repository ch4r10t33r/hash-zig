const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    std.debug.print("Command line args: {d}\n", .{args.len});
    for (args, 0..) |arg, i| {
        std.debug.print("  arg[{}]: {s}\n", .{ i, arg });
    }

    var lifetime_power: u8 = 10; // Default to 2^10
    if (args.len > 1) {
        lifetime_power = std.fmt.parseInt(u8, args[1], 10) catch 10;
        std.debug.print("Parsed lifetime_power: {d}\n", .{lifetime_power});
    } else {
        std.debug.print("No args provided, using default lifetime_power: {d}\n", .{lifetime_power});
    }

    std.debug.print("Hash-Zig Performance Benchmark\n", .{});
    std.debug.print("==============================\n", .{});
    std.debug.print("Focus: Key Generation Performance for Lifetime 2^{d}\n", .{lifetime_power});
    std.debug.print("Parameters: Winternitz (22 chains × 256, w=8)\n", .{});
    std.debug.print("Target: Measure improvements from optimizations\n\n", .{});

    // Determine lifetime based on power
    const lifetime: hash_zig.core.KeyLifetime = switch (lifetime_power) {
        10 => .lifetime_2_10,
        16 => .lifetime_2_16,
        18 => .lifetime_2_18,
        20 => .lifetime_2_20,
        28 => .lifetime_2_28,
        32 => .lifetime_2_32,
        else => .lifetime_2_10,
    };

    const num_signatures = @as(usize, 1) << @intCast(lifetime_power);
    const expected_time_sec = @as(f64, @floatFromInt(num_signatures)) / 1000.0; // Rough estimate

    const lifetimes = [_]struct { name: []const u8, lifetime: hash_zig.core.KeyLifetime, expected_time_sec: f64, description: []const u8 }{
        .{ .name = std.fmt.allocPrint(allocator, "2^{d}", .{lifetime_power}) catch "2^10", .lifetime = lifetime, .expected_time_sec = expected_time_sec, .description = std.fmt.allocPrint(allocator, "{d} signatures - Winternitz w=8", .{num_signatures}) catch "1,024 signatures - Winternitz w=8" },
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
        var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
        const keygen_end = std.time.nanoTimestamp();
        defer keypair.deinit(allocator);

        const keygen_duration_ns = keygen_end - keygen_start;
        const keygen_duration_sec = @as(f64, @floatFromInt(keygen_duration_ns)) / 1_000_000_000.0;

        // Calculate performance metrics
        const tree_height: u32 = config.lifetime.treeHeight();
        const total_signatures = @as(usize, 1) << @intCast(tree_height);
        const signatures_per_sec = @as(f64, @floatFromInt(total_signatures)) / keygen_duration_sec;
        const time_per_signature_ms = (keygen_duration_sec * 1000.0) / @as(f64, @floatFromInt(total_signatures));

        // Performance assessment
        const performance_ratio = keygen_duration_sec / config.expected_time_sec;
        const performance_status = if (performance_ratio < 0.8) "🚀 Excellent" else if (performance_ratio < 1.2) "✅ Good" else if (performance_ratio < 2.0) "⚠️  Slow" else "🐌 Very Slow";

        // Sign benchmark
        const message = "Performance test message";
        const sign_start = std.time.nanoTimestamp();
        var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, 0, &seed);
        const sign_end = std.time.nanoTimestamp();
        defer signature.deinit(allocator);

        const sign_duration_ns = sign_end - sign_start;
        const sign_duration_sec = @as(f64, @floatFromInt(sign_duration_ns)) / 1_000_000_000.0;

        // Verify benchmark
        const verify_start = std.time.nanoTimestamp();
        const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);
        const verify_end = std.time.nanoTimestamp();

        const verify_duration_ns = verify_end - verify_start;
        const verify_duration_sec = @as(f64, @floatFromInt(verify_duration_ns)) / 1_000_000_000.0;

        // Display detailed key generation results
        std.debug.print("\n📊 KEY GENERATION RESULTS:\n", .{});
        std.debug.print("  Duration: {d:.3}s {s}\n", .{ keygen_duration_sec, performance_status });
        std.debug.print("  Signatures: {d} (2^{d})\n", .{ total_signatures, tree_height });
        std.debug.print("  Throughput: {d:.1} signatures/sec\n", .{signatures_per_sec});
        std.debug.print("  Time per signature: {d:.3}ms\n", .{time_per_signature_ms});
        std.debug.print("  Expected: ~{d:.1}s (ratio: {d:.2}x)\n", .{ config.expected_time_sec, performance_ratio });

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
        std.debug.print("BENCHMARK_RESULT: {s}:performance_ratio:{d:.2}\n", .{ config.name, performance_ratio });
    }

    std.debug.print("\nBenchmark completed successfully!\n", .{});
}
