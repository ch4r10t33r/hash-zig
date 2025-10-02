const std = @import("std");
const hash_zig = @import("hash-zig");
const optimized_signature = @import("optimized_signature");
const params = hash_zig.params;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Optimized Hash-Zig Performance Benchmark\n", .{});
    std.debug.print("========================================\n", .{});
    std.debug.print("Comparing original vs optimized implementations\n\n", .{});

    // Test parameters
    const lifetimes = [_]params.KeyLifetime{ .lifetime_2_10, .lifetime_2_16 };
    const test_message = "Performance test message for hash-based signatures";

    for (lifetimes) |lifetime| {
        const num_sigs = @as(usize, 1) << @intCast(@intFromEnum(lifetime));
        std.debug.print("Testing lifetime: {} ({} signatures)\n", .{ lifetime, num_sigs });
        std.debug.print("------------------------------------------------\n", .{});

        // Test original implementation
        std.debug.print("Original implementation:\n", .{});
        const original_time = try benchmarkOriginal(allocator, lifetime, test_message);
        std.debug.print("  Key generation: {d:.3}s\n", .{original_time});

        // Test optimized implementation
        std.debug.print("Optimized implementation:\n", .{});
        const optimized_time = try benchmarkOptimized(allocator, lifetime, test_message);
        std.debug.print("  Key generation: {d:.3}s\n", .{optimized_time});

        const speedup = original_time / optimized_time;
        std.debug.print("  Speedup: {d:.2}x\n", .{speedup});
        std.debug.print("\n", .{});
    }
}

fn benchmarkOriginal(allocator: std.mem.Allocator, lifetime: params.KeyLifetime, message: []const u8) !f64 {
    const params_orig = hash_zig.Parameters.init(lifetime);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params_orig);
    defer sig_scheme.deinit();

    const seed: [32]u8 = .{42} ** 32;

    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    defer keypair.deinit(allocator);
    const end_time = std.time.nanoTimestamp();

    const duration_ns = end_time - start_time;
    const duration_sec = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    // Test signing performance
    const sign_start = std.time.nanoTimestamp();
    var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
    defer signature.deinit(allocator);
    const sign_end = std.time.nanoTimestamp();

    const sign_duration_ns = sign_end - sign_start;
    const sign_duration_sec = @as(f64, @floatFromInt(sign_duration_ns)) / 1_000_000_000.0;

    // Test verification performance
    const verify_start = std.time.nanoTimestamp();
    const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);
    const verify_end = std.time.nanoTimestamp();

    const verify_duration_ns = verify_end - verify_start;
    const verify_duration_sec = @as(f64, @floatFromInt(verify_duration_ns)) / 1_000_000_000.0;

    std.debug.print("    Sign: {d:.3}ms\n", .{sign_duration_sec * 1000});
    std.debug.print("    Verify: {d:.3}ms\n", .{verify_duration_sec * 1000});
    std.debug.print("    Valid: {}\n", .{is_valid});

    return duration_sec;
}

fn benchmarkOptimized(allocator: std.mem.Allocator, lifetime: params.KeyLifetime, message: []const u8) !f64 {
    const params_opt = hash_zig.Parameters.init(lifetime);
    var sig_scheme = try optimized_signature.OptimizedHashSignature.init(allocator, params_opt);
    defer sig_scheme.deinit();

    const seed: [32]u8 = .{42} ** 32;

    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(&seed);
    defer keypair.deinit(&sig_scheme.arena);
    const end_time = std.time.nanoTimestamp();

    const duration_ns = end_time - start_time;
    const duration_sec = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    // Test signing performance
    const sign_start = std.time.nanoTimestamp();
    var signature = try sig_scheme.sign(message, keypair.secret_key, 0);
    defer signature.deinit(&sig_scheme.arena);
    const sign_end = std.time.nanoTimestamp();

    const sign_duration_ns = sign_end - sign_start;
    const sign_duration_sec = @as(f64, @floatFromInt(sign_duration_ns)) / 1_000_000_000.0;

    // Test verification performance
    const verify_start = std.time.nanoTimestamp();
    const is_valid = try sig_scheme.verify(message, signature, keypair.public_key);
    const verify_end = std.time.nanoTimestamp();

    const verify_duration_ns = verify_end - verify_start;
    const verify_duration_sec = @as(f64, @floatFromInt(verify_duration_ns)) / 1_000_000_000.0;

    std.debug.print("    Sign: {d:.3}ms\n", .{sign_duration_sec * 1000});
    std.debug.print("    Verify: {d:.3}ms\n", .{verify_duration_sec * 1000});
    std.debug.print("    Valid: {}\n", .{is_valid});

    return duration_sec;
}
