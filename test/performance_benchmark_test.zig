//! Performance benchmark tests matching Rust hash-sig criterion benchmarks
//! Based on https://github.com/b-wagn/hash-sig benchmark suite

const std = @import("std");
const hash_zig = @import("hash-zig");

const BenchmarkResult = struct {
    operation: []const u8,
    lifetime: hash_zig.KeyLifetimeRustCompat,
    duration_ns: u64,
    duration_ms: u64,
    duration_s: f64,
    iterations: usize,
    rate_per_sec: f64,
};

/// Benchmark key generation performance
fn benchmarkKeyGeneration(allocator: std.mem.Allocator, lifetime: hash_zig.KeyLifetimeRustCompat, iterations: usize) !BenchmarkResult {
    std.debug.print("Benchmarking key generation for lifetime {} ({} iterations)...\n", .{ lifetime, iterations });

    var timer = try std.time.Timer.start();
    const start_ns = timer.read();

    for (0..iterations) |_| {
        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
        defer scheme.deinit();

        const max_epochs = lifetime.maxSignatures();
        const keypair = try scheme.keyGen(0, @intCast(max_epochs));
        defer keypair.secret_key.deinit();

        _ = keypair.public_key; // Use the keypair to avoid optimization
    }

    const end_ns = timer.read();
    const duration_ns = end_ns - start_ns;
    const duration_ms = duration_ns / 1_000_000;
    const duration_s = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;
    const rate_per_sec = @as(f64, @floatFromInt(iterations)) / duration_s;

    return BenchmarkResult{
        .operation = "key_generation",
        .lifetime = lifetime,
        .duration_ns = duration_ns,
        .duration_ms = duration_ms,
        .duration_s = duration_s,
        .iterations = iterations,
        .rate_per_sec = rate_per_sec,
    };
}

/// Benchmark signing performance
fn benchmarkSigning(allocator: std.mem.Allocator, lifetime: hash_zig.KeyLifetimeRustCompat, iterations: usize) !BenchmarkResult {
    std.debug.print("Benchmarking signing for lifetime {} ({} iterations)...\n", .{ lifetime, iterations });

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();

    const max_epochs = lifetime.maxSignatures();
    const keypair = try scheme.keyGen(0, @intCast(max_epochs));
    defer keypair.secret_key.deinit();

    const message = [_]u8{ 0x42, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b } ++ [_]u8{0x00} ** 23; // "Benchmark" + padding
    const epoch: u32 = 0;

    // Prepare key for epoch
    var prep_iterations: u32 = 0;
    const log_lifetime = lifetime.logLifetime();
    while (true) {
        const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
        const epoch_u64 = @as(u64, epoch);
        if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
        if (prep_iterations >= epoch) break;
        try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
        prep_iterations += 1;
    }

    var timer = try std.time.Timer.start();
    const start_ns = timer.read();

    for (0..iterations) |_| {
        const signature = try scheme.sign(keypair.secret_key, epoch, message);
        defer signature.deinit();

        _ = signature.rho; // Use the signature to avoid optimization
    }

    const end_ns = timer.read();
    const duration_ns = end_ns - start_ns;
    const duration_ms = duration_ns / 1_000_000;
    const duration_s = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;
    const rate_per_sec = @as(f64, @floatFromInt(iterations)) / duration_s;

    return BenchmarkResult{
        .operation = "signing",
        .lifetime = lifetime,
        .duration_ns = duration_ns,
        .duration_ms = duration_ms,
        .duration_s = duration_s,
        .iterations = iterations,
        .rate_per_sec = rate_per_sec,
    };
}

/// Benchmark verification performance
fn benchmarkVerification(allocator: std.mem.Allocator, lifetime: hash_zig.KeyLifetimeRustCompat, iterations: usize) !BenchmarkResult {
    std.debug.print("Benchmarking verification for lifetime {} ({} iterations)...\n", .{ lifetime, iterations });

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();

    const max_epochs = lifetime.maxSignatures();
    const keypair = try scheme.keyGen(0, @intCast(max_epochs));
    defer keypair.secret_key.deinit();

    const message = [_]u8{ 0x42, 0x65, 0x6e, 0x63, 0x68, 0x6d, 0x61, 0x72, 0x6b } ++ [_]u8{0x00} ** 23; // "Benchmark" + padding
    const epoch: u32 = 0;

    // Prepare key for epoch
    var prep_iterations: u32 = 0;
    const log_lifetime = lifetime.logLifetime();
    while (true) {
        const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
        const epoch_u64 = @as(u64, epoch);
        if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
        if (prep_iterations >= epoch) break;
        try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
        prep_iterations += 1;
    }

    // Generate signature once
    const signature = try scheme.sign(keypair.secret_key, epoch, message);
    defer signature.deinit();

    var timer = try std.time.Timer.start();
    const start_ns = timer.read();

    for (0..iterations) |_| {
        const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
        try std.testing.expect(is_valid);
    }

    const end_ns = timer.read();
    const duration_ns = end_ns - start_ns;
    const duration_ms = duration_ns / 1_000_000;
    const duration_s = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;
    const rate_per_sec = @as(f64, @floatFromInt(iterations)) / duration_s;

    return BenchmarkResult{
        .operation = "verification",
        .lifetime = lifetime,
        .duration_ns = duration_ns,
        .duration_ms = duration_ms,
        .duration_s = duration_s,
        .iterations = iterations,
        .rate_per_sec = rate_per_sec,
    };
}

/// Run comprehensive performance benchmarks
fn runPerformanceBenchmarks(allocator: std.mem.Allocator) !void {
    std.debug.print("Running comprehensive performance benchmarks...\n", .{});

    const benchmark_configs = [_]struct {
        lifetime: hash_zig.KeyLifetimeRustCompat,
        keygen_iterations: usize,
        sign_iterations: usize,
        verify_iterations: usize,
    }{
        .{ .lifetime = .lifetime_2_8, .keygen_iterations = 1, .sign_iterations = 100, .verify_iterations = 1000 },
        .{ .lifetime = .lifetime_2_18, .keygen_iterations = 1, .sign_iterations = 10, .verify_iterations = 100 },
    };

    var results = std.ArrayList(BenchmarkResult).init(allocator);
    defer results.deinit();

    for (benchmark_configs) |config| {
        // Benchmark key generation
        const keygen_result = try benchmarkKeyGeneration(allocator, config.lifetime, config.keygen_iterations);
        try results.append(keygen_result);

        // Benchmark signing
        const sign_result = try benchmarkSigning(allocator, config.lifetime, config.sign_iterations);
        try results.append(sign_result);

        // Benchmark verification
        const verify_result = try benchmarkVerification(allocator, config.lifetime, config.verify_iterations);
        try results.append(verify_result);
    }

    // Print benchmark results
    std.debug.print("\n📊 PERFORMANCE BENCHMARK RESULTS\n", .{});
    std.debug.print("=" ** 60 ++ "\n", .{});

    for (results.items) |result| {
        std.debug.print("Operation: {s}\n", .{result.operation});
        std.debug.print("Lifetime: {}\n", .{result.lifetime});
        std.debug.print("Iterations: {}\n", .{result.iterations});
        std.debug.print("Duration: {d:.3}s ({d} ms)\n", .{ result.duration_s, result.duration_ms });
        std.debug.print("Rate: {d:.1} operations/second\n", .{result.rate_per_sec});
        std.debug.print("-" ** 40 ++ "\n", .{});
    }

    // Performance assessment
    std.debug.print("\n🎯 PERFORMANCE ASSESSMENT\n", .{});
    std.debug.print("=" ** 30 ++ "\n", .{});

    for (results.items) |result| {
        if (std.mem.eql(u8, result.operation, "key_generation")) {
            if (result.duration_s < 5.0) {
                std.debug.print("✅ Key generation for {}: FAST ({d:.2}s)\n", .{ result.lifetime, result.duration_s });
            } else if (result.duration_s < 30.0) {
                std.debug.print("⚠️  Key generation for {}: MODERATE ({d:.2}s)\n", .{ result.lifetime, result.duration_s });
            } else {
                std.debug.print("🐌 Key generation for {}: SLOW ({d:.2}s)\n", .{ result.lifetime, result.duration_s });
            }
        } else if (std.mem.eql(u8, result.operation, "signing")) {
            if (result.rate_per_sec > 1000.0) {
                std.debug.print("✅ Signing for {}: FAST ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            } else if (result.rate_per_sec > 100.0) {
                std.debug.print("⚠️  Signing for {}: MODERATE ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            } else {
                std.debug.print("🐌 Signing for {}: SLOW ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            }
        } else if (std.mem.eql(u8, result.operation, "verification")) {
            if (result.rate_per_sec > 10000.0) {
                std.debug.print("✅ Verification for {}: FAST ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            } else if (result.rate_per_sec > 1000.0) {
                std.debug.print("⚠️  Verification for {}: MODERATE ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            } else {
                std.debug.print("🐌 Verification for {}: SLOW ({d:.0} ops/sec)\n", .{ result.lifetime, result.rate_per_sec });
            }
        }
    }
}

// Main benchmark test
test "performance benchmark test suite" {
    const allocator = std.testing.allocator;

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("🚀 PERFORMANCE BENCHMARK TEST SUITE\n", .{});
    std.debug.print("Matching Rust hash-sig criterion benchmarks\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    try runPerformanceBenchmarks(allocator);

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("🎉 PERFORMANCE BENCHMARKS COMPLETED! 🎉\n", .{});
    std.debug.print("✅ All performance benchmarks executed successfully\n", .{});
    std.debug.print("✅ Performance metrics collected and analyzed\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
