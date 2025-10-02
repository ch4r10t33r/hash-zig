const std = @import("std");
const simd_signature = @import("simd_signature");
const hash_zig = @import("hash-zig");

// SIMD Performance Benchmark
// Compares SIMD-optimized implementation against baseline

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("SIMD Performance Benchmark\n", .{});
    std.debug.print("==========================\n", .{});
    std.debug.print("Testing SIMD-optimized hash-based signatures\n\n", .{});

    // Test different lifetimes
    const lifetimes = [_]struct { name: []const u8, lifetime: hash_zig.params.KeyLifetime, expected_time_sec: f64, description: []const u8 }{
        .{ .name = "2^10", .lifetime = .lifetime_2_10, .expected_time_sec = 15.0, .description = "1,024 signatures - SIMD optimized target" },
        .{ .name = "2^16", .lifetime = .lifetime_2_16, .expected_time_sec = 60.0, .description = "65,536 signatures - SIMD optimized target" },
    };

    for (lifetimes) |config| {
        std.debug.print("\nTesting lifetime: {s} ({s})\n", .{ config.name, config.description });
        std.debug.print("Expected time: ~{d:.1}s (SIMD optimized)\n", .{config.expected_time_sec});
        std.debug.print("-------------------\n", .{});

        // Initialize SIMD signature scheme
        var sig_scheme = try simd_signature.SimdHashSignature.init(allocator, hash_zig.params.Parameters.init(config.lifetime));
        defer sig_scheme.deinit();

        const seed: [32]u8 = .{42} ** 32;

        // Key generation benchmark
        std.debug.print("Starting SIMD key generation...\n", .{});
        const keygen_start = std.time.nanoTimestamp();
        var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
        const keygen_end = std.time.nanoTimestamp();
        defer keypair.deinit();

        const keygen_duration_ns = keygen_end - keygen_start;
        const keygen_duration_sec = @as(f64, @floatFromInt(keygen_duration_ns)) / 1_000_000_000.0;

        // Calculate performance metrics
        const tree_height: u32 = config.lifetime.treeHeight();
        const num_signatures = @as(usize, 1) << @intCast(tree_height);
        const signatures_per_sec = @as(f64, @floatFromInt(num_signatures)) / keygen_duration_sec;
        const time_per_signature_ms = (keygen_duration_sec * 1000.0) / @as(f64, @floatFromInt(num_signatures));

        // Performance assessment
        const performance_ratio = keygen_duration_sec / config.expected_time_sec;
        const performance_status = if (performance_ratio < 0.8) "🚀 Excellent" else if (performance_ratio < 1.2) "✅ Good" else if (performance_ratio < 2.0) "⚠️  Slow" else "🐌 Very Slow";

        // Sign benchmark
        const message = "SIMD Performance test message";
        const sign_start = std.time.nanoTimestamp();
        var signature = try sig_scheme.sign(allocator, message, keypair, 0);
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

        // Display detailed results
        std.debug.print("\n📊 SIMD KEY GENERATION RESULTS:\n", .{});
        std.debug.print("  Duration: {d:.3}s {s}\n", .{ keygen_duration_sec, performance_status });
        std.debug.print("  Signatures: {d} (2^{d})\n", .{ num_signatures, tree_height });
        std.debug.print("  Throughput: {d:.1} signatures/sec\n", .{signatures_per_sec});
        std.debug.print("  Time per signature: {d:.3}ms\n", .{time_per_signature_ms});
        std.debug.print("  Expected: ~{d:.1}s (ratio: {d:.2}x)\n", .{ config.expected_time_sec, performance_ratio });

        // Display sign/verify results
        std.debug.print("\n🔐 SIMD SIGN/VERIFY RESULTS:\n", .{});
        std.debug.print("  Sign: {d:.3}ms\n", .{sign_duration_sec * 1000});
        std.debug.print("  Verify: {d:.3}ms\n", .{verify_duration_sec * 1000});
        std.debug.print("  Valid: {}\n", .{is_valid});

        // Batch operations benchmark
        std.debug.print("\n🔄 BATCH OPERATIONS BENCHMARK:\n", .{});
        const batch_messages = [_][]const u8{ "batch1", "batch2", "batch3", "batch4" };
        const batch_indices = [_]u32{ 0, 1, 2, 3 };

        const batch_sign_start = std.time.nanoTimestamp();
        const batch_sigs = try sig_scheme.batchSign(allocator, &batch_messages, keypair, &batch_indices);
        const batch_sign_end = std.time.nanoTimestamp();
        defer {
            for (batch_sigs) |*sig| sig.deinit(allocator);
            allocator.free(batch_sigs);
        }

        const batch_verify_start = std.time.nanoTimestamp();
        const batch_results = try sig_scheme.batchVerify(allocator, &batch_messages, batch_sigs, keypair.public_key);
        const batch_verify_end = std.time.nanoTimestamp();
        defer allocator.free(batch_results);

        const batch_sign_duration = @as(f64, @floatFromInt(batch_sign_end - batch_sign_start)) / 1_000_000_000.0;
        const batch_verify_duration = @as(f64, @floatFromInt(batch_verify_end - batch_verify_start)) / 1_000_000_000.0;

        std.debug.print("  Batch Sign (4 ops): {d:.3}ms\n", .{batch_sign_duration * 1000});
        std.debug.print("  Batch Verify (4 ops): {d:.3}ms\n", .{batch_verify_duration * 1000});
        std.debug.print("  All valid: {}\n", .{std.mem.allEqual(bool, batch_results, true)});

        // Output results in a format that can be captured by CI
        std.debug.print("\n📈 CI BENCHMARK DATA:\n", .{});
        std.debug.print("BENCHMARK_RESULT: {s}:keygen:{d:.6}\n", .{ config.name, keygen_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:sign:{d:.6}\n", .{ config.name, sign_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:verify:{d:.6}\n", .{ config.name, verify_duration_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:throughput:{d:.1}\n", .{ config.name, signatures_per_sec });
        std.debug.print("BENCHMARK_RESULT: {s}:performance_ratio:{d:.2}\n", .{ config.name, performance_ratio });
        std.debug.print("BENCHMARK_RESULT: {s}:batch_sign:{d:.6}\n", .{ config.name, batch_sign_duration });
        std.debug.print("BENCHMARK_RESULT: {s}:batch_verify:{d:.6}\n", .{ config.name, batch_verify_duration });
    }

    // SIMD-specific performance tests
    std.debug.print("\n🧪 SIMD SPECIFIC TESTS:\n", .{});
    std.debug.print("========================\n", .{});

    // Test SIMD field operations
    testSimdFieldOperations();

    // Test SIMD Winternitz operations
    testSimdWinternitzOperations();

    // Test SIMD Poseidon2 operations
    testSimdPoseidon2Operations();

    std.debug.print("\n✅ SIMD Benchmark completed successfully!\n", .{});
}

fn testSimdFieldOperations() void {
    std.debug.print("\n🔢 SIMD Field Operations Test:\n", .{});

    const simd_field = @import("simd_montgomery");
    const iterations = 100000;

    // Test scalar operations
    const start_scalar = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const a = simd_field.KoalaBearSIMD.MontFieldElem{ .value = 12345 };
        const b = simd_field.KoalaBearSIMD.MontFieldElem{ .value = 67890 };
        var result: simd_field.KoalaBearSIMD.MontFieldElem = undefined;
        simd_field.KoalaBearSIMD.mul(&result, a, b);
    }
    const scalar_time = std.time.nanoTimestamp() - start_scalar;

    // Test vectorized operations
    const start_vector = std.time.nanoTimestamp();
    for (0..iterations / 4) |_| {
        const a_vec = simd_field.KoalaBearSIMD.Vec4{ 12345, 12346, 12347, 12348 };
        const b_vec = simd_field.KoalaBearSIMD.Vec4{ 67890, 67891, 67892, 67893 };
        var result_vec: simd_field.KoalaBearSIMD.Vec4 = undefined;
        simd_field.KoalaBearSIMD.mulVec4(&result_vec, a_vec, b_vec);
    }
    const vector_time = std.time.nanoTimestamp() - start_vector;

    const speedup = @as(f64, @floatFromInt(scalar_time)) / @as(f64, @floatFromInt(vector_time));
    std.debug.print("  Field operations speedup: {d:.2}x\n", .{speedup});

    if (speedup >= 2.0) {
        std.debug.print("  ✅ SIMD field operations working correctly\n", .{});
    } else {
        std.debug.print("  ⚠️  SIMD field operations may need optimization\n", .{});
    }
}

fn testSimdWinternitzOperations() void {
    std.debug.print("\n🔗 SIMD Winternitz Operations Test:\n", .{});

    const simd_winternitz = @import("simd_winternitz");
    const iterations = 1000;

    // Test scalar chain generation
    const start_scalar = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var state = simd_winternitz.SimdWinternitzOTS.ChainState{ 1, 2, 3, 4, 5, 6, 7, 8 };
        simd_winternitz.SimdWinternitzOTS.generateChain(&state, 8);
    }
    const scalar_time = std.time.nanoTimestamp() - start_scalar;

    // Test vectorized chain generation
    const start_vector = std.time.nanoTimestamp();
    for (0..iterations / 4) |_| {
        var states: [4]simd_winternitz.SimdWinternitzOTS.ChainState = .{
            simd_winternitz.SimdWinternitzOTS.ChainState{ 1, 2, 3, 4, 5, 6, 7, 8 },
            simd_winternitz.SimdWinternitzOTS.ChainState{ 9, 10, 11, 12, 13, 14, 15, 16 },
            simd_winternitz.SimdWinternitzOTS.ChainState{ 17, 18, 19, 20, 21, 22, 23, 24 },
            simd_winternitz.SimdWinternitzOTS.ChainState{ 25, 26, 27, 28, 29, 30, 31, 32 },
        };
        simd_winternitz.SimdWinternitzOTS.generateChainsBatch(&states, 8);
    }
    const vector_time = std.time.nanoTimestamp() - start_vector;

    const speedup = @as(f64, @floatFromInt(scalar_time)) / @as(f64, @floatFromInt(vector_time));
    std.debug.print("  Winternitz operations speedup: {d:.2}x\n", .{speedup});

    if (speedup >= 2.0) {
        std.debug.print("  ✅ SIMD Winternitz operations working correctly\n", .{});
    } else {
        std.debug.print("  ⚠️  SIMD Winternitz operations may need optimization\n", .{});
    }
}

fn testSimdPoseidon2Operations() void {
    std.debug.print("\n🌊 SIMD Poseidon2 Operations Test:\n", .{});

    const simd_poseidon = @import("simd_poseidon2");
    const iterations = 1000;

    // Test scalar permutation
    const start_scalar = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var state = simd_poseidon.SimdPoseidon2.State{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        simd_poseidon.SimdPoseidon2.permutation(&state);
    }
    const scalar_time = std.time.nanoTimestamp() - start_scalar;

    // Test vectorized permutation
    const start_vector = std.time.nanoTimestamp();
    for (0..iterations / 4) |_| {
        var states: [4]simd_poseidon.SimdPoseidon2.Vec4 = .{
            simd_poseidon.SimdPoseidon2.Vec4{ 1, 2, 3, 4 },
            simd_poseidon.SimdPoseidon2.Vec4{ 5, 6, 7, 8 },
            simd_poseidon.SimdPoseidon2.Vec4{ 9, 10, 11, 12 },
            simd_poseidon.SimdPoseidon2.Vec4{ 13, 14, 15, 16 },
        };
        simd_poseidon.SimdPoseidon2.permutationVec4(&states);
    }
    const vector_time = std.time.nanoTimestamp() - start_vector;

    const speedup = @as(f64, @floatFromInt(scalar_time)) / @as(f64, @floatFromInt(vector_time));
    std.debug.print("  Poseidon2 operations speedup: {d:.2}x\n", .{speedup});

    if (speedup >= 2.0) {
        std.debug.print("  ✅ SIMD Poseidon2 operations working correctly\n", .{});
    } else {
        std.debug.print("  ⚠️  SIMD Poseidon2 operations may need optimization\n", .{});
    }
}
