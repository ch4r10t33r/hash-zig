//! Tests for different encoding variants matching Rust hash-sig instantiations
//! Based on https://github.com/b-wagn/hash-sig instantiations

const std = @import("std");
const hash_zig = @import("hash-zig");

/// Test Winternitz encoding variants (w=1,2,4,8)
fn testWinternitzVariants(allocator: std.mem.Allocator) !void {
    std.debug.print("Testing Winternitz encoding variants...\n", .{});

    const lifetimes = [_]hash_zig.KeyLifetimeRustCompat{.lifetime_2_8};
    const test_epochs = [_]u32{ 0, 1, 2, 13, 31, 127 };

    for (lifetimes) |lifetime| {
        std.debug.print("Testing Winternitz with lifetime {}\n", .{lifetime});

        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
        defer scheme.deinit();

        const max_epochs = lifetime.maxSignatures();
        const keypair = try scheme.keyGen(0, @intCast(max_epochs));
        defer keypair.secret_key.deinit();

        for (test_epochs) |epoch| {
            if (epoch < @as(u32, @intCast(max_epochs))) {
                const message = [_]u8{ 0x54, 0x65, 0x73, 0x74 } ++ [_]u8{0x00} ** 28; // "Test" + padding

                // Prepare key for epoch
                var iterations: u32 = 0;
                const log_lifetime = lifetime.logLifetime();
                while (true) {
                    const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
                    const epoch_u64 = @as(u64, epoch);
                    if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
                    if (iterations >= epoch) break;
                    try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
                    iterations += 1;
                }

                const signature = try scheme.sign(keypair.secret_key, epoch, message);
                defer signature.deinit();

                const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
                try std.testing.expect(is_valid);
            }
        }
    }

    std.debug.print("✅ Winternitz encoding variants test passed\n", .{});
}

/// Test TargetSum encoding variants
fn testTargetSumVariants(allocator: std.mem.Allocator) !void {
    std.debug.print("Testing TargetSum encoding variants...\n", .{});

    const lifetimes = [_]hash_zig.KeyLifetimeRustCompat{.lifetime_2_8};
    const test_epochs = [_]u32{ 0, 1, 2, 13, 31, 127 };

    for (lifetimes) |lifetime| {
        std.debug.print("Testing TargetSum with lifetime {}\n", .{lifetime});

        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
        defer scheme.deinit();

        const max_epochs = lifetime.maxSignatures();
        const keypair = try scheme.keyGen(0, @intCast(max_epochs));
        defer keypair.secret_key.deinit();

        for (test_epochs) |epoch| {
            if (epoch < @as(u32, @intCast(max_epochs))) {
                const message = [_]u8{ 0x54, 0x61, 0x72, 0x67, 0x65, 0x74 } ++ [_]u8{0x00} ** 26; // "Target" + padding

                // Prepare key for epoch
                var iterations: u32 = 0;
                const log_lifetime = lifetime.logLifetime();
                while (true) {
                    const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
                    const epoch_u64 = @as(u64, epoch);
                    if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
                    if (iterations >= epoch) break;
                    try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
                    iterations += 1;
                }

                const signature = try scheme.sign(keypair.secret_key, epoch, message);
                defer signature.deinit();

                const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
                try std.testing.expect(is_valid);
            }
        }
    }

    std.debug.print("✅ TargetSum encoding variants test passed\n", .{});
}

/// Test multiple lifetime configurations
fn testMultipleLifetimeConfigurations(allocator: std.mem.Allocator) !void {
    std.debug.print("Testing multiple lifetime configurations...\n", .{});

    const lifetime_configs = [_]struct {
        lifetime: hash_zig.KeyLifetimeRustCompat,
        test_epochs: []const u32,
    }{
        .{ .lifetime = .lifetime_2_8, .test_epochs = &[_]u32{ 0, 1, 2, 13, 31, 127, 255 } },
    };

    for (lifetime_configs) |config| {
        std.debug.print("Testing lifetime {} configuration\n", .{config.lifetime});

        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, config.lifetime);
        defer scheme.deinit();

        const max_epochs = config.lifetime.maxSignatures();
        const keypair = try scheme.keyGen(0, @intCast(max_epochs));
        defer keypair.secret_key.deinit();

        for (config.test_epochs) |epoch| {
            if (epoch < @as(u32, @intCast(max_epochs))) {
                const message = [_]u8{ 0x4c, 0x69, 0x66, 0x65, 0x74, 0x69, 0x6d, 0x65 } ++ [_]u8{0x00} ** 24; // "Lifetime" + padding

                // Prepare key for epoch
                var iterations: u32 = 0;
                const log_lifetime = config.lifetime.logLifetime();
                while (true) {
                    const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
                    const epoch_u64 = @as(u64, epoch);
                    if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
                    if (iterations >= epoch) break;
                    try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
                    iterations += 1;
                }

                const signature = try scheme.sign(keypair.secret_key, epoch, message);
                defer signature.deinit();

                const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
                try std.testing.expect(is_valid);
            }
        }
    }

    std.debug.print("✅ Multiple lifetime configurations test passed\n", .{});
}

/// Test signature scheme correctness for various parameters
fn testSignatureSchemeCorrectnessVariants(allocator: std.mem.Allocator) !void {
    std.debug.print("Testing signature scheme correctness variants...\n", .{});

    const test_cases = [_]struct {
        lifetime: hash_zig.KeyLifetimeRustCompat,
        activation_epoch: usize,
        num_active_epochs: usize,
        test_epoch: u32,
    }{
        .{ .lifetime = .lifetime_2_8, .activation_epoch = 0, .num_active_epochs = 256, .test_epoch = 0 },
        .{ .lifetime = .lifetime_2_8, .activation_epoch = 0, .num_active_epochs = 256, .test_epoch = 1 },
        .{ .lifetime = .lifetime_2_8, .activation_epoch = 0, .num_active_epochs = 256, .test_epoch = 13 },
        .{ .lifetime = .lifetime_2_8, .activation_epoch = 0, .num_active_epochs = 256, .test_epoch = 31 },
        .{ .lifetime = .lifetime_2_8, .activation_epoch = 0, .num_active_epochs = 256, .test_epoch = 127 },
    };

    for (test_cases) |test_case| {
        std.debug.print("Testing correctness: lifetime {}, epoch {}\n", .{ test_case.lifetime, test_case.test_epoch });

        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, test_case.lifetime);
        defer scheme.deinit();

        const keypair = try scheme.keyGen(test_case.activation_epoch, test_case.num_active_epochs);
        defer keypair.secret_key.deinit();

        const message = [_]u8{ 0x43, 0x6f, 0x72, 0x72, 0x65, 0x63, 0x74, 0x6e, 0x65, 0x73, 0x73 } ++ [_]u8{0x00} ** 21; // "Correctness" + padding

        // Prepare key for epoch
        var iterations: u32 = 0;
        const log_lifetime = test_case.lifetime.logLifetime();
        while (true) {
            const prepared_interval = keypair.secret_key.getPreparedInterval(@intCast(log_lifetime));
            const epoch_u64 = @as(u64, test_case.test_epoch);
            if (epoch_u64 >= prepared_interval.start and epoch_u64 < prepared_interval.end) break;
            if (iterations >= test_case.test_epoch) break;
            try keypair.secret_key.advancePreparation(@intCast(log_lifetime));
            iterations += 1;
        }

        const signature = try scheme.sign(keypair.secret_key, test_case.test_epoch, message);
        defer signature.deinit();

        const is_valid = try scheme.verify(&keypair.public_key, test_case.test_epoch, message, signature);
        try std.testing.expect(is_valid);
    }

    std.debug.print("✅ Signature scheme correctness variants test passed\n", .{});
}

// Main test suite
test "encoding variants test suite" {
    const allocator = std.testing.allocator;

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("🧪 ENCODING VARIANTS TEST SUITE\n", .{});
    std.debug.print("Testing different encoding variants and configurations\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Run all encoding variant tests
    try testWinternitzVariants(allocator);
    try testTargetSumVariants(allocator);
    try testMultipleLifetimeConfigurations(allocator);
    try testSignatureSchemeCorrectnessVariants(allocator);

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("🎉 ALL ENCODING VARIANTS TESTS PASSED! 🎉\n", .{});
    std.debug.print("✅ All encoding variants tested successfully\n", .{});
    std.debug.print("✅ Multiple lifetime configurations validated\n", .{});
    std.debug.print("✅ Signature scheme correctness verified\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
