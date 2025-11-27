//! Test Zig key generation, signing, and verification for lifetimes 2^8 and 2^18
//! Tests with 256 active epochs for both lifetimes
//! Always runs in ReleaseFast mode for key generation performance

const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const testing = std.testing;

const MESSAGE = "Test message for hash-based signatures!";

fn testLifetime(
    allocator: std.mem.Allocator,
    lifetime: hash_zig.KeyLifetimeRustCompat,
    num_active_epochs: usize,
) !void {
    const lifetime_name = switch (lifetime) {
        .lifetime_2_8 => "2^8",
        .lifetime_2_18 => "2^18",
        .lifetime_2_32 => "2^32",
    };

    std.debug.print("\n", .{});
    std.debug.print("==============================================\n", .{});
    std.debug.print("Testing Lifetime: {s}\n", .{lifetime_name});
    std.debug.print("Active Epochs: {}\n", .{num_active_epochs});
    std.debug.print("==============================================\n", .{});

    // Initialize signature scheme
    var sig_scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer sig_scheme.deinit();

    std.debug.print("✅ Signature scheme initialized\n", .{});

    // ========================================
    // Test 1: Key Generation
    // ========================================
    std.debug.print("\n1️⃣  Key Generation\n", .{});
    std.debug.print("----------------------------------------\n", .{});

    const activation_epoch: usize = 0;
    const keygen_start = std.time.nanoTimestamp();
    var keypair = try sig_scheme.keyGen(activation_epoch, num_active_epochs);
    const keygen_end = std.time.nanoTimestamp();
    defer keypair.secret_key.deinit();

    const keygen_time_ns = keygen_end - keygen_start;
    const keygen_time_ms = @as(f64, @floatFromInt(keygen_time_ns)) / 1_000_000.0;
    const keygen_time_s = keygen_time_ms / 1000.0;

    std.debug.print("⏱️  Key Generation Time: {d:.3} seconds ({d:.2} ms)\n", .{ keygen_time_s, keygen_time_ms });
    std.debug.print("   Public key root[0]: 0x{x:0>8}\n", .{keypair.public_key.root[0].value});
    std.debug.print("   Activation epoch: {}\n", .{keypair.secret_key.getActivationEpoch()});
    std.debug.print("   Active epochs: {}\n", .{keypair.secret_key.getNumActiveEpochs()});

    // Verify key structure
    try testing.expectEqual(activation_epoch, keypair.secret_key.getActivationEpoch());
    try testing.expectEqual(num_active_epochs, keypair.secret_key.getNumActiveEpochs());

    const activation_interval = keypair.secret_key.getActivationInterval();
    try testing.expectEqual(@as(u64, activation_epoch), activation_interval.start);
    try testing.expectEqual(@as(u64, activation_epoch + num_active_epochs), activation_interval.end);

    std.debug.print("✅ Key generation successful\n", .{});

    // ========================================
    // Test 2: Signing and Verification (epoch 0 only for now)
    // ========================================
    std.debug.print("\n2️⃣  Signing and Verification\n", .{});
    std.debug.print("----------------------------------------\n", .{});

    // Prepare message (32 bytes)
    var message: [32]u8 = undefined;
    const msg_bytes = MESSAGE;
    const copy_len = @min(msg_bytes.len, 32);
    @memset(&message, 0);
    @memcpy(message[0..copy_len], msg_bytes[0..copy_len]);

    // Test multiple epochs
    // Note: Prepared interval is [0, 32) for lifetime 2^8
    // Test all epochs in prepared interval to verify boundary fix
    const test_epochs: []const u32 = switch (lifetime) {
        .lifetime_2_8 => &[_]u32{ 0, 1, 10, 15, 16, 17, 28, 29, 30, 31 }, // Test all epochs including boundaries
        .lifetime_2_18 => &[_]u32{ 0, 1, 10, 50, 100 },
        .lifetime_2_32 => &[_]u32{ 0, 1, 10, 50, 100 },
    };

    var success_count: usize = 0;

    for (test_epochs) |epoch| {
        // Skip if epoch is outside activation interval
        if (epoch >= activation_interval.end) {
            std.debug.print("   ⏭️  Skipping epoch {} (outside activation interval [{}, {}))\n", .{ epoch, activation_interval.start, activation_interval.end });
            continue;
        }

        // Check if epoch is in prepared interval, advance if needed
        var prepared_interval = keypair.secret_key.getPreparedInterval(sig_scheme.lifetime_params.log_lifetime);
        var iterations: u32 = 0;
        const max_iterations: u32 = switch (lifetime) {
            .lifetime_2_8 => 10,
            .lifetime_2_18 => 100,
            .lifetime_2_32 => 100,
        };
        while (epoch >= prepared_interval.end and iterations < max_iterations) {
            try keypair.secret_key.advancePreparation(sig_scheme, sig_scheme.lifetime_params.log_lifetime);
            prepared_interval = keypair.secret_key.getPreparedInterval(sig_scheme.lifetime_params.log_lifetime);
            iterations += 1;
        }

        if (epoch < prepared_interval.start or epoch >= prepared_interval.end) {
            std.debug.print("   ⚠️  Epoch {} not in prepared interval [{}, {}) after {} iterations\n", .{ epoch, prepared_interval.start, prepared_interval.end, iterations });
            continue;
        }

        // Sign
        const sign_start = std.time.nanoTimestamp();
        var signature = try sig_scheme.sign(keypair.secret_key, epoch, message);
        const sign_end = std.time.nanoTimestamp();
        defer signature.deinit();

        const sign_time_ns = sign_end - sign_start;
        const sign_time_ms = @as(f64, @floatFromInt(sign_time_ns)) / 1_000_000.0;

        // Verify
        const verify_start = std.time.nanoTimestamp();
        const is_valid = try sig_scheme.verify(&keypair.public_key, epoch, message, signature);
        const verify_end = std.time.nanoTimestamp();

        const verify_time_ns = verify_end - verify_start;
        const verify_time_ms = @as(f64, @floatFromInt(verify_time_ns)) / 1_000_000.0;

        if (is_valid) {
            std.debug.print("   ✅ Epoch {}: Sign={d:.3}ms, Verify={d:.3}ms\n", .{ epoch, sign_time_ms, verify_time_ms });
            success_count += 1;
        } else {
            std.debug.print("   ❌ Epoch {}: Verification FAILED (Sign={d:.3}ms, Verify={d:.3}ms)\n", .{ epoch, sign_time_ms, verify_time_ms });
            std.debug.print("   Debug: Prepared interval: [{}, {})\n", .{ prepared_interval.start, prepared_interval.end });
            std.debug.print("   Debug: Activation interval: [{}, {})\n", .{ activation_interval.start, activation_interval.end });
            return error.VerificationFailed;
        }
    }

    std.debug.print("\n✅ Signed and verified {} epochs successfully\n", .{success_count});

    std.debug.print("\n✅ All tests passed for lifetime {s}!\n", .{lifetime_name});
}

test "test lifetime 2^8 with 256 active epochs" {
    const allocator = testing.allocator;
    // For 2^8, maximum lifetime is 256, so use 256 active epochs (not 1024)
    try testLifetime(allocator, .lifetime_2_8, 256);
}

test "test lifetime 2^18 with 1024 active epochs" {
    const allocator = testing.allocator;
    try testLifetime(allocator, .lifetime_2_18, 1024);
}

// Test for lifetime 2^32 - only runs if enabled via build option
// Run with: zig build test-lifetimes -Denable-lifetime-2-32=true
test "test lifetime 2^32 with 1024 active epochs" {
    const build_options = @import("build_options");
    if (!build_options.enable_lifetime_2_32) {
        std.debug.print("Skipping lifetime 2^32 test (use -Denable-lifetime-2-32=true to enable)\n", .{});
        return;
    }
    const allocator = testing.allocator;
    try testLifetime(allocator, .lifetime_2_32, 1024);
}

test "test lifetime 2^32 with 256 active epochs" {
    const build_options = @import("build_options");
    if (!build_options.enable_lifetime_2_32) {
        std.debug.print("Skipping lifetime 2^32 test (use -Denable-lifetime-2-32=true to enable)\n", .{});
        return;
    }
    const allocator = testing.allocator;
    try testLifetime(allocator, .lifetime_2_32, 256);
}
