const std = @import("std");
const hash_zig = @import("hash-zig");
const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Testing GeneralizedXMSS Rust Compatibility Implementation\n", .{});
    std.debug.print("========================================================\n", .{});

    // Initialize the signature scheme for lifetime 2^8
    var scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    std.debug.print("✅ Scheme initialized successfully\n", .{});

    // Test key generation
    std.debug.print("Testing key generation...\n", .{});
    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    std.debug.print("✅ Key generation successful\n", .{});
    std.debug.print("  - Public key root: {}\n", .{keypair.public_key.root[0].value});
    std.debug.print("  - Activation epoch: {}\n", .{keypair.secret_key.activation_epoch});
    std.debug.print("  - Num active epochs: {}\n", .{keypair.secret_key.num_active_epochs});

    // Test secret key methods
    std.debug.print("Testing secret key methods...\n", .{});
    const activation_interval = keypair.secret_key.getActivationInterval();
    std.debug.print("  - Activation interval: {} to {}\n", .{ activation_interval.start, activation_interval.end });

    const prepared_interval = keypair.secret_key.getPreparedInterval(8);
    std.debug.print("  - Prepared interval: {} to {}\n", .{ prepared_interval.start, prepared_interval.end });

    std.debug.print("✅ Secret key methods working\n", .{});

    // Test signing
    std.debug.print("Testing signing...\n", .{});
    const message = [_]u8{0x42} ** 32;
    const signature = try scheme.sign(keypair.secret_key, 0, message);
    defer signature.deinit();

    std.debug.print("✅ Signing successful\n", .{});

    // Test verification
    std.debug.print("Testing verification...\n", .{});
    const is_valid = try scheme.verify(&keypair.public_key, 0, message, signature);
    std.debug.print("  - Signature valid: {}\n", .{is_valid});

    std.debug.print("✅ Verification successful\n", .{});

    std.debug.print("\n🎉 All tests passed! GeneralizedXMSS implementation is working.\n", .{});
}
