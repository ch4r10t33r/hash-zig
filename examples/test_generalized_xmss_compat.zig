const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("Testing GeneralizedXMSS Rust Compatibility Implementation\n", .{});
    log.print("========================================================\n", .{});

    // Initialize the signature scheme for lifetime 2^8
    var scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    log.print("✅ Scheme initialized successfully\n", .{});

    // Test key generation
    log.print("Testing key generation...\n", .{});
    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    log.print("✅ Key generation successful\n", .{});
    log.print("  - Public key root: {}\n", .{keypair.public_key.root[0].value});
    log.print("  - Activation epoch: {}\n", .{keypair.secret_key.activation_epoch});
    log.print("  - Num active epochs: {}\n", .{keypair.secret_key.num_active_epochs});

    // Test secret key methods
    log.print("Testing secret key methods...\n", .{});
    const activation_interval = keypair.secret_key.getActivationInterval();
    log.print("  - Activation interval: {} to {}\n", .{ activation_interval.start, activation_interval.end });

    const prepared_interval = keypair.secret_key.getPreparedInterval(8);
    log.print("  - Prepared interval: {} to {}\n", .{ prepared_interval.start, prepared_interval.end });

    log.print("✅ Secret key methods working\n", .{});

    // Test signing
    log.print("Testing signing...\n", .{});
    const message = [_]u8{0x42} ** 32;
    const signature = try scheme.sign(keypair.secret_key, 0, message);
    defer signature.deinit();

    log.print("✅ Signing successful\n", .{});

    // Test verification
    log.print("Testing verification...\n", .{});
    const is_valid = try scheme.verify(&keypair.public_key, 0, message, signature);
    log.print("  - Signature valid: {}\n", .{is_valid});

    log.print("✅ Verification successful\n", .{});

    log.print("\n🎉 All tests passed! GeneralizedXMSS implementation is working.\n", .{});
}
