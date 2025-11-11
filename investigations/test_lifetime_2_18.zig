const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    log.print("hash-zig Lifetime 2^18 Test\n", .{});
    log.print("===========================\n", .{});

    // Initialize signature scheme for lifetime 2^18
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_18);
    defer scheme.deinit();

    log.print("✅ Scheme initialized (lifetime 2^18)\n", .{});

    // Generate key pair with activation_epoch=0 and num_active_epochs=256
    var keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    log.print("✅ Keypair generated\n", .{});
    log.print("   - Public key root[0]: {x}\n", .{keypair.public_key.root[0].value});
    log.print("   - Activation interval: {}..{}\n", .{
        keypair.secret_key.activation_epoch,
        keypair.secret_key.activation_epoch + keypair.secret_key.num_active_epochs - 1,
    });

    // Prepare message and epoch
    const epoch: u32 = 0;
    const message = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f } ++ [_]u8{0x00} ** 27; // "Hello" padded to 32 bytes

    // Sign message
    var signature = try scheme.sign(keypair.secret_key, epoch, message);
    defer signature.deinit();
    log.print("✅ Message signed (epoch {})\n", .{epoch});

    // Verify signature
    const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
    log.print("✅ Signature verification result: {}\n", .{is_valid});

    try std.testing.expect(is_valid);

    log.print("🎉 Lifetime 2^18 sign/verify completed successfully\n", .{});
}
