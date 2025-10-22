const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("hash-zig Basic Usage Example\n", .{});
    std.debug.print("============================\n", .{});
    std.debug.print("Demonstrating key generation, signing, and verification with timing\n\n", .{});

    // Initialize the GeneralizedXMSS signature scheme for lifetime 2^8
    std.debug.print("1. Initializing signature scheme (lifetime 2^8)...\n", .{});
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();
    std.debug.print("✅ Signature scheme initialized\n\n", .{});

    // Generate a keypair with timing
    std.debug.print("2. Generating keypair...\n", .{});
    var keygen_timer = try std.time.Timer.start();
    const keypair = try scheme.keyGen(0, 256); // activation_epoch=0, num_active_epochs=256
    const keygen_elapsed = keygen_timer.read();
    const keygen_ms = keygen_elapsed / 1_000_000;
    const keygen_s = @as(f64, @floatFromInt(keygen_elapsed)) / 1_000_000_000.0;

    std.debug.print("✅ Key generation completed\n", .{});
    std.debug.print("⏱️  Key generation time: {d:.2} seconds ({d} ms)\n", .{ keygen_s, keygen_ms });
    std.debug.print("📊 Generation rate: {d:.1} signatures/second\n", .{256.0 / keygen_s});
    std.debug.print("🔑 Public key root: {}\n", .{keypair.public_key.root[0].value});
    std.debug.print("🔐 Secret key epochs: 0 to {}\n\n", .{keypair.secret_key.getActivationInterval().end});

    // Prepare a message to sign
    const message = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 } ++ [_]u8{0x00} ** 20; // "Hello World!" + padding
    const epoch: u32 = 0;

    // Sign the message with timing
    std.debug.print("3. Signing message...\n", .{});
    std.debug.print("📝 Message: \"Hello World!\" (32 bytes)\n", .{});
    std.debug.print("📅 Epoch: {}\n", .{epoch});

    var sign_timer = try std.time.Timer.start();
    const signature = try scheme.sign(keypair.secret_key, epoch, message);
    const sign_elapsed = sign_timer.read();
    const sign_ms = sign_elapsed / 1_000_000;
    const sign_s = @as(f64, @floatFromInt(sign_elapsed)) / 1_000_000_000.0;

    std.debug.print("✅ Signing completed\n", .{});
    std.debug.print("⏱️  Signing time: {d:.3} seconds ({d} ms)\n", .{ sign_s, sign_ms });
    std.debug.print("📊 Signing rate: {d:.1} signatures/second\n\n", .{1.0 / sign_s});

    // Verify the signature with timing
    std.debug.print("4. Verifying signature...\n", .{});

    var verify_timer = try std.time.Timer.start();
    const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
    const verify_elapsed = verify_timer.read();
    const verify_ms = verify_elapsed / 1_000_000;
    const verify_s = @as(f64, @floatFromInt(verify_elapsed)) / 1_000_000_000.0;

    std.debug.print("✅ Verification completed\n", .{});
    std.debug.print("⏱️  Verification time: {d:.3} seconds ({d} ms)\n", .{ verify_s, verify_ms });
    std.debug.print("📊 Verification rate: {d:.1} verifications/second\n", .{1.0 / verify_s});
    std.debug.print("🎯 Signature valid: {}\n\n", .{is_valid});

    // Performance summary
    std.debug.print("📈 Performance Summary\n", .{});
    std.debug.print("======================\n", .{});
    std.debug.print("Key Generation: {d:.2}s ({d} ms)\n", .{ keygen_s, keygen_ms });
    std.debug.print("Signing:        {d:.3}s ({d} ms)\n", .{ sign_s, sign_ms });
    std.debug.print("Verification:   {d:.3}s ({d} ms)\n", .{ verify_s, verify_ms });

    const total_time = keygen_s + sign_s + verify_s;
    std.debug.print("Total Time:     {d:.3}s\n", .{total_time});

    // Clean up
    keypair.secret_key.deinit();
    signature.deinit();

    std.debug.print("\n🎉 Example completed successfully!\n", .{});
    std.debug.print("💡 Tip: Use 'zig build -Doptimize=ReleaseFast' for better performance\n", .{});
}
