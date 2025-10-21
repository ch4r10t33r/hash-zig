const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Testing Zig internal signing and verification...\n", .{});

    // Initialize the scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    // Generate keypair
    std.debug.print("Generating keypair...\n", .{});
    var keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Test message
    const test_message = "Hello, Zig internal test!";
    const epoch: u32 = 0;

    // Convert message to bytes
    var message_bytes: [32]u8 = undefined;
    @memset(&message_bytes, 0);
    @memcpy(message_bytes[0..@min(test_message.len, 32)], test_message);

    // Sign the message
    std.debug.print("Signing message...\n", .{});
    const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature.deinit();

    // Verify the signature
    std.debug.print("Verifying signature...\n", .{});
    const is_valid = try scheme.verify(&keypair.public_key, epoch, message_bytes, signature);

    std.debug.print("Result: {}\n", .{is_valid});
    
    if (is_valid) {
        std.debug.print("✅ SUCCESS: Zig internal signing and verification works!\n", .{});
    } else {
        std.debug.print("❌ FAILED: Zig internal verification failed!\n", .{});
    }
}
