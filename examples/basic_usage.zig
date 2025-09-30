//! Example usage of the hash-zig library

const std = @import("std");
const hash_sig = @import("hash-zig");

pub fn main() !void {
    // zlinter-disable-next-line no_deprecated - Standard allocator pattern for examples
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Hash-Sig Example\n", .{});
    std.debug.print("================\n\n", .{});

    // Initialize with 128-bit security
    const params = hash_sig.Parameters.init(.level_128, .lifetime_2_10);
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    std.debug.print("Generating keypair...\n", .{});
    var keypair = try sig_scheme.generateKeyPair(allocator);
    defer keypair.deinit(allocator);

    std.debug.print("Public key (first 16 bytes): ", .{});
    for (keypair.public_key[0..@min(16, keypair.public_key.len)]) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});
    std.debug.print("Secret key (first 16 bytes): ", .{});
    for (keypair.secret_key[0..@min(16, keypair.secret_key.len)]) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Sign a message
    const message = "Hello, Hash-based Signatures with Poseidon2!";
    std.debug.print("Signing message: \"{s}\"\n", .{message});

    var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
    defer signature.deinit(allocator);

    std.debug.print("Signature generated (index: {})\n\n", .{signature.index});

    // Verify the signature
    std.debug.print("Verifying signature...\n", .{});
    const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);

    if (is_valid) {
        std.debug.print("✓ Signature is VALID\n", .{});
    } else {
        std.debug.print("✗ Signature is INVALID\n", .{});
    }

    // Try with wrong message
    const wrong_message = "Different message";
    std.debug.print("\nVerifying with wrong message: \"{s}\"\n", .{wrong_message});
    const is_valid_wrong = try sig_scheme.verify(allocator, wrong_message, signature, keypair.public_key);

    if (!is_valid_wrong) {
        std.debug.print("✓ Correctly rejected invalid signature\n", .{});
    } else {
        std.debug.print("✗ Incorrectly accepted invalid signature\n", .{});
    }
}
