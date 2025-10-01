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

    // Initialize with 128-bit security (only security level supported)
    // Using lifetime_2_10 (1,024 signatures)
    const params = hash_sig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    std.debug.print("Lifetime: 2^10 = 1,024 signatures\n", .{});
    std.debug.print("Parameters: 64 chains of length 8 (w=8)\n", .{});
    std.debug.print("Hash: Poseidon2\n\n", .{});

    std.debug.print("Generating keypair...\n", .{});

    // Generate a random seed for key generation
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);

    // Measure key generation time
    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    const end_time = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const duration_ns = end_time - start_time;
    const duration_ms = @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0;
    const duration_sec = duration_ms / 1000.0;

    std.debug.print("Key generation completed in {d:.3} seconds\n", .{duration_sec});
    std.debug.print("\nBENCHMARK_RESULT: {d:.6}\n", .{duration_sec});

    std.debug.print("\nPublic Key:\n", .{});
    std.debug.print("  Length: {} bytes\n", .{keypair.public_key.len});
    std.debug.print("  Content: ", .{});
    for (keypair.public_key) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    std.debug.print("Secret Key:\n", .{});
    std.debug.print("  Length: {} bytes\n", .{keypair.secret_key.len});
    std.debug.print("  Content: ", .{});
    for (keypair.secret_key) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Sign a message
    const message = "Hello, Hash-based Signatures with Poseidon2!";
    std.debug.print("Signing message: \"{s}\"\n", .{message});

    const sign_start = std.time.nanoTimestamp();
    var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
    const sign_end = std.time.nanoTimestamp();
    defer signature.deinit(allocator);

    const sign_duration_ms = @as(f64, @floatFromInt(sign_end - sign_start)) / 1_000_000.0;
    std.debug.print("Signature generated (index: {}) in {d:.2} ms\n", .{ signature.index, sign_duration_ms });
    std.debug.print("  OTS signature parts: {}\n", .{signature.ots_signature.len});
    std.debug.print("  Auth path length: {}\n\n", .{signature.auth_path.len});

    // Verify the signature
    std.debug.print("Verifying signature...\n", .{});

    const verify_start = std.time.nanoTimestamp();
    const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);
    const verify_end = std.time.nanoTimestamp();

    const verify_duration_ms = @as(f64, @floatFromInt(verify_end - verify_start)) / 1_000_000.0;

    if (is_valid) {
        std.debug.print("✓ Signature is VALID (verified in {d:.2} ms)\n", .{verify_duration_ms});
    } else {
        std.debug.print("✗ Signature is INVALID (checked in {d:.2} ms)\n", .{verify_duration_ms});
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
