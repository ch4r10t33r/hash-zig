//! Integration tests for hash-sig

const std = @import("std");
const hash_zig = @import("hash-zig");

test "full signature workflow with verification" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42); // Use deterministic seed for testing

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    const message = "Test message";
    
    // Generate RNG seed for encoding randomness
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);
    
    var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, 0, &rng_seed);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);
    
    // CRITICAL: Signature verification MUST pass
    try std.testing.expect(is_valid);
}

test "signature verification must succeed for valid signature" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    const message = "Critical test message";
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);
    
    var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, 0, &rng_seed);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);
    
    // This is a CRITICAL test - if this fails, the implementation is broken
    if (!is_valid) {
        std.debug.print("\n⚠️  CRITICAL FAILURE: Signature verification failed!\n", .{});
        std.debug.print("This indicates a bug in key generation, signing, or verification.\n", .{});
        return error.SignatureVerificationFailed;
    }
    
    try std.testing.expect(is_valid);
}

test "public key has no repeating patterns" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    const pk = keypair.public_key.root;
    
    // Check for repeating 4-byte patterns (this was the bug)
    if (pk.len >= 8) {
        const num_chunks = pk.len / 4;
        var first_chunk: [4]u8 = undefined;
        @memcpy(&first_chunk, pk[0..4]);

        var all_same = true;
        var i: usize = 1;
        while (i < num_chunks) : (i += 1) {
            const chunk_offset = i * 4;
            if (!std.mem.eql(u8, &first_chunk, pk[chunk_offset..chunk_offset + 4])) {
                all_same = false;
                break;
            }
        }

        // If all chunks are the same, print error and fail
        if (all_same) {
            std.debug.print("\n⚠️  BUG DETECTED: Public key has repeating pattern!\n", .{});
            std.debug.print("Pattern: ", .{});
            for (first_chunk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            std.debug.print("Full key: ", .{});
            for (pk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.RepeatingPatternInPublicKey;
        }

        try std.testing.expect(!all_same);
    }
}

test "deterministic key generation from same seed" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme1 = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme1.deinit();
    
    var sig_scheme2 = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme2.deinit();

    // Use a fixed seed
    const seed: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    // Generate first keypair
    var keypair1 = try sig_scheme1.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair1.deinit(allocator);

    // Generate second keypair with same seed
    var keypair2 = try sig_scheme2.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair2.deinit(allocator);

    // Both keypairs should be identical
    try std.testing.expectEqualSlices(u8, keypair1.public_key.root, keypair2.public_key.root);
}

test "different seeds generate different keys" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // First seed
    const seed1: [32]u8 = .{1} ** 32;

    // Second seed (different)
    const seed2: [32]u8 = .{2} ** 32;

    // Generate keypairs
    var keypair1 = try sig_scheme.generateKeyPair(allocator, &seed1, 0, 0);
    defer keypair1.deinit(allocator);

    var keypair2 = try sig_scheme.generateKeyPair(allocator, &seed2, 0, 0);
    defer keypair2.deinit(allocator);

    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, keypair1.public_key.root, keypair2.public_key.root));
}

test "invalid seed length returns error" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Seed with wrong length (16 bytes instead of 32)
    const invalid_seed: [16]u8 = .{1} ** 16;

    // Should return error
    const result = sig_scheme.generateKeyPair(allocator, &invalid_seed, 0, 0);
    try std.testing.expectError(error.InvalidSeedLength, result);
}

test "multiple signatures with same keypair all verify" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    // Test multiple messages
    const messages = [_][]const u8{
        "First message",
        "Second message",
        "Third message",
    };

    for (messages, 0..) |message, epoch| {
        var rng_seed: [32]u8 = undefined;
        std.crypto.random.bytes(&rng_seed);
        
        var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, @intCast(epoch), &rng_seed);
        defer signature.deinit(allocator);

        const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);
        
        // Each signature must verify
        if (!is_valid) {
            std.debug.print("\n⚠️  Signature {d} failed to verify for message: {s}\n", .{epoch, message});
            return error.SignatureVerificationFailed;
        }
        
        try std.testing.expect(is_valid);
    }
}
