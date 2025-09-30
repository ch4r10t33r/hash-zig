//! Integration tests for hash-sig

const std = @import("std");
const hash_sig = @import("hash-sig");

test "full signature workflow" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.initDefault();
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    defer keypair.deinit(allocator);

    const message = "Test message";
    var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);
    try std.testing.expect(is_valid);
}

test "default parameters" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.initDefault();
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    defer keypair.deinit(allocator);

    try std.testing.expect(keypair.public_key.len > 0);
    try std.testing.expect(keypair.secret_key.len > 0);
    try std.testing.expect(keypair.public_key.len == 32); // 128-bit security
}

test "deterministic key generation from same seed" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.initDefault();
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Use a fixed seed
    const seed: [32]u8 = .{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    // Generate first keypair
    var keypair1 = try sig_scheme.generateKeyPair(allocator, &seed);
    defer keypair1.deinit(allocator);

    // Generate second keypair with same seed
    var keypair2 = try sig_scheme.generateKeyPair(allocator, &seed);
    defer keypair2.deinit(allocator);

    // Both keypairs should be identical
    try std.testing.expectEqualSlices(u8, keypair1.public_key, keypair2.public_key);
    try std.testing.expectEqualSlices(u8, keypair1.secret_key, keypair2.secret_key);
}

test "different seeds generate different keys" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.initDefault();
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // First seed
    const seed1: [32]u8 = .{1} ** 32;

    // Second seed (different)
    const seed2: [32]u8 = .{2} ** 32;

    // Generate keypairs
    var keypair1 = try sig_scheme.generateKeyPair(allocator, &seed1);
    defer keypair1.deinit(allocator);

    var keypair2 = try sig_scheme.generateKeyPair(allocator, &seed2);
    defer keypair2.deinit(allocator);

    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, keypair1.public_key, keypair2.public_key));
    try std.testing.expect(!std.mem.eql(u8, keypair1.secret_key, keypair2.secret_key));
}

test "invalid seed length returns error" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.initDefault();
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Seed with wrong length (16 bytes instead of 32)
    const invalid_seed: [16]u8 = .{1} ** 16;

    // Should return error
    const result = sig_scheme.generateKeyPair(allocator, &invalid_seed);
    try std.testing.expectError(error.InvalidSeedLength, result);
}
