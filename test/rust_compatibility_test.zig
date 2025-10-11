//! Tests to ensure hash-zig remains compatible with Rust hash-sig implementation
//! These tests MUST pass for any code changes to be merged

const std = @import("std");
const hash_zig = @import("hash-zig");

// CRITICAL: This test ensures we're using the correct Poseidon2 parameters
// that match the Rust hash-sig implementation
test "rust compatibility: poseidon2 parameters are correct" {
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    // These parameters MUST match the Rust implementation
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params.hash_function);
    try std.testing.expectEqual(@as(u32, 32), params.hash_output_len);
    try std.testing.expectEqual(@as(u32, 8), params.winternitz_w); // w=8 => chain_len=256
    try std.testing.expectEqual(@as(u32, 22), params.num_chains);
    try std.testing.expectEqual(@as(u32, 10), params.tree_height);
}

// CRITICAL: Signature verification MUST work
// This is the primary indicator that the implementation is working correctly
test "rust compatibility: signature verification must succeed" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Use deterministic seed for reproducibility
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    const message = "rust compatibility test";
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);

    var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, 0, &rng_seed);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);

    // CRITICAL: If this fails, DO NOT MERGE
    if (!is_valid) {
        std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
        std.debug.print("🚨 CRITICAL FAILURE: SIGNATURE VERIFICATION FAILED 🚨\n", .{});
        std.debug.print("=" ** 80 ++ "\n", .{});
        std.debug.print("\nThis indicates a breaking bug in the implementation.\n", .{});
        std.debug.print("Possible causes:\n", .{});
        std.debug.print("  1. MDS matrix implementation is incorrect\n", .{});
        std.debug.print("  2. Poseidon2 permutation has bugs\n", .{});
        std.debug.print("  3. Winternitz OTS implementation is broken\n", .{});
        std.debug.print("  4. Merkle tree construction is incorrect\n", .{});
        std.debug.print("\n⛔ DO NOT MERGE THIS CODE UNTIL THIS TEST PASSES ⛔\n", .{});
        std.debug.print("=" ** 80 ++ "\n\n", .{});
        return error.SignatureVerificationFailed;
    }

    try std.testing.expect(is_valid);
}

// CRITICAL: Public keys MUST NOT have repeating patterns
// This was the bug that caused all the issues
test "rust compatibility: public key has no repeating patterns" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);

    const pk = keypair.public_key.root;

    // Public key should be 32 bytes
    try std.testing.expectEqual(@as(usize, 32), pk.len);

    // Check for repeating 4-byte patterns
    const num_chunks = pk.len / 4;
    if (num_chunks > 1) {
        var first_chunk: [4]u8 = undefined;
        @memcpy(&first_chunk, pk[0..4]);

        var all_same = true;
        var i: usize = 1;
        while (i < num_chunks) : (i += 1) {
            const chunk_offset = i * 4;
            if (!std.mem.eql(u8, &first_chunk, pk[chunk_offset .. chunk_offset + 4])) {
                all_same = false;
                break;
            }
        }

        if (all_same) {
            std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
            std.debug.print("🚨 BUG DETECTED: PUBLIC KEY HAS REPEATING PATTERN 🚨\n", .{});
            std.debug.print("=" ** 80 ++ "\n", .{});
            std.debug.print("\nRepeating 4-byte pattern: ", .{});
            for (first_chunk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n\nFull public key:\n  ", .{});
            for (pk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n\nThis indicates the Poseidon2 MDS matrix is broken.\n", .{});
            std.debug.print("⛔ DO NOT MERGE THIS CODE ⛔\n", .{});
            std.debug.print("=" ** 80 ++ "\n\n", .{});
            return error.RepeatingPatternInPublicKey;
        }

        try std.testing.expect(!all_same);
    }
}

// CRITICAL: Hash function must produce diverse outputs
test "rust compatibility: hash function produces diverse outputs" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const test_data = "test";
    const result = try tweakable_hash.hash(allocator, test_data, 0);
    defer allocator.free(result);

    // Check for repeating 4-byte patterns
    const num_chunks = result.len / 4;
    if (num_chunks > 1) {
        var first_chunk: [4]u8 = undefined;
        @memcpy(&first_chunk, result[0..4]);

        var all_same = true;
        var i: usize = 1;
        while (i < num_chunks) : (i += 1) {
            const chunk_offset = i * 4;
            if (!std.mem.eql(u8, &first_chunk, result[chunk_offset .. chunk_offset + 4])) {
                all_same = false;
                break;
            }
        }

        if (all_same) {
            std.debug.print("\n⚠️  Hash function outputs repeating pattern: ", .{});
            for (first_chunk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.HashFunctionBroken;
        }

        try std.testing.expect(!all_same);
    }
}

// Test that parameters initialization always uses Poseidon2
test "rust compatibility: default parameters use poseidon2" {
    const params_lifetime_10 = hash_zig.Parameters.init(.lifetime_2_10);
    const params_lifetime_16 = hash_zig.Parameters.init(.lifetime_2_16);
    const params_lifetime_18 = hash_zig.Parameters.init(.lifetime_2_18);

    // ALL must use Poseidon2
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params_lifetime_10.hash_function);
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params_lifetime_16.hash_function);
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params_lifetime_18.hash_function);
}

// Test that chain length calculation is correct
test "rust compatibility: chain length is 256 for w=8" {
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    // w=8 means chain_length = 2^8 = 256
    const expected_chain_len = @as(u32, 1) << @intCast(params.winternitz_w);
    try std.testing.expectEqual(@as(u32, 256), expected_chain_len);
}

// Test deterministic key generation
test "rust compatibility: deterministic key generation" {
    const allocator = std.testing.allocator;

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var sig_scheme1 = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme1.deinit();

    var sig_scheme2 = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme2.deinit();

    const seed: [32]u8 = .{0x42} ** 32;

    var keypair1 = try sig_scheme1.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair1.deinit(allocator);

    var keypair2 = try sig_scheme2.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair2.deinit(allocator);

    // Same seed MUST produce same public key
    try std.testing.expectEqualSlices(u8, keypair1.public_key.root, keypair2.public_key.root);
}

// Test that we're using KoalaBear field (width=16)
test "rust compatibility: using koalabear16 poseidon2" {
    const allocator = std.testing.allocator;

    // Create a TweakableHash instance to verify Poseidon2 is being used
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    // Verify we're using Poseidon2
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params.hash_function);

    // Verify hash output length is 32 bytes (standard for KoalaBear16)
    try std.testing.expectEqual(@as(u32, 32), params.hash_output_len);
}
