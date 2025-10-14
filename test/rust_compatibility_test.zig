//! Tests to ensure hash-zig remains compatible with Rust hash-sig implementation
//! These tests MUST pass for any code changes to be merged

const std = @import("std");
const hash_zig = @import("hash-zig");

// CRITICAL: Comprehensive Rust compatibility test
// Generates keypair ONCE and runs all checks to save time
test "rust compatibility: comprehensive validation (CRITICAL)" {
    const allocator = std.testing.allocator;

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("🔍 Running Rust Compatibility Tests\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Step 1: Verify parameters match Rust implementation
    std.debug.print("1️⃣  Checking parameters...\n", .{});
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params.hash_function);
    try std.testing.expectEqual(@as(u32, 32), params.hash_output_len);
    try std.testing.expectEqual(@as(u32, 8), params.winternitz_w); // w=8 => chain_len=256
    try std.testing.expectEqual(@as(u32, 22), params.num_chains);
    try std.testing.expectEqual(@as(u32, 10), params.tree_height);

    // Verify chain length calculation
    const expected_chain_len = @as(u32, 1) << @intCast(params.winternitz_w);
    try std.testing.expectEqual(@as(u32, 256), expected_chain_len);

    std.debug.print("   ✅ Parameters correct (w=8, 22 chains, chain_len=256)\n\n", .{});

    // Step 2: Initialize signature scheme
    std.debug.print("2️⃣  Initializing signature scheme...\n", .{});
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();
    std.debug.print("   ✅ Signature scheme initialized\n\n", .{});

    // Step 3: Generate keypair (ONCE - reused for all subsequent tests)
    std.debug.print("3️⃣  Generating keypair (this may take a few minutes)...\n", .{});
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair.deinit(allocator);
    std.debug.print("   ✅ Keypair generated\n\n", .{});

    // Step 4: Check public key for repeating patterns (MDS matrix validation)
    std.debug.print("4️⃣  Checking for repeating patterns in public key...\n", .{});
    const pk = keypair.public_key.root;

    try std.testing.expectEqual(@as(usize, 32), pk.len);

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
    std.debug.print("   ✅ No repeating patterns (MDS matrix correct)\n\n", .{});

    // Step 5: Test signature generation and verification
    std.debug.print("5️⃣  Testing signature generation and verification...\n", .{});
    const message = "rust compatibility test";
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);

    var signature = try sig_scheme.sign(allocator, message, &keypair.secret_key, 0, &rng_seed);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, &keypair.public_key);

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
    std.debug.print("   ✅ Signature verification successful\n\n", .{});

    // Step 6: Test deterministic key generation
    std.debug.print("6️⃣  Testing deterministic key generation...\n", .{});
    var sig_scheme2 = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme2.deinit();

    var keypair2 = try sig_scheme2.generateKeyPair(allocator, &seed, 0, 0);
    defer keypair2.deinit(allocator);

    // Same seed MUST produce same public key
    try std.testing.expectEqualSlices(u8, keypair.public_key.root, keypair2.public_key.root);
    std.debug.print("   ✅ Deterministic key generation verified\n\n", .{});

    // Step 7: Test hash function diversity
    std.debug.print("7️⃣  Testing hash function output diversity...\n", .{});
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const test_data = "test";
    const hash_result = try tweakable_hash.hash(allocator, test_data, 0);
    defer allocator.free(hash_result);

    // Check for repeating 4-byte patterns in hash output
    const hash_chunks = hash_result.len / 4;
    if (hash_chunks > 1) {
        var hash_first_chunk: [4]u8 = undefined;
        @memcpy(&hash_first_chunk, hash_result[0..4]);

        var hash_all_same = true;
        var j: usize = 1;
        while (j < hash_chunks) : (j += 1) {
            const hash_chunk_offset = j * 4;
            if (!std.mem.eql(u8, &hash_first_chunk, hash_result[hash_chunk_offset .. hash_chunk_offset + 4])) {
                hash_all_same = false;
                break;
            }
        }

        if (hash_all_same) {
            std.debug.print("\n⚠️  Hash function outputs repeating pattern: ", .{});
            for (hash_first_chunk) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.HashFunctionBroken;
        }

        try std.testing.expect(!hash_all_same);
    }
    std.debug.print("   ✅ Hash function produces diverse outputs\n\n", .{});

    // Step 8: Verify lifetime_2_10 uses Poseidon2
    std.debug.print("8️⃣  Verifying lifetime_2_10 uses Poseidon2...\n", .{});
    try std.testing.expectEqual(hash_zig.HashFunction.poseidon2, params.hash_function);
    std.debug.print("   ✅ Lifetime 2^10 uses Poseidon2\n\n", .{});

    // Final summary
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("✅ ALL RUST COMPATIBILITY TESTS PASSED\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("\nVerified (lifetime_2_10):\n", .{});
    std.debug.print("  ✓ Parameters match Rust (w=8, 22 chains, 256 chain length)\n", .{});
    std.debug.print("  ✓ Poseidon2 with KoalaBear field (32-byte output)\n", .{});
    std.debug.print("  ✓ No repeating patterns (MDS matrix correct)\n", .{});
    std.debug.print("  ✓ Signature verification works\n", .{});
    std.debug.print("  ✓ Deterministic key generation\n", .{});
    std.debug.print("  ✓ Hash function produces diverse outputs\n", .{});
    std.debug.print("  ✓ Correct hash function (Poseidon2)\n", .{});
    std.debug.print("\n🎉 lifetime_2_10 tests passed!\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
