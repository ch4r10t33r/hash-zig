//! Basic usage example for field-native (Rust-compatible) hash-based signatures
//!
//! This example demonstrates:
//! - Key generation using field-native operations
//! - Message signing
//! - Signature verification
//! - Performance timing for each operation
//!
//! The field-native implementation operates directly on KoalaBear field elements,
//! matching the architecture of the Rust hash-sig library.

const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 70 ++ "\n", .{});
    std.debug.print("Hash-Zig: Field-Native (Rust-Compatible) Signature Example\n", .{});
    std.debug.print("=" ** 70 ++ "\n\n", .{});

    // Initialize parameters for 2^10 = 1,024 signatures
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  Lifetime: 2^{} = {d} signatures\n", .{ params.tree_height, @as(u64, 1) << @intCast(params.tree_height) });
    std.debug.print("  Hash Function: Poseidon2 (KoalaBear field)\n", .{});
    std.debug.print("  Winternitz Parameter: w={d}\n", .{params.winternitz_w});
    std.debug.print("  Number of Chains: {d} ({d} message + {d} checksum)\n", .{
        params.num_chains,
        params.num_message_chains,
        params.num_checksum_chains,
    });
    std.debug.print("  Chain Length: {d}\n", .{@as(u32, 1) << @intCast(params.winternitz_w)});
    std.debug.print("  Tree Height: {d}\n", .{params.tree_height});
    std.debug.print("  Field-Native: Yes (4-byte field elements)\n", .{});
    std.debug.print("\n", .{});

    // Initialize signature scheme
    var hash_sig = try hash_zig.HashSignatureNative.init(allocator, params);
    defer hash_sig.deinit();

    // Generate seed (must be exactly 32 bytes)
    const seed = "example_seed_32_bytes_long_pad!!";
    std.debug.print("Seed: {s}...\n\n", .{seed[0..16]});

    // Step 1: Key Generation
    std.debug.print("Step 1: Generating keypair...\n", .{});
    std.debug.print("-" ** 70 ++ "\n", .{});

    const key_gen_start = std.time.milliTimestamp();
    var keypair = try hash_sig.generateKeyPair(
        allocator,
        seed,
        0, // activation_epoch
        1024, // num_active_epochs (all 2^10 signatures)
    );
    defer keypair.deinit(allocator);
    const key_gen_end = std.time.milliTimestamp();
    const key_gen_time = key_gen_end - key_gen_start;

    // Serialize public key to get its representation
    const pk_serialized = try keypair.public_key.serialize(allocator);
    defer allocator.free(pk_serialized);

    std.debug.print("✅ Keypair generated successfully!\n", .{});
    std.debug.print("   Public Key Root (first element): {d}\n", .{keypair.public_key.root[0].toU32()});
    std.debug.print("   Public Key Size: {d} bytes\n", .{pk_serialized.len});
    std.debug.print("   Secret Key Tree Levels: {d}\n", .{keypair.secret_key.tree.len});
    std.debug.print("   Activation Epoch: {d}\n", .{keypair.secret_key.activation_epoch});
    std.debug.print("   Active Epochs: {d}\n", .{keypair.secret_key.num_active_epochs});
    std.debug.print("   ⏱️  Time: {d}.{d:0>3} seconds\n", .{
        @divFloor(key_gen_time, 1000),
        @mod(key_gen_time, 1000),
    });
    std.debug.print("\n", .{});

    // Step 2: Signing
    std.debug.print("Step 2: Signing message...\n", .{});
    std.debug.print("-" ** 70 ++ "\n", .{});

    // Create a message hash (20 bytes for Winternitz encoding)
    const message = "Hello, field-native world! This is a Rust-compatible signature.";
    std.debug.print("Message: \"{s}\"\n", .{message});

    // Hash message to 20 bytes (160 bits) for encoding
    var message_hash: [20]u8 = undefined;
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(message);
    var full_hash: [32]u8 = undefined;
    hasher.final(&full_hash);
    @memcpy(&message_hash, full_hash[0..20]);

    std.debug.print("Message Hash: ", .{});
    for (message_hash[0..8]) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("...\n", .{});

    const epoch: u64 = 42; // Use epoch 42 for signing
    std.debug.print("Epoch: {d}\n", .{epoch});

    const sign_start = std.time.milliTimestamp();
    var signature = try hash_sig.sign(allocator, &keypair.secret_key, &message_hash, epoch);
    defer signature.deinit(allocator);
    const sign_end = std.time.milliTimestamp();
    const sign_time = sign_end - sign_start;

    std.debug.print("✅ Signature generated successfully!\n", .{});
    std.debug.print("   Signature Epoch: {d}\n", .{signature.epoch});
    std.debug.print("   OTS Signature Parts: {d}\n", .{signature.hashes.len});
    std.debug.print("   Auth Path Length: {d}\n", .{signature.auth_path.len});
    std.debug.print("   ⏱️  Time: {d} ms\n", .{sign_time});
    std.debug.print("\n", .{});

    // Step 3: Verification
    std.debug.print("Step 3: Verifying signature...\n", .{});
    std.debug.print("-" ** 70 ++ "\n", .{});

    const verify_start = std.time.milliTimestamp();
    const is_valid = try hash_sig.verify(allocator, &keypair.public_key, &message_hash, &signature);
    const verify_end = std.time.milliTimestamp();
    const verify_time = verify_end - verify_start;

    if (is_valid) {
        std.debug.print("✅ Signature is VALID!\n", .{});
    } else {
        std.debug.print("❌ Signature is INVALID!\n", .{});
    }
    std.debug.print("   ⏱️  Time: {d} ms\n", .{verify_time});
    std.debug.print("\n", .{});

    // Step 4: Test with wrong message (should fail)
    std.debug.print("Step 4: Testing with wrong message...\n", .{});
    std.debug.print("-" ** 70 ++ "\n", .{});

    const wrong_message = "This is a different message!";
    std.debug.print("Wrong Message: \"{s}\"\n", .{wrong_message});

    var wrong_hash: [20]u8 = undefined;
    hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(wrong_message);
    hasher.final(&full_hash);
    @memcpy(&wrong_hash, full_hash[0..20]);

    const is_invalid = try hash_sig.verify(allocator, &keypair.public_key, &wrong_hash, &signature);

    if (!is_invalid) {
        std.debug.print("✅ Correctly rejected invalid signature!\n", .{});
    } else {
        std.debug.print("❌ ERROR: Accepted invalid signature!\n", .{});
    }
    std.debug.print("\n", .{});

    // Summary
    std.debug.print("=" ** 70 ++ "\n", .{});
    std.debug.print("Performance Summary (lifetime 2^10)\n", .{});
    std.debug.print("=" ** 70 ++ "\n", .{});
    std.debug.print("  Key Generation: {d}.{d:0>3} seconds\n", .{
        @divFloor(key_gen_time, 1000),
        @mod(key_gen_time, 1000),
    });
    std.debug.print("  Signing:        {d} ms\n", .{sign_time});
    std.debug.print("  Verification:   {d} ms\n", .{verify_time});
    std.debug.print("\n", .{});

    std.debug.print("Key Characteristics:\n", .{});
    std.debug.print("  Total Signatures: {d}\n", .{keypair.secret_key.num_active_epochs});
    std.debug.print("  Public Key Size:  {d} bytes\n", .{pk_serialized.len});
    std.debug.print("  Tree Levels:      {d}\n", .{keypair.secret_key.tree.len});
    std.debug.print("  Field Elements:   4-byte KoalaBear field\n", .{});
    std.debug.print("\n", .{});

    std.debug.print("✅ All operations completed successfully!\n", .{});
    std.debug.print("=" ** 70 ++ "\n\n", .{});
}
