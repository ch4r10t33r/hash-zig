//! Cross-implementation compatibility test with Rust hash-sig
//!
//! This program generates keys and signatures using the field-native implementation
//! and outputs them in a format that can be compared with the Rust hash-sig library.
//!
//! Usage:
//!   zig build rust-compat-test
//!
//! To compare with Rust:
//!   1. Run this program and save the output
//!   2. Run the Rust keygen_bench with the same seed
//!   3. Compare the public key roots

const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("Zig hash-zig ↔ Rust hash-sig Cross-Implementation Compatibility Test\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Use the same parameters as Rust: lifetime 2^18 (262,144 signatures)
    const params = hash_zig.Parameters.init(.lifetime_2_18);

    std.debug.print("Configuration:\n", .{});
    std.debug.print("  Implementation: Zig hash-zig (field-native)\n", .{});
    std.debug.print("  Lifetime: 2^{d} = {d} signatures\n", .{ params.tree_height, @as(u64, 1) << @intCast(params.tree_height) });
    std.debug.print("  Hash Function: Poseidon2 (KoalaBear field)\n", .{});
    std.debug.print("  Winternitz W: {d}\n", .{params.winternitz_w});
    std.debug.print("  Chains: {d} ({d} message + {d} checksum)\n", .{
        params.num_chains,
        params.num_message_chains,
        params.num_checksum_chains,
    });
    std.debug.print("  Chain Length: {d}\n", .{@as(u32, 1) << @intCast(params.winternitz_w)});
    std.debug.print("  Build mode: ReleaseFast (optimized for speed)\n", .{});
    std.debug.print("\n", .{});

    // Use the same seed as Rust default: 0x42 repeated 32 times
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    std.debug.print("Seed (32 bytes): ", .{});
    for (seed) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    const num_leaves = @as(u64, 1) << @intCast(params.tree_height);
    std.debug.print("Total leaves to generate: {d}\n", .{num_leaves});
    std.debug.print("⏰ Expected time: ~1-2 hours (building full 2^{d} tree)\n\n", .{params.tree_height});

    // Initialize signature scheme
    var hash_sig = try hash_zig.HashSignatureNative.init(allocator, params);
    defer hash_sig.deinit();

    // ====================================================================
    // Step 1: Key Generation
    // ====================================================================
    std.debug.print("Step 1: Generating keypair...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const num_active_epochs = @as(u64, 1) << @intCast(params.tree_height);

    const key_gen_start = std.time.milliTimestamp();
    var keypair = try hash_sig.generateKeyPair(
        allocator,
        &seed,
        0, // activation_epoch
        num_active_epochs, // num_active_epochs (full lifetime 2^18 = 262,144)
    );
    defer keypair.deinit(allocator);
    const key_gen_end = std.time.milliTimestamp();
    const key_gen_time = key_gen_end - key_gen_start;

    std.debug.print("✅ Keypair generated in {d}.{d:0>3} seconds\n\n", .{
        @divFloor(key_gen_time, 1000),
        @mod(key_gen_time, 1000),
    });

    // ====================================================================
    // Output Public Key Information
    // ====================================================================
    std.debug.print("PUBLIC KEY (Zig field-native):\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const root = keypair.public_key.root;
    std.debug.print("  Root (field element): {d}\n", .{root.value});

    // Convert root to bytes (4 bytes for KoalaBear)
    const root_bytes = root.toBytes();
    std.debug.print("  Root (4 bytes hex):   ", .{});
    for (root_bytes) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Hash the root with SHA3-256 for comparison
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(&root_bytes);
    var root_hash: [32]u8 = undefined;
    hasher.final(&root_hash);

    std.debug.print("  Root SHA3-256 hash:   ", .{});
    for (root_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Serialize full public key
    const pk_serialized = try keypair.public_key.serialize(allocator);
    defer allocator.free(pk_serialized);

    std.debug.print("  Serialized size:      {d} bytes\n", .{pk_serialized.len});
    std.debug.print("  Serialized (hex):     ", .{});
    for (pk_serialized) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // ====================================================================
    // Step 2: Sign a test message
    // ====================================================================
    std.debug.print("Step 2: Signing test message...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const test_message = "Hello, Rust! This is Zig speaking.";
    std.debug.print("Message: \"{s}\"\n", .{test_message});

    // Hash message to 20 bytes
    var message_hash: [20]u8 = undefined;
    hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(test_message);
    var full_hash: [32]u8 = undefined;
    hasher.final(&full_hash);
    @memcpy(&message_hash, full_hash[0..20]);

    std.debug.print("Message hash (20 bytes): ", .{});
    for (message_hash) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    const epoch: u64 = 0;
    std.debug.print("Epoch: {d}\n", .{epoch});

    const sign_start = std.time.milliTimestamp();
    var signature = try hash_sig.sign(allocator, &keypair.secret_key, &message_hash, epoch);
    defer signature.deinit(allocator);
    const sign_end = std.time.milliTimestamp();
    const sign_time = sign_end - sign_start;

    std.debug.print("✅ Signature generated in {d} ms\n", .{sign_time});
    std.debug.print("   OTS signature parts: {d}\n", .{signature.hashes.len});
    std.debug.print("   Auth path length: {d}\n", .{signature.auth_path.len});
    std.debug.print("\n", .{});

    // Output first signature part (for debugging)
    std.debug.print("SIGNATURE (first OTS part, first 4 field elements):\n", .{});
    if (signature.hashes.len > 0 and signature.hashes[0].len >= 4) {
        for (signature.hashes[0][0..4], 0..) |elem, i| {
            std.debug.print("  [{d}]: {d} (0x{x:0>8})\n", .{ i, elem.value, elem.value });
        }
    }
    std.debug.print("\n", .{});

    // ====================================================================
    // Step 3: Verify signature
    // ====================================================================
    std.debug.print("Step 3: Verifying signature...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const verify_start = std.time.milliTimestamp();
    const is_valid = try hash_sig.verify(allocator, &keypair.public_key, &message_hash, &signature);
    const verify_end = std.time.milliTimestamp();
    const verify_time = verify_end - verify_start;

    if (is_valid) {
        std.debug.print("✅ Signature is VALID\n", .{});
    } else {
        std.debug.print("❌ Signature is INVALID\n", .{});
    }
    std.debug.print("   Verification time: {d} ms\n\n", .{verify_time});

    // ====================================================================
    // Step 4: Output JSON for automated comparison
    // ====================================================================
    std.debug.print("JSON OUTPUT (for automated comparison):\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    // Create JSON output
    var json_buffer = std.ArrayList(u8).init(allocator);
    defer json_buffer.deinit();
    var json_writer = json_buffer.writer();

    try json_writer.writeAll("{\n");
    try json_writer.writeAll("  \"implementation\": \"zig-hash-zig-field-native\",\n");
    try json_writer.print("  \"lifetime\": {d},\n", .{@as(u64, 1) << @intCast(params.tree_height)});
    try json_writer.print("  \"tree_height\": {d},\n", .{params.tree_height});
    try json_writer.writeAll("  \"hash_function\": \"Poseidon2KoalaBear\",\n");
    try json_writer.print("  \"winternitz_w\": {d},\n", .{params.winternitz_w});
    try json_writer.print("  \"num_chains\": {d},\n", .{params.num_chains});
    try json_writer.writeAll("  \"seed_hex\": \"");
    for (seed) |byte| {
        try json_writer.print("{x:0>2}", .{byte});
    }
    try json_writer.writeAll("\",\n");
    try json_writer.print("  \"root_field_element\": {d},\n", .{root.value});
    try json_writer.writeAll("  \"root_hex\": \"");
    for (root_bytes) |byte| {
        try json_writer.print("{x:0>2}", .{byte});
    }
    try json_writer.writeAll("\",\n");
    try json_writer.writeAll("  \"root_sha3_256\": \"");
    for (root_hash) |byte| {
        try json_writer.print("{x:0>2}", .{byte});
    }
    try json_writer.writeAll("\",\n");
    try json_writer.print("  \"keygen_time_ms\": {d},\n", .{key_gen_time});
    try json_writer.print("  \"sign_time_ms\": {d},\n", .{sign_time});
    try json_writer.print("  \"verify_time_ms\": {d},\n", .{verify_time});
    try json_writer.print("  \"signature_valid\": {any}\n", .{is_valid});
    try json_writer.writeAll("}\n");

    std.debug.print("{s}\n", .{json_buffer.items});

    // ====================================================================
    // Summary
    // ====================================================================
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("Summary:\n", .{});
    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("✅ Key generation: {d}.{d:0>3}s\n", .{
        @divFloor(key_gen_time, 1000),
        @mod(key_gen_time, 1000),
    });
    std.debug.print("✅ Signing: {d}ms\n", .{sign_time});
    std.debug.print("✅ Verification: {d}ms ({s})\n", .{ verify_time, if (is_valid) "VALID" else "INVALID" });
    std.debug.print("\n", .{});
    std.debug.print("To compare with Rust:\n", .{});
    std.debug.print("1. Run this program: zig build rust-compat-test > zig_output.txt\n", .{});
    std.debug.print("2. Run Rust benchmark with same seed:\n", .{});
    std.debug.print("   cd ../hash-sig-benchmarks/rust_benchmark\n", .{});
    std.debug.print("   cargo run --release > rust_output.txt\n", .{});
    std.debug.print("3. Compare the 'root_sha3_256' hashes\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
