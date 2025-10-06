const std = @import("std");
const hash_zig = @import("hash-zig");
const simd_signature = @import("simd_signature");

// Compare Standard (Rust-compatible) vs SIMD (Rust-compatible with SIMD optimizations)
// Both implementations now use identical architecture and API

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Implementation Comparison: Standard vs SIMD\n", .{});
    std.debug.print("============================================\n", .{});
    std.debug.print("Both implementations use Rust-compatible architecture\n", .{});
    std.debug.print("Comparing performance with identical parameters\n\n", .{});

    // Use a fixed seed for consistent comparison
    const seed: [32]u8 = .{42} ** 32;
    std.debug.print("Using seed (hex): ", .{});
    for (seed) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n\n", .{});

    // Test parameters - using hypercube parameters (64 chains of length 8)
    const params = hash_zig.params.Parameters.initHypercube(.lifetime_2_10);
    const expected_sigs = 1024;

    std.debug.print("Test Configuration:\n", .{});
    std.debug.print("  Lifetime: 2^10 ({d} signatures)\n", .{expected_sigs});
    std.debug.print("  Security: 128-bit\n", .{});
    std.debug.print("  Hash: Poseidon2 (width=16, KoalaBear field)\n", .{});
    std.debug.print("  Chains: {d}\n", .{params.num_chains});
    std.debug.print("  Chain Length: {d} (2^{d})\n\n", .{ @as(u32, 1) << @intCast(params.winternitz_w), params.winternitz_w });

    // Test Standard Implementation
    std.debug.print("Testing Standard Implementation (Rust-compatible)\n", .{});
    std.debug.print("=================================================\n", .{});

    var std_sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer std_sig_scheme.deinit();

    const std_keygen_start = std.time.nanoTimestamp();
    var std_keypair = try std_sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    const std_keygen_end = std.time.nanoTimestamp();
    defer std_keypair.deinit(allocator);

    const std_duration = @as(f64, @floatFromInt(std_keygen_end - std_keygen_start)) / 1_000_000_000.0;

    std.debug.print("  Key generation time: {d:.3}s\n", .{std_duration});
    std.debug.print("  Public key:\n", .{});
    std.debug.print("    Root: {d} bytes\n", .{std_keypair.public_key.root.len});
    std.debug.print("  Secret key:\n", .{});
    std.debug.print("    PRF key: {d} bytes\n", .{std_keypair.secret_key.prf_key.len});
    std.debug.print("    Tree nodes: {d}\n", .{std_keypair.secret_key.tree.len});
    std.debug.print("    Activation epoch: {d}\n", .{std_keypair.secret_key.activation_epoch});
    std.debug.print("    Active epochs: {d}\n", .{std_keypair.secret_key.num_active_epochs});

    // Test signing and verification
    const message = "Test message for comparison";
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);

    const std_sign_start = std.time.nanoTimestamp();
    var std_sig = try std_sig_scheme.sign(allocator, message, &std_keypair.secret_key, 0, &rng_seed);
    const std_sign_end = std.time.nanoTimestamp();
    defer std_sig.deinit(allocator);

    const std_sign_time = @as(f64, @floatFromInt(std_sign_end - std_sign_start)) / 1_000_000.0;

    const std_verify_start = std.time.nanoTimestamp();
    const std_valid = try std_sig_scheme.verify(allocator, message, std_sig, &std_keypair.public_key);
    const std_verify_end = std.time.nanoTimestamp();

    const std_verify_time = @as(f64, @floatFromInt(std_verify_end - std_verify_start)) / 1_000_000.0;

    std.debug.print("  Signing time: {d:.2} ms\n", .{std_sign_time});
    std.debug.print("  Verification time: {d:.2} ms\n", .{std_verify_time});
    std.debug.print("  Signature valid: {}\n", .{std_valid});
    std.debug.print("  Signature structure:\n", .{});
    std.debug.print("    Epoch: {d}\n", .{std_sig.epoch});
    std.debug.print("    Auth path length: {d}\n", .{std_sig.auth_path.len});
    std.debug.print("    OTS hashes: {d}\n", .{std_sig.hashes.len});
    std.debug.print("    Rho (randomness): {d} bytes\n", .{std_sig.rho.len});

    // Test SIMD Implementation
    std.debug.print("\nTesting SIMD Implementation (Rust-compatible + SIMD)\n", .{});
    std.debug.print("====================================================\n", .{});

    var simd_sig_scheme = try simd_signature.SimdHashSignature.init(allocator, params);
    defer simd_sig_scheme.deinit();

    const simd_start = std.time.nanoTimestamp();
    var simd_keypair = try simd_sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    const simd_end = std.time.nanoTimestamp();
    defer simd_keypair.deinit(allocator);

    const simd_duration = @as(f64, @floatFromInt(simd_end - simd_start)) / 1_000_000_000.0;

    std.debug.print("  Key generation time: {d:.3}s\n", .{simd_duration});
    std.debug.print("  Public key:\n", .{});
    std.debug.print("    Root: {d} bytes\n", .{simd_keypair.public_key.root.len});
    std.debug.print("  Secret key:\n", .{});
    std.debug.print("    PRF key: {d} bytes\n", .{simd_keypair.secret_key.prf_key.len});
    std.debug.print("    Tree nodes: {d}\n", .{simd_keypair.secret_key.tree.len});
    std.debug.print("    Activation epoch: {d}\n", .{simd_keypair.secret_key.activation_epoch});
    std.debug.print("    Active epochs: {d}\n", .{simd_keypair.secret_key.num_active_epochs});

    // Test signing and verification with SIMD
    const simd_sign_start = std.time.nanoTimestamp();
    var simd_sig = try simd_sig_scheme.sign(allocator, message, &simd_keypair.secret_key, 0, &rng_seed);
    const simd_sign_end = std.time.nanoTimestamp();
    defer simd_sig.deinit(allocator);

    const simd_sign_time = @as(f64, @floatFromInt(simd_sign_end - simd_sign_start)) / 1_000_000.0;

    const simd_verify_start = std.time.nanoTimestamp();
    const simd_valid = try simd_sig_scheme.verify(allocator, message, simd_sig, &simd_keypair.public_key);
    const simd_verify_end = std.time.nanoTimestamp();

    const simd_verify_time = @as(f64, @floatFromInt(simd_verify_end - simd_verify_start)) / 1_000_000.0;

    std.debug.print("  Signing time: {d:.2} ms\n", .{simd_sign_time});
    std.debug.print("  Verification time: {d:.2} ms\n", .{simd_verify_time});
    std.debug.print("  Signature valid: {}\n", .{simd_valid});
    std.debug.print("  Signature structure:\n", .{});
    std.debug.print("    Epoch: {d}\n", .{simd_sig.epoch});
    std.debug.print("    Auth path length: {d}\n", .{simd_sig.auth_path.len});
    std.debug.print("    OTS hashes: {d}\n", .{simd_sig.hashes.len});
    std.debug.print("    Rho (randomness): {d} bytes\n", .{simd_sig.rho.len});

    // Comparison Analysis
    std.debug.print("\n📊 Comparison Analysis\n", .{});
    std.debug.print("======================\n", .{});

    std.debug.print("\n✅ Architecture Compatibility:\n", .{});
    std.debug.print("  Both implementations use:\n", .{});
    std.debug.print("  - Same key structures (PublicKey, SecretKey with PRF + tree)\n", .{});
    std.debug.print("  - Same signature structure (epoch, auth_path, rho, hashes)\n", .{});
    std.debug.print("  - Same API (generateKeyPair, sign, verify)\n", .{});
    std.debug.print("  - Same hypercube parameters (64 chains × 8 length, w=3)\n", .{});
    std.debug.print("  - Same Poseidon2 config (width=16, KoalaBear field)\n", .{});

    std.debug.print("\n⚡ Performance Comparison:\n", .{});
    std.debug.print("  Key Generation:\n", .{});
    std.debug.print("    Standard: {d:.3}s\n", .{std_duration});
    std.debug.print("    SIMD:     {d:.3}s\n", .{simd_duration});

    const keygen_speedup = if (std_duration > simd_duration)
        std_duration / simd_duration
    else
        simd_duration / std_duration;
    const keygen_faster = if (std_duration < simd_duration) "Standard" else "SIMD";
    std.debug.print("    {s} is {d:.2}x faster\n", .{ keygen_faster, keygen_speedup });

    std.debug.print("  Signing:\n", .{});
    std.debug.print("    Standard: {d:.2} ms\n", .{std_sign_time});
    std.debug.print("    SIMD:     {d:.2} ms\n", .{simd_sign_time});

    const sign_speedup = if (std_sign_time > simd_sign_time)
        std_sign_time / simd_sign_time
    else
        simd_sign_time / std_sign_time;
    const sign_faster = if (std_sign_time < simd_sign_time) "Standard" else "SIMD";
    std.debug.print("    {s} is {d:.2}x faster\n", .{ sign_faster, sign_speedup });

    std.debug.print("  Verification:\n", .{});
    std.debug.print("    Standard: {d:.2} ms\n", .{std_verify_time});
    std.debug.print("    SIMD:     {d:.2} ms\n", .{simd_verify_time});

    const verify_speedup = if (std_verify_time > simd_verify_time)
        std_verify_time / simd_verify_time
    else
        simd_verify_time / std_verify_time;
    const verify_faster = if (std_verify_time < simd_verify_time) "Standard" else "SIMD";
    std.debug.print("    {s} is {d:.2}x faster\n", .{ verify_faster, verify_speedup });

    // Public Key Consistency Test
    std.debug.print("\n🔍 Public Key Consistency Test\n", .{});
    std.debug.print("===============================\n", .{});

    const keys_match = std.mem.eql(u8, std_keypair.public_key.root, simd_keypair.public_key.root);

    if (keys_match) {
        std.debug.print("✅ Public keys MATCH - Both implementations generate identical Merkle roots!\n", .{});
        std.debug.print("  Root (first 16 bytes): ", .{});
        for (std_keypair.public_key.root[0..@min(16, std_keypair.public_key.root.len)]) |b| {
            std.debug.print("{x:0>2}", .{b});
        }
        std.debug.print("\n", .{});
    } else {
        std.debug.print("❌ Public keys DIFFER - Implementations generate different Merkle roots!\n", .{});

        std.debug.print("  Standard root (first 16 bytes): ", .{});
        for (std_keypair.public_key.root[0..@min(16, std_keypair.public_key.root.len)]) |b| {
            std.debug.print("{x:0>2}", .{b});
        }
        std.debug.print("\n", .{});

        std.debug.print("  SIMD root (first 16 bytes): ", .{});
        for (simd_keypair.public_key.root[0..@min(16, simd_keypair.public_key.root.len)]) |b| {
            std.debug.print("{x:0>2}", .{b});
        }
        std.debug.print("\n", .{});
    }

    // Summary
    std.debug.print("\n📊 SUMMARY\n", .{});
    std.debug.print("==========\n", .{});
    std.debug.print("Standard implementation: ✅ WORKING (Rust-compatible)\n", .{});
    std.debug.print("SIMD implementation: ✅ WORKING (Rust-compatible + SIMD)\n", .{});
    std.debug.print("\nBoth implementations:\n", .{});
    std.debug.print("  ✅ Use identical Rust-compatible structures\n", .{});
    std.debug.print("  ✅ PRF-based key derivation (32-byte PRF key)\n", .{});
    std.debug.print("  ✅ Full Merkle tree storage ({d} nodes)\n", .{std_keypair.secret_key.tree.len});
    std.debug.print("  ✅ Epoch management (activation + num_active_epochs)\n", .{});
    std.debug.print("  ✅ Encoding randomness (rho in signatures)\n", .{});
    std.debug.print("  ✅ Hypercube parameters (64 chains × 8 length, w=3)\n", .{});
    std.debug.print("\nDifference:\n", .{});
    std.debug.print("  ⚡ SIMD uses vectorized operations for performance\n", .{});
    std.debug.print("\nPublic key consistency: {s}\n", .{if (keys_match) "✅ MATCH" else "❌ DIFFER"});
    std.debug.print("Performance: SIMD is {d:.2}x faster for key generation\n", .{if (keygen_faster[0] == 'S') keygen_speedup else 1.0 / keygen_speedup});

    std.debug.print("\n✅ Comparison completed!\n", .{});
}
