//! Test ShakePRFtoF compatibility with Rust implementation
//! This program generates keys using ShakePRFtoF and compares with expected Rust output

const std = @import("std");
const hash_zig = @import("hash-zig");
const ShakePRFtoF_8_7 = @import("../src/prf/shake_prf_to_field.zig").ShakePRFtoF_8_7;

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig ShakePRFtoF Compatibility Test\n", .{});
    std.debug.print("==================================\n", .{});
    std.debug.print("Testing compatibility with Rust ShakePRFtoF<8, 7>\n", .{});
    std.debug.print("\n", .{});

    // Use the same seed as the Rust test
    const seed = [_]u8{0x42} ** 32;
    std.debug.print("Seed: ", .{});
    for (seed) |b| std.debug.print("{x:02}", .{b});
    std.debug.print("\n\n", .{});

    // Test ShakePRFtoF directly
    std.debug.print("1. Testing ShakePRFtoF<8, 7> directly:\n", .{});
    std.debug.print("----------------------------------------\n", .{});

    // Generate domain elements
    const domain = ShakePRFtoF_8_7.getDomainElement(seed, 0, 0);
    std.debug.print("Domain elements (epoch=0, index=0):\n", .{});
    for (domain, 0..) |val, i| {
        std.debug.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    std.debug.print("\n", .{});

    // Generate randomness
    const message = [_]u8{0x48} ** 32; // "H" repeated
    const randomness = ShakePRFtoF_8_7.getRandomness(seed, 0, &message, 0);
    std.debug.print("Randomness (epoch=0, message='H'*32, counter=0):\n", .{});
    for (randomness, 0..) |val, i| {
        std.debug.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    std.debug.print("\n", .{});

    // Test with different parameters
    const domain_1 = ShakePRFtoF_8_7.getDomainElement(seed, 1, 1);
    std.debug.print("Domain elements (epoch=1, index=1):\n", .{});
    for (domain_1, 0..) |val, i| {
        std.debug.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    std.debug.print("\n", .{});

    // Test key generation
    std.debug.print("2. Testing HashSignatureShakeCompat:\n", .{});
    std.debug.print("-------------------------------------\n", .{});

    var sig_scheme = try hash_zig.HashSignatureShakeCompat.init(allocator, .lifetime_2_8);
    defer sig_scheme.deinit();

    const keypair = try sig_scheme.keyGen(&seed);
    defer allocator.free(keypair.public_key);
    defer allocator.free(keypair.private_key);

    std.debug.print("Generated keypair:\n", .{});
    std.debug.print("  Public key ({} elements):\n", .{keypair.public_key.len});
    for (keypair.public_key, 0..) |pk, i| {
        std.debug.print("    [{}]: {} (0x{:08})\n", .{ i, pk.value, pk.value });
    }

    std.debug.print("  Private key ({} elements):\n", .{keypair.private_key.len});
    for (keypair.private_key, 0..) |sk, i| {
        std.debug.print("    [{}]: {} (0x{:08})\n", .{ i, sk.value, sk.value });
    }
    std.debug.print("\n", .{});

    // Convert public key to bytes for comparison
    var public_key_bytes = try allocator.alloc(u8, keypair.public_key.len * 4);
    defer allocator.free(public_key_bytes);
    for (keypair.public_key, 0..) |pk, i| {
        const val = pk.value;
        var slice = public_key_bytes[i * 4 .. i * 4 + 4];
        std.mem.writeInt(u32, slice[0..4], val, .little);
    }

    // Hash the public key for comparison
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(public_key_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    std.debug.print("3. Results for comparison:\n", .{});
    std.debug.print("---------------------------\n", .{});
    std.debug.print("Public key size: {} bytes\n", .{public_key_bytes.len});
    std.debug.print("Public key hex: ", .{});
    for (public_key_bytes) |b| std.debug.print("{x:02}", .{b});
    std.debug.print("\n", .{});

    std.debug.print("Public key SHA3: ", .{});
    for (digest) |b| std.debug.print("{x:02}", .{b});
    std.debug.print("\n", .{});

    std.debug.print("\nExpected Rust output:\n", .{});
    std.debug.print("Public key SHA3: ecb752f1e7e8b29ed1629784cc64667d644ca9d553caede9413aa248eb7edf20\n", .{});

    std.debug.print("\nComparison:\n", .{});
    const expected_sha3 = "ecb752f1e7e8b29ed1629784cc64667d644ca9d553caede9413aa248eb7edf20";
    var expected_bytes: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = std.fmt.parseInt(u4, expected_sha3[i * 2 .. i * 2 + 1], 16) catch 0;
        const lo = std.fmt.parseInt(u4, expected_sha3[i * 2 + 1 .. i * 2 + 2], 16) catch 0;
        expected_bytes[i] = (@as(u8, hi) << 4) | @as(u8, lo);
    }

    const matches = std.mem.eql(u8, &digest, &expected_bytes);
    if (matches) {
        std.debug.print("✅ SUCCESS: SHA3 hashes match!\n", .{});
    } else {
        std.debug.print("❌ MISMATCH: SHA3 hashes differ\n", .{});
        std.debug.print("  Expected: ", .{});
        for (expected_bytes) |b| std.debug.print("{x:02}", .{b});
        std.debug.print("\n", .{});
        std.debug.print("  Got:      ", .{});
        for (digest) |b| std.debug.print("{x:02}", .{b});
        std.debug.print("\n", .{});
    }

    std.debug.print("\n✅ ShakePRFtoF compatibility test completed!\n", .{});
}
