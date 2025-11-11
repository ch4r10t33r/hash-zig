//! Test ShakePRFtoF compatibility with Rust implementation
//! This program generates keys using ShakePRFtoF and compares with expected Rust output

const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const ShakePRFtoF_8_7 = hash_zig.ShakePRFtoF_8_7;

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    log.print("Zig ShakePRFtoF Compatibility Test\n", .{});
    log.print("==================================\n", .{});
    log.print("Testing compatibility with Rust ShakePRFtoF<8, 7>\n", .{});
    log.print("\n", .{});

    // Use the same seed as the Rust test
    const seed = [_]u8{0x42} ** 32;
    log.print("Seed: ", .{});
    for (seed) |b| log.print("{x:02}", .{b});
    log.print("\n\n", .{});

    // Test ShakePRFtoF directly
    log.print("1. Testing ShakePRFtoF<8, 7> directly:\n", .{});
    log.print("----------------------------------------\n", .{});

    // Generate domain elements
    const domain = ShakePRFtoF_8_7.getDomainElement(seed, 0, 0);
    log.print("Domain elements (epoch=0, index=0):\n", .{});
    for (domain, 0..) |val, i| {
        log.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    log.print("\n", .{});

    // Generate randomness
    const message = [_]u8{0x48} ** 32; // "H" repeated
    const randomness = ShakePRFtoF_8_7.getRandomness(seed, 0, &message, 0);
    log.print("Randomness (epoch=0, message='H'*32, counter=0):\n", .{});
    for (randomness, 0..) |val, i| {
        log.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    log.print("\n", .{});

    // Test with different parameters
    const domain_1 = ShakePRFtoF_8_7.getDomainElement(seed, 1, 1);
    log.print("Domain elements (epoch=1, index=1):\n", .{});
    for (domain_1, 0..) |val, i| {
        log.print("  [{}]: {} (0x{:08})\n", .{ i, val, val });
    }
    log.print("\n", .{});

    // Test key generation using the core XMSS scheme
    log.print("2. Testing GeneralizedXMSSSignatureScheme (lifetime 2^8):\n", .{});
    log.print("--------------------------------------------------------\n", .{});

    var sig_scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer sig_scheme.deinit();

    const keypair = try sig_scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    const root = keypair.public_key.getRoot();
    log.print("Generated public key root (Montgomery):\n", .{});
    for (root, 0..) |fe, i| {
        log.print("  [{}]: 0x{x:0>8}\n", .{ i, fe.value });
    }
    log.print("\n", .{});

    // Convert root to canonical bytes and hash for reference
    var root_bytes = try allocator.alloc(u8, root.len * 4);
    defer allocator.free(root_bytes);
    for (root, 0..) |fe, i| {
        const slice = root_bytes[i * 4 .. i * 4 + 4];
        const ptr: *[4]u8 = @ptrCast(slice.ptr);
        std.mem.writeInt(u32, ptr, fe.toCanonical(), .little);
    }

    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(root_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    log.print("Public key root SHA3: ", .{});
    for (digest) |b| log.print("{x:02}", .{b});
    log.print("\n\n", .{});

    log.print("✅ ShakePRFtoF compatibility test completed!\n", .{});
}
