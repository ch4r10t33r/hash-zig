const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    log.print("=== Zig Poseidon2 Isolated Test ===\n", .{});
    log.print("SEED: {s}\n", .{seed_hex});

    // Parse seed
    const seed_bytes = try std.fmt.allocPrint(allocator, "{s}", .{seed_hex});
    defer allocator.free(seed_bytes);

    var seed_array: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = seed_bytes[i * 2 .. i * 2 + 2];
        seed_array[i] = std.fmt.parseInt(u8, hex_pair, 16) catch unreachable;
    }

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    log.print("\n=== Test Isolated Poseidon2 Hash Function ===\n", .{});

    // Test with the exact inputs that should produce 0x31461cb0
    const test_message = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
    };

    const test_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x43438199 },
        hash_zig.FieldElement{ .value = 0x6e1ec07a },
        hash_zig.FieldElement{ .value = 0x76ddd3e4 },
        hash_zig.FieldElement{ .value = 0x6fb9732d },
        hash_zig.FieldElement{ .value = 0x4da34f48 },
    };

    log.print("Test message (2 elements):\n", .{});
    for (test_message, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("Test parameter (5 elements):\n", .{});
    for (test_parameter, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test the tree hash function with level 5, position 0
    const level: u8 = 5;
    const pos: u32 = 0;

    log.print("\nLevel: {}, Position: {}\n", .{ level, pos });

    // Test the hash operation
    const hash_result = try scheme.applyPoseidonTreeTweakHash(test_message[0..], level, pos, test_parameter);
    defer allocator.free(hash_result);

    log.print("\nTree hash result:\n", .{});
    for (hash_result, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("\nExpected result: 0x31461cb0\n", .{});
    log.print("Actual result: 0x{x}\n", .{hash_result[0].value});
    log.print("Match: {}\n", .{hash_result[0].value == 0x31461cb0});

    // Test with the exact inputs that should produce 0x646a2743 (from our previous test)
    log.print("\n=== Test with 16-element input ===\n", .{});

    const test_message_16 = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
        hash_zig.FieldElement{ .value = 0x7e118cb3 },
        hash_zig.FieldElement{ .value = 0x6aeeecb5 },
        hash_zig.FieldElement{ .value = 0x4ea08a17 },
        hash_zig.FieldElement{ .value = 0x2c138707 },
        hash_zig.FieldElement{ .value = 0x65d14fc6 },
        hash_zig.FieldElement{ .value = 0x2c5e70b5 },
        hash_zig.FieldElement{ .value = 0x30ff8f32 },
        hash_zig.FieldElement{ .value = 0x59e166e4 },
        hash_zig.FieldElement{ .value = 0x7e8fc675 },
        hash_zig.FieldElement{ .value = 0x60080f45 },
        hash_zig.FieldElement{ .value = 0x5bbb59d8 },
        hash_zig.FieldElement{ .value = 0x5d5742ec },
        hash_zig.FieldElement{ .value = 0x1e0d8135 },
        hash_zig.FieldElement{ .value = 0x4915976b },
    };

    const hash_result_16 = try scheme.applyPoseidonTreeTweakHash(test_message_16[0..], level, pos, test_parameter);
    defer allocator.free(hash_result_16);

    log.print("16-element hash result:\n", .{});
    for (hash_result_16, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("\nExpected result: 0x646a2743\n", .{});
    log.print("Actual result: 0x{x}\n", .{hash_result_16[0].value});
    log.print("Match: {}\n", .{hash_result_16[0].value == 0x646a2743});

    // Test if the issue is in the input preparation
    log.print("\n=== Input Preparation Analysis ===\n", .{});
    log.print("The issue might be in how the input is prepared for Poseidon2.\n", .{});
    log.print("Let's check if the tweak computation is correct.\n", .{});

    // Compute tweak manually
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]u32{
        @as(u32, @intCast(tweak_bigint % p)),
        @as(u32, @intCast((tweak_bigint / p) % p)),
    };

    log.print("Tweak bigint: 0x{x}\n", .{tweak_bigint});
    log.print("Tweak[0]: 0x{x} ({})\n", .{ tweak[0], tweak[0] });
    log.print("Tweak[1]: 0x{x} ({})\n", .{ tweak[1], tweak[1] });
}
