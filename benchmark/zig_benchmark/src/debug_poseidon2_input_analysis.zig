const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Poseidon2 Input Analysis ===\n", .{});
    std.debug.print("SEED: {s}\n", .{seed_hex});

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

    std.debug.print("\n=== Analyze Poseidon2 Input Preparation ===\n", .{});

    // Test with the exact inputs from the debug output
    const left_child = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
        hash_zig.FieldElement{ .value = 0x7e118cb3 },
        hash_zig.FieldElement{ .value = 0x6aeeecb5 },
        hash_zig.FieldElement{ .value = 0x4ea08a17 },
        hash_zig.FieldElement{ .value = 0x2c138707 },
        hash_zig.FieldElement{ .value = 0x65d14fc6 },
        hash_zig.FieldElement{ .value = 0x2c5e70b5 },
    };

    const right_child = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x30ff8f32 },
        hash_zig.FieldElement{ .value = 0x59e166e4 },
        hash_zig.FieldElement{ .value = 0x7e8fc675 },
        hash_zig.FieldElement{ .value = 0x60080f45 },
        hash_zig.FieldElement{ .value = 0x5bbb59d8 },
        hash_zig.FieldElement{ .value = 0x5d5742ec },
        hash_zig.FieldElement{ .value = 0x1e0d8135 },
        hash_zig.FieldElement{ .value = 0x4915976b },
    };

    const test_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 1128497561 },
        hash_zig.FieldElement{ .value = 1847509114 },
        hash_zig.FieldElement{ .value = 1994249188 },
        hash_zig.FieldElement{ .value = 1874424621 },
        hash_zig.FieldElement{ .value = 1302548296 },
    };

    std.debug.print("Left child values:\n", .{});
    for (left_child, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("Right child values:\n", .{});
    for (right_child, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("Parameter values:\n", .{});
    for (test_parameter, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Concatenate left and right children
    var combined_children = try allocator.alloc(hash_zig.FieldElement, left_child.len + right_child.len);
    defer allocator.free(combined_children);
    @memcpy(combined_children[0..left_child.len], left_child[0..]);
    @memcpy(combined_children[left_child.len..], right_child[0..]);

    std.debug.print("\nCombined children (16 elements):\n", .{});
    for (combined_children, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test tweak computation
    const level: u8 = 5;
    const pos_in_level: u32 = 0;
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos_in_level) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = @as(u32, @intCast(tweak_bigint % p)) },
        hash_zig.FieldElement{ .value = @as(u32, @intCast((tweak_bigint / p) % p)) },
    };

    std.debug.print("\nTweak computation:\n", .{});
    std.debug.print("  Level: {}, Pos: {}\n", .{ level, pos_in_level });
    std.debug.print("  Tweak bigint: 0x{x}\n", .{tweak_bigint});
    std.debug.print("  Tweak[0]: 0x{x} ({})\n", .{ tweak[0].value, tweak[0].value });
    std.debug.print("  Tweak[1]: 0x{x} ({})\n", .{ tweak[1].value, tweak[1].value });

    // Show the complete input that will be passed to Poseidon2
    std.debug.print("\nComplete Poseidon2 input (parameter + tweak + message):\n", .{});
    std.debug.print("Parameter (5 elements):\n", .{});
    for (test_parameter, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, val.value });
    }
    std.debug.print("Tweak (2 elements):\n", .{});
    for (tweak, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, val.value });
    }
    std.debug.print("Message (16 elements):\n", .{});
    for (combined_children, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, val.value });
    }

    // Test the hash function
    const hash_result = try scheme.applyPoseidonTreeTweakHash(combined_children, level, pos_in_level, test_parameter);
    defer allocator.free(hash_result);

    std.debug.print("\nPoseidon2 hash result:\n", .{});
    for (hash_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("\nExpected result: 0x31461cb0\n", .{});
    std.debug.print("Actual result: 0x{x}\n", .{hash_result[0].value});
    std.debug.print("Match: {}\n", .{hash_result[0].value == 0x31461cb0});
}
