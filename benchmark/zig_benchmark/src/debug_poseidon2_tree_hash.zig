const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Poseidon2 Tree Hash Analysis ===\n", .{});
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

    std.debug.print("\n=== Test Poseidon2 Tree Hash Directly ===\n", .{});

    // Test the exact tree hash function with known inputs
    const test_input = [_]hash_zig.FieldElement{
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

    const test_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 1128497561 },
        hash_zig.FieldElement{ .value = 1847509114 },
        hash_zig.FieldElement{ .value = 1994249188 },
        hash_zig.FieldElement{ .value = 1874424621 },
        hash_zig.FieldElement{ .value = 1302548296 },
    };

    // Test tree hash for level 5, position 0
    const hash_result = try scheme.applyPoseidonTreeTweakHash(test_input[0..2], // First two elements
        5, // level
        0, // position
        test_parameter);
    defer allocator.free(hash_result);

    std.debug.print("Tree hash result for level 5, pos 0:\n", .{});
    for (hash_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

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

    // Concatenate left and right children
    var combined_children = try allocator.alloc(hash_zig.FieldElement, left_child.len + right_child.len);
    defer allocator.free(combined_children);
    @memcpy(combined_children[0..left_child.len], left_child[0..]);
    @memcpy(combined_children[left_child.len..], right_child[0..]);

    const hash_result2 = try scheme.applyPoseidonTreeTweakHash(combined_children, 5, // level
        0, // position
        test_parameter);
    defer allocator.free(hash_result2);

    std.debug.print("\nTree hash result for concatenated children:\n", .{});
    for (hash_result2, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("\nExpected result from debug output: 0x31461cb0\n", .{});
    std.debug.print("Actual result: 0x{x}\n", .{hash_result2[0].value});
    std.debug.print("Match: {}\n", .{hash_result2[0].value == 0x31461cb0});
}
