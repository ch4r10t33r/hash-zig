const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Poseidon2 Field Arithmetic Test ===\n", .{});
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

    std.debug.print("\n=== Test Field Arithmetic Operations ===\n", .{});

    // Test basic field operations
    const field1 = hash_zig.FieldElement{ .value = 0x1640cb16 };
    const field2 = hash_zig.FieldElement{ .value = 0x54503ce2 };

    std.debug.print("Field1: 0x{x} ({})\n", .{ field1.value, field1.value });
    std.debug.print("Field2: 0x{x} ({})\n", .{ field2.value, field2.value });

    // Test if the issue is in the field arithmetic itself
    std.debug.print("\n=== Test Simple Hash Operation ===\n", .{});

    // Test with a very simple input
    const simple_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 1 },
        hash_zig.FieldElement{ .value = 2 },
    };

    const simple_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x43438199 },
        hash_zig.FieldElement{ .value = 0x6e1ec07a },
        hash_zig.FieldElement{ .value = 0x76ddd3e4 },
        hash_zig.FieldElement{ .value = 0x6fb9732d },
        hash_zig.FieldElement{ .value = 0x4da34f48 },
    };

    std.debug.print("Simple input (2 elements):\n", .{});
    for (simple_input, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    const simple_result = try scheme.applyPoseidonTreeTweakHash(simple_input[0..], 5, // level
        0, // position
        simple_parameter);
    defer allocator.free(simple_result);

    std.debug.print("Simple hash result:\n", .{});
    for (simple_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test if the issue is in the input size
    std.debug.print("\n=== Test Different Input Sizes ===\n", .{});

    // Test with 1 element
    const single_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
    };

    const single_result = try scheme.applyPoseidonTreeTweakHash(single_input[0..], 5, // level
        0, // position
        simple_parameter);
    defer allocator.free(single_result);

    std.debug.print("Single element result:\n", .{});
    for (single_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test with 3 elements
    const triple_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
        hash_zig.FieldElement{ .value = 0x7e118cb3 },
    };

    const triple_result = try scheme.applyPoseidonTreeTweakHash(triple_input[0..], 5, // level
        0, // position
        simple_parameter);
    defer allocator.free(triple_result);

    std.debug.print("Triple element result:\n", .{});
    for (triple_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("\n=== Analysis ===\n", .{});
    std.debug.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    std.debug.print("Even simple inputs produce different results than expected.\n", .{});
    std.debug.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
}
