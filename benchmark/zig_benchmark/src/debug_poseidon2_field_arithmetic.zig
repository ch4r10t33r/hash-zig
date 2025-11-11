const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    log.print("=== Zig Poseidon2 Field Arithmetic Test ===\n", .{});
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

    log.print("\n=== Test Field Arithmetic Operations ===\n", .{});

    // Test basic field operations
    const field1 = hash_zig.FieldElement{ .value = 0x1640cb16 };
    const field2 = hash_zig.FieldElement{ .value = 0x54503ce2 };

    log.print("Field1: 0x{x} ({})\n", .{ field1.value, field1.value });
    log.print("Field2: 0x{x} ({})\n", .{ field2.value, field2.value });

    // Test if the issue is in the field arithmetic itself
    log.print("\n=== Test Simple Hash Operation ===\n", .{});

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

    log.print("Simple input (2 elements):\n", .{});
    for (simple_input, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    const simple_result = try scheme.applyPoseidonTreeTweakHash(simple_input[0..], 5, // level
        0, // position
        simple_parameter);
    defer allocator.free(simple_result);

    log.print("Simple hash result:\n", .{});
    for (simple_result, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test if the issue is in the input size
    log.print("\n=== Test Different Input Sizes ===\n", .{});

    // Test with 1 element
    const single_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
    };

    const single_result = try scheme.applyPoseidonTreeTweakHash(single_input[0..], 5, // level
        0, // position
        simple_parameter);
    defer allocator.free(single_result);

    log.print("Single element result:\n", .{});
    for (single_result, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
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

    log.print("Triple element result:\n", .{});
    for (triple_result, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("\n=== Analysis ===\n", .{});
    log.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    log.print("Even simple inputs produce different results than expected.\n", .{});
    log.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
}
