const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Tweak Level Debug ===\n", .{});
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

    std.debug.print("\n=== Test Tweak Computation for Each Level ===\n", .{});

    // Test parameters
    const test_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x43438199 },
        hash_zig.FieldElement{ .value = 0x6e1ec07a },
        hash_zig.FieldElement{ .value = 0x76ddd3e4 },
        hash_zig.FieldElement{ .value = 0x6fb9732d },
        hash_zig.FieldElement{ .value = 0x4da34f48 },
    };

    // Test the exact tree building process step by step
    std.debug.print("\n=== Step-by-Step Tree Building ===\n", .{});

    // Layer 4 -> 5: First hash operation (should produce 0x31461cb0)
    const left_child_1 = hash_zig.FieldElement{ .value = 0x1640cb16 };
    const right_child_1 = hash_zig.FieldElement{ .value = 0x54503ce2 };
    const level_1: u8 = 5;
    const pos_1: u32 = 0;

    std.debug.print("Layer 4 -> 5: Level={}, Pos={}\n", .{ level_1, pos_1 });

    // Compute tweak for level 5, position 0
    const tweak_bigint_1 = (@as(u128, level_1) << 40) | (@as(u128, pos_1) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak_1 = [_]u32{
        @as(u32, @intCast(tweak_bigint_1 % p)),
        @as(u32, @intCast((tweak_bigint_1 / p) % p)),
    };

    std.debug.print("Tweak bigint: 0x{x}\n", .{tweak_bigint_1});
    std.debug.print("Tweak[0]: 0x{x} ({})\n", .{ tweak_1[0], tweak_1[0] });
    std.debug.print("Tweak[1]: 0x{x} ({})\n", .{ tweak_1[1], tweak_1[1] });

    // Test the hash operation
    const input_1 = [_]hash_zig.FieldElement{ left_child_1, right_child_1 };
    const hash_result_1 = try scheme.applyPoseidonTreeTweakHash(input_1[0..], level_1, pos_1, test_parameter);
    defer allocator.free(hash_result_1);

    std.debug.print("Hash result: 0x{x}\n", .{hash_result_1[0].value});
    std.debug.print("Expected: 0x31461cb0\n", .{});
    std.debug.print("Match: {}\n", .{hash_result_1[0].value == 0x31461cb0});

    // Layer 5 -> 6: Second hash operation (this is where divergence occurs)
    const left_child_2 = hash_zig.FieldElement{ .value = 0x31461cb0 }; // Result from first hash
    const right_child_2 = hash_zig.FieldElement{ .value = 0x267020c1 }; // From debug output
    const level_2: u8 = 6;
    const pos_2: u32 = 0;

    std.debug.print("\nLayer 5 -> 6: Level={}, Pos={}\n", .{ level_2, pos_2 });

    // Compute tweak for level 6, position 0
    const tweak_bigint_2 = (@as(u128, level_2) << 40) | (@as(u128, pos_2) << 8) | 0x01;
    const tweak_2 = [_]u32{
        @as(u32, @intCast(tweak_bigint_2 % p)),
        @as(u32, @intCast((tweak_bigint_2 / p) % p)),
    };

    std.debug.print("Tweak bigint: 0x{x}\n", .{tweak_bigint_2});
    std.debug.print("Tweak[0]: 0x{x} ({})\n", .{ tweak_2[0], tweak_2[0] });
    std.debug.print("Tweak[1]: 0x{x} ({})\n", .{ tweak_2[1], tweak_2[1] });

    // Test the hash operation
    const input_2 = [_]hash_zig.FieldElement{ left_child_2, right_child_2 };
    const hash_result_2 = try scheme.applyPoseidonTreeTweakHash(input_2[0..], level_2, pos_2, test_parameter);
    defer allocator.free(hash_result_2);

    std.debug.print("Hash result: 0x{x}\n", .{hash_result_2[0].value});
    std.debug.print("Expected from debug: 0x1ee6716\n", .{});
    std.debug.print("Match: {}\n", .{hash_result_2[0].value == 0x1ee6716});

    // Test if the issue is in the tweak computation
    std.debug.print("\n=== Tweak Computation Analysis ===\n", .{});
    std.debug.print("Level 5 tweak: 0x{x}\n", .{tweak_bigint_1});
    std.debug.print("Level 6 tweak: 0x{x}\n", .{tweak_bigint_2});
    std.debug.print("Difference: 0x{x}\n", .{tweak_bigint_2 - tweak_bigint_1});
}
