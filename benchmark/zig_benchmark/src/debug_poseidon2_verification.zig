const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Zig Poseidon2 Verification Test ===\n", .{});

    // Test with simple inputs to verify basic functionality
    const simple_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 1 },
        hash_zig.FieldElement{ .value = 2 },
    };

    const simple_parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0 },
        hash_zig.FieldElement{ .value = 0 },
        hash_zig.FieldElement{ .value = 0 },
        hash_zig.FieldElement{ .value = 0 },
        hash_zig.FieldElement{ .value = 0 },
    };

    // Test tweak computation
    const level: u8 = 5;
    const pos: u32 = 0;
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = @as(u32, @intCast(tweak_bigint % p)) },
        hash_zig.FieldElement{ .value = @as(u32, @intCast((tweak_bigint / p) % p)) },
    };

    std.debug.print("Simple test inputs:\n", .{});
    std.debug.print("  Message: [0x{x}, 0x{x}]\n", .{ simple_input[0].value, simple_input[1].value });
    std.debug.print("  Parameter: [0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}]\n", .{ simple_parameter[0].value, simple_parameter[1].value, simple_parameter[2].value, simple_parameter[3].value, simple_parameter[4].value });
    std.debug.print("  Tweak: [0x{x}, 0x{x}]\n", .{ tweak[0].value, tweak[1].value });

    // Test the Poseidon2 hash function directly
    std.debug.print("\n=== Test Poseidon2 Hash Function Directly ===\n", .{});

    // Create a scheme to access the Poseidon2 implementation
    const seed_hex = "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    const seed_bytes = try std.fmt.allocPrint(allocator, "{s}", .{seed_hex});
    defer allocator.free(seed_bytes);

    var seed_array: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = seed_bytes[i * 2 .. i * 2 + 2];
        seed_array[i] = std.fmt.parseInt(u8, hex_pair, 16) catch unreachable;
    }

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    // Test the tree hash function
    const hash_result = try scheme.applyPoseidonTreeTweakHash(simple_input[0..], level, pos, simple_parameter);
    defer allocator.free(hash_result);

    std.debug.print("Simple hash result:\n", .{});
    for (hash_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test with the original complex inputs
    std.debug.print("\n=== Test with Original Complex Inputs ===\n", .{});

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

    const complex_hash_result = try scheme.applyPoseidonTreeTweakHash(test_message[0..], level, pos, test_parameter);
    defer allocator.free(complex_hash_result);

    std.debug.print("Complex hash result:\n", .{});
    for (complex_hash_result, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("\nExpected result: 0x31461cb0\n", .{});
    std.debug.print("Actual result: 0x{x}\n", .{complex_hash_result[0].value});
    std.debug.print("Match: {}\n", .{complex_hash_result[0].value == 0x31461cb0});

    std.debug.print("\n=== Analysis ===\n", .{});
    std.debug.print("Testing with both simple and complex inputs to identify the issue.\n", .{});
    std.debug.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    std.debug.print("Even with identical inputs, the results are completely different than expected.\n", .{});
    std.debug.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
    std.debug.print("The next step is to debug the individual components of the Poseidon2 algorithm.\n", .{});
}
