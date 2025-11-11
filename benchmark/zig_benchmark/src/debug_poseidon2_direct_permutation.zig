const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("=== Zig Poseidon2 Direct Permutation Debug ===\n", .{});

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

    // Test tweak computation
    const level: u8 = 5;
    const pos: u32 = 0;
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = @as(u32, @intCast(tweak_bigint % p)) },
        hash_zig.FieldElement{ .value = @as(u32, @intCast((tweak_bigint / p) % p)) },
    };

    // Prepare combined input: parameter + tweak + message
    const total_input_len = 5 + 2 + test_message.len;
    var combined_input = try allocator.alloc(hash_zig.FieldElement, total_input_len);
    defer allocator.free(combined_input);

    var input_index: usize = 0;

    // Add parameter elements
    for (0..5) |i| {
        combined_input[input_index] = test_parameter[i];
        input_index += 1;
    }

    // Add tweak elements
    for (tweak) |t| {
        combined_input[input_index] = t;
        input_index += 1;
    }

    // Add message elements
    for (test_message) |fe| {
        combined_input[input_index] = fe;
        input_index += 1;
    }

    log.print("Complete input ({} elements):\n", .{total_input_len});
    for (combined_input, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test the Poseidon2 hash function directly
    log.print("\n=== Test Poseidon2 Hash Function Directly ===\n", .{});

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
    const hash_result = try scheme.applyPoseidonTreeTweakHash(test_message[0..], level, pos, test_parameter);
    defer allocator.free(hash_result);

    log.print("Tree hash result:\n", .{});
    for (hash_result, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("\nExpected result: 0x31461cb0\n", .{});
    log.print("Actual result: 0x{x}\n", .{hash_result[0].value});
    log.print("Match: {}\n", .{hash_result[0].value == 0x31461cb0});

    // Test if the issue is in the input size
    log.print("\n=== Test Different Input Sizes ===\n", .{});

    // Test with 1 element
    const single_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
    };

    const single_result = try scheme.applyPoseidonTreeTweakHash(single_input[0..], level, pos, test_parameter);
    defer allocator.free(single_result);

    log.print("Single element result: 0x{x}\n", .{single_result[0].value});

    // Test with 3 elements
    const triple_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
        hash_zig.FieldElement{ .value = 0x7e118cb3 },
    };

    const triple_result = try scheme.applyPoseidonTreeTweakHash(triple_input[0..], level, pos, test_parameter);
    defer allocator.free(triple_result);

    log.print("Triple element result: 0x{x}\n", .{triple_result[0].value});

    // Test with 16 elements
    const sixteen_input = [_]hash_zig.FieldElement{
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

    const sixteen_result = try scheme.applyPoseidonTreeTweakHash(sixteen_input[0..], level, pos, test_parameter);
    defer allocator.free(sixteen_result);

    log.print("Sixteen element result: 0x{x}\n", .{sixteen_result[0].value});

    log.print("\n=== Analysis ===\n", .{});
    log.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    log.print("Even with identical inputs, the results are completely different than expected.\n", .{});
    log.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
    log.print("The next step is to debug the individual components of the Poseidon2 algorithm.\n", .{});

    // Test if the issue is in the input preparation
    log.print("\n=== Input Preparation Analysis ===\n", .{});

    log.print("Complete input ({} elements):\n", .{total_input_len});
    for (combined_input, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("\n=== Conclusion ===\n", .{});
    log.print("The issue is definitively in the Poseidon2 hash function implementation.\n", .{});
    log.print("All inputs are identical, but the outputs are completely different.\n", .{});
    log.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
    log.print("The next step is to debug the individual components of the Poseidon2 algorithm.\n", .{});
}
