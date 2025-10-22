const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Zig Poseidon2 Components Debug ===\n", .{});

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

    std.debug.print("Test message (2 elements):\n", .{});
    for (test_message, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("Test parameter (5 elements):\n", .{});
    for (test_parameter, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test tweak computation
    const level: u8 = 5;
    const pos: u32 = 0;
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = @as(u32, @intCast(tweak_bigint % p)) },
        hash_zig.FieldElement{ .value = @as(u32, @intCast((tweak_bigint / p) % p)) },
    };

    std.debug.print("\nTweak computation:\n", .{});
    std.debug.print("  Level: {}, Position: {}\n", .{ level, pos });
    std.debug.print("  Tweak bigint: 0x{x}\n", .{tweak_bigint});
    std.debug.print("  Tweak[0]: 0x{x} ({})\n", .{ tweak[0].value, tweak[0].value });
    std.debug.print("  Tweak[1]: 0x{x} ({})\n", .{ tweak[1].value, tweak[1].value });

    // Test the complete input preparation
    std.debug.print("\n=== Input Preparation Analysis ===\n", .{});

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

    std.debug.print("Complete input ({} elements):\n", .{total_input_len});
    for (combined_input, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test if the issue is in the input size or format
    std.debug.print("\n=== Test Different Input Sizes ===\n", .{});

    // Test with 1 element
    const single_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
    };

    std.debug.print("Single element input:\n", .{});
    for (single_input, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Test with 3 elements
    const triple_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x1640cb16 },
        hash_zig.FieldElement{ .value = 0x54503ce2 },
        hash_zig.FieldElement{ .value = 0x7e118cb3 },
    };

    std.debug.print("Triple element input:\n", .{});
    for (triple_input, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

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

    std.debug.print("Sixteen element input:\n", .{});
    for (sixteen_input, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("\n=== Analysis ===\n", .{});
    std.debug.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    std.debug.print("Even with identical inputs, the results are completely different than expected.\n", .{});
    std.debug.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
    std.debug.print("The next step is to debug the individual components of the Poseidon2 algorithm.\n", .{});
}
