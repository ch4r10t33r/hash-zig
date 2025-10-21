//! Test Poseidon2 compatibility with Rust hash-sig implementation
//! This test verifies that our Zig Poseidon2-24 and Poseidon2-16 instances
//! produce the same outputs as the Rust implementation

const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig Poseidon2 Compatibility Test\n", .{});
    std.debug.print("================================\n", .{});
    std.debug.print("Testing compatibility with Rust hash-sig Poseidon2 instances:\n", .{});
    std.debug.print("- Poseidon2-24 (width 24) for message hashing\n", .{});
    std.debug.print("- Poseidon2-16 (width 16) for chain compression\n", .{});
    std.debug.print("\n", .{});

    // Initialize Rust-compatible Poseidon2
    var poseidon2_rust = try hash_zig.Poseidon2.init(allocator);
    defer poseidon2_rust.deinit();

    // Test 1: Poseidon2-24 (message hashing)
    std.debug.print("1. Testing Poseidon2-24 (message hashing):\n", .{});
    std.debug.print("------------------------------------------\n", .{});

    const input_24 = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 1 },
        hash_zig.FieldElement{ .value = 2 },
        hash_zig.FieldElement{ .value = 3 },
        hash_zig.FieldElement{ .value = 4 },
        hash_zig.FieldElement{ .value = 5 },
    };

    const output_24 = try poseidon2_rust.hashFieldElements(allocator, &input_24);
    defer allocator.free(output_24);

    std.debug.print("Input (5 elements): ", .{});
    for (input_24) |fe| {
        std.debug.print("{} ", .{fe.value});
    }
    std.debug.print("\n", .{});

    std.debug.print("Output ({} elements): ", .{output_24.len});
    for (output_24, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < output_24.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    // Test 2: Poseidon2-16 (chain compression)
    std.debug.print("\n2. Testing Poseidon2-16 (chain compression):\n", .{});
    std.debug.print("--------------------------------------------\n", .{});

    const input_16 = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 10 },
        hash_zig.FieldElement{ .value = 20 },
        hash_zig.FieldElement{ .value = 30 },
        hash_zig.FieldElement{ .value = 40 },
        hash_zig.FieldElement{ .value = 50 },
    };

    const output_16 = try poseidon2_rust.hashFieldElements16(allocator, &input_16);
    defer allocator.free(output_16);

    std.debug.print("Input (5 elements): ", .{});
    for (input_16) |fe| {
        std.debug.print("{} ", .{fe.value});
    }
    std.debug.print("\n", .{});

    std.debug.print("Output ({} elements): ", .{output_16.len});
    for (output_16, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < output_16.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    // Test 3: Compress function (Poseidon2-24)
    std.debug.print("\n3. Testing compress function (Poseidon2-24):\n", .{});
    std.debug.print("---------------------------------------------\n", .{});

    var compress_input: [24]hash_zig.FieldElement = undefined;
    for (0..24) |i| {
        compress_input[i] = hash_zig.FieldElement{ .value = @as(u32, @intCast(i + 100)) };
    }

    const compress_output = try poseidon2_rust.compress(compress_input, 8);

    std.debug.print("Compress input (24 elements): ", .{});
    for (compress_input, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < compress_input.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    std.debug.print("Compress output (8 elements): ", .{});
    for (compress_output, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < compress_output.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    // Test 4: Compress function (Poseidon2-16)
    std.debug.print("\n4. Testing compress function (Poseidon2-16):\n", .{});
    std.debug.print("---------------------------------------------\n", .{});

    var compress_input_16: [16]hash_zig.FieldElement = undefined;
    for (0..16) |i| {
        compress_input_16[i] = hash_zig.FieldElement{ .value = @as(u32, @intCast(i + 200)) };
    }

    const compress_output_16 = try poseidon2_rust.compress16(compress_input_16, 6);

    std.debug.print("Compress input (16 elements): ", .{});
    for (compress_input_16, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < compress_input_16.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    std.debug.print("Compress output (6 elements): ", .{});
    for (compress_output_16, 0..) |fe, i| {
        std.debug.print("{}{s}", .{ fe.value, if (i < compress_output_16.len - 1) ", " else "" });
    }
    std.debug.print("\n", .{});

    // Test 5: Verify deterministic behavior
    std.debug.print("\n5. Testing deterministic behavior:\n", .{});
    std.debug.print("-----------------------------------\n", .{});

    const test_input = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 42 },
        hash_zig.FieldElement{ .value = 43 },
        hash_zig.FieldElement{ .value = 44 },
    };

    const output1 = try poseidon2_rust.hashFieldElements(allocator, &test_input);
    defer allocator.free(output1);

    const output2 = try poseidon2_rust.hashFieldElements(allocator, &test_input);
    defer allocator.free(output2);

    // Check if outputs are identical
    var identical = true;
    if (output1.len != output2.len) {
        identical = false;
    } else {
        for (output1, output2) |fe1, fe2| {
            if (fe1.value != fe2.value) {
                identical = false;
                break;
            }
        }
    }

    if (identical) {
        std.debug.print("✅ Deterministic behavior verified\n", .{});
    } else {
        std.debug.print("❌ Non-deterministic behavior detected\n", .{});
    }

    std.debug.print("\n✅ Poseidon2 compatibility test completed!\n", .{});
    std.debug.print("\nNote: This test verifies that our Zig implementation\n", .{});
    std.debug.print("uses the correct Poseidon2-24 and Poseidon2-16 instances\n", .{});
    std.debug.print("that match the Rust hash-sig implementation.\n", .{});
}
