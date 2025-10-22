const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Exact Tree Hash Test ===\n", .{});
    
    // Create a scheme instance to use the exact same tree hashing function
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, [_]u8{0} ** 32);
    defer scheme.deinit();
    
    // Test the exact tree hash operation from the debug output
    // Hash [0] = 0x434acaa6 + 0x11d39140 -> 0x1cfad8f9
    
    // Create the input as it would be in the actual implementation
    // 16 field elements (8 from left + 8 from right)
    var input = try allocator.alloc(hash_zig.FieldElement, 16);
    defer allocator.free(input);
    
    // Left array: [left_first, 0, 0, 0, 0, 0, 0, 0]
    input[0] = hash_zig.FieldElement{ .value = 0x434acaa6 };
    for (1..8) |i| {
        input[i] = hash_zig.FieldElement{ .value = 0 };
    }
    
    // Right array: [right_first, 0, 0, 0, 0, 0, 0, 0]
    input[8] = hash_zig.FieldElement{ .value = 0x11d39140 };
    for (9..16) |i| {
        input[i] = hash_zig.FieldElement{ .value = 0 };
    }
    
    const level: u8 = 5;  // Layer 4 -> 5
    const pos_in_level: u32 = 0;
    
    // Test parameters (from the debug output)
    const parameter = [_]hash_zig.FieldElement{
        hash_zig.FieldElement{ .value = 0x4db7f162 }, // 1303900514
        hash_zig.FieldElement{ .value = 0x13461418 }, // 323359768
        hash_zig.FieldElement{ .value = 0x3e9098c6 },  // 1049663686
        hash_zig.FieldElement{ .value = 0x41d3e974 }, // 1104406900
        hash_zig.FieldElement{ .value = 0x3e3263f7 }, // 1043489783
    };
    
    std.debug.print("Input (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, input[i].value });
    }
    
    std.debug.print("Level: {}, Position: {}\n", .{ level, pos_in_level });
    
    // Use the exact same tree hashing function as the implementation
    const hash_result = try scheme.applyPoseidonTreeTweakHash(input, level, pos_in_level, parameter);
    defer allocator.free(hash_result);
    
    std.debug.print("\nTree hash result (first 8 elements):\n", .{});
    for (0..8) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, hash_result[i].value });
    }
    
    std.debug.print("\nExpected from Zig debug: 0x1cfad8f9\n", .{});
    std.debug.print("Got: 0x{x}\n", .{hash_result[0].value});
    std.debug.print("Match: {}\n", .{hash_result[0].value == 0x1cfad8f9});
    
    // Test with different input format - maybe the issue is in the input construction
    std.debug.print("\n=== Alternative Input Format ===\n", .{});
    
    // Try with just the first elements of each array
    var input2 = try allocator.alloc(hash_zig.FieldElement, 2);
    defer allocator.free(input2);
    
    input2[0] = hash_zig.FieldElement{ .value = 0x434acaa6 };
    input2[1] = hash_zig.FieldElement{ .value = 0x11d39140 };
    
    const hash_result2 = try scheme.applyPoseidonTreeTweakHash(input2, level, pos_in_level, parameter);
    defer allocator.free(hash_result2);
    
    std.debug.print("Alternative format result: 0x{x}\n", .{hash_result2[0].value});
    std.debug.print("Expected: 0x1cfad8f9\n", .{});
    std.debug.print("Match: {}\n", .{hash_result2[0].value == 0x1cfad8f9});
}
