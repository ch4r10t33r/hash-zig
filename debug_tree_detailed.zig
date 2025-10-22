const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

const F = poseidon2.Field;

pub fn main() !void {
    std.debug.print("=== Detailed Tree Hash Test ===\n", .{});
    
    // Test the exact tree hash operation from the debug output
    // Hash [0] = 0x434acaa6 + 0x11d39140 -> 0x1cfad8f9
    
    const left_child = F.fromU32(0x434acaa6);
    const right_child = F.fromU32(0x11d39140);
    const level: u8 = 5;  // Layer 4 -> 5
    const pos_in_level: u32 = 0;
    
    std.debug.print("Input:\n", .{});
    std.debug.print("  Left child: 0x{x} ({})\n", .{ left_child.toU32(), left_child.toU32() });
    std.debug.print("  Right child: 0x{x} ({})\n", .{ right_child.toU32(), right_child.toU32() });
    std.debug.print("  Level: {}, Position: {}\n", .{ level, pos_in_level });
    
    // Test tweak computation (matching Rust implementation)
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos_in_level) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]F{
        F.fromU32(@as(u32, @intCast(tweak_bigint % p))),
        F.fromU32(@as(u32, @intCast((tweak_bigint / p) % p))),
    };
    
    std.debug.print("\nTweak computation:\n", .{});
    std.debug.print("  Tweak bigint: 0x{x}\n", .{tweak_bigint});
    std.debug.print("  Tweak[0]: 0x{x} ({})\n", .{ tweak[0].toU32(), tweak[0].toU32() });
    std.debug.print("  Tweak[1]: 0x{x} ({})\n", .{ tweak[1].toU32(), tweak[1].toU32() });
    
    // Test parameters (from the debug output)
    const parameter = [_]F{
        F.fromU32(0x4db7f162), // 1303900514
        F.fromU32(0x13461418), // 323359768
        F.fromU32(0x3e9098c6),  // 1049663686
        F.fromU32(0x41d3e974), // 1104406900
        F.fromU32(0x3e3263f7), // 1043489783
    };
    
    std.debug.print("\nParameters:\n", .{});
    for (parameter, 0..) |param, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, param.toU32(), param.toU32() });
    }
    
    // Test 1: Direct Poseidon2-24 call (like in debug_tree_comparison.zig)
    std.debug.print("\n=== Test 1: Direct Poseidon2-24 ===\n", .{});
    var input1: [24]F = undefined;
    
    // Add parameter elements (5)
    for (0..5) |i| {
        input1[i] = parameter[i];
    }
    
    // Add tweak elements (2)
    input1[5] = tweak[0];
    input1[6] = tweak[1];
    
    // Add message elements (16) - left and right children + padding
    input1[7] = left_child;
    input1[8] = right_child;
    for (9..24) |i| {
        input1[i] = F.zero;
    }
    
    var state1: [24]F = input1;
    poseidon2.poseidon2_24(&state1);
    
    std.debug.print("Result: 0x{x}\n", .{state1[0].toU32()});
    std.debug.print("Expected: 0x1cfad8f9\n", .{});
    std.debug.print("Match: {}\n", .{state1[0].toU32() == 0x1cfad8f9});
    
    // Test 2: Using the hashFieldElements approach (like in the actual implementation)
    std.debug.print("\n=== Test 2: hashFieldElements approach ===\n", .{});
    
    // Prepare input as it would be in the actual implementation
    var input2 = [_]F{
        parameter[0], parameter[1], parameter[2], parameter[3], parameter[4], // 5 parameter elements
        tweak[0], tweak[1], // 2 tweak elements
        left_child, right_child, // 2 message elements
    };
    
    std.debug.print("Input length: {}\n", .{input2.len});
    std.debug.print("Input (first 10 elements):\n", .{});
    for (0..@min(10, input2.len)) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, input2[i].toU32() });
    }
    
    // Apply Poseidon2-24 to the input
    var state2: [24]F = undefined;
    for (0..@min(input2.len, 24)) |i| {
        state2[i] = input2[i];
    }
    for (input2.len..24) |i| {
        state2[i] = F.zero;
    }
    
    poseidon2.poseidon2_24(&state2);
    
    std.debug.print("Result: 0x{x}\n", .{state2[0].toU32()});
    std.debug.print("Expected: 0x1cfad8f9\n", .{});
    std.debug.print("Match: {}\n", .{state2[0].toU32() == 0x1cfad8f9});
    
    // Test 3: Check if the issue is in the input format
    std.debug.print("\n=== Test 3: Different input formats ===\n", .{});
    
    // Try with 16-element input (like the actual tree hashing)
    var input3: [16]F = undefined;
    for (0..8) |i| {
        input3[i] = left_child;
    }
    for (8..16) |i| {
        input3[i] = right_child;
    }
    
    std.debug.print("16-element input (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, input3[i].toU32() });
    }
    
    // Apply Poseidon2-16 to the 16-element input
    var state3: [16]F = input3;
    poseidon2.poseidon2_16(&state3);
    
    std.debug.print("Poseidon2-16 result: 0x{x}\n", .{state3[0].toU32()});
    
    // Test 4: Check if the issue is in the tweak calculation
    std.debug.print("\n=== Test 4: Tweak calculation verification ===\n", .{});
    
    // Verify the tweak calculation step by step
    const level_u128 = @as(u128, level);
    const pos_u128 = @as(u128, pos_in_level);
    const separator = 0x01;
    
    const tweak_calc = (level_u128 << 40) | (pos_u128 << 8) | separator;
    std.debug.print("Level: {}\n", .{level});
    std.debug.print("Position: {}\n", .{pos_in_level});
    std.debug.print("Level << 40: 0x{x}\n", .{level_u128 << 40});
    std.debug.print("Position << 8: 0x{x}\n", .{pos_u128 << 8});
    std.debug.print("Separator: 0x{x}\n", .{separator});
    std.debug.print("Combined: 0x{x}\n", .{tweak_calc});
    std.debug.print("Expected: 0x50000000001\n", .{});
    std.debug.print("Match: {}\n", .{tweak_calc == 0x50000000001});
}
