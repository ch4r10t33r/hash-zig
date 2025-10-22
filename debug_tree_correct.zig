const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

const F = poseidon2.Field;

pub fn main() !void {
    std.debug.print("=== Correct Tree Hash Test ===\n", .{});
    
    // Test the exact tree hash operation from the debug output
    // Hash [0] = 0x434acaa6 + 0x11d39140 -> 0x1cfad8f9
    
    // The input should be 16 field elements (8 from left + 8 from right)
    // But we only know the first element of each array
    const left_first = F.fromU32(0x434acaa6);
    const right_first = F.fromU32(0x11d39140);
    const level: u8 = 5;  // Layer 4 -> 5
    const pos_in_level: u32 = 0;
    
    std.debug.print("Input:\n", .{});
    std.debug.print("  Left child[0]: 0x{x} ({})\n", .{ left_first.toU32(), left_first.toU32() });
    std.debug.print("  Right child[0]: 0x{x} ({})\n", .{ right_first.toU32(), right_first.toU32() });
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
    
    // Test with 16-element input (8 from left + 8 from right)
    // We'll use the first element for both arrays and pad with zeros
    var input: [24]F = undefined;
    
    // Add parameter elements (5)
    for (0..5) |i| {
        input[i] = parameter[i];
    }
    
    // Add tweak elements (2)
    input[5] = tweak[0];
    input[6] = tweak[1];
    
    // Add message elements (16) - 8 from left + 8 from right
    // Left array: [left_first, 0, 0, 0, 0, 0, 0, 0]
    input[7] = left_first;
    for (8..15) |i| {
        input[i] = F.zero;
    }
    
    // Right array: [right_first, 0, 0, 0, 0, 0, 0, 0]
    input[15] = right_first;
    for (16..23) |i| {
        input[i] = F.zero;
    }
    
    // Pad to 24 elements
    input[23] = F.zero;
    
    std.debug.print("\nPoseidon2 input (first 10 elements):\n", .{});
    for (0..10) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, input[i].toU32() });
    }
    
    // Apply Poseidon2-24
    var state: [24]F = input;
    poseidon2.poseidon2_24(&state);
    
    std.debug.print("\nPoseidon2 output (first 8 elements):\n", .{});
    for (0..8) |i| {
        std.debug.print("  [{}] = 0x{x}\n", .{ i, state[i].toU32() });
    }
    
    std.debug.print("\nExpected from Zig debug: 0x1cfad8f9\n", .{});
    std.debug.print("Got: 0x{x}\n", .{state[0].toU32()});
    std.debug.print("Match: {}\n", .{state[0].toU32() == 0x1cfad8f9});
    
    // Test with different input format - maybe the issue is in how we're constructing the input
    std.debug.print("\n=== Alternative Input Format ===\n", .{});
    
    // Try with the exact format from the debug output
    // The debug shows: Hash [0] = 0x434acaa6 + 0x11d39140 -> 0x1cfad8f9
    // This suggests the input might be just the first elements of each array
    
    var input2: [24]F = undefined;
    
    // Add parameter elements (5)
    for (0..5) |i| {
        input2[i] = parameter[i];
    }
    
    // Add tweak elements (2)
    input2[5] = tweak[0];
    input2[6] = tweak[1];
    
    // Add message elements - just the first elements
    input2[7] = left_first;
    input2[8] = right_first;
    for (9..24) |i| {
        input2[i] = F.zero;
    }
    
    var state2: [24]F = input2;
    poseidon2.poseidon2_24(&state2);
    
    std.debug.print("Alternative format result: 0x{x}\n", .{state2[0].toU32()});
    std.debug.print("Expected: 0x1cfad8f9\n", .{});
    std.debug.print("Match: {}\n", .{state2[0].toU32() == 0x1cfad8f9});
}
