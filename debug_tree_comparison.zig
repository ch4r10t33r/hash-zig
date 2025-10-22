const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

const F = poseidon2.Field;

pub fn main() !void {
    std.debug.print("=== Tree Building Comparison Test ===\n", .{});
    
    // Test the exact tree hash operation that should produce the first hash
    // From the debug output: Hash [0] = 0x434acaa6 + 0x11d39140 -> 0x1cfad8f9
    
    const left_child = F.fromU32(0x434acaa6);
    const right_child = F.fromU32(0x11d39140);
    const level: u8 = 5;  // Layer 4 -> 5
    const pos_in_level: u32 = 0;
    
    std.debug.print("Left child: 0x{x} ({})\n", .{ left_child.toU32(), left_child.toU32() });
    std.debug.print("Right child: 0x{x} ({})\n", .{ right_child.toU32(), right_child.toU32() });
    std.debug.print("Level: {}, Position: {}\n", .{ level, pos_in_level });
    
    // Test tweak computation (matching Rust implementation)
    const tweak_bigint = (@as(u128, level) << 40) | (@as(u128, pos_in_level) << 8) | 0x01;
    const p: u128 = 2130706433; // KoalaBear field modulus
    const tweak = [_]F{
        F.fromU32(@as(u32, @intCast(tweak_bigint % p))),
        F.fromU32(@as(u32, @intCast((tweak_bigint / p) % p))),
    };
    
    std.debug.print("Tweak bigint: 0x{x}\n", .{tweak_bigint});
    std.debug.print("Tweak[0]: 0x{x} ({})\n", .{ tweak[0].toU32(), tweak[0].toU32() });
    std.debug.print("Tweak[1]: 0x{x} ({})\n", .{ tweak[1].toU32(), tweak[1].toU32() });
    
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
    
    // Prepare input for Poseidon2-24
    var input: [24]F = undefined;
    
    // Add parameter elements (5)
    for (0..5) |i| {
        input[i] = parameter[i];
    }
    
    // Add tweak elements (2)
    input[5] = tweak[0];
    input[6] = tweak[1];
    
    // Add message elements (16) - left and right children + padding
    input[7] = left_child;
    input[8] = right_child;
    for (9..24) |i| {
        input[i] = F.zero;
    }
    
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
}
