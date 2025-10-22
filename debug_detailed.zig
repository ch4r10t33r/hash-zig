const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

pub fn main() !void {
    // Test with simple values
    var state_16 = [_]u32{0} ** 16;
    state_16[0] = 1;
    state_16[1] = 2;

    const F = poseidon2.Field;
    
    // Convert to field elements
    var monty_state_16 = [_]F{undefined} ** 16;
    for (state_16, 0..) |val, i| {
        monty_state_16[i] = F.fromU32(val);
    }

    std.debug.print("=== Detailed Debug Test ===\n", .{});
    std.debug.print("Input: [1, 2, 0, 0, ...]\n", .{});
    
    // Print initial state
    std.debug.print("Initial state (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }

    // Step 1: Initial MDS transformation
    std.debug.print("\n=== Step 1: Initial MDS ===\n", .{});
    poseidon2.mds_light_permutation_16(&monty_state_16);
    std.debug.print("After initial MDS (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }

    // Step 2: First external round
    std.debug.print("\n=== Step 2: First External Round ===\n", .{});
    const rc = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0];
    std.debug.print("Round constants (first 4): [{}, {}, {}, {}]\n", .{ rc[0], rc[1], rc[2], rc[3] });
    
    // Add round constants
    for (0..16) |i| {
        monty_state_16[i] = monty_state_16[i].add(F.fromU32(rc[i]));
    }
    
    // Apply S-box
    for (0..16) |i| {
        monty_state_16[i] = poseidon2.sbox(monty_state_16[i]);
    }
    
    // Apply MDS light permutation
    poseidon2.mds_light_permutation_16(&monty_state_16);
    
    std.debug.print("After first external round (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }
    
    // Expected from Rust: [1862878127, 1696502448, 192279764, 1895619622]
    std.debug.print("Expected from Rust: [1862878127, 1696502448, 192279764, 1895619622]\n", .{});
    
    // Step 3: First internal round
    std.debug.print("\n=== Step 3: First Internal Round ===\n", .{});
    const internal_rc = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0];
    std.debug.print("Internal round constant: {}\n", .{internal_rc});
    
    // Add round constant to state[0]
    monty_state_16[0] = monty_state_16[0].add(F.fromU32(internal_rc));
    std.debug.print("After adding RC to state[0]: {}\n", .{ monty_state_16[0].toU32() });
    
    // Apply S-box to state[0]
    monty_state_16[0] = poseidon2.sbox(monty_state_16[0]);
    std.debug.print("After S-box on state[0]: {}\n", .{ monty_state_16[0].toU32() });
    
    // Apply internal layer matrix
    poseidon2.apply_internal_layer_16(&monty_state_16, internal_rc);
    
    std.debug.print("After internal layer (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }
    
    // Expected from Rust: [623538379, 204833952, 1327256962, 155492469]
    std.debug.print("Expected from Rust: [623538379, 204833952, 1327256962, 155492469]\n", .{});
}
