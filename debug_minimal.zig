const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

pub fn main() !void {
    // Test with simple values
    var state_16 = [_]u32{0} ** 16;
    state_16[0] = 1;
    state_16[1] = 2;

    const F = poseidon2.Poseidon2KoalaBear16Plonky3.Field;

    // Convert to field elements
    var monty_state_16 = [_]F{undefined} ** 16;
    for (state_16, 0..) |val, i| {
        monty_state_16[i] = F.fromU32(val);
    }

    std.debug.print("=== Minimal Debug Test ===\n", .{});
    std.debug.print("Input: [1, 2, 0, 0, ...]\n", .{});

    // Print initial state
    std.debug.print("Initial state (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }

    // Apply initial MDS transformation first
    std.debug.print("\n=== Initial MDS Transformation ===\n", .{});
    poseidon2.mds_light_permutation_16(&monty_state_16);
    std.debug.print("After initial MDS (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, monty_state_16[i].toU32() });
    }

    // Test just the first external round
    std.debug.print("\n=== First External Round ===\n", .{});
    const rc = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0];

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

    // Expected from Rust trace: [1862878127, 1696502448, 192279764, 1895619622]
    std.debug.print("Expected from Rust: [1862878127, 1696502448, 192279764, 1895619622]\n", .{});
}
