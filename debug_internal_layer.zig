const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

pub fn main() !void {
    const F = poseidon2.Field;

    // Test internal layer with the exact values from the first external round
    var state_16 = [_]F{undefined} ** 16;
    state_16[0] = F.fromU32(1862878127);
    state_16[1] = F.fromU32(1696502448);
    state_16[2] = F.fromU32(192279764);
    state_16[3] = F.fromU32(1895619622);

    // Fill the rest with zeros
    for (4..16) |i| {
        state_16[i] = F.fromU32(0);
    }

    std.debug.print("=== Debug Internal Layer ===\n", .{});
    std.debug.print("Before internal layer (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, state_16[i].toU32() });
    }

    // Apply first internal round manually
    const rc = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0];
    std.debug.print("Internal round constant: {}\n", .{rc});

    // Add round constant to state[0]
    state_16[0] = state_16[0].add(F.fromU32(rc));
    std.debug.print("After adding RC to state[0]: {}\n", .{state_16[0].toU32()});

    // Apply S-box to state[0]
    state_16[0] = poseidon2.sbox(state_16[0]);
    std.debug.print("After S-box on state[0]: {}\n", .{state_16[0].toU32()});

    // Compute partial sum of state[1..]
    var part_sum = F.zero;
    for (state_16[1..]) |elem| {
        part_sum = part_sum.add(elem);
    }
    std.debug.print("Partial sum of state[1..]: {}\n", .{part_sum.toU32()});

    // Compute full sum
    const full_sum = part_sum.add(state_16[0]);
    std.debug.print("Full sum: {}\n", .{full_sum.toU32()});

    // Apply internal matrix: state[0] = part_sum - state[0]
    state_16[0] = part_sum.sub(state_16[0]);
    std.debug.print("After setting state[0] = part_sum - state[0]: {}\n", .{state_16[0].toU32()});

    // Apply V-based operations for i >= 1
    state_16[1] = state_16[1].add(full_sum);
    state_16[2] = state_16[2].double().add(full_sum);
    state_16[3] = state_16[3].halve().add(full_sum);

    std.debug.print("After V-based operations (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {}\n", .{ i, state_16[i].toU32() });
    }

    // Expected from Rust: [623538379, 204833952, 1327256962, 155492469]
    std.debug.print("Expected from Rust: [623538379, 204833952, 1327256962, 155492469]\n", .{});
}
