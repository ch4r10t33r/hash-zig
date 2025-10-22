const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== V-based Operations Debugging ===\n", .{});

    // Test with the exact values from the trace
    var state: [16]F = undefined;
    state[0] = F.fromU32(1862878127);
    state[1] = F.fromU32(1696502448);
    state[2] = F.fromU32(192279764);
    state[3] = F.fromU32(1895619622);
    for (4..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Initial state (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    const rc = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0];
    std.debug.print("Internal round constant: {}\n", .{rc});

    // Step 1: Add round constant to state[0]
    state[0] = state[0].add(F.fromU32(rc));
    std.debug.print("After adding RC to state[0]: {} (normal: {})\n", .{ state[0].value, state[0].toU32() });

    // Step 2: Apply S-box to state[0]
    state[0] = poseidon2.sbox(state[0]);
    std.debug.print("After S-box on state[0]: {} (normal: {})\n", .{ state[0].value, state[0].toU32() });

    // Step 3: Compute partial sum of state[1..]
    var part_sum = F.zero;
    for (state[1..]) |elem| {
        part_sum = part_sum.add(elem);
    }
    std.debug.print("Partial sum of state[1..]: {} (normal: {})\n", .{ part_sum.value, part_sum.toU32() });

    // Step 4: Compute full sum
    const full_sum = part_sum.add(state[0]);
    std.debug.print("Full sum: {} (normal: {})\n", .{ full_sum.value, full_sum.toU32() });

    // Step 5: Apply internal matrix: state[0] = part_sum - state[0]
    state[0] = part_sum.sub(state[0]);
    std.debug.print("After setting state[0] = part_sum - state[0]: {} (normal: {})\n", .{ state[0].value, state[0].toU32() });

    // Now let's check if the issue is with the V-based operations
    // Let's try a different approach - maybe the issue is with the order of operations
    std.debug.print("\n=== Testing Different V-based Operations ===\n", .{});

    // Let's try the exact operations from the Plonky3 source
    // Maybe the issue is that we need to apply the operations in a different order

    // Reset state for testing
    state[0] = F.fromU32(1862878127);
    state[1] = F.fromU32(1696502448);
    state[2] = F.fromU32(192279764);
    state[3] = F.fromU32(1895619622);
    for (4..16) |i| {
        state[i] = F.zero;
    }

    // Apply the same steps as before
    state[0] = state[0].add(F.fromU32(rc));
    state[0] = poseidon2.sbox(state[0]);

    part_sum = F.zero;
    for (state[1..]) |elem| {
        part_sum = part_sum.add(elem);
    }
    const full_sum2 = part_sum.add(state[0]);
    state[0] = part_sum.sub(state[0]);

    std.debug.print("Full sum for V operations: {} (normal: {})\n", .{ full_sum2.value, full_sum2.toU32() });

    // Now let's try applying the V operations one by one and see if we can match the expected values
    std.debug.print("\n=== Step-by-step V Operations ===\n", .{});

    // state[1] += full_sum
    const old_state1 = state[1].toU32();
    state[1] = state[1].add(full_sum2);
    std.debug.print("state[1] = {} + {} = {} (normal: {})\n", .{ old_state1, full_sum2.toU32(), state[1].value, state[1].toU32() });

    // Check if this matches the expected value
    const expected_state1 = 1561259414;
    std.debug.print("Expected state[1]: {}\n", .{expected_state1});
    std.debug.print("Match: {}\n", .{state[1].toU32() == expected_state1});

    // If not, let's try a different approach
    if (state[1].toU32() != expected_state1) {
        std.debug.print("Trying alternative approach...\n", .{});

        // Maybe the issue is with the full_sum calculation
        // Let's try recalculating it
        const alt_full_sum = state[0].add(part_sum);
        std.debug.print("Alternative full sum: {} (normal: {})\n", .{ alt_full_sum.value, alt_full_sum.toU32() });

        // Try with alternative full sum
        state[1] = F.fromU32(1696502448); // Reset
        state[1] = state[1].add(alt_full_sum);
        std.debug.print("state[1] with alt full sum = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });
        std.debug.print("Match with alt full sum: {}\n", .{state[1].toU32() == expected_state1});
    }
}
