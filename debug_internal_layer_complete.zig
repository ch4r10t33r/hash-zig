const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Complete Internal Layer Debugging ===\n", .{});

    // Test with the exact values from the trace
    var state: [16]F = undefined;
    state[0] = F.fromU32(1862878127);
    state[1] = F.fromU32(1696502448);
    state[2] = F.fromU32(192279764);
    state[3] = F.fromU32(1895619622);
    for (4..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Initial state (all elements):\n", .{});
    for (0..16) |i| {
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

    // Now let's apply ALL the V-based operations step by step
    std.debug.print("\n=== Complete V-based Operations ===\n", .{});

    // state[1] += full_sum
    const old_state1 = state[1].toU32();
    state[1] = state[1].add(full_sum);
    std.debug.print("state[1] = {} + {} = {} (normal: {})\n", .{ old_state1, full_sum.toU32(), state[1].value, state[1].toU32() });

    // state[2] = state[2].double() + full_sum
    const old_state2 = state[2].toU32();
    const state2_double = state[2].double();
    state[2] = state2_double.add(full_sum);
    std.debug.print("state[2] = {}*2 + {} = {} + {} = {} (normal: {})\n", .{ old_state2, full_sum.toU32(), state2_double.toU32(), full_sum.toU32(), state[2].value, state[2].toU32() });

    // state[3] = state[3].halve() + full_sum
    const old_state3 = state[3].toU32();
    const state3_halve = state[3].halve();
    state[3] = state3_halve.add(full_sum);
    std.debug.print("state[3] = {}/2 + {} = {} + {} = {} (normal: {})\n", .{ old_state3, full_sum.toU32(), state3_halve.toU32(), full_sum.toU32(), state[3].value, state[3].toU32() });

    // Continue with the remaining V-based operations
    std.debug.print("\nRemaining V-based operations:\n", .{});

    // state[4] = full_sum + state[4].double() + state[4]
    const old_state4 = state[4].toU32();
    const state4_double = state[4].double();
    state[4] = full_sum.add(state4_double).add(state[4]);
    std.debug.print("state[4] = {} + {}*2 + {} = {} + {} + {} = {} (normal: {})\n", .{ full_sum.toU32(), old_state4, old_state4, full_sum.toU32(), state4_double.toU32(), old_state4, state[4].value, state[4].toU32() });

    // state[5] = full_sum + state[5].double().double()
    const old_state5 = state[5].toU32();
    const state5_double_double = state[5].double().double();
    state[5] = full_sum.add(state5_double_double);
    std.debug.print("state[5] = {} + {}*4 = {} + {} = {} (normal: {})\n", .{ full_sum.toU32(), old_state5, full_sum.toU32(), state5_double_double.toU32(), state[5].value, state[5].toU32() });

    // state[6] = full_sum - state[6].halve()
    const old_state6 = state[6].toU32();
    const state6_halve = state[6].halve();
    state[6] = full_sum.sub(state6_halve);
    std.debug.print("state[6] = {} - {}/2 = {} - {} = {} (normal: {})\n", .{ full_sum.toU32(), old_state6, full_sum.toU32(), state6_halve.toU32(), state[6].value, state[6].toU32() });

    // state[7] = full_sum - (state[7].double() + state[7])
    const old_state7 = state[7].toU32();
    const state7_double = state[7].double();
    const state7_triple = state7_double.add(state[7]);
    state[7] = full_sum.sub(state7_triple);
    std.debug.print("state[7] = {} - ({}*2 + {}) = {} - {} = {} (normal: {})\n", .{ full_sum.toU32(), old_state7, old_state7, full_sum.toU32(), state7_triple.toU32(), state[7].value, state[7].toU32() });

    // Continue with the remaining operations...
    std.debug.print("\nFinal state after complete V-based operations (first 8 elements):\n", .{});
    for (0..8) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    // Expected from Rust: [1311927403, 1561259414, 249316494, 812566777]
    std.debug.print("\nExpected from Rust: [1311927403, 1561259414, 249316494, 812566777]\n", .{});
    std.debug.print("state[0] match: {}\n", .{state[0].toU32() == 1311927403});
    std.debug.print("state[1] match: {}\n", .{state[1].toU32() == 1561259414});
    std.debug.print("state[2] match: {}\n", .{state[2].toU32() == 249316494});
    std.debug.print("state[3] match: {}\n", .{state[3].toU32() == 812566777});
}
