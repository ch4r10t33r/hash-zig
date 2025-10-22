const std = @import("std");
const poseidon2_plonky3 = @import("poseidon2_plonky3_compat");

const F = poseidon2_plonky3.Poseidon2KoalaBear16Plonky3.Field;

pub fn main() !void {
    std.debug.print("=== Debugging Poseidon2-16 Implementation ===\n", .{});

    // Test with the same input as our comparison
    var state: [16]F = undefined;
    state[0] = F.fromU32(305419896);
    state[1] = F.fromU32(2596069104);
    for (2..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Initial state:\n", .{});
    for (0..16) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    // Apply first external round
    std.debug.print("\n=== First External Round ===\n", .{});
    const first_rcs = poseidon2_plonky3.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0];
    std.debug.print("Round constants: {any}\n", .{first_rcs});

    // Add round constants
    for (0..16) |i| {
        const old_value = state[i].toU32();
        state[i] = state[i].add(F.fromU32(first_rcs[i]));
        std.debug.print("  state[{}] = {} + {} = {} (normal: {})\n", .{ i, old_value, first_rcs[i], state[i].value, state[i].toU32() });
    }

    // Apply S-box to all elements
    std.debug.print("\nAfter S-box:\n", .{});
    for (0..16) |i| {
        const old_value = state[i].toU32();
        state[i] = state[i].mul(state[i]).mul(state[i]); // x^3
        std.debug.print("  state[{}] = {}^3 = {} (normal: {})\n", .{ i, old_value, state[i].value, state[i].toU32() });
    }

    // Apply MDS matrix to first 4 elements
    std.debug.print("\nAfter MDS matrix (first 4 elements):\n", .{});
    const x = state[0..4];

    // t01 = x[0] + x[1]
    const t01 = x[0].add(x[1]);
    std.debug.print("  t01 = {} + {} = {} (normal: {})\n", .{ x[0].toU32(), x[1].toU32(), t01.value, t01.toU32() });

    // t23 = x[2] + x[3]
    const t23 = x[2].add(x[3]);
    std.debug.print("  t23 = {} + {} = {} (normal: {})\n", .{ x[2].toU32(), x[3].toU32(), t23.value, t23.toU32() });

    // t0123 = t01 + t23
    const t0123 = t01.add(t23);
    std.debug.print("  t0123 = {} + {} = {} (normal: {})\n", .{ t01.toU32(), t23.toU32(), t0123.value, t0123.toU32() });

    // t01123 = t0123 + x[1]
    const t01123 = t0123.add(x[1]);
    std.debug.print("  t01123 = {} + {} = {} (normal: {})\n", .{ t0123.toU32(), x[1].toU32(), t01123.value, t01123.toU32() });

    // t01233 = t0123 + x[3]
    const t01233 = t0123.add(x[3]);
    std.debug.print("  t01233 = {} + {} = {} (normal: {})\n", .{ t0123.toU32(), x[3].toU32(), t01233.value, t01233.toU32() });

    // Apply the MDS matrix transformation
    // x[3] = t01233 + x[0].double()
    x[3] = t01233.add(x[0].double());
    std.debug.print("  x[3] = {} + {}*2 = {} (normal: {})\n", .{ t01233.toU32(), x[0].toU32(), x[3].value, x[3].toU32() });

    // x[1] = t01123 + x[2].double()
    x[1] = t01123.add(x[2].double());
    std.debug.print("  x[1] = {} + {}*2 = {} (normal: {})\n", .{ t01123.toU32(), x[2].toU32(), x[1].value, x[1].toU32() });

    // x[0] = t01123 + t01
    x[0] = t01123.add(t01);
    std.debug.print("  x[0] = {} + {} = {} (normal: {})\n", .{ t01123.toU32(), t01.toU32(), x[0].value, x[0].toU32() });

    // x[2] = t01233 + t23
    x[2] = t01233.add(t23);
    std.debug.print("  x[2] = {} + {} = {} (normal: {})\n", .{ t01233.toU32(), t23.toU32(), x[2].value, x[2].toU32() });

    std.debug.print("\nFinal state after first external round:\n", .{});
    for (0..16) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }
}
