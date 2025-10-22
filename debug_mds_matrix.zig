const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== MDS Matrix Debugging ===\n", .{});

    // Test with known values
    var state: [16]F = undefined;
    state[0] = F.fromU32(305419896);
    state[1] = F.fromU32(2596069104);
    for (2..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Initial state (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    // Apply MDS matrix manually step by step
    std.debug.print("\n=== Manual MDS Matrix Application ===\n", .{});
    const x = state[0..4];

    // t01 = x[0] + x[1]
    const t01 = x[0].add(x[1]);
    std.debug.print("t01 = x[0] + x[1] = {} + {} = {} (normal: {})\n", .{ x[0].toU32(), x[1].toU32(), t01.value, t01.toU32() });

    // t23 = x[2] + x[3]
    const t23 = x[2].add(x[3]);
    std.debug.print("t23 = x[2] + x[3] = {} + {} = {} (normal: {})\n", .{ x[2].toU32(), x[3].toU32(), t23.value, t23.toU32() });

    // t0123 = t01 + t23
    const t0123 = t01.add(t23);
    std.debug.print("t0123 = t01 + t23 = {} + {} = {} (normal: {})\n", .{ t01.toU32(), t23.toU32(), t0123.value, t0123.toU32() });

    // t01123 = t0123 + x[1]
    const t01123 = t0123.add(x[1]);
    std.debug.print("t01123 = t0123 + x[1] = {} + {} = {} (normal: {})\n", .{ t0123.toU32(), x[1].toU32(), t01123.value, t01123.toU32() });

    // t01233 = t0123 + x[3]
    const t01233 = t0123.add(x[3]);
    std.debug.print("t01233 = t0123 + x[3] = {} + {} = {} (normal: {})\n", .{ t0123.toU32(), x[3].toU32(), t01233.value, t01233.toU32() });

    // Apply the MDS matrix transformation
    std.debug.print("\n=== Applying MDS Matrix ===\n", .{});

    // x[3] = t01233 + x[0].double()
    const x0_double = x[0].double();
    x[3] = t01233.add(x0_double);
    std.debug.print("x[3] = t01233 + x[0].double() = {} + {} = {} (normal: {})\n", .{ t01233.toU32(), x0_double.toU32(), x[3].value, x[3].toU32() });

    // x[1] = t01123 + x[2].double()
    const x2_double = x[2].double();
    x[1] = t01123.add(x2_double);
    std.debug.print("x[1] = t01123 + x[2].double() = {} + {} = {} (normal: {})\n", .{ t01123.toU32(), x2_double.toU32(), x[1].value, x[1].toU32() });

    // x[0] = t01123 + t01
    x[0] = t01123.add(t01);
    std.debug.print("x[0] = t01123 + t01 = {} + {} = {} (normal: {})\n", .{ t01123.toU32(), t01.toU32(), x[0].value, x[0].toU32() });

    // x[2] = t01233 + t23
    x[2] = t01233.add(t23);
    std.debug.print("x[2] = t01233 + t23 = {} + {} = {} (normal: {})\n", .{ t01233.toU32(), t23.toU32(), x[2].value, x[2].toU32() });

    std.debug.print("\nFinal state after manual MDS (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    // Now test with the function
    std.debug.print("\n=== Testing MDS Function ===\n", .{});

    // Reset state
    state[0] = F.fromU32(305419896);
    state[1] = F.fromU32(2596069104);
    for (2..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Before function call (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    poseidon2.apply_mat4(&state, 0);

    std.debug.print("After function call (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }
}
