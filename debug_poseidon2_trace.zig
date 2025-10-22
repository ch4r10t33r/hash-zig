const std = @import("std");
const poseidon2 = @import("src/poseidon2/root.zig");

pub fn main() !void {
    // Test with simple values to trace execution
    var state_16 = [_]u32{0} ** 16;
    state_16[0] = 1;
    state_16[1] = 2;

    const F = poseidon2.Poseidon2KoalaBear16Plonky3.Field;

    // Convert to Montgomery form
    var monty_state_16 = [_]F{undefined} ** 16;
    for (state_16, 0..) |val, i| {
        monty_state_16[i] = F.fromU32(val);
    }

    std.debug.print("=== Tracing Poseidon2-16 Execution ===\n", .{});
    std.debug.print("Input: [1, 2, 0, 0, ...]\n", .{});

    // Print initial state
    std.debug.print("\nInitial state (Montgomery form):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, monty_state_16[i].value, monty_state_16[i].toU32() });
    }

    // Step 1: Initial MDS transformation
    std.debug.print("\n=== Step 1: Initial MDS Transformation ===\n", .{});
    poseidon2.mds_light_permutation_16(&monty_state_16);
    std.debug.print("After initial MDS (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, monty_state_16[i].value, monty_state_16[i].toU32() });
    }

    // Step 2: First external round
    std.debug.print("\n=== Step 2: First External Round ===\n", .{});
    const rc = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0];
    std.debug.print("Round constants (first 4): [{}, {}, {}, {}]\n", .{ rc[0], rc[1], rc[2], rc[3] });

    // Add round constants
    for (0..16) |i| {
        const before = monty_state_16[i];
        monty_state_16[i] = monty_state_16[i].add(F.fromU32(rc[i]));
        if (i < 4) {
            std.debug.print("  state[{}] = {} + {} = {} (normal: {})\n", .{ i, before.toU32(), rc[i], monty_state_16[i].value, monty_state_16[i].toU32() });
        }
    }

    // Apply S-box
    std.debug.print("\nAfter S-box (first 4 elements):\n", .{});
    for (0..16) |i| {
        const before = monty_state_16[i];
        monty_state_16[i] = poseidon2.sbox(monty_state_16[i]);
        if (i < 4) {
            std.debug.print("  state[{}] = {}^3 = {} (normal: {})\n", .{ i, before.toU32(), monty_state_16[i].value, monty_state_16[i].toU32() });
        }
    }

    // Apply MDS matrix (4x4 blocks)
    std.debug.print("\nAfter MDS matrix 4x4 blocks (first 4 elements):\n", .{});
    for (0..4) |i| {
        poseidon2.apply_mat4(&monty_state_16, i * 4);
    }
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, monty_state_16[i].value, monty_state_16[i].toU32() });
    }

    // Apply outer circulant matrix
    std.debug.print("\nAfter outer circulant matrix (first 4 elements):\n", .{});
    var sums: [4]F = undefined;
    for (0..4) |k| {
        sums[k] = F.zero;
        var j: usize = 0;
        while (j < 16) : (j += 4) {
            sums[k] = sums[k].add(monty_state_16[j + k]);
        }
    }

    for (0..16) |i| {
        const before = monty_state_16[i];
        monty_state_16[i] = monty_state_16[i].add(sums[i % 4]);
        if (i < 4) {
            std.debug.print("  state[{}] = {} + sum[{}] = {} (normal: {})\n", .{ i, before.toU32(), i % 4, monty_state_16[i].value, monty_state_16[i].toU32() });
        }
    }

    // Step 3: First internal round
    std.debug.print("\n=== Step 3: First Internal Round ===\n", .{});
    const internal_rc = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0];
    std.debug.print("Internal round constant: {}\n", .{internal_rc});

    // Add round constant to state[0]
    const before_internal = monty_state_16[0];
    monty_state_16[0] = monty_state_16[0].add(F.fromU32(internal_rc));
    std.debug.print("After adding RC to state[0]: {} + {} = {} (normal: {})\n", .{ before_internal.toU32(), internal_rc, monty_state_16[0].value, monty_state_16[0].toU32() });

    // Apply S-box to state[0]
    const before_sbox = monty_state_16[0];
    monty_state_16[0] = poseidon2.sbox(monty_state_16[0]);
    std.debug.print("After S-box on state[0]: {}^3 = {} (normal: {})\n", .{ before_sbox.toU32(), monty_state_16[0].value, monty_state_16[0].toU32() });

    // Apply internal layer matrix
    poseidon2.apply_internal_layer_16(&monty_state_16, internal_rc);

    std.debug.print("After internal layer (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, monty_state_16[i].value, monty_state_16[i].toU32() });
    }

    // Continue with a few more rounds
    std.debug.print("\n=== Continuing with more rounds ===\n", .{});

    // Second external round
    const rc2 = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[1];
    for (0..16) |i| {
        monty_state_16[i] = monty_state_16[i].add(F.fromU32(rc2[i]));
    }
    for (0..16) |i| {
        monty_state_16[i] = poseidon2.sbox(monty_state_16[i]);
    }
    for (0..4) |i| {
        poseidon2.apply_mat4(&monty_state_16, i * 4);
    }
    var sums2: [4]F = undefined;
    for (0..4) |k| {
        sums2[k] = F.zero;
        var j: usize = 0;
        while (j < 16) : (j += 4) {
            sums2[k] = sums2[k].add(monty_state_16[j + k]);
        }
    }
    for (0..16) |i| {
        monty_state_16[i] = monty_state_16[i].add(sums2[i % 4]);
    }

    std.debug.print("After second external round (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, monty_state_16[i].value, monty_state_16[i].toU32() });
    }
}
