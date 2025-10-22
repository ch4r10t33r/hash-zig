const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Detailed Rust Comparison ===\n", .{});

    // Test the exact case from context.md that should produce 0x31461cb0
    var state: [16]F = undefined;
    state[0] = F.fromU32(305419896);
    state[1] = F.fromU32(2596069104);
    for (2..16) |i| {
        state[i] = F.zero;
    }

    std.debug.print("Input: [305419896, 2596069104]\n", .{});
    std.debug.print("Expected: 0x31461cb0 ({} in decimal)\n", .{0x31461cb0});

    // Let's trace through the first few steps to see where we diverge
    std.debug.print("\n=== Initial State ===\n", .{});
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Apply initial MDS transformation
    std.debug.print("\n=== After Initial MDS ===\n", .{});
    poseidon2.mds_light_permutation_16(&state);
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Apply first external round
    std.debug.print("\n=== After First External Round ===\n", .{});
    poseidon2.apply_external_layer_16(&state, poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0]);
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Apply first internal round
    std.debug.print("\n=== After First Internal Round ===\n", .{});
    poseidon2.apply_internal_layer_16(&state, poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0]);
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Apply second external round
    std.debug.print("\n=== After Second External Round ===\n", .{});
    poseidon2.apply_external_layer_16(&state, poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[1]);
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Apply second internal round
    std.debug.print("\n=== After Second Internal Round ===\n", .{});
    poseidon2.apply_internal_layer_16(&state, poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[1]);
    std.debug.print("state[0] = {} (normal: {})\n", .{ state[0].value, state[0].toU32() });
    std.debug.print("state[1] = {} (normal: {})\n", .{ state[1].value, state[1].toU32() });

    // Now let's run the full permutation and see the final result
    std.debug.print("\n=== Full Permutation Result ===\n", .{});

    // Reset state
    state[0] = F.fromU32(305419896);
    state[1] = F.fromU32(2596069104);
    for (2..16) |i| {
        state[i] = F.zero;
    }

    poseidon2.poseidon2_16_plonky3(&state);
    const result = state[0].toU32();
    std.debug.print("Final result: 0x{x} ({} in decimal)\n", .{ result, result });
    std.debug.print("Expected: 0x31461cb0 ({} in decimal)\n", .{0x31461cb0});
    std.debug.print("Match: {}\n", .{result == 0x31461cb0});

    // Let's also test with a simple case to see if our basic implementation works
    std.debug.print("\n=== Simple Test Case ===\n", .{});
    var simple_state: [16]F = undefined;
    simple_state[0] = F.fromU32(1);
    for (1..16) |i| {
        simple_state[i] = F.zero;
    }

    poseidon2.poseidon2_16_plonky3(&simple_state);
    const simple_result = simple_state[0].toU32();
    std.debug.print("Simple test result: 0x{x} ({} in decimal)\n", .{ simple_result, simple_result });
}
