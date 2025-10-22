const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Internal Layer Reference Implementation ===\n", .{});

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

    // Let's try a completely different approach
    // Maybe the issue is that we need to apply the operations in a different order
    // or there's a bug in our implementation

    // Let's check if there's an issue with the internal layer implementation
    // by comparing with a manual step-by-step implementation

    std.debug.print("\n=== Manual Internal Layer Implementation ===\n", .{});

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

    // Now let's try a different approach to the V-based operations
    // Maybe the issue is that we need to apply them in a different order
    // or there's a bug in our understanding

    std.debug.print("\n=== Alternative V-based Operations ===\n", .{});

    // Let's try applying the V operations in a different order
    // Maybe the issue is that we need to apply them to the original state values
    // before they were modified

    // Reset state for alternative approach
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

    // Let's try a different approach - maybe the issue is with the V operations themselves
    // Let's check if there's an issue with the order of operations

    // Try applying the V operations in a different order
    std.debug.print("\n=== Different Order V Operations ===\n", .{});

    // Maybe the issue is that we need to apply the V operations to the original state
    // before the internal matrix transformation

    // Reset state
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
    const full_sum3 = part_sum.add(state[0]);

    // Maybe the issue is that we need to apply the V operations before
    // the internal matrix transformation

    // Apply V operations to original state
    state[1] = state[1].add(full_sum3);
    state[2] = state[2].double().add(full_sum3);
    state[3] = state[3].halve().add(full_sum3);

    // Then apply internal matrix transformation
    state[0] = part_sum.sub(state[0]);

    std.debug.print("After alternative V operations (first 4 elements):\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, state[i].value, state[i].toU32() });
    }

    // Expected from Rust: [1311927403, 1561259414, 249316494, 812566777]
    std.debug.print("\nExpected from Rust: [1311927403, 1561259414, 249316494, 812566777]\n", .{});
    std.debug.print("state[0] match: {}\n", .{state[0].toU32() == 1311927403});
    std.debug.print("state[1] match: {}\n", .{state[1].toU32() == 1561259414});
    std.debug.print("state[2] match: {}\n", .{state[2].toU32() == 249316494});
    std.debug.print("state[3] match: {}\n", .{state[3].toU32() == 812566777});
}
