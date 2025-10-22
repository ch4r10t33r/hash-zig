const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    std.debug.print("=== Zig Round Constants Debug ===\n", .{});

    // Test round constants from our implementation
    std.debug.print("\n=== External Initial Round Constants (16-width) ===\n", .{});
    const poseidon2 = @import("../../src/poseidon2/root.zig");
    const rc_initial = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL;

    for (rc_initial, 0..) |round, i| {
        std.debug.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) std.debug.print(", ", .{});
            std.debug.print("0x{x}", .{val});
        }
        std.debug.print("]\n", .{});
    }

    std.debug.print("\n=== External Final Round Constants (16-width) ===\n", .{});
    const rc_final = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL;

    for (rc_final, 0..) |round, i| {
        std.debug.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) std.debug.print(", ", .{});
            std.debug.print("0x{x}", .{val});
        }
        std.debug.print("]\n", .{});
    }

    std.debug.print("\n=== Internal Round Constants (16-width) ===\n", .{});
    const rc_internal = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL;

    for (rc_internal, 0..) |round, i| {
        std.debug.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) std.debug.print(", ", .{});
            std.debug.print("0x{x}", .{val});
        }
        std.debug.print("]\n", .{});
    }

    // Test if the issue is in the round constants themselves
    std.debug.print("\n=== Round Constants Analysis ===\n", .{});
    std.debug.print("The round constants should match Plonky3 exactly.\n", .{});
    std.debug.print("If they don't match, that would explain the different results.\n", .{});

    // Test specific round constants that might be causing issues
    std.debug.print("\n=== Test Specific Round Constants ===\n", .{});

    // Test the first round constant
    const first_rc = rc_initial[0];
    std.debug.print("First round constant: [", .{});
    for (first_rc, 0..) |val, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("0x{x}", .{val});
    }
    std.debug.print("]\n", .{});

    // Test if the issue is in the round constant application
    std.debug.print("\n=== Round Constant Application Test ===\n", .{});
    std.debug.print("The issue might be in how the round constants are applied.\n", .{});
    std.debug.print("Let's check if the round constants are being applied correctly.\n", .{});

    std.debug.print("\n=== Analysis ===\n", .{});
    std.debug.print("The round constants should match Plonky3 exactly.\n", .{});
    std.debug.print("If they don't match, that would explain the different results.\n", .{});
    std.debug.print("The next step is to compare these constants with the actual Plonky3 values.\n", .{});
}
