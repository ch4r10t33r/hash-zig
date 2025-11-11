const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    log.print("=== Zig Round Constants Debug ===\n", .{});

    // Test round constants from our implementation
    log.print("\n=== External Initial Round Constants (16-width) ===\n", .{});
    const poseidon2 = @import("../../src/poseidon2/root.zig");
    const rc_initial = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL;

    for (rc_initial, 0..) |round, i| {
        log.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) log.print(", ", .{});
            log.print("0x{x}", .{val});
        }
        log.print("]\n", .{});
    }

    log.print("\n=== External Final Round Constants (16-width) ===\n", .{});
    const rc_final = poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL;

    for (rc_final, 0..) |round, i| {
        log.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) log.print(", ", .{});
            log.print("0x{x}", .{val});
        }
        log.print("]\n", .{});
    }

    log.print("\n=== Internal Round Constants (16-width) ===\n", .{});
    const rc_internal = poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL;

    for (rc_internal, 0..) |round, i| {
        log.print("Round {}: [", .{i});
        for (round, 0..) |val, j| {
            if (j > 0) log.print(", ", .{});
            log.print("0x{x}", .{val});
        }
        log.print("]\n", .{});
    }

    // Test if the issue is in the round constants themselves
    log.print("\n=== Round Constants Analysis ===\n", .{});
    log.print("The round constants should match Plonky3 exactly.\n", .{});
    log.print("If they don't match, that would explain the different results.\n", .{});

    // Test specific round constants that might be causing issues
    log.print("\n=== Test Specific Round Constants ===\n", .{});

    // Test the first round constant
    const first_rc = rc_initial[0];
    log.print("First round constant: [", .{});
    for (first_rc, 0..) |val, i| {
        if (i > 0) log.print(", ", .{});
        log.print("0x{x}", .{val});
    }
    log.print("]\n", .{});

    // Test if the issue is in the round constant application
    log.print("\n=== Round Constant Application Test ===\n", .{});
    log.print("The issue might be in how the round constants are applied.\n", .{});
    log.print("Let's check if the round constants are being applied correctly.\n", .{});

    log.print("\n=== Analysis ===\n", .{});
    log.print("The round constants should match Plonky3 exactly.\n", .{});
    log.print("If they don't match, that would explain the different results.\n", .{});
    log.print("The next step is to compare these constants with the actual Plonky3 values.\n", .{});
}
