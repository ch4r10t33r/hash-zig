const std = @import("std");
const poseidon2 = @import("src/poseidon2/poseidon2.zig");

pub fn main() !void {
    std.debug.print("=== Round Constants Verification ===\n", .{});

    // Print first few round constants
    std.debug.print("First 4 internal round constants:\n", .{});
    for (0..4) |i| {
        std.debug.print("  RC[{}] = 0x{x} ({})\n", .{ i, poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[i], poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[i] });
    }

    std.debug.print("\nFirst external round constants (initial):\n", .{});
    for (0..4) |i| {
        std.debug.print("  External RC[0][{}] = 0x{x} ({})\n", .{ i, poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0][i], poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0][i] });
    }

    // Let's also check if there are any obvious issues with the constants
    std.debug.print("\nChecking for potential issues:\n", .{});

    // Check if any constants are zero
    var has_zero = false;
    for (poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL) |rc| {
        if (rc == 0) {
            has_zero = true;
            break;
        }
    }
    std.debug.print("Internal constants have zero: {}\n", .{has_zero});

    // Check external constants
    var external_has_zero = false;
    for (poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL) |round| {
        for (round) |rc| {
            if (rc == 0) {
                external_has_zero = true;
                break;
            }
        }
    }
    std.debug.print("External constants have zero: {}\n", .{external_has_zero});

    // Check if constants are within reasonable range
    var max_internal: u32 = 0;
    for (poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL) |rc| {
        if (rc > max_internal) max_internal = rc;
    }
    std.debug.print("Max internal constant: 0x{x} ({})\n", .{ max_internal, max_internal });

    var max_external: u32 = 0;
    for (poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL) |round| {
        for (round) |rc| {
            if (rc > max_external) max_external = rc;
        }
    }
    std.debug.print("Max external constant: 0x{x} ({})\n", .{ max_external, max_external });
}
