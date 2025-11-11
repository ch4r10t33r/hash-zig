const std = @import("std");
const log = @import("hash-zig").utils.log;
const poseidon2 = @import("src/poseidon2/root.zig");

pub fn main() !void {
    log.print("=== Verifying Round Constants ===\n", .{});

    log.print("\nExternal Initial Round 0:\n", .{});
    for (poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0], 0..) |rc, i| {
        if (i < 4) {
            log.print("  RC[{}] = {}\n", .{ i, rc });
        }
    }

    log.print("\nInternal Round 0:\n", .{});
    log.print("  RC = {}\n", .{poseidon2.PLONKY3_KOALABEAR_RC16_INTERNAL[0]});

    log.print("\nExternal Final Round 0:\n", .{});
    for (poseidon2.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL[0], 0..) |rc, i| {
        if (i < 4) {
            log.print("  RC[{}] = {}\n", .{ i, rc });
        }
    }

    // Compare with Plonky3 values from poseidon2.rs
    log.print("\n=== Expected from Plonky3 ===\n", .{});
    log.print("External Initial Round 0: [2128964168, 288780357, 316938561, 2126233899, ...]\n", .{});
    log.print("Internal Round 0: 2102596038\n", .{});
    log.print("External Final Round 0: [1423960925, 2101391318, 1915532054, 275400051, ...]\n", .{});
}
