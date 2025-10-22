const std = @import("std");
const poseidon2_plonky3 = @import("src/hash/poseidon2_plonky3_compat.zig");

pub fn main() !void {
    std.debug.print("=== Verifying Round Constants ===\n", .{});
    
    std.debug.print("\nExternal Initial Round 0:\n", .{});
    for (poseidon2_plonky3.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL[0], 0..) |rc, i| {
        if (i < 4) {
            std.debug.print("  RC[{}] = {}\n", .{ i, rc });
        }
    }
    
    std.debug.print("\nInternal Round 0:\n", .{});
    std.debug.print("  RC = {}\n", .{poseidon2_plonky3.PLONKY3_KOALABEAR_RC16_INTERNAL[0]});
    
    std.debug.print("\nExternal Final Round 0:\n", .{});
    for (poseidon2_plonky3.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL[0], 0..) |rc, i| {
        if (i < 4) {
            std.debug.print("  RC[{}] = {}\n", .{ i, rc });
        }
    }
    
    // Compare with Plonky3 values from poseidon2.rs
    std.debug.print("\n=== Expected from Plonky3 ===\n", .{});
    std.debug.print("External Initial Round 0: [2128964168, 288780357, 316938561, 2126233899, ...]\n", .{});
    std.debug.print("Internal Round 0: 2102596038\n", .{});
    std.debug.print("External Final Round 0: [1423960925, 2101391318, 1915532054, 275400051, ...]\n", .{});
}
