const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    std.debug.print("=== Parameter Generation Debug ===\n", .{});

    // Use the same seed as the comparison test
    const seed = [_]u8{0x42} ** 32;

    // Initialize RNG
    var rng = hash_zig.prf.ChaCha12Rng.init(seed);

    std.debug.print("SEED: {x}\n", .{std.fmt.fmtSliceHexUpper(&seed)});
    std.debug.print("SEED (bytes): {any}\n", .{seed});

    // Generate parameters exactly like in the key generation
    std.debug.print("\nGenerating parameters...\n", .{});

    var parameter: [5]hash_zig.core.FieldElement = undefined;
    for (0..5) |i| {
        const val = rng.random().int(u32);
        parameter[i] = hash_zig.core.FieldElement{ .value = val };
        std.debug.print("Parameter[{}] = {} (0x{x})\n", .{ i, val, val });
    }

    std.debug.print("\nParameter array: {any}\n", .{parameter});

    // Generate PRF key
    std.debug.print("\nGenerating PRF key...\n", .{});
    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);
    std.debug.print("PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Check RNG state after parameter and PRF key generation
    std.debug.print("\nRNG state after parameter and PRF key generation:\n", .{});
    for (0..10) |i| {
        const val = rng.random().int(u32);
        std.debug.print("  [{}] = {}\n", .{ i, val });
    }
}
