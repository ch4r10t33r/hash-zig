const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    std.debug.print("=== Chain Computation Debug ===\n", .{});

    // Use the same seed as the comparison test
    const seed = [_]u8{0x42} ** 32;

    // Initialize RNG
    var rng = hash_zig.prf.ChaCha12Rng.init(seed);

    std.debug.print("SEED: {x}\n", .{std.fmt.fmtSliceHexUpper(&seed)});

    // Generate parameters and PRF key (same as before)
    var parameter: [5]hash_zig.core.FieldElement = undefined;
    for (0..5) |i| {
        parameter[i] = hash_zig.core.FieldElement{ .value = rng.random().int(u32) };
    }

    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);

    std.debug.print("Parameter: {any}\n", .{parameter});
    std.debug.print("PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Test the first few domain elements and chain computations
    std.debug.print("\nTesting domain elements and chain computations:\n", .{});

    // Test domain element generation for epoch 0, chain 0
    const domain_elements_0_0 = hash_zig.prf.ShakePRFtoF_8_7.getDomainElement(prf_key, 0, 0);
    std.debug.print("Domain elements for epoch 0, chain 0: {any}\n", .{domain_elements_0_0});

    // Test domain element generation for epoch 0, chain 1
    const domain_elements_0_1 = hash_zig.prf.ShakePRFtoF_8_7.getDomainElement(prf_key, 0, 1);
    std.debug.print("Domain elements for epoch 0, chain 1: {any}\n", .{domain_elements_0_1});

    // Test domain element generation for epoch 1, chain 0
    const domain_elements_1_0 = hash_zig.prf.ShakePRFtoF_8_7.getDomainElement(prf_key, 1, 0);
    std.debug.print("Domain elements for epoch 1, chain 0: {any}\n", .{domain_elements_1_0});

    // Check RNG state after domain element generation
    std.debug.print("\nRNG state after domain element generation:\n", .{});
    for (0..10) |i| {
        const val = rng.random().int(u32);
        std.debug.print("  [{}] = {}\n", .{ i, val });
    }
}
