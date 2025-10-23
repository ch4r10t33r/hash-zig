const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    std.debug.print("=== Parameter Generation RNG Consumption ===\n", .{});

    // Use same seed as Rust
    const seed = [_]u8{0x42} ** 32;
    std.debug.print("SEED: {any}\n\n", .{seed});

    // Create scheme with fixed seed
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed);

    // Print initial RNG state
    std.debug.print("Initial RNG state: {any}\n", .{scheme.getRngState()});

    // Generate parameters and track RNG consumption
    std.debug.print("\n=== Parameter Generation ===\n", .{});
    const parameter = try scheme.generateRandomParameter();
    std.debug.print("Parameters: {any}\n", .{parameter});
    std.debug.print("RNG state after parameter generation: {any}\n", .{scheme.getRngState()});

    // Clean up memory
    scheme.deinit();
}
