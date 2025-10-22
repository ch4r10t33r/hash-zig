const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Internal RNG State Analysis ===\n", .{});
    std.debug.print("SEED: {s}\n", .{seed_hex});

    // Parse seed
    const seed_bytes = try std.fmt.allocPrint(allocator, "{s}", .{seed_hex});
    defer allocator.free(seed_bytes);

    var seed_array: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = seed_bytes[i * 2 .. i * 2 + 2];
        seed_array[i] = std.fmt.parseInt(u8, hex_pair, 16) catch unreachable;
    }

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    std.debug.print("\n=== Internal RNG State Before Key Generation ===\n", .{});
    // Access the internal RNG to check its state
    std.debug.print("Internal RNG state before: {any}\n", .{scheme.rng});

    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("\n=== Internal RNG State After Key Generation ===\n", .{});
    std.debug.print("Internal RNG state after: {any}\n", .{scheme.rng});

    std.debug.print("\n=== Final Results ===\n", .{});
    std.debug.print("Root values: {any}\n", .{result.public_key.root});
    std.debug.print("Parameter values: {any}\n", .{result.public_key.parameter});
}
