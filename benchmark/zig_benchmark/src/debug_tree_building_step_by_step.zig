const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    log.print("=== Zig Tree Building Step-by-Step Analysis ===\n", .{});
    log.print("SEED: {s}\n", .{seed_hex});

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

    log.print("\n=== Key Generation ===\n", .{});
    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    log.print("Final root values: {any}\n", .{result.public_key.root});
    log.print("Parameter values: {any}\n", .{result.public_key.parameter});

    // Show the exact values in hex
    log.print("\n=== Hex Values ===\n", .{});
    log.print("Root values (hex):\n", .{});
    for (result.public_key.root, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    log.print("Parameter values (hex):\n", .{});
    for (result.public_key.parameter, 0..) |val, i| {
        log.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }
}
