const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig RNG Consumption During Tree Building ===\n", .{});
    std.debug.print("SEED: {s}\n", .{seed_hex});

    // Parse seed
    const seed_bytes = try std.fmt.allocPrint(allocator, "{s}", .{seed_hex});
    defer allocator.free(seed_bytes);

    var seed_array: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = seed_bytes[i * 2 .. i * 2 + 2];
        seed_array[i] = std.fmt.parseInt(u8, hex_pair, 16) catch unreachable;
    }

    // Use first 8 bytes as u64 seed for DefaultPrng comparison
    const seed_u64 = std.mem.readInt(u64, seed_array[0..8], .little);

    std.debug.print("\n=== RNG State Before Key Generation ===\n", .{});
    std.debug.print("First 10 RNG values (DefaultPrng):\n", .{});
    var rng = std.Random.DefaultPrng.init(seed_u64);
    for (0..10) |i| {
        const val = rng.random().int(u32);
        std.debug.print("  [{}] = {} (0x{x})\n", .{ i, val, val });
    }

    std.debug.print("\n=== Key Generation ===\n", .{});
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("Final root values: {any}\n", .{result.public_key.root});

    std.debug.print("\n=== RNG State After Key Generation ===\n", .{});
    var rng2 = std.Random.DefaultPrng.init(seed_u64);
    const next_val = rng2.random().int(u32);
    std.debug.print("Next RNG value: {} (0x{x})\n", .{ next_val, next_val });

    std.debug.print("Next 5 RNG values after key generation:\n", .{});
    for (0..5) |i| {
        const val = rng2.random().int(u32);
        std.debug.print("  [{}] = {} (0x{x})\n", .{ i, val, val });
    }
}
