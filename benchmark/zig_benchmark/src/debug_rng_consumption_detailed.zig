const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Detailed RNG Consumption Analysis ===\n", .{});
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

    std.debug.print("\n=== RNG State Analysis ===\n", .{});
    std.debug.print("First 20 RNG values (DefaultPrng):\n", .{});
    var rng = std.Random.DefaultPrng.init(seed_u64);
    for (0..20) |i| {
        const val = rng.random().int(u32);
        std.debug.print("  [{}] = {} (0x{x})\n", .{ i, val, val });
    }

    std.debug.print("\n=== Key Generation with RNG Tracking ===\n", .{});
    std.debug.print("RNG values consumed during key generation:\n", .{});

    // Track RNG consumption during key generation
    var rng2 = std.Random.DefaultPrng.init(seed_u64);
    var rng_values = std.ArrayList(u32).init(allocator);
    defer rng_values.deinit();

    for (0..50) |i| { // Track first 50 values
        const val = rng2.random().int(u32);
        try rng_values.append(val);
        if (i < 20) {
            std.debug.print("  [{}] = {} (0x{x})\n", .{ i, val, val });
        }
    }

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Final root values: {any}\n", .{result.public_key.root});

    std.debug.print("\n=== RNG State After Key Generation ===\n", .{});
    var rng3 = std.Random.DefaultPrng.init(seed_u64);
    const next_val = rng3.random().int(u32);
    std.debug.print("Next RNG value: {} (0x{x})\n", .{ next_val, next_val });

    // Calculate total RNG consumption
    const total_consumed = rng_values.items.len;
    std.debug.print("Total RNG values consumed: {}\n", .{total_consumed});

    // Show the pattern of RNG consumption
    std.debug.print("\n=== RNG Consumption Pattern ===\n", .{});
    std.debug.print("First 10 values: {any}\n", .{rng_values.items[0..10]});
    std.debug.print("Values 10-20: {any}\n", .{rng_values.items[10..20]});
    if (rng_values.items.len > 20) {
        std.debug.print("Values 20-30: {any}\n", .{rng_values.items[20..30]});
    }
    if (rng_values.items.len > 30) {
        std.debug.print("Values 30-40: {any}\n", .{rng_values.items[30..40]});
    }
    if (rng_values.items.len > 40) {
        std.debug.print("Values 40-50: {any}\n", .{rng_values.items[40..50]});
    }
}
