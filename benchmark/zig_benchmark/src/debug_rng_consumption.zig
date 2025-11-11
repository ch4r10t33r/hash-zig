const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;
const LifetimeParams = hash_zig.LifetimeParams;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";

    log.print("=== Zig RNG Consumption Investigation ===\n", .{});
    log.print("SEED: {s}\n", .{seed_hex});

    // Parse seed - use first 8 bytes as u64 seed
    const seed_bytes = try std.fmt.allocPrint(allocator, "{s}", .{seed_hex});
    defer allocator.free(seed_bytes);

    var seed_array: [32]u8 = undefined;
    for (0..32) |i| {
        const hex_pair = seed_bytes[i * 2 .. i * 2 + 2];
        seed_array[i] = std.fmt.parseInt(u8, hex_pair, 16) catch unreachable;
    }

    // Use first 8 bytes as u64 seed for DefaultPrng
    const seed_u64 = std.mem.readInt(u64, seed_array[0..8], .little);

    log.print("\n=== Step 1: First 10 RNG values ===\n", .{});
    var rng = std.Random.DefaultPrng.init(seed_u64);
    for (0..10) |i| {
        const val = rng.random().int(u32);
        log.print("  [{}] = {} (0x{x})\n", .{ i, val, val });
    }

    log.print("\n=== Step 2: Run key_gen and check parameters ===\n", .{});
    var scheme = try GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed_array);
    defer scheme.deinit();

    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    log.print("Public key parameters: {any}\n", .{result.public_key.parameter});

    log.print("\n=== Step 4: Check RNG state after key_gen ===\n", .{});
    // Create a new RNG to check the state
    var rng4 = std.Random.DefaultPrng.init(seed_u64);
    const next_val = rng4.random().int(u32);
    log.print("Next RNG value after key_gen: {} (0x{x})\n", .{ next_val, next_val });
}
