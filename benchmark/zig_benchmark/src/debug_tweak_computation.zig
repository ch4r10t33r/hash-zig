const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Tweak Computation Analysis ===\n", .{});
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

    std.debug.print("\n=== Tweak Computation Test ===\n", .{});

    // Test tweak computation for different levels and positions
    const test_cases = [_]struct { level: u8, pos: u32 }{
        .{ .level = 5, .pos = 0 },
        .{ .level = 5, .pos = 1 },
        .{ .level = 6, .pos = 0 },
        .{ .level = 6, .pos = 1 },
        .{ .level = 7, .pos = 0 },
        .{ .level = 7, .pos = 1 },
    };

    for (test_cases) |test_case| {
        // Compute tweak: ((level as u128) << 40) | ((pos_in_level as u128) << 8) | 0x01
        const tweak_bigint = (@as(u128, test_case.level) << 40) | (@as(u128, test_case.pos) << 8) | 0x01;

        // Convert to 2 field elements using base-p representation
        const p: u128 = 2130706433; // KoalaBear field modulus
        const tweak = [_]hash_zig.FieldElement{
            hash_zig.FieldElement{ .value = @as(u32, @intCast(tweak_bigint % p)) },
            hash_zig.FieldElement{ .value = @as(u32, @intCast((tweak_bigint / p) % p)) },
        };

        std.debug.print("Level {}, Pos {}: tweak_bigint = 0x{x}, tweak[0] = 0x{x}, tweak[1] = 0x{x}\n", .{ test_case.level, test_case.pos, tweak_bigint, tweak[0].value, tweak[1].value });
    }

    std.debug.print("\n=== Tree Building with Tweak Debug ===\n", .{});

    // Generate a key to see the tree building process
    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("Final root values: {any}\n", .{result.public_key.root});
}
