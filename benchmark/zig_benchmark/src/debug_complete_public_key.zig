const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = envVarOwned(allocator, init, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Complete Public Key ===\n", .{});
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

    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("Public Key Root: {any}\n", .{result.public_key.root});
    std.debug.print("Public Key Parameters: {any}\n", .{result.public_key.parameter});
}

fn envVarOwned(allocator: std.mem.Allocator, init: std.process.Init, key: []const u8) ![]u8 {
    const value = init.environ_map.get(key) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}
