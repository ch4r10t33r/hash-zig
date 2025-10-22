const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const seed_hex = std.process.getEnvVarOwned(allocator, "SEED_HEX") catch "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242";
    defer allocator.free(seed_hex);

    std.debug.print("=== Zig Tree Construction Detailed Analysis ===\n", .{});
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

    std.debug.print("\n=== Key Generation with Tree Construction Analysis ===\n", .{});
    const result = try scheme.keyGen(0, 256);
    defer result.secret_key.deinit();

    std.debug.print("=== Final Results ===\n", .{});
    std.debug.print("Root values: {any}\n", .{result.public_key.root});
    std.debug.print("Parameter values: {any}\n", .{result.public_key.parameter});

    // Show hex values for easy comparison
    std.debug.print("\n=== Hex Values for Comparison ===\n", .{});
    std.debug.print("Root values (hex):\n", .{});
    for (result.public_key.root, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    std.debug.print("Parameter values (hex):\n", .{});
    for (result.public_key.parameter, 0..) |val, i| {
        std.debug.print("  [{}] = 0x{x} ({})\n", .{ i, val.value, val.value });
    }

    // Show the exact values that should match
    std.debug.print("\n=== Expected Rust Values ===\n", .{});
    std.debug.print("Rust should produce these exact values:\n", .{});
    std.debug.print("Root values: [0x103f1bb5, 0x30b1d019, 0x61d32bd3, 0x55611904, 0x70f21cee, 0x5b96b359, 0x287c76b5, 0x3867c91b]\n", .{});
    std.debug.print("Parameter values: [0x43438199, 0x6e1ec07a, 0x76ddd3e4, 0x6fb9732d, 0x4da34f48]\n", .{});

    // Check if values match
    const expected_root = [_]u32{ 0x103f1bb5, 0x30b1d019, 0x61d32bd3, 0x55611904, 0x70f21cee, 0x5b96b359, 0x287c76b5, 0x3867c91b };
    const expected_param = [_]u32{ 0x43438199, 0x6e1ec07a, 0x76ddd3e4, 0x6fb9732d, 0x4da34f48 };

    var root_matches = true;
    for (result.public_key.root, 0..) |val, i| {
        if (val.value != expected_root[i]) {
            root_matches = false;
            break;
        }
    }

    var param_matches = true;
    for (result.public_key.parameter, 0..) |val, i| {
        if (val.value != expected_param[i]) {
            param_matches = false;
            break;
        }
    }

    std.debug.print("\n=== Comparison Results ===\n", .{});
    std.debug.print("Root values match: {}\n", .{root_matches});
    std.debug.print("Parameter values match: {}\n", .{param_matches});

    if (!root_matches) {
        std.debug.print("ROOT MISMATCH DETECTED!\n", .{});
        std.debug.print("Expected: [0x103f1bb5, 0x30b1d019, 0x61d32bd3, 0x55611904, 0x70f21cee, 0x5b96b359, 0x287c76b5, 0x3867c91b]\n", .{});
        std.debug.print("Actual:   [0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}, 0x{x}]\n", .{ result.public_key.root[0].value, result.public_key.root[1].value, result.public_key.root[2].value, result.public_key.root[3].value, result.public_key.root[4].value, result.public_key.root[5].value, result.public_key.root[6].value, result.public_key.root[7].value });
    }
}
