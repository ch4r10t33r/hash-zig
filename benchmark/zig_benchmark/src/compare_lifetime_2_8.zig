const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig hash-zig Determinism Check (lifetime 2^8)\n", .{});
    std.debug.print("================================================\n", .{});

    // Deterministic 32-byte seed (0x42 repeated) to mirror Rust StdRng example
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var scheme1 = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed);
    defer scheme1.deinit();

    var scheme2 = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed);
    defer scheme2.deinit();

    const kp1 = try scheme1.keyGen(0, 256);
    defer kp1.secret_key.deinit();

    const kp2 = try scheme2.keyGen(0, 256);
    defer kp2.secret_key.deinit();

    const root1 = kp1.public_key.getRoot();
    const root2 = kp2.public_key.getRoot();

    const param1 = kp1.public_key.getParameter();
    const param2 = kp2.public_key.getParameter();

    const roots_equal = root1.value == root2.value;
    var params_equal = true;
    inline for (param1, 0..) |fe, i| {
        if (fe.value != param2[i].value) {
            params_equal = false;
            break;
        }
    }

    const equal = roots_equal and params_equal;
    std.debug.print("Public keys equal: {}\n", .{equal});
    if (equal) {
        std.debug.print("✅ Deterministic: same seed -> identical public keys (2^8)\n", .{});
    } else {
        std.debug.print("❌ Different public keys (2^8).\n", .{});
    }
}
