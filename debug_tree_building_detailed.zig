const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use the same seed as Rust
    const seed_hex = "4242424242424242424242424242424242424242424242424242424242424242";
    var seed: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = std.fmt.parseInt(u8, seed_hex[i * 2 .. i * 2 + 1], 16) catch 0;
        const lo = std.fmt.parseInt(u8, seed_hex[i * 2 + 1 .. i * 2 + 2], 16) catch 0;
        seed[i] = (hi << 4) | lo;
    }

    std.debug.print("SEED (bytes): {any}\n", .{seed});

    // Create signature scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    // Generate keypair
    const keypair = try scheme.keyGen(seed);

    // Print the public key
    const pk_json = try hash_zig.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(pk_json);

    std.debug.print("Public Key (JSON): {s}\n", .{pk_json});
}
