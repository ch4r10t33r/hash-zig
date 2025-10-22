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

    // Generate parameter and PRF key
    const parameter = try scheme.generateRandomParameter();
    const prf_key = try scheme.generateRandomPRFKey();

    std.debug.print("Parameter: {any}\n", .{parameter});
    std.debug.print("PRF key: {}\n", .{std.fmt.fmtSliceHexLower(prf_key)});

    // Test domain element generation for first epoch and chain
    const domain_elements = hash_zig.ShakePRFtoF_8_7.getDomainElement(prf_key, 0, 0);
    std.debug.print("Domain elements for epoch=0, chain=0: {any}\n", .{domain_elements});

    // Test chain computation for first epoch and chain
    const chain_end = try scheme.computeHashChain(domain_elements, 0, 0, parameter);
    std.debug.print("Chain end for epoch=0, chain=0: 0x{x}\n", .{chain_end.value});
}
