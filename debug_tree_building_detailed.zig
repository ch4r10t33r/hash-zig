const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Detailed Tree Building Analysis ===\n", .{});

    // Create scheme with same seed as benchmark
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, [_]u8{0x42} ** 32);
    defer scheme.deinit();

    std.debug.print("Scheme RNG state: {any}\n", .{scheme.getRngState()});

    // Generate parameters (should match Rust exactly)
    const parameters = try scheme.generateRandomParameter();
    std.debug.print("Parameters: {any}\n", .{parameters});

    // Generate PRF key (should match Rust exactly)
    const prf_key = try scheme.generateRandomPRFKey();
    std.debug.print("PRF key: {}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Test domain element generation for epoch 0, chain 0
    std.debug.print("\n=== Testing Domain Element Generation ===\n", .{});
    const domain_elements = try scheme.generateRandomDomain(8);
    std.debug.print("Domain elements: {any}\n", .{domain_elements});

    // Test chain computation for epoch 0, chain 0
    std.debug.print("\n=== Testing Chain Computation ===\n", .{});
    const chain_end = try scheme.applyPoseidonChainTweakHash(domain_elements, 0, // epoch
        0, // chain_index
        0, // pos_in_chain
        parameters);
    std.debug.print("Chain end: 0x{x}\n", .{chain_end[0].value});

    // Test bottom tree building
    std.debug.print("\n=== Testing Bottom Tree Building ===\n", .{});
    var leaf_hashes = [_]hash_zig.FieldElement{chain_end[0]};
    const bottom_tree_root = try scheme.buildBottomTree(&leaf_hashes, parameters);
    std.debug.print("Bottom tree root: 0x{x}\n", .{bottom_tree_root[0].value});

    // Test top tree building with multiple bottom tree roots
    std.debug.print("\n=== Testing Top Tree Building ===\n", .{});
    var bottom_tree_roots: [16][8]hash_zig.FieldElement = undefined;
    for (0..16) |i| {
        for (0..8) |j| {
            bottom_tree_roots[i][j] = hash_zig.FieldElement{ .value = @intCast(i * 8 + j) };
        }
    }

    const top_tree_root = try scheme.buildTopTreeAsArray(&bottom_tree_roots, parameters);
    std.debug.print("Top tree root: {any}\n", .{top_tree_root});
}
