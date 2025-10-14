//! Debug compatibility issues between Zig and Rust
//!
//! This program outputs detailed intermediate values for debugging

const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🔍 DEBUG: Zig vs Rust Compatibility\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Test 1: ChaCha12 RNG Output
    std.debug.print("Test 1: ChaCha12 RNG (PRF Key Generation)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    
    var prf_key: [32]u8 = undefined;
    var rng = hash_zig.chacha12_rng.init(seed);
    rng.fill(&prf_key);

    std.debug.print("Seed:    ", .{});
    for (seed[0..16]) |byte| std.debug.print("{x:0>2}", .{byte});
    std.debug.print("...\n", .{});

    std.debug.print("PRF Key: ", .{});
    for (prf_key) |byte| std.debug.print("{x:0>2}", .{byte});
    std.debug.print("\n\n", .{});

    // Test 2: PRF Output (First Chain, First Epoch)
    std.debug.print("Test 2: PRF Output (epoch=0, chain_index=0)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var hash = try hash_zig.TweakableHash.init(allocator, params);
    defer hash.deinit();

    const prf_output = try hash.prfHashFieldElements(allocator, &prf_key, 0, 0, 7);
    defer allocator.free(prf_output);

    std.debug.print("PRF output (7 field elements):\n", .{});
    for (prf_output, 0..) |elem, i| {
        std.debug.print("  [{d}]: {d} (0x{x:0>8})\n", .{ i, elem.value, elem.value });
    }
    std.debug.print("\n", .{});

    // Test 3: Simple Poseidon2 Permutation
    std.debug.print("Test 3: Poseidon2 Permutation (simple input)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var simple_input: [4]hash_zig.FieldElement = undefined;
    for (0..4) |i| {
        simple_input[i] = hash_zig.FieldElement.fromU32(@intCast(i));
    }

    std.debug.print("Input:  ", .{});
    for (simple_input) |elem| {
        std.debug.print("{d} ", .{elem.value});
    }
    std.debug.print("\n", .{});

    const tweak = hash_zig.PoseidonTweak{ .tree_tweak = .{
        .level = 0,
        .pos_in_level = 0,
    } };

    const output = try hash.hashFieldElements(allocator, &simple_input, tweak, 1);
    defer allocator.free(output);

    std.debug.print("Output: {d} (0x{x:0>8})\n\n", .{ output[0].value, output[0].value });

    // Test 4: First OTS Public Key (Epoch 0)
    std.debug.print("Test 4: First OTS Public Key (epoch=0)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var wots = try hash_zig.WinternitzOTSNative.init(allocator, params);
    defer wots.deinit();

    const sk = try wots.generatePrivateKey(allocator, &prf_key, 0);
    defer {
        for (sk) |k| allocator.free(k);
        allocator.free(sk);
    }

    std.debug.print("Private key (first chain, first 4 elements):\n", .{});
    if (sk.len > 0 and sk[0].len >= 4) {
        for (sk[0][0..4], 0..) |elem, i| {
            std.debug.print("  [{d}]: {d} (0x{x:0>8})\n", .{ i, elem.value, elem.value });
        }
    }
    std.debug.print("\n", .{});

    const pk = try wots.generatePublicKey(allocator, sk, 0);
    defer allocator.free(pk);

    std.debug.print("Public key (first 4 elements out of {d} total):\n", .{pk.len});
    for (pk[0..@min(4, pk.len)], 0..) |elem, i| {
        std.debug.print("  [{d}]: {d} (0x{x:0>8})\n", .{ i, elem.value, elem.value });
    }
    std.debug.print("\n", .{});

    // Test 5: First Tree Leaf
    std.debug.print("Test 5: First Tree Leaf (hashed OTS public key)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const leaf_tweak = hash_zig.PoseidonTweak{ .tree_tweak = .{
        .level = 0,
        .pos_in_level = 0,
    } };

    const leaf_hash = try hash.hashFieldElements(allocator, pk, leaf_tweak, 1);
    defer allocator.free(leaf_hash);

    std.debug.print("Leaf[0]: {d} (0x{x:0>8})\n\n", .{ leaf_hash[0].value, leaf_hash[0].value });

    // Test 6: Tweak Encoding
    std.debug.print("Test 6: Tweak Encoding\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const tree_tweak = hash_zig.PoseidonTweak{ .tree_tweak = .{
        .level = 1,
        .pos_in_level = 0,
    } };

    const tweak_fes = tree_tweak.toFieldElements(2);
    std.debug.print("TreeTweak{{level=1, pos=0}} → [{d}, {d}]\n", .{
        tweak_fes[0].value,
        tweak_fes[1].value,
    });

    const chain_tweak = hash_zig.PoseidonTweak{ .chain_tweak = .{
        .epoch = 0,
        .chain_index = 0,
        .pos_in_chain = 0,
    } };

    const chain_tweak_fes = chain_tweak.toFieldElements(2);
    std.debug.print("ChainTweak{{epoch=0, chain=0, pos=0}} → [{d}, {d}]\n\n", .{
        chain_tweak_fes[0].value,
        chain_tweak_fes[1].value,
    });

    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("✅ Debug output complete\n", .{});
    std.debug.print("Compare these values with Rust implementation to find divergence point\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}

