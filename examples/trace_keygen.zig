const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("COMPLETE KEY GENERATION TRACE (Lifetime 2^10)\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    const seed = [_]u8{0x42} ** 32;
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    std.debug.print("Parameters:\n", .{});
    std.debug.print("  tree_height: {d}\n", .{params.tree_height});
    std.debug.print("  num_message_chains: {d}\n", .{params.num_message_chains});
    std.debug.print("  num_checksum_chains: {d}\n", .{params.num_checksum_chains});
    std.debug.print("  total_chains: {d}\n", .{params.num_message_chains + params.num_checksum_chains});
    std.debug.print("  chain_hash_output_len_fe: {d}\n", .{params.chain_hash_output_len_fe});
    std.debug.print("  tree_hash_output_len_fe: {d}\n", .{params.tree_hash_output_len_fe});
    std.debug.print("\n", .{});

    // === STEP 1: Initialize RNG ===
    std.debug.print("STEP 1: Initialize RNG with seed\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    std.debug.print("Seed: {s}\n\n", .{std.fmt.fmtSliceHexLower(&seed)});

    var rng = hash_zig.chacha12_rng.init(seed);

    // === STEP 2: Generate parameter (5 FE) ===
    std.debug.print("STEP 2: Generate parameter (5 field elements)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var parameter: [5]hash_zig.FieldElement = undefined;
    for (0..5) |i| {
        var bytes: [4]u8 = undefined;
        rng.fill(&bytes);
        const val = std.mem.readInt(u32, &bytes, .little);
        parameter[i] = hash_zig.FieldElement.fromU32(val);
        std.debug.print("parameter[{d}] = {d} (0x{x:0>8})\n", .{ i, val, val });
    }
    std.debug.print("\n", .{});

    // === STEP 3: Generate PRF key ===
    std.debug.print("STEP 3: Generate PRF key (32 bytes)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);
    std.debug.print("PRF key: {s}\n\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // === STEP 4: Generate first OTS private key (epoch 0) ===
    std.debug.print("STEP 4: Generate first OTS private key (epoch 0)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const num_chains = params.num_message_chains + params.num_checksum_chains;
    std.debug.print("Total chains: {d}\n", .{num_chains});
    std.debug.print("Output length per chain: {d} field elements\n\n", .{params.chain_hash_output_len_fe});

    // Show first 2 chains
    for (0..@min(2, num_chains)) |chain_idx| {
        const chain_output = try hash_zig.prf.ShakePRF.getDomainElementsNative(
            allocator,
            &prf_key,
            0, // epoch
            chain_idx,
            params.chain_hash_output_len_fe,
        );
        defer allocator.free(chain_output);

        std.debug.print("Chain {d} (epoch=0, chain={d}):\n", .{ chain_idx, chain_idx });
        for (chain_output, 0..) |elem, i| {
            std.debug.print("  [{d}] = {d}\n", .{ i, elem.toU32() });
        }
        std.debug.print("\n", .{});
    }

    // === STEP 5: Generate first OTS public key ===
    std.debug.print("STEP 5: Generate first OTS public key\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var param_wots = try hash_zig.WinternitzOTSNative.initWithParameter(
        allocator,
        params,
        parameter,
    );
    defer param_wots.deinit();

    const first_sk = try param_wots.generatePrivateKey(allocator, &prf_key, 0);
    defer {
        for (first_sk) |chain| {
            allocator.free(chain);
        }
        allocator.free(first_sk);
    }

    const first_pk = try param_wots.generatePublicKey(allocator, first_sk, 0);
    defer allocator.free(first_pk);

    std.debug.print("Public key length: {d} field elements\n\n", .{first_pk.len});

    // Show first 10 elements of public key
    std.debug.print("First 10 elements of public key:\n", .{});
    for (0..@min(10, first_pk.len)) |i| {
        std.debug.print("  [{d}] = {d}\n", .{ i, first_pk[i].toU32() });
    }
    std.debug.print("\n", .{});

    // === STEP 6: Hash OTS public key to get tree leaf ===
    std.debug.print("STEP 6: Hash OTS public key to tree leaf\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    std.debug.print("Total public key length: {d} field elements\n", .{first_pk.len});
    std.debug.print("First 5 elements: ", .{});
    for (0..@min(5, first_pk.len)) |i| {
        std.debug.print("{d}", .{first_pk[i].toU32()});
        if (i < 4) std.debug.print(", ", .{});
    }
    std.debug.print("\nLast 2 elements: {d}, {d}\n\n", .{
        first_pk[first_pk.len - 2].toU32(),
        first_pk[first_pk.len - 1].toU32(),
    });

    const tree_tweak = hash_zig.PoseidonTweak{
        .tree_tweak = .{
            .level = 0,
            .pos_in_level = 0,
        },
    };

    // For lifetime_2_10: tree_hash_output_len_fe = 7
    const first_leaf = try param_wots.hash.hashFieldElements(
        allocator,
        first_pk,
        tree_tweak,
        7, // comptime value for lifetime_2_10
    );
    defer allocator.free(first_leaf);

    std.debug.print("Tree leaf (level=0, pos=0):\n", .{});
    for (first_leaf, 0..) |elem, i| {
        std.debug.print("  [{d}] = {d}\n", .{ i, elem.toU32() });
    }
    std.debug.print("\n", .{});

    // === STEP 7: Generate second leaf for comparison ===
    std.debug.print("STEP 7: Generate second tree leaf (epoch 1)\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    const second_sk = try param_wots.generatePrivateKey(allocator, &prf_key, 1);
    defer {
        for (second_sk) |chain| {
            allocator.free(chain);
        }
        allocator.free(second_sk);
    }

    const second_pk = try param_wots.generatePublicKey(allocator, second_sk, 1);
    defer allocator.free(second_pk);

    const tree_tweak2 = hash_zig.PoseidonTweak{
        .tree_tweak = .{
            .level = 0,
            .pos_in_level = 1,
        },
    };

    const second_leaf = try param_wots.hash.hashFieldElements(
        allocator,
        second_pk,
        tree_tweak2,
        7, // comptime value for lifetime_2_10
    );
    defer allocator.free(second_leaf);

    std.debug.print("Tree leaf (level=0, pos=1):\n", .{});
    for (second_leaf, 0..) |elem, i| {
        std.debug.print("  [{d}] = {d}\n", .{ i, elem.toU32() });
    }
    std.debug.print("\n", .{});

    // === STEP 8: Compute parent node ===
    std.debug.print("STEP 8: Compute parent node from first two leaves\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    // Combine two leaves
    var combined = try allocator.alloc(hash_zig.FieldElement, first_leaf.len + second_leaf.len);
    defer allocator.free(combined);

    @memcpy(combined[0..first_leaf.len], first_leaf);
    @memcpy(combined[first_leaf.len..], second_leaf);

    std.debug.print("Combined input length: {d} field elements\n", .{combined.len});
    std.debug.print("First 5 elements: ", .{});
    for (0..@min(5, combined.len)) |i| {
        std.debug.print("{d}", .{combined[i].toU32()});
        if (i < 4) std.debug.print(", ", .{});
    }
    std.debug.print("\n\n", .{});

    const parent_tweak = hash_zig.PoseidonTweak{
        .tree_tweak = .{
            .level = 1,
            .pos_in_level = 0,
        },
    };

    const parent_node = try param_wots.hash.hashFieldElements(
        allocator,
        combined,
        parent_tweak,
        7, // comptime value for lifetime_2_10
    );
    defer allocator.free(parent_node);

    std.debug.print("Parent node (level=1, pos=0):\n", .{});
    for (parent_node, 0..) |elem, i| {
        std.debug.print("  [{d}] = {d}\n", .{ i, elem.toU32() });
    }
    std.debug.print("\n", .{});

    std.debug.print("=" ** 80 ++ "\n", .{});
    std.debug.print("✅ Trace complete - Use these values to compare with Rust\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
