const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("COMPREHENSIVE FIELD-NATIVE DEBUG OUTPUT\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Use the same seed as Rust
    const seed = [_]u8{0x42} ** 32;
    std.debug.print("Seed: {s}\n\n", .{std.fmt.fmtSliceHexLower(&seed)});

    // Initialize parameters for 2^10
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    std.debug.print("Parameters:\n", .{});
    std.debug.print("  Tree height: {d}\n", .{params.tree_height});
    std.debug.print("  Winternitz w: {d}\n", .{params.winternitz_w});
    std.debug.print("  Message chains: {d}\n", .{params.num_message_chains});
    std.debug.print("  Checksum chains: {d}\n", .{params.num_checksum_chains});
    std.debug.print("  Total chains: {d}\n", .{params.num_message_chains + params.num_checksum_chains});
    std.debug.print("  Chain hash output len (FE): {d}\n", .{params.chain_hash_output_len_fe});
    std.debug.print("  Tree hash output len (FE): {d}\n", .{params.tree_hash_output_len_fe});
    std.debug.print("\n", .{});

    // Step 1: Generate parameter (5 random field elements)
    std.debug.print("Step 1: Generating random parameter...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    var rng = hash_zig.chacha12_rng.init(seed);
    var parameter: [5]hash_zig.FieldElement = undefined;
    for (0..5) |i| {
        var bytes: [4]u8 = undefined;
        rng.fill(&bytes);
        const val = std.mem.readInt(u32, &bytes, .little);
        parameter[i] = hash_zig.FieldElement.fromU32(val);
        std.debug.print("  parameter[{d}] = {d} (0x{x:0>8})\n", .{ i, val, val });
    }
    std.debug.print("\n", .{});

    // Step 2: Generate PRF key (32 bytes)
    std.debug.print("Step 2: Generating PRF key...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);
    std.debug.print("  PRF key: {s}\n\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Step 3: Generate first OTS private key (epoch=0, all chains)
    std.debug.print("Step 3: Generating first OTS private key (epoch 0)...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    const prf = hash_zig.prf.ShakePRF{};
    const num_chains = params.num_message_chains + params.num_checksum_chains;
    
    // Show first 3 chains
    for (0..@min(3, num_chains)) |chain_idx| {
        const chain_output = try hash_zig.prf.ShakePRF.getDomainElementsNative(
            allocator,
            &prf_key,
            0, // epoch
            chain_idx,
            params.chain_hash_output_len_fe,
        );
        defer allocator.free(chain_output);
        
        std.debug.print("  Chain {d}: ", .{chain_idx});
        for (chain_output, 0..) |elem, i| {
            std.debug.print("{d}", .{elem.toU32()});
            if (i < chain_output.len - 1) std.debug.print(", ", .{});
        }
        std.debug.print("\n", .{});
    }
    std.debug.print("  ... ({d} total chains)\n\n", .{num_chains});

    // Step 4: Generate first OTS public key
    std.debug.print("Step 4: Generating first OTS public key...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    var sig_native = try hash_zig.HashSignatureNative.init(allocator, params);
    defer sig_native.deinit();

    // Create parameterized WOTS
    var param_wots = try hash_zig.WinternitzOTSNative.initWithParameter(
        allocator,
        params,
        parameter,
    );
    defer param_wots.deinit();

    const first_sk = try param_wots.generatePrivateKey(allocator, &prf_key, 0);
    defer allocator.free(first_sk);
    
    const first_pk = try param_wots.generatePublicKey(allocator, first_sk);
    defer {
        for (first_pk) |chain| {
            allocator.free(chain);
        }
        allocator.free(first_pk);
    }

    std.debug.print("  First OTS public key has {d} chains\n", .{first_pk.len});
    std.debug.print("  First chain (first 3 elements): ", .{});
    for (0..@min(3, first_pk[0].len)) |i| {
        std.debug.print("{d}", .{first_pk[0][i].toU32()});
        if (i < @min(3, first_pk[0].len) - 1) std.debug.print(", ", .{});
    }
    std.debug.print("\n\n", .{});

    // Step 5: Hash OTS public key to get tree leaf
    std.debug.print("Step 5: Hashing OTS public key to tree leaf...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    // Flatten all chains into single array
    const pk_flat_len = first_pk.len * first_pk[0].len;
    var pk_flat = try allocator.alloc(hash_zig.FieldElement, pk_flat_len);
    defer allocator.free(pk_flat);
    
    var idx: usize = 0;
    for (first_pk) |chain| {
        for (chain) |elem| {
            pk_flat[idx] = elem;
            idx += 1;
        }
    }

    const tree_tweak = hash_zig.PoseidonTweak{
        .tree_tweak = .{
            .level = 0,
            .pos_in_level = 0,
        },
    };

    const first_leaf = try param_wots.hash.hashFieldElements(
        allocator,
        pk_flat,
        params.tree_hash_output_len_fe,
        tree_tweak,
    );
    defer allocator.free(first_leaf);

    std.debug.print("  First tree leaf: ", .{});
    for (first_leaf, 0..) |elem, i| {
        std.debug.print("{d}", .{elem.toU32()});
        if (i < first_leaf.len - 1) std.debug.print(", ", .{});
    }
    std.debug.print("\n\n", .{});

    // Step 6: Build full Merkle tree (showing just the root)
    std.debug.print("Step 6: Building Merkle tree...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    
    // Generate all leaves
    const num_leaves = @as(usize, 1) << @intCast(params.tree_height);
    var all_leaves = try allocator.alloc([]hash_zig.FieldElement, num_leaves);
    defer {
        for (all_leaves) |leaf| {
            allocator.free(leaf);
        }
        allocator.free(all_leaves);
    }

    for (0..num_leaves) |epoch| {
        const sk = try param_wots.generatePrivateKey(allocator, &prf_key, @intCast(epoch));
        defer allocator.free(sk);
        
        const pk = try param_wots.generatePublicKey(allocator, sk);
        defer {
            for (pk) |chain| {
                allocator.free(chain);
            }
            allocator.free(pk);
        }

        // Flatten
        var pk_flat_i = try allocator.alloc(hash_zig.FieldElement, pk_flat_len);
        var idx_i: usize = 0;
        for (pk) |chain| {
            for (chain) |elem| {
                pk_flat_i[idx_i] = elem;
                idx_i += 1;
            }
        }

        const leaf_tweak = hash_zig.PoseidonTweak{
            .tree_tweak = .{
                .level = 0,
                .pos_in_level = epoch,
            },
        };

        const leaf = try param_wots.hash.hashFieldElements(
            allocator,
            pk_flat_i,
            params.tree_hash_output_len_fe,
            leaf_tweak,
        );
        allocator.free(pk_flat_i);
        all_leaves[epoch] = leaf;

        if (epoch < 3 or epoch == num_leaves - 1) {
            std.debug.print("  Leaf {d}: ", .{epoch});
            for (leaf, 0..) |elem, i| {
                std.debug.print("{d}", .{elem.toU32()});
                if (i < leaf.len - 1) std.debug.print(", ", .{});
            }
            std.debug.print("\n", .{});
        } else if (epoch == 3) {
            std.debug.print("  ... ({d} total leaves)\n", .{num_leaves});
        }
    }
    std.debug.print("\n", .{});

    // Build tree
    var param_tree = try hash_zig.MerkleTreeNative.initWithParameter(
        allocator,
        params,
        parameter,
    );
    defer param_tree.deinit();

    const tree_levels = try param_tree.buildFullTree(allocator, all_leaves);
    defer {
        for (tree_levels) |level| {
            for (level) |node| {
                allocator.free(node);
            }
            allocator.free(level);
        }
        allocator.free(tree_levels);
    }

    const root_level = tree_levels[tree_levels.len - 1];
    const root = root_level[0];
    
    std.debug.print("  Merkle root ({d} elements): ", .{root.len});
    for (root, 0..) |elem, i| {
        std.debug.print("{d}", .{elem.toU32()});
        if (i < root.len - 1) std.debug.print(", ", .{});
    }
    std.debug.print("\n\n", .{});

    // Convert root to bytes for SHA3 comparison
    var root_bytes = try allocator.alloc(u8, root.len * 4);
    defer allocator.free(root_bytes);
    
    for (root, 0..) |elem, i| {
        const val = elem.toU32();
        std.mem.writeInt(u32, root_bytes[i * 4 ..][0..4], val, .little);
    }

    // Compute SHA3-256 of root
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(root_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    std.debug.print("Step 7: Final comparison values...\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});
    std.debug.print("  Root bytes ({d} bytes): {s}\n", .{ root_bytes.len, std.fmt.fmtSliceHexLower(root_bytes) });
    std.debug.print("  SHA3-256 of root: {s}\n", .{std.fmt.fmtSliceHexLower(&digest)});

    std.debug.print("\n" ++ "=" ** 80 ++ "\n", .{});
    std.debug.print("✅ Debug output complete\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});
}

