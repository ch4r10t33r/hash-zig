const std = @import("std");
const hash_zig = @import("src/root.zig");

pub fn main() !void {
    std.debug.print("=== Bottom Tree Generation Debug ===\n", .{});

    // Use the same seed as the comparison test
    const seed = [_]u8{0x42} ** 32;

    // Initialize RNG
    var rng = hash_zig.prf.ChaCha12Rng.init(seed);

    std.debug.print("SEED: {x}\n", .{std.fmt.fmtSliceHexUpper(&seed)});

    // Generate parameters and PRF key (same as before)
    var parameter: [5]hash_zig.core.FieldElement = undefined;
    for (0..5) |i| {
        parameter[i] = hash_zig.core.FieldElement{ .value = rng.random().int(u32) };
    }

    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);

    std.debug.print("Parameter: {any}\n", .{parameter});
    std.debug.print("PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Now let's simulate the bottom tree generation process
    // For lifetime 2^8, we need 16 bottom trees
    const num_bottom_trees = 16;
    const leafs_per_bottom_tree = 1 << 4; // 2^4 = 16 leaves per bottom tree

    std.debug.print("\nGenerating {} bottom trees with {} leaves each\n", .{ num_bottom_trees, leafs_per_bottom_tree });

    // Generate bottom tree roots
    var bottom_tree_roots = try std.heap.page_allocator.alloc([8]hash_zig.core.FieldElement, num_bottom_trees);
    defer std.heap.page_allocator.free(bottom_tree_roots);

    for (0..num_bottom_trees) |bottom_tree_index| {
        std.debug.print("\n--- Bottom Tree {} ---\n", .{bottom_tree_index});

        // Calculate epoch range for this bottom tree
        const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
        const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;

        std.debug.print("Epoch range: {} to {}\n", .{ epoch_range_start, epoch_range_end - 1 });

        // Generate chain ends hashes for each epoch
        var chain_ends_hashes = try std.heap.page_allocator.alloc(hash_zig.core.FieldElement, leafs_per_bottom_tree);
        defer std.heap.page_allocator.free(chain_ends_hashes);

        for (epoch_range_start..epoch_range_end) |epoch| {
            // For now, let's just generate a simple hash for each epoch
            // This is a simplified version - in reality, this would involve chain computation
            const hash_val = rng.random().int(u32);
            chain_ends_hashes[epoch - epoch_range_start] = hash_zig.core.FieldElement{ .value = hash_val };
            std.debug.print("  Epoch {}: 0x{x}\n", .{ epoch, hash_val });
        }

        // Build bottom tree from leaf hashes
        // This is where the actual tree building happens
        var leaf_nodes = try std.heap.page_allocator.alloc([8]hash_zig.core.FieldElement, chain_ends_hashes.len);
        defer std.heap.page_allocator.free(leaf_nodes);

        for (0..chain_ends_hashes.len) |i| {
            // Convert single field element to array of 8 field elements
            leaf_nodes[i][0] = chain_ends_hashes[i];
            for (1..8) |j| {
                leaf_nodes[i][j] = hash_zig.core.FieldElement{ .value = 0 };
            }
        }

        // Simple tree building (for debugging)
        var current_level = try std.heap.page_allocator.alloc([8]hash_zig.core.FieldElement, leaf_nodes.len);
        @memcpy(current_level, leaf_nodes);

        var level_size = leaf_nodes.len;
        while (level_size > 1) {
            const next_level_size = (level_size + 1) / 2;
            var next_level = try std.heap.page_allocator.alloc([8]hash_zig.core.FieldElement, next_level_size);

            for (0..next_level_size) |i| {
                if (i * 2 + 1 < level_size) {
                    // Both children exist - for now, just copy the left child
                    next_level[i] = current_level[i * 2];
                } else {
                    // Only left child exists
                    next_level[i] = current_level[i * 2];
                }
            }

            std.heap.page_allocator.free(current_level);
            current_level = next_level;
            level_size = next_level_size;
        }

        bottom_tree_roots[bottom_tree_index] = current_level[0];
        std.debug.print("Bottom tree {} root: 0x{x}\n", .{ bottom_tree_index, current_level[0][0].value });

        std.heap.page_allocator.free(current_level);
    }

    // Check RNG state after bottom tree generation
    std.debug.print("\nRNG state after bottom tree generation:\n", .{});
    for (0..10) |i| {
        const val = rng.random().int(u32);
        std.debug.print("  [{}] = {}\n", .{ i, val });
    }
}
