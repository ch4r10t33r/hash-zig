const std = @import("std");
const hash_zig = @import("hash-zig");

const FieldElement = hash_zig.core.FieldElement;
const ChaCha12Rng = hash_zig.prf.ChaCha12Rng;
const GeneralizedXMSSSignatureScheme = hash_zig.signature.GeneralizedXMSSSignatureScheme;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== BOTTOM TREE ROOTS COMPARISON ===\n", .{});
    std.debug.print("Comparing bottom tree roots between Rust and Zig\n", .{});

    // Initialize with same seed
    const seed: [32]u8 = [_]u8{42} ** 32;
    var rng = ChaCha12Rng.init(seed);

    // Generate parameters and PRF key (matching rust_algorithm_port.zig)
    const parameter = try generateParameters(&rng);
    const prf_key = try generatePRFKey(&rng);

    std.debug.print("Parameters: [{}, {}, {}, {}, {}]\n", .{ parameter[0].value, parameter[1].value, parameter[2].value, parameter[3].value, parameter[4].value });
    std.debug.print("PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Build bottom trees and compare roots
    const num_bottom_trees = 16;
    var bottom_tree_roots = try allocator.alloc([8]FieldElement, num_bottom_trees);
    defer allocator.free(bottom_tree_roots);

    std.debug.print("\n=== BOTTOM TREE ROOTS COMPARISON ===\n", .{});

    // Build first few bottom trees for detailed comparison
    for (0..@min(4, num_bottom_trees)) |tree_index| {
        std.debug.print("\n--- Bottom Tree {} ---\n", .{tree_index});

        // Generate leaves
        const tree_leafs = try generateLeavesFromPrfKey(prf_key, tree_index, parameter, allocator);
        defer allocator.free(tree_leafs);

        // Convert to FieldElement array
        var leafs_array = try allocator.alloc([8]FieldElement, tree_leafs.len);
        defer allocator.free(leafs_array);

        for (tree_leafs, 0..) |leaf, j| {
            for (0..8) |k| {
                leafs_array[j][k] = FieldElement{ .value = leaf[k] };
            }
        }

        // Print first few leaves for debugging
        std.debug.print("Leaves (first 3):\n", .{});
        for (0..@min(3, leafs_array.len)) |j| {
            std.debug.print("  Leaf {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j, leafs_array[j][0].value, leafs_array[j][1].value, leafs_array[j][2].value, leafs_array[j][3].value, leafs_array[j][4].value, leafs_array[j][5].value, leafs_array[j][6].value, leafs_array[j][7].value });
        }

        // Build bottom tree
        const bottom_tree = try new_bottom_tree(8, tree_index, parameter, leafs_array, &rng);
        bottom_tree_roots[tree_index] = root(&bottom_tree);

        std.debug.print("Bottom tree {} root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ tree_index, bottom_tree_roots[tree_index][0].value, bottom_tree_roots[tree_index][1].value, bottom_tree_roots[tree_index][2].value, bottom_tree_roots[tree_index][3].value, bottom_tree_roots[tree_index][4].value, bottom_tree_roots[tree_index][5].value, bottom_tree_roots[tree_index][6].value, bottom_tree_roots[tree_index][7].value });

        // Debug the tree structure
        std.debug.print("Tree structure:\n", .{});
        for (bottom_tree.layers.items, 0..) |layer, layer_idx| {
            std.debug.print("  Layer {}: {} nodes, start_index={}\n", .{ layer_idx, layer.nodes.len, layer.start_index });
            if (layer.nodes.len <= 4) { // Only print if not too many nodes
                for (layer.nodes, 0..) |node, node_idx| {
                    std.debug.print("    Node {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ node_idx, node[0].value, node[1].value, node[2].value, node[3].value, node[4].value, node[5].value, node[6].value, node[7].value });
                }
            }
        }
    }

    // Build remaining bottom trees
    for (4..num_bottom_trees) |tree_index| {
        const tree_leafs = try generateLeavesFromPrfKey(prf_key, tree_index, parameter, allocator);
        defer allocator.free(tree_leafs);

        var leafs_array = try allocator.alloc([8]FieldElement, tree_leafs.len);
        defer allocator.free(leafs_array);

        for (tree_leafs, 0..) |leaf, j| {
            for (0..8) |k| {
                leafs_array[j][k] = FieldElement{ .value = leaf[k] };
            }
        }

        const bottom_tree = try new_bottom_tree(8, tree_index, parameter, leafs_array, &rng);
        bottom_tree_roots[tree_index] = root(&bottom_tree);
    }

    // Print all bottom tree roots for comparison
    std.debug.print("\n=== ALL BOTTOM TREE ROOTS ===\n", .{});
    for (bottom_tree_roots, 0..) |tree_root, i| {
        std.debug.print("Root {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, tree_root[0].value, tree_root[1].value, tree_root[2].value, tree_root[3].value, tree_root[4].value, tree_root[5].value, tree_root[6].value, tree_root[7].value });
    }

    // Expected Rust bottom tree roots (from previous runs)
    const expected_rust_roots = [_][8]u32{
        [_]u32{ 272571317, 816959513, 1641229267, 1432426756, 1894915310, 1536602969, 679245493, 946325787 },
        [_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 }, // Placeholder - need to get from Rust
        [_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 }, // Placeholder - need to get from Rust
        [_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 }, // Placeholder - need to get from Rust
    };

    std.debug.print("\n=== COMPARISON WITH EXPECTED RUST ===\n", .{});
    for (0..@min(4, bottom_tree_roots.len)) |i| {
        const zig_root = bottom_tree_roots[i];
        const rust_root = expected_rust_roots[i];

        std.debug.print("Bottom tree {} comparison:\n", .{i});
        std.debug.print("  Zig:  [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ zig_root[0].value, zig_root[1].value, zig_root[2].value, zig_root[3].value, zig_root[4].value, zig_root[5].value, zig_root[6].value, zig_root[7].value });
        std.debug.print("  Rust: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ rust_root[0], rust_root[1], rust_root[2], rust_root[3], rust_root[4], rust_root[5], rust_root[6], rust_root[7] });

        // Check if they match
        var matches = true;
        for (0..8) |j| {
            if (zig_root[j].value != rust_root[j]) {
                matches = false;
                break;
            }
        }
        std.debug.print("  Match: {}\n", .{matches});
    }
}

// Helper functions (simplified versions for testing)
fn generateParameters(_: *ChaCha12Rng) ![5]FieldElement {
    // This should NOT consume RNG state in Rust
    return [_]FieldElement{
        FieldElement{ .value = 1128497561 },
        FieldElement{ .value = 1847509114 },
        FieldElement{ .value = 1994249188 },
        FieldElement{ .value = 1874424621 },
        FieldElement{ .value = 1302548296 },
    };
}

fn generatePRFKey(rng: *ChaCha12Rng) ![32]u8 {
    // This SHOULD consume RNG state in Rust
    var key: [32]u8 = undefined;
    rng.fill(&key);
    return key;
}

fn generateLeavesFromPrfKey(
    _: [32]u8,
    bottom_tree_index: usize,
    _: [5]FieldElement,
    alloc: std.mem.Allocator,
) ![]@Vector(8, u32) {
    // Simplified implementation for testing
    const leafs_per_bottom_tree = 16;
    var leaves = try alloc.alloc(@Vector(8, u32), leafs_per_bottom_tree);

    for (0..leafs_per_bottom_tree) |i| {
        const epoch = bottom_tree_index * leafs_per_bottom_tree + i;
        // Generate deterministic leaves for testing
        for (0..8) |j| {
            leaves[i][j] = @as(u32, @intCast(epoch * 8 + j + 1000));
        }
    }

    return leaves;
}

fn new_bottom_tree(
    _: usize,
    bottom_tree_index: usize,
    _: [5]FieldElement,
    leafs: [][8]FieldElement,
    _: *ChaCha12Rng,
) !HashSubTree {
    // Simplified implementation for testing

    // Create a simple tree structure
    var layers = std.ArrayList(HashTreeLayer).init(std.heap.page_allocator);

    // Add leaf layer
    const leaf_layer = HashTreeLayer{ .start_index = 0, .nodes = leafs };
    try layers.append(leaf_layer);

    // Add root layer
    var root_nodes = try std.heap.page_allocator.alloc([8]FieldElement, 1);
    for (0..8) |i| {
        root_nodes[0][i] = FieldElement{ .value = @as(u32, @intCast(bottom_tree_index * 8 + i + 2000)) };
    }
    const root_layer = HashTreeLayer{ .start_index = 0, .nodes = root_nodes };
    try layers.append(root_layer);

    return HashSubTree{ .layers = layers };
}

fn root(tree: *const HashSubTree) [8]FieldElement {
    const last_layer = tree.layers.items[tree.layers.items.len - 1];
    return last_layer.nodes[0];
}

const HashSubTree = struct {
    layers: std.ArrayList(HashTreeLayer),
};

const HashTreeLayer = struct {
    start_index: usize,
    nodes: [][8]FieldElement,
};
