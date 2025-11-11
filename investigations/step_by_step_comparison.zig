const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

const FieldElement = hash_zig.FieldElement;
const ChaCha12Rng = hash_zig.prf.ChaCha12Rng;
const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("=== STEP-BY-STEP COMPARISON ===\n", .{});
    log.print("Comparing Rust and Zig implementations step-by-step\n", .{});

    // Initialize with same seed
    const seed: [32]u8 = [_]u8{42} ** 32;
    var rng = ChaCha12Rng.init(seed);

    log.print("Initial seed: {x}\n", .{std.fmt.fmtSliceHexLower(&seed)});

    // Step 1: Parameter generation
    log.print("\n=== STEP 1: PARAMETER GENERATION ===\n", .{});

    // Get RNG state before parameter generation
    var rng_state_before: [32]u8 = undefined;
    rng.fill(&rng_state_before);
    log.print("RNG state before parameters: {x}\n", .{std.fmt.fmtSliceHexLower(&rng_state_before)});

    // Generate parameters (should NOT consume RNG in Rust)
    const parameter = try generateParameters(&rng);
    log.print("Generated parameters: [{}, {}, {}, {}, {}]\n", .{ parameter[0].value, parameter[1].value, parameter[2].value, parameter[3].value, parameter[4].value });

    // Get RNG state after parameter generation
    var rng_state_after: [32]u8 = undefined;
    rng.fill(&rng_state_after);
    log.print("RNG state after parameters: {x}\n", .{std.fmt.fmtSliceHexLower(&rng_state_after)});

    // Step 2: PRF key generation
    log.print("\n=== STEP 2: PRF KEY GENERATION ===\n", .{});

    // Get RNG state before PRF key generation
    var rng_state_before_prf: [32]u8 = undefined;
    rng.fill(&rng_state_before_prf);
    log.print("RNG state before PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&rng_state_before_prf)});

    // Generate PRF key (should consume RNG in Rust)
    const prf_key = try generatePRFKey(&rng);
    log.print("Generated PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Get RNG state after PRF key generation
    var rng_state_after_prf: [32]u8 = undefined;
    rng.fill(&rng_state_after_prf);
    log.print("RNG state after PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&rng_state_after_prf)});

    // Step 3: Bottom tree building
    log.print("\n=== STEP 3: BOTTOM TREE BUILDING ===\n", .{});

    const num_bottom_trees = 16;
    var bottom_tree_roots = try allocator.alloc([8]FieldElement, num_bottom_trees);
    defer allocator.free(bottom_tree_roots);

    // Build first two bottom trees sequentially (matching Rust)
    for (0..2) |tree_index| {
        log.print("\n--- Building Bottom Tree {} ---\n", .{tree_index});

        // Get RNG state before this bottom tree
        var rng_state_before_tree: [32]u8 = undefined;
        rng.fill(&rng_state_before_tree);
        log.print("RNG state before bottom tree {}: {x}\n", .{ tree_index, std.fmt.fmtSliceHexLower(&rng_state_before_tree) });

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

        // Print first few leaves for comparison
        log.print("Bottom tree {} leaves (first 3):\n", .{tree_index});
        for (0..@min(3, leafs_array.len)) |j| {
            log.print("  Leaf {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j, leafs_array[j][0].value, leafs_array[j][1].value, leafs_array[j][2].value, leafs_array[j][3].value, leafs_array[j][4].value, leafs_array[j][5].value, leafs_array[j][6].value, leafs_array[j][7].value });
        }

        // Build bottom tree
        const bottom_tree = try new_bottom_tree(8, tree_index, parameter, leafs_array, &rng);
        bottom_tree_roots[tree_index] = root(&bottom_tree);

        log.print("Bottom tree {} root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ tree_index, bottom_tree_roots[tree_index][0].value, bottom_tree_roots[tree_index][1].value, bottom_tree_roots[tree_index][2].value, bottom_tree_roots[tree_index][3].value, bottom_tree_roots[tree_index][4].value, bottom_tree_roots[tree_index][5].value, bottom_tree_roots[tree_index][6].value, bottom_tree_roots[tree_index][7].value });
    }

    // Build remaining bottom trees (2-15)
    for (2..num_bottom_trees) |tree_index| {
        log.print("\n--- Building Bottom Tree {} ---\n", .{tree_index});

        // Get RNG state before this bottom tree
        var rng_state_before_tree: [32]u8 = undefined;
        rng.fill(&rng_state_before_tree);
        log.print("RNG state before bottom tree {}: {x}\n", .{ tree_index, std.fmt.fmtSliceHexLower(&rng_state_before_tree) });

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

        // Build bottom tree
        const bottom_tree = try new_bottom_tree(8, tree_index, parameter, leafs_array, &rng);
        bottom_tree_roots[tree_index] = root(&bottom_tree);

        log.print("Bottom tree {} root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ tree_index, bottom_tree_roots[tree_index][0].value, bottom_tree_roots[tree_index][1].value, bottom_tree_roots[tree_index][2].value, bottom_tree_roots[tree_index][3].value, bottom_tree_roots[tree_index][4].value, bottom_tree_roots[tree_index][5].value, bottom_tree_roots[tree_index][6].value, bottom_tree_roots[tree_index][7].value });
    }

    // Step 4: Top tree building
    log.print("\n=== STEP 4: TOP TREE BUILDING ===\n", .{});

    // Get RNG state before top tree
    var rng_state_before_top: [32]u8 = undefined;
    rng.fill(&rng_state_before_top);
    log.print("RNG state before top tree: {x}\n", .{std.fmt.fmtSliceHexLower(&rng_state_before_top)});

    // Print top tree input roots
    log.print("Top tree input roots (first 3):\n", .{});
    for (0..@min(3, bottom_tree_roots.len)) |i| {
        log.print("  Root {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, bottom_tree_roots[i][0].value, bottom_tree_roots[i][1].value, bottom_tree_roots[i][2].value, bottom_tree_roots[i][3].value, bottom_tree_roots[i][4].value, bottom_tree_roots[i][5].value, bottom_tree_roots[i][6].value, bottom_tree_roots[i][7].value });
    }

    // Build top tree
    const top_tree = try new_top_tree(&rng, 8, 0, parameter, bottom_tree_roots);
    const final_root = root(&top_tree);

    log.print("\n=== FINAL RESULT ===\n", .{});
    log.print("Zig final root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ final_root[0].value, final_root[1].value, final_root[2].value, final_root[3].value, final_root[4].value, final_root[5].value, final_root[6].value, final_root[7].value });
    log.print("Expected Rust: [272571317, 816959513, 1641229267, 1432426756, 1894915310, 1536602969, 679245493, 946325787]\n", .{});
}

// Helper functions (simplified versions for testing)
fn generateParameters(_rng: *ChaCha12Rng) ![5]FieldElement {
    // This should NOT consume RNG state in Rust
    _ = _rng;
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
    prf_key: [32]u8,
    bottom_tree_index: usize,
    parameter: [5]FieldElement,
    alloc: std.mem.Allocator,
) ![]@Vector(8, u32) {
    // Simplified implementation for testing
    _ = prf_key;
    _ = parameter;
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
    _depth: usize,
    bottom_tree_index: usize,
    _parameter: [5]FieldElement,
    leafs: [][8]FieldElement,
    _rng: *ChaCha12Rng,
) !HashSubTree {
    // Simplified implementation for testing
    _ = _depth;
    _ = _parameter;
    _ = _rng;

    // Create a simple tree structure
    var layers = std.ArrayList(HashTreeLayer).init(std.heap.page_allocator);
    defer layers.deinit();

    // Add leaf layer
    const leaf_layer = HashTreeLayer{ .start_index = 0, .nodes = leafs };
    try layers.append(leaf_layer);

    // Add root layer
    var root_nodes = try std.heap.page_allocator.alloc([8]FieldElement, 1);
    for (0..8) |i| {
        root_nodes[0][i] = FieldElement.fromCanonical(@intCast(bottom_tree_index * 8 + i + 2000));
    }
    const root_layer = HashTreeLayer{ .start_index = 0, .nodes = root_nodes };
    try layers.append(root_layer);

    return HashSubTree{ .layers = layers };
}

fn new_top_tree(
    _rng: *ChaCha12Rng,
    _depth: usize,
    _start_index: usize,
    _parameter: [5]FieldElement,
    roots: [][8]FieldElement,
) !HashSubTree {
    // Simplified implementation for testing
    _ = _rng;
    _ = _depth;
    _ = _start_index;
    _ = _parameter;

    var layers = std.ArrayList(HashTreeLayer).init(std.heap.page_allocator);
    defer layers.deinit();

    // Add root layer
    const root_layer = HashTreeLayer{ .start_index = 0, .nodes = roots };
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
