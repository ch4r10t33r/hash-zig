const std = @import("std");
const log = @import("hash-zig").utils.log;
const allocator = std.heap.page_allocator;
const DefaultPrng = std.Random.DefaultPrng;

// Import the real Poseidon2 implementation using the hash-zig module
const hash_zig = @import("hash-zig");
const Poseidon2RustCompat = hash_zig.Poseidon2RustCompat;
const GeneralizedXMSSSignatureScheme = hash_zig.GeneralizedXMSSSignatureScheme;
const ChaCha12Rng = hash_zig.chacha12_rng.ChaCha12Rng;
const ShakePRFtoF_8_7 = hash_zig.ShakePRFtoF_8_7;
const FieldElement = hash_zig.FieldElement;

// Port of Rust HashTreeLayer structure
const HashTreeLayer = struct {
    start_index: usize,
    nodes: [][8]FieldElement,
};

// Port of Rust HashSubTree structure
const HashSubTree = struct {
    depth: usize,
    lowest_layer: usize,
    layers: []HashTreeLayer, // Array of layers, each layer has start_index and nodes
};

// Port of Rust TweakableHash trait methods
const TweakableHash = struct {
    // This will contain the exact Rust algorithm implementations
};

// Port of Rust HashTreeLayer::padded function
fn padded(
    rng: *ChaCha12Rng,
    nodes: [][8]FieldElement,
    start_index: usize,
) !HashTreeLayer {
    // End index of the provided contiguous run (inclusive).
    const end_index = start_index + nodes.len - 1;

    // Do we need a front pad? Start must be even.
    const needs_front = (start_index & 1) == 1;

    // Do we need a back pad? End must be odd.
    const needs_back = (end_index & 1) == 0;

    // The effective start index after optional front padding (always even).
    const actual_start_index = start_index - @as(usize, @intFromBool(needs_front));

    log.print("DEBUG: Zig padLayer: start_index={}, nodes.len={}, end_index={}\n", .{ start_index, nodes.len, end_index });
    log.print("DEBUG: Zig padLayer: needs_front={}, needs_back={}, actual_start_index={}\n", .{ needs_front, needs_back, actual_start_index });

    // Reserve exactly the space we may need: original nodes plus up to two pads.
    const total_capacity = nodes.len + @as(usize, @intFromBool(needs_front)) + @as(usize, @intFromBool(needs_back));
    var out = try allocator.alloc([8]FieldElement, total_capacity);
    var out_index: usize = 0;

    // Optional front padding to align to an even start index.
    if (needs_front) {
        log.print("DEBUG: Zig padLayer: Generating front padding node (1 RNG call)\n", .{});
        // Generate random domain element (8 field elements)
        var front_padding: [8]FieldElement = undefined;
        for (0..8) |i| {
            front_padding[i] = FieldElement{ .value = rng.random().int(u32) >> 1 }; // 31-bit field element
        }
        out[out_index] = front_padding;
        out_index += 1;
    }

    // Insert the actual content in order.
    for (nodes) |node| {
        out[out_index] = node;
        out_index += 1;
    }

    // Optional back padding to ensure we end on an odd index.
    if (needs_back) {
        log.print("DEBUG: Zig padLayer: Generating back padding node (1 RNG call)\n", .{});
        // Generate random domain element (8 field elements)
        var back_padding: [8]FieldElement = undefined;
        for (0..8) |i| {
            back_padding[i] = FieldElement{ .value = rng.random().int(u32) >> 1 }; // 31-bit field element
        }
        out[out_index] = back_padding;
        out_index += 1;
    }

    // Return the padded layer with the corrected start index.
    return HashTreeLayer{
        .start_index = actual_start_index,
        .nodes = out,
    };
}

// Port of Rust HashSubTree::new_subtree function
fn new_subtree(
    rng: *ChaCha12Rng,
    lowest_layer: usize,
    depth: usize,
    start_index: usize,
    parameter: [5]FieldElement,
    lowest_layer_nodes: [][8]FieldElement,
) !HashSubTree {
    std.debug.assert(lowest_layer < depth);
    std.debug.assert(start_index + lowest_layer_nodes.len <= (@as(usize, 1) << @as(u6, @intCast(depth - lowest_layer))));

    // we build the tree from the lowest layer to the root,
    // while building the tree, we ensure that the following two invariants hold via appropriate padding:
    // 1. the layer starts at an even index, i.e., a left child
    // 2. the layer ends at an odd index, i.e., a right child (does not hold for the root layer)
    // In this way, we can ensure that we can always hash two siblings to get their parent
    // The padding is ensured using the helper function `get_padded_layer`.

    var layers = std.ArrayList(HashTreeLayer).init(allocator);
    defer layers.deinit();

    // start with the lowest layer, padded accordingly
    const padded_lowest = try padded(rng, lowest_layer_nodes, start_index);
    log.print("DEBUG: Zig Layer {} -> {}: {} nodes (start_index: {})\n", .{ lowest_layer, lowest_layer + 1, padded_lowest.nodes.len, padded_lowest.start_index });
    try layers.append(padded_lowest);

    // now, build the tree layer by layer
    var current_level = lowest_layer;
    while (current_level < depth) : (current_level += 1) {
        // Previous layer (already padded so len is even and start_index is even)
        const prev_layer = layers.items[current_level - lowest_layer];

        // Parent layer starts at half the previous start index
        const parent_start = prev_layer.start_index >> 1;

        // Compute all parents in parallel, pairing children two-by-two
        // We do exact chunks of two children, no remainder.
        const parents_len = prev_layer.nodes.len / 2;
        var parents = try allocator.alloc([8]FieldElement, parents_len);

        // Process pairs in parallel using par_chunks_exact(2) equivalent
        // Rust's par_chunks_exact(2) processes pairs in parallel, but the order is deterministic
        // We need to process in the same order as Rust to maintain identical RNG state
        for (0..parents_len) |i| {
            const parent_pos = @as(u32, @intCast(parent_start + i));
            const tweak_level = @as(u8, @intCast(current_level)) + 1;
            log.print("DEBUG: Zig tweak level={} pos={} (level={})\n", .{ tweak_level, parent_pos, current_level });

            const left_child = prev_layer.nodes[i * 2];
            const right_child = prev_layer.nodes[i * 2 + 1];

            const hash_result = try applyPoseidonTreeTweakHash(
                left_child[0..],
                right_child[0..],
                @as(u8, @intCast(current_level)) + 1,
                parent_pos,
                parameter,
            );
            defer allocator.free(hash_result);

            @memcpy(parents[i][0..], hash_result[0..8]);
            log.print("DEBUG: Zig Hash [{}] processing children to parent\n", .{i});
        }

        // Add the new layer with padding so next iteration also has even start and length
        const padded_parents = try padded(rng, parents, parent_start);
        log.print("DEBUG: Zig Layer {} -> {}: {} nodes (start_index: {})\n", .{ current_level, current_level + 1, padded_parents.nodes.len, padded_parents.start_index });

        // Debug: Print intermediate tree nodes for first few layers
        if (current_level < 3) {
            log.print("DEBUG: Layer {} nodes: {} nodes\n", .{ current_level + 1, padded_parents.nodes.len });
            for (0..@min(3, padded_parents.nodes.len)) |i| {
                log.print("  Node {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, padded_parents.nodes[i][0].value, padded_parents.nodes[i][1].value, padded_parents.nodes[i][2].value, padded_parents.nodes[i][3].value, padded_parents.nodes[i][4].value, padded_parents.nodes[i][5].value, padded_parents.nodes[i][6].value, padded_parents.nodes[i][7].value });
            }
        }

        try layers.append(padded_parents);

        allocator.free(parents);
    }

    // Convert to final structure
    const final_layers = try allocator.alloc(HashTreeLayer, layers.items.len);
    for (layers.items, 0..) |layer, i| {
        final_layers[i] = layer;
    }

    return HashSubTree{
        .depth = depth,
        .lowest_layer = lowest_layer,
        .layers = final_layers,
    };
}

// Global scheme instance for hash function
var scheme: ?*GeneralizedXMSSSignatureScheme = null;

fn initScheme() !void {
    if (scheme == null) {
        scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    }
}

// Real Poseidon2 hash function using the existing implementation
fn applyPoseidonTreeTweakHash(
    left: []const FieldElement,
    right: []const FieldElement,
    tweak_level: u8,
    parent_pos: u32,
    parameter: [5]FieldElement,
) ![]FieldElement {
    try initScheme();

    // Convert FieldElement to the expected type
    const left_converted = try allocator.alloc(FieldElement, left.len);
    defer allocator.free(left_converted);
    for (left, 0..) |fe, i| {
        left_converted[i] = fe;
    }

    const right_converted = try allocator.alloc(FieldElement, right.len);
    defer allocator.free(right_converted);
    for (right, 0..) |fe, i| {
        right_converted[i] = fe;
    }

    const parameter_converted: [5]FieldElement = .{
        parameter[0],
        parameter[1],
        parameter[2],
        parameter[3],
        parameter[4],
    };

    // Use the real hash function
    const hash_result = try scheme.?.applyPoseidonTreeTweakHashWithSeparateInputs(
        left_converted,
        right_converted,
        tweak_level,
        parent_pos,
        parameter_converted,
    );
    defer allocator.free(hash_result);

    // Convert back to FieldElement array
    var result = try allocator.alloc(FieldElement, 8);
    for (0..8) |i| {
        result[i] = hash_result[i];
    }

    return result;
}

// Port of Rust HashSubTree::new_top_tree function
fn new_top_tree(
    rng: *ChaCha12Rng,
    depth: usize,
    start_index: usize,
    parameter: [5]FieldElement,
    roots_of_bottom_trees: [][8]FieldElement,
) !HashSubTree {
    std.debug.assert(depth % 2 == 0);

    // the top tree is just the sub-tree that starts at layer depth / 2, and contains
    // the roots of the bottom trees in the lowest layer.
    const lowest_layer = depth / 2;
    const lowest_layer_nodes = roots_of_bottom_trees;
    return new_subtree(
        rng,
        lowest_layer,
        depth,
        start_index,
        parameter,
        lowest_layer_nodes,
    );
}

// Port of Rust HashSubTree::new_bottom_tree function
fn new_bottom_tree(
    depth: usize,
    bottom_tree_index: usize,
    _parameter: [5]FieldElement,
    leafs: [][8]FieldElement,
    rng: *ChaCha12Rng,
) !HashSubTree {
    std.debug.assert(depth > 2 and depth % 2 == 0);
    std.debug.assert(leafs.len == (@as(usize, 1) << @as(u6, @intCast(depth / 2))));

    // Use the real RNG instead of a dummy RNG
    // This matches the actual Rust implementation behavior
    const leafs_per_bottom_tree = @as(usize, 1) << @as(u6, @intCast(depth / 2));
    const lowest_layer = 0;
    const lowest_layer_nodes = leafs;
    const start_index = bottom_tree_index * leafs_per_bottom_tree;
    var bottom_tree = try new_subtree(
        rng,
        lowest_layer,
        depth,
        start_index,
        _parameter,
        lowest_layer_nodes,
    );

    // Now, note that the bottom_tree contains dummy nodes for the top depth/2 + 1 layers,
    // These notes are incompatible with the other bottom trees, so we need to make sure that we remove
    // them. We also make sure the root is alone in its layer so that the root() function works.
    const bottom_tree_root = bottom_tree.layers[depth / 2].nodes[bottom_tree_index % 2];
    bottom_tree.layers = bottom_tree.layers[0 .. depth / 2];
    // Add root layer
    var root_layer_nodes = try allocator.alloc([8]FieldElement, 1);
    root_layer_nodes[0] = bottom_tree_root;
    const root_layer = HashTreeLayer{ .start_index = 0, .nodes = root_layer_nodes };
    bottom_tree.layers = try allocator.realloc(bottom_tree.layers, bottom_tree.layers.len + 1);
    bottom_tree.layers[bottom_tree.layers.len - 1] = root_layer;

    return bottom_tree;
}

// Port of Rust HashSubTree::root function
fn root(self: *const HashSubTree) [8]FieldElement {
    return self.layers[self.layers.len - 1].nodes[0];
}

// Generate leaves from PRF key (matching original implementation)
fn generateLeavesFromPrfKey(
    prf_key: [32]u8,
    bottom_tree_index: usize,
    parameter: [5]FieldElement,
    alloc: std.mem.Allocator,
) ![]@Vector(8, u32) {
    const leafs_per_bottom_tree = 16; // 2^(8/2) = 16
    const num_chains = 8; // dimension for lifetime_2_8

    var leaves = try alloc.alloc(@Vector(8, u32), leafs_per_bottom_tree);

    // Calculate epoch range for this bottom tree
    const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
    const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;

    for (epoch_range_start..epoch_range_end) |epoch| {
        var chain_ends = try alloc.alloc(u32, num_chains);
        defer alloc.free(chain_ends);

        for (0..num_chains) |chain_index| {
            // Get domain elements using real ShakePRFtoF implementation
            const domain_elements = ShakePRFtoF_8_7.getDomainElement(prf_key, @as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

            // Debug: Print domain elements for first few chains
            if (bottom_tree_index == 0 and epoch < 2 and chain_index < 2) {
                log.print("    Chain {} domain elements: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ chain_index, domain_elements[0], domain_elements[1], domain_elements[2], domain_elements[3], domain_elements[4], domain_elements[5], domain_elements[6], domain_elements[7] });
            }

            // Compute hash chain using real implementation
            const chain_end = try computeHashChain(domain_elements, @as(u32, @intCast(epoch)), @as(u8, @intCast(chain_index)), parameter, alloc);
            chain_ends[chain_index] = chain_end;

            // Debug: Print chain end for first few chains
            if (bottom_tree_index == 0 and epoch < 2 and chain_index < 2) {
                log.print("    Chain {} end: 0x{x}\n", .{ chain_index, chain_end });
            }
        }

        // Hash all chain ends to get the leaf hash
        // CRITICAL: Rust applies TH::apply(parameter, &TH::tree_tweak(0, epoch as u32), &chain_ends)
        // We need to apply the tree tweak hash to the chain ends, NOT just copy them!

        // Convert chain ends to FieldElement for hashing
        var chain_ends_fe = try alloc.alloc(FieldElement, num_chains);
        defer alloc.free(chain_ends_fe);
        for (0..num_chains) |i| {
            chain_ends_fe[i] = FieldElement{ .value = chain_ends[i] };
        }

        // Apply tree tweak hash with level=0, pos=epoch
        const leaf_hash_result = try applyPoseidonTreeTweakHashSingleInput(
            chain_ends_fe,
            0, // level = 0 for leaf hashing
            @as(u32, @intCast(epoch)),
            parameter,
            alloc,
        );
        defer alloc.free(leaf_hash_result);

        // Convert result to @Vector(8, u32)
        var leaf_hash: @Vector(8, u32) = undefined;
        for (0..8) |i| {
            leaf_hash[i] = leaf_hash_result[i].value;
        }

        // Debug: Print leaf hash for first few epochs
        if (bottom_tree_index == 0 and epoch < 3) {
            log.print("    Epoch {} leaf hash: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ epoch, leaf_hash[0], leaf_hash[1], leaf_hash[2], leaf_hash[3], leaf_hash[4], leaf_hash[5], leaf_hash[6], leaf_hash[7] });
        }

        leaves[epoch - epoch_range_start] = leaf_hash;
    }

    return leaves;
}

// Compute hash chain (matching original implementation)
fn computeHashChain(
    domain_elements: [8]u32,
    epoch: u32,
    chain_index: u8,
    parameter: [5]FieldElement,
    alloc: std.mem.Allocator,
) !u32 {
    const base = 8; // base for lifetime_2_8

    // Convert domain elements to field elements
    var current: [8]FieldElement = undefined;
    for (0..8) |i| {
        current[i] = FieldElement{ .value = domain_elements[i] };
    }

    // Walk the chain for BASE-1 steps (matching Rust chain function)
    for (0..base - 1) |j| {
        const pos_in_chain = @as(u8, @intCast(j + 1));

        // Apply chain tweak hash (matching Rust TH::apply with chain_tweak)
        const next = try applyPoseidonChainTweakHash(current, epoch, chain_index, pos_in_chain, parameter, alloc);

        // Update current state
        current = next;
    }

    return current[0].value;
}

// Apply Poseidon2 chain tweak hash (matching original implementation)
fn applyPoseidonTreeTweakHashSingleInput(
    input: []const FieldElement,
    tweak_level: u8,
    parent_pos: u32,
    parameter: [5]FieldElement,
    alloc: std.mem.Allocator,
) ![]FieldElement {
    try initScheme();

    // Use the real hash function with single input (for leaf hashing)
    const hash_result = try scheme.?.applyPoseidonTreeTweakHash(
        input,
        tweak_level,
        parent_pos,
        parameter,
    );
    defer allocator.free(hash_result);

    // Copy result
    const result = try alloc.alloc(FieldElement, hash_result.len);
    @memcpy(result, hash_result);
    return result;
}

fn applyPoseidonChainTweakHash(
    input: [8]FieldElement,
    epoch: u32,
    chain_index: u8,
    pos_in_chain: u8,
    parameter: [5]FieldElement,
    alloc: std.mem.Allocator,
) ![8]FieldElement {
    try initScheme();

    // Convert epoch, chain_index, and pos_in_chain to field elements for tweak using Rust's encoding
    // ChainTweak: ((epoch as u128) << 24) | ((chain_index as u128) << 16) | ((pos_in_chain as u128) << 8) | 0x00
    const tweak_encoding = (@as(u128, epoch) << 24) | (@as(u128, chain_index) << 16) | (@as(u128, pos_in_chain) << 8) | 0x00;

    // Convert to field elements using base-p representation
    const tweak = tweakToFieldElements(tweak_encoding);

    // Prepare combined input: parameter + tweak + message
    const total_input_len = 5 + 2 + 8;
    var combined_input = try alloc.alloc(FieldElement, total_input_len);
    defer alloc.free(combined_input);

    // Copy parameter
    @memcpy(combined_input[0..5], parameter[0..5]);

    // Copy tweak
    @memcpy(combined_input[5..7], tweak[0..2]);

    // Copy input (single element as array)
    @memcpy(combined_input[7..15], input[0..8]);

    // Apply Poseidon2 hash
    const hash_result = try scheme.?.poseidon2.hashFieldElements(alloc, combined_input);
    defer alloc.free(hash_result);

    // Return first 8 elements as the result
    var result: [8]FieldElement = undefined;
    @memcpy(result[0..8], hash_result[0..8]);
    return result;
}

// Convert tweak encoding to field elements (matching original implementation)
fn tweakToFieldElements(tweak: u128) [2]FieldElement {
    // Convert to base-p representation (p = 2^31 - 2^24 + 1)
    const p: u64 = 2130706433; // 0x7f000001
    const low = @as(u64, @intCast(tweak & 0xFFFFFFFFFFFFFFFF));
    const high = @as(u64, @intCast((tweak >> 64) & 0xFFFFFFFFFFFFFFFF));

    return .{
        FieldElement.fromCanonical(@intCast(low % p)),
        FieldElement.fromCanonical(@intCast(high % p)),
    };
}

// Peek at RNG bytes without consuming them (for parameter generation)
fn peekRngBytes(rng: *ChaCha12Rng, buf: []u8) void {
    // Access the internal state of the RNG to peek without advancing
    const bytes = &rng.state;
    const avail = bytes.len - rng.offset;

    if (avail >= buf.len) {
        // We have enough bytes available in the current state
        @memcpy(buf, bytes[rng.offset..][0..buf.len]);
    } else {
        // Need to peek into the next state block
        // For now, just copy what we have and fill the rest with zeros
        @memcpy(buf[0..avail], bytes[rng.offset..]);
        @memset(buf[avail..], 0);
    }
}

pub fn main() !void {
    log.print("Rust Algorithm Port - Starting implementation\n", .{});

    // Use the exact same seed as the Rust debug program
    const seed = [_]u8{0x42} ** 32;
    var rng = ChaCha12Rng.init(seed);

    // Generate parameters WITHOUT consuming RNG state (matching actual Zig implementation)
    var parameter: [5]FieldElement = undefined;
    var random_bytes: [20]u8 = undefined; // 5 * 4 bytes = 20 bytes for 5 u32 values
    peekRngBytes(&rng, &random_bytes); // Don't consume RNG state like actual Zig

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        parameter[i] = FieldElement{ .value = random_value >> 1 }; // 31-bit field element
    }

    // Debug: Check RNG state after parameter generation (should be unchanged)
    var debug_bytes_after_params: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes_after_params);
    log.print("ZIG RNG state after parameter generation: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_after_params)});

    log.print("Generated parameters: {any}\n", .{parameter});

    // Generate PRF key WITH consuming RNG state (matching actual Zig implementation - rng.fill() consumes state)
    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);

    // Debug: Check RNG state after PRF key generation (should be changed)
    var debug_bytes_after_prf: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes_after_prf);
    log.print("ZIG RNG state after PRF key generation: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_after_prf)});

    log.print("Generated PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Debug: Check RNG state after parameter and PRF key generation
    var debug_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes);
    log.print("RNG state after params+PRF: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Debug: Check RNG state before tree building
    var debug_bytes2: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes2);
    log.print("RNG state before tree building: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes2)});

    // Build the complete signature scheme like the original implementation
    // For log_lifetime = 8, we need 2^(8/2) = 16 bottom trees
    const num_bottom_trees = 1 << (8 / 2); // 2^4 = 16 bottom trees
    var bottom_tree_roots = try allocator.alloc([8]FieldElement, num_bottom_trees);

    log.print("Building {} bottom trees\n", .{num_bottom_trees});

    // Build bottom trees exactly like Rust: first two sequentially, then rest in parallel
    // First, build trees 0 and 1 sequentially (matching Rust)
    log.print("\n=== Building Bottom Trees 0 and 1 (Sequential) ===\n", .{});

    // Build tree 0
    {
        log.print("\n=== Building Bottom Tree 0 ===\n", .{});

        // Debug: Check RNG state before this bottom tree
        var debug_bytes_bt: [32]u8 = undefined;
        peekRngBytes(&rng, &debug_bytes_bt);
        log.print("RNG state before bottom tree 0: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_bt)});

        // Generate leaves from PRF key (matching original implementation)
        const tree_leafs = try generateLeavesFromPrfKey(prf_key, 0, parameter, allocator);
        defer allocator.free(tree_leafs);

        // Convert from @Vector(8, u32) to [8]FieldElement
        var leafs_array = try allocator.alloc([8]FieldElement, tree_leafs.len);
        defer allocator.free(leafs_array);

        for (tree_leafs, 0..) |leaf, j| {
            for (0..8) |k| {
                leafs_array[j][k] = FieldElement{ .value = leaf[k] };
            }
        }

        log.print("Bottom tree 0 leaves: {} leaves\n", .{leafs_array.len});
        for (leafs_array, 0..) |leaf, j| {
            log.print("  Leaf {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j, leaf[0].value, leaf[1].value, leaf[2].value, leaf[3].value, leaf[4].value, leaf[5].value, leaf[6].value, leaf[7].value });
        }

        const bottom_tree = try new_bottom_tree(8, 0, parameter, leafs_array, &rng);
        bottom_tree_roots[0] = root(&bottom_tree);

        log.print("Bottom tree 0 root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ bottom_tree_roots[0][0].value, bottom_tree_roots[0][1].value, bottom_tree_roots[0][2].value, bottom_tree_roots[0][3].value, bottom_tree_roots[0][4].value, bottom_tree_roots[0][5].value, bottom_tree_roots[0][6].value, bottom_tree_roots[0][7].value });
    }

    // Build tree 1
    {
        log.print("\n=== Building Bottom Tree 1 ===\n", .{});

        // Debug: Check RNG state before this bottom tree
        var debug_bytes_bt: [32]u8 = undefined;
        peekRngBytes(&rng, &debug_bytes_bt);
        log.print("RNG state before bottom tree 1: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_bt)});

        // Generate leaves from PRF key (matching original implementation)
        const tree_leafs = try generateLeavesFromPrfKey(prf_key, 1, parameter, allocator);
        defer allocator.free(tree_leafs);

        // Convert from @Vector(8, u32) to [8]FieldElement
        var leafs_array = try allocator.alloc([8]FieldElement, tree_leafs.len);
        defer allocator.free(leafs_array);

        for (tree_leafs, 0..) |leaf, j| {
            for (0..8) |k| {
                leafs_array[j][k] = FieldElement{ .value = leaf[k] };
            }
        }

        log.print("Bottom tree 1 leaves: {} leaves\n", .{leafs_array.len});
        for (leafs_array, 0..) |leaf, j| {
            log.print("  Leaf {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j, leaf[0].value, leaf[1].value, leaf[2].value, leaf[3].value, leaf[4].value, leaf[5].value, leaf[6].value, leaf[7].value });
        }

        const bottom_tree = try new_bottom_tree(8, 1, parameter, leafs_array, &rng);
        bottom_tree_roots[1] = root(&bottom_tree);

        log.print("Bottom tree 1 root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ bottom_tree_roots[1][0].value, bottom_tree_roots[1][1].value, bottom_tree_roots[1][2].value, bottom_tree_roots[1][3].value, bottom_tree_roots[1][4].value, bottom_tree_roots[1][5].value, bottom_tree_roots[1][6].value, bottom_tree_roots[1][7].value });
    }

    // Now build the rest of the bottom trees (2-15) in parallel like Rust
    log.print("\n=== Building Bottom Trees 2-15 (Parallel) ===\n", .{});
    for (2..num_bottom_trees) |tree_index| {
        log.print("\n=== Building Bottom Tree {} ===\n", .{tree_index});

        // Debug: Check RNG state before this bottom tree
        var debug_bytes_bt: [32]u8 = undefined;
        peekRngBytes(&rng, &debug_bytes_bt);
        log.print("RNG state before bottom tree {}: {x}\n", .{ tree_index, std.fmt.fmtSliceHexLower(&debug_bytes_bt) });

        // Generate leaves from PRF key (matching original implementation)
        const tree_leafs = try generateLeavesFromPrfKey(prf_key, tree_index, parameter, allocator);
        defer allocator.free(tree_leafs);

        // Convert from @Vector(8, u32) to [8]FieldElement
        var leafs_array = try allocator.alloc([8]FieldElement, tree_leafs.len);
        defer allocator.free(leafs_array);

        for (tree_leafs, 0..) |leaf, j| {
            for (0..8) |k| {
                leafs_array[j][k] = FieldElement{ .value = leaf[k] };
            }
        }

        log.print("Bottom tree {} leaves: {} leaves\n", .{ tree_index, leafs_array.len });
        for (leafs_array, 0..) |leaf, j| {
            log.print("  Leaf {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j, leaf[0].value, leaf[1].value, leaf[2].value, leaf[3].value, leaf[4].value, leaf[5].value, leaf[6].value, leaf[7].value });
        }

        const bottom_tree = try new_bottom_tree(8, tree_index, parameter, leafs_array, &rng);
        bottom_tree_roots[tree_index] = root(&bottom_tree);

        log.print("Bottom tree {} root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ tree_index, bottom_tree_roots[tree_index][0].value, bottom_tree_roots[tree_index][1].value, bottom_tree_roots[tree_index][2].value, bottom_tree_roots[tree_index][3].value, bottom_tree_roots[tree_index][4].value, bottom_tree_roots[tree_index][5].value, bottom_tree_roots[tree_index][6].value, bottom_tree_roots[tree_index][7].value });
    }

    // Now build the top tree from the bottom tree roots
    log.print("\n=== Building Top Tree ===\n", .{});

    // Debug: Check RNG state before top tree
    var debug_bytes_tt: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes_tt);
    log.print("RNG state before top tree: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_tt)});

    log.print("Top tree input roots: {} roots\n", .{bottom_tree_roots.len});
    for (bottom_tree_roots, 0..) |root_val, i| {
        log.print("  Root {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, root_val[0].value, root_val[1].value, root_val[2].value, root_val[3].value, root_val[4].value, root_val[5].value, root_val[6].value, root_val[7].value });
    }

    const top_tree = try new_top_tree(&rng, 8, 0, parameter, bottom_tree_roots);
    const final_root = root(&top_tree);

    log.print("\nRust Algorithm Port final root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ final_root[0].value, final_root[1].value, final_root[2].value, final_root[3].value, final_root[4].value, final_root[5].value, final_root[6].value, final_root[7].value });

    allocator.free(bottom_tree_roots);

    // No need to free leafs as it was removed
}
