const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Deep Processing Order and RNG Analysis ===\n\n", .{});

    // Initialize RNG with fixed seed (matching rust_algorithm_port.zig)
    const seed = [_]u8{0x42} ** 32;
    var rng = hash_zig.prf.ChaCha12Rng.init(seed);

    // Generate parameters WITHOUT consuming RNG state (matching Rust)
    var parameter: [5]hash_zig.core.KoalaBearField = undefined;
    var random_bytes: [20]u8 = undefined;
    peekRngBytes(&rng, &random_bytes);

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        parameter[i] = hash_zig.core.KoalaBearField{ .value = random_value >> 1 };
    }

    // Generate PRF key WITHOUT consuming RNG state (matching Rust)
    var prf_key_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &prf_key_bytes);
    const prf_key = prf_key_bytes;

    std.debug.print("=== RNG State After Parameter/PRF Generation ===\n", .{});
    var debug_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Generate bottom tree roots with detailed tracking
    var bottom_tree_roots = std.ArrayList([8]hash_zig.core.KoalaBearField).init(allocator);
    defer bottom_tree_roots.deinit();

    std.debug.print("\n=== Bottom Tree Generation with Processing Order ===\n", .{});
    for (0..16) |bottom_tree_index| {
        std.debug.print("\n--- Bottom Tree {} ---\n", .{bottom_tree_index});

        // Track RNG state before bottom tree generation
        var debug_bytes_before: [32]u8 = undefined;
        peekRngBytes(&rng, &debug_bytes_before);
        std.debug.print("RNG State Before: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_before)});

        // Generate leaves for this bottom tree
        const leaves = try generateLeavesFromPrfKey(prf_key, bottom_tree_index, parameter, allocator);
        defer allocator.free(leaves);

        // Build bottom tree with processing order tracking
        const root = try buildBottomTreeWithOrder(leaves, parameter, allocator);
        try bottom_tree_roots.append(root);

        // Track RNG state after bottom tree generation
        var debug_bytes_after: [32]u8 = undefined;
        peekRngBytes(&rng, &debug_bytes_after);
        std.debug.print("RNG State After: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_after)});

        std.debug.print("Bottom Tree {} Root: {any}\n", .{ bottom_tree_index, root });
    }

    std.debug.print("\n=== RNG State After Bottom Tree Generation ===\n", .{});
    var debug_bytes_bottom: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes_bottom);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_bottom)});

    // Build top tree with detailed processing order tracking
    std.debug.print("\n=== Top Tree Building with Processing Order ===\n", .{});
    const final_root = try buildTopTreeWithOrder(bottom_tree_roots.items, parameter, allocator);
    std.debug.print("Final Root: {any}\n", .{final_root});

    std.debug.print("\n=== RNG State After Top Tree Generation ===\n", .{});
    var debug_bytes_top: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes_top);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes_top)});

    std.debug.print("\n=== Analysis Complete ===\n", .{});
}

// Peek RNG bytes without consuming state (matching rust_algorithm_port.zig)
fn peekRngBytes(rng: *hash_zig.prf.ChaCha12Rng, buf: []u8) void {
    // Access the internal state of the RNG to peek without advancing
    const bytes = &rng.state;
    const avail = bytes.len - rng.offset;

    if (avail >= buf.len) {
        // We have enough bytes available in the current state
        @memcpy(buf, bytes[rng.offset..][0..buf.len]);
    } else {
        // Need to peek into the next state block
        const first_part = avail;

        if (first_part > 0) {
            @memcpy(buf[0..first_part], bytes[rng.offset..][0..first_part]);
        }

        // For the second part, we need to peek into the next state
        // This is a simplified version - in practice, we'd need to compute the next state
        @memset(buf[first_part..], 0);
    }
}

// Apply Poseidon chain tweak hash (matching rust_algorithm_port.zig)
fn applyPoseidonChainTweakHash(
    input: [8]hash_zig.core.KoalaBearField,
    epoch: u32,
    chain_index: u8,
    pos_in_chain: u8,
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![8]hash_zig.core.KoalaBearField {
    // Convert epoch, chain_index, and pos_in_chain to field elements for tweak using Rust's encoding
    // ChainTweak: ((epoch as u128) << 24) | ((chain_index as u128) << 16) | ((pos_in_chain as u128) << 8) | 0x00
    const tweak_encoding = (@as(u128, epoch) << 24) | (@as(u128, chain_index) << 16) | (@as(u128, pos_in_chain) << 8) | 0x00;

    // Convert to field elements using base-p representation
    const tweak = tweakToFieldElements(tweak_encoding);

    // Prepare combined input: parameter + tweak + message
    const total_input_len = 5 + 2 + 8;
    var combined_input = try alloc.alloc(hash_zig.core.KoalaBearField, total_input_len);
    defer alloc.free(combined_input);

    // Copy parameter
    for (0..5) |i| {
        combined_input[i] = parameter[i];
    }

    // Copy tweak
    for (0..2) |i| {
        combined_input[5 + i] = tweak[i];
    }

    // Copy message
    for (0..8) |i| {
        combined_input[5 + 2 + i] = input[i];
    }

    // Apply Poseidon2 hash
    var poseidon2 = try hash_zig.hash.Poseidon2RustCompat.init(alloc);
    const hash_result = try poseidon2.hashFieldElements(alloc, combined_input);
    defer alloc.free(hash_result);

    // Return first 8 elements
    var result: [8]hash_zig.core.KoalaBearField = undefined;
    for (0..8) |i| {
        result[i] = hash_result[i];
    }

    return result;
}

// Apply Poseidon tree tweak hash (matching rust_algorithm_port.zig)
fn applyPoseidonTreeTweakHash(
    input: []u32,
    level: u8,
    position: u32,
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![8]hash_zig.core.KoalaBearField {
    // Convert level and position to field elements for tweak using Rust's encoding
    // TreeTweak: ((level as u128) << 32) | (position as u128)
    const tweak_encoding = (@as(u128, level) << 32) | @as(u128, position);

    // Convert to field elements using base-p representation
    const tweak = tweakToFieldElements(tweak_encoding);

    // Prepare combined input: parameter + tweak + message
    const total_input_len = 5 + 2 + input.len;
    var combined_input = try alloc.alloc(hash_zig.core.KoalaBearField, total_input_len);
    defer alloc.free(combined_input);

    // Copy parameter
    for (0..5) |i| {
        combined_input[i] = parameter[i];
    }

    // Copy tweak
    for (0..2) |i| {
        combined_input[5 + i] = tweak[i];
    }

    // Copy message
    for (input, 0..) |value, i| {
        combined_input[5 + 2 + i] = hash_zig.core.KoalaBearField{ .value = value };
    }

    // Apply Poseidon2 hash
    var poseidon2 = try hash_zig.hash.Poseidon2RustCompat.init(alloc);
    const hash_result = try poseidon2.hashFieldElements(alloc, combined_input);
    defer alloc.free(hash_result);

    // Return first 8 elements
    var result: [8]hash_zig.core.KoalaBearField = undefined;
    for (0..8) |i| {
        result[i] = hash_result[i];
    }

    return result;
}

// Convert tweak encoding to field elements (matching rust_algorithm_port.zig)
fn tweakToFieldElements(tweak: u128) [2]hash_zig.core.KoalaBearField {
    // Convert to base-p representation
    const p = hash_zig.core.KoalaBearField.PRIME;

    var result: [2]hash_zig.core.KoalaBearField = undefined;
    result[0] = hash_zig.core.KoalaBearField{ .value = @as(u32, @intCast(tweak % p)) };
    result[1] = hash_zig.core.KoalaBearField{ .value = @as(u32, @intCast((tweak / p) % p)) };

    return result;
}

// Simplified leaf generation (matching rust_algorithm_port.zig)
fn generateLeavesFromPrfKey(
    prf_key: [32]u8,
    bottom_tree_index: usize,
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![]@Vector(8, u32) {
    const leafs_per_bottom_tree = 16;
    const num_chains = 8;

    var leaves = try alloc.alloc(@Vector(8, u32), leafs_per_bottom_tree);

    const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
    const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;

    for (epoch_range_start..epoch_range_end) |epoch| {
        var chain_ends = try alloc.alloc(u32, num_chains);
        defer alloc.free(chain_ends);

        for (0..num_chains) |chain_index| {
            const chain_ends_slice = try computeHashChain(prf_key, epoch, chain_index, parameter, alloc);
            defer alloc.free(chain_ends_slice);
            chain_ends[chain_index] = chain_ends_slice[0].value;
        }

        // Apply tree tweak to chain ends (matching Rust)
        const tree_tweak = try applyPoseidonTreeTweakHash(
            chain_ends,
            @as(u8, @intCast(0)),
            @as(u32, @intCast(epoch)),
            parameter,
            alloc,
        );

        // Convert to leaf format
        var leaf: @Vector(8, u32) = undefined;
        for (0..8) |i| {
            leaf[i] = tree_tweak[i].value;
        }
        leaves[epoch - epoch_range_start] = leaf;
    }

    return leaves;
}

// Simplified hash chain computation (matching rust_algorithm_port.zig)
fn computeHashChain(
    prf_key: [32]u8,
    epoch: usize,
    chain_index: usize,
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![]hash_zig.core.KoalaBearField {
    const chain_length = 8;
    var chain = try alloc.alloc(hash_zig.core.KoalaBearField, chain_length);

    // Generate domain element
    const domain_element = hash_zig.prf.ShakePRFtoF_8_7.getDomainElement(prf_key, @as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

    // Initialize chain
    chain[0] = hash_zig.core.KoalaBearField{ .value = domain_element[0] };

    // Compute chain
    for (1..chain_length) |i| {
        // Create input array with single element
        var input: [8]hash_zig.core.KoalaBearField = undefined;
        input[0] = chain[i - 1];
        for (1..8) |j| {
            input[j] = hash_zig.core.KoalaBearField{ .value = 0 };
        }

        const chain_tweak = try applyPoseidonChainTweakHash(
            input,
            @as(u32, @intCast(epoch)),
            @as(u8, @intCast(chain_index)),
            @as(u8, @intCast(i)),
            parameter,
            alloc,
        );
        chain[i] = chain_tweak[0];
    }

    return chain;
}

// Build bottom tree with processing order tracking
fn buildBottomTreeWithOrder(
    leaves: []@Vector(8, u32),
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![8]hash_zig.core.KoalaBearField {
    if (leaves.len == 0) return error.EmptyLeaves;

    var current_nodes = try alloc.alloc([8]hash_zig.core.KoalaBearField, leaves.len);
    defer alloc.free(current_nodes);

    for (leaves, 0..) |leaf, i| {
        for (0..8) |j| {
            current_nodes[i][j] = hash_zig.core.KoalaBearField{ .value = leaf[j] };
        }
    }

    var current_len = current_nodes.len;
    var level: usize = 0;

    while (current_len > 1) {
        std.debug.print("DEBUG: Bottom Tree Layer {} -> {}: {} nodes\n", .{ level, level + 1, current_len });

        const parents_len = current_len / 2;
        var next_nodes = try alloc.alloc([8]hash_zig.core.KoalaBearField, parents_len);

        const parent_start: usize = 0;
        std.debug.print("DEBUG: Processing {} parent nodes in layer {}\n", .{ parents_len, level });

        for (0..parents_len) |i| {
            const parent_pos = @as(u32, @intCast(parent_start + i));
            const tweak_level = @as(u8, @intCast(level)) + 1;

            std.debug.print("DEBUG: Processing parent {} at position {} with tweak level {}\n", .{ i, parent_pos, tweak_level });

            const left_child = current_nodes[i * 2];
            const right_child = current_nodes[i * 2 + 1];

            var message: [16]u32 = undefined;
            for (0..8) |j| {
                message[j] = left_child[j].value;
                message[8 + j] = right_child[j].value;
            }

            const hash_result = try applyPoseidonTreeTweakHash(message[0..], tweak_level, parent_pos, parameter, alloc);
            next_nodes[i] = hash_result;
        }

        alloc.free(current_nodes);
        current_nodes = next_nodes;
        current_len = parents_len;
        level += 1;
    }

    const final_root = current_nodes[0];
    return final_root;
}

// Build top tree with processing order tracking
fn buildTopTreeWithOrder(
    bottom_tree_roots: [][8]hash_zig.core.KoalaBearField,
    parameter: [5]hash_zig.core.KoalaBearField,
    alloc: std.mem.Allocator,
) ![8]hash_zig.core.KoalaBearField {
    if (bottom_tree_roots.len == 0) return error.EmptyRoots;

    std.debug.print("DEBUG: Building top tree from {} bottom tree roots\n", .{bottom_tree_roots.len});

    var current_nodes = try alloc.alloc([8]hash_zig.core.KoalaBearField, bottom_tree_roots.len);
    defer alloc.free(current_nodes);

    for (bottom_tree_roots, 0..) |root, i| {
        current_nodes[i] = root;
    }

    var current_len = current_nodes.len;
    var level: usize = 0;

    while (current_len > 1) {
        std.debug.print("DEBUG: Top Tree Layer {} -> {}: {} nodes\n", .{ level, level + 1, current_len });

        const parents_len = current_len / 2;
        var next_nodes = try alloc.alloc([8]hash_zig.core.KoalaBearField, parents_len);

        const parent_start: usize = 0;
        std.debug.print("DEBUG: Processing {} parent nodes in layer {}\n", .{ parents_len, level });

        for (0..parents_len) |i| {
            const parent_pos = @as(u32, @intCast(parent_start + i));
            const tweak_level = @as(u8, @intCast(level)) + 5; // Top tree starts at level 5

            std.debug.print("DEBUG: Processing parent {} at position {} with tweak level {}\n", .{ i, parent_pos, tweak_level });

            const left_child = current_nodes[i * 2];
            const right_child = current_nodes[i * 2 + 1];

            var message: [16]u32 = undefined;
            for (0..8) |j| {
                message[j] = left_child[j].value;
                message[8 + j] = right_child[j].value;
            }

            const hash_result = try applyPoseidonTreeTweakHash(message[0..], tweak_level, parent_pos, parameter, alloc);
            next_nodes[i] = hash_result;
        }

        alloc.free(current_nodes);
        current_nodes = next_nodes;
        current_len = parents_len;
        level += 1;
    }

    const final_root = current_nodes[0];
    return final_root;
}
