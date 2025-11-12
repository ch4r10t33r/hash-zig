//! Merkle tree for hash-based signatures (Field-Native Implementation)
//!
//! This implementation operates directly on field elements (KoalaBear)
//! for compatibility with the Rust hash-sig implementation.
//!
//! Key differences from byte-based implementation (merkle.zig):
//! - Tree nodes are single FieldElement, not byte arrays
//! - Hash function operates on field elements
//! - Uses TreeTweak for domain separation
//! - Authentication paths are field element arrays

const std = @import("std");
const params = @import("params.zig");
const tweakable_hash = @import("../hash/tweakable_hash.zig");
const tweak_types = @import("../hash/tweak.zig");
const field_types = @import("../core/field.zig");
const Parameters = params.Parameters;
const TweakableHash = tweakable_hash.TweakableHash;
const FieldElement = field_types.FieldElement;
const PoseidonTweak = tweak_types.PoseidonTweak;
const Allocator = std.mem.Allocator;

pub const MerkleTreeNative = struct {
    params: Parameters,
    hash: TweakableHash,
    height: u32,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !MerkleTreeNative {
        return .{
            .params = parameters,
            .hash = try TweakableHash.init(allocator, parameters),
            .height = parameters.tree_height,
            .allocator = allocator,
        };
    }

    pub fn initWithParameter(
        allocator: Allocator,
        parameters: Parameters,
        parameter: [5]FieldElement,
    ) !MerkleTreeNative {
        return .{
            .params = parameters,
            .hash = try TweakableHash.initWithParameter(allocator, parameters, parameter),
            .height = parameters.tree_height,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MerkleTreeNative) void {
        self.hash.deinit();
    }

    const NodeWorkerCtx = struct {
        tree: *MerkleTreeNative,
        current_level: []FieldElement,
        next_level: []FieldElement,
        current_len: usize,
        level_num: u32, // Current level in the tree (0 = leaves)
        allocator: Allocator,
        index: std.atomic.Value(usize),
        error_flag: std.atomic.Value(bool),
    };

    fn nodeWorker(ctx: *NodeWorkerCtx) void {
        const total = ctx.next_level.len;
        while (!ctx.error_flag.load(.monotonic)) {
            const i = ctx.index.fetchAdd(1, .monotonic);
            if (i >= total) break;

            const left_idx = i * 2;
            const right_idx = left_idx + 1;

            if (right_idx < ctx.current_len) {
                const left = ctx.current_level[left_idx];
                const right = ctx.current_level[right_idx];
                var input = [2]FieldElement{ left, right };
                const tweak = PoseidonTweak{ .tree_tweak = .{
                    .level = @intCast(ctx.level_num + 1),
                    .pos_in_level = @intCast(i),
                } };
                const result = ctx.tree.hash.hashFieldElements(
                    ctx.allocator,
                    &input,
                    tweak,
                    1,
                ) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };
                defer ctx.allocator.free(result);
                ctx.next_level[i] = result[0];
            } else {
                // Odd node, promote directly
                ctx.next_level[i] = ctx.current_level[left_idx];
            }
        }
    }

    /// Build Merkle tree from field element leaves
    /// Returns the root as a single FieldElement (for backward compatibility)
    pub fn buildTree(self: *MerkleTreeNative, allocator: Allocator, leaves: []const FieldElement) !FieldElement {
        if (leaves.len == 0) return error.EmptyLeaves;
        if (leaves.len == 1) return leaves[0];

        // Allocate for current level
        var level = try allocator.alloc(FieldElement, leaves.len);
        @memcpy(level, leaves);

        var current_len = leaves.len;
        const num_cpus = std.Thread.getCpuCount() catch 8;
        var level_num: u32 = 0;

        while (current_len > 1) {
            const next_len = (current_len + 1) / 2;
            var next_level = try allocator.alloc(FieldElement, next_len);

            // Initialize to zero
            @memset(next_level, FieldElement.zero());

            const num_threads = @min(num_cpus, next_len);

            if (num_threads > 1) {
                // Parallel processing
                var ctx = NodeWorkerCtx{
                    .tree = self,
                    .current_level = level,
                    .next_level = next_level,
                    .current_len = current_len,
                    .level_num = level_num,
                    .allocator = allocator,
                    .index = std.atomic.Value(usize).init(0),
                    .error_flag = std.atomic.Value(bool).init(false),
                };

                var threads = try allocator.alloc(std.Thread, num_threads);
                defer allocator.free(threads);

                for (0..num_threads) |i| {
                    threads[i] = try std.Thread.spawn(.{}, nodeWorker, .{&ctx});
                }

                for (threads) |thread| {
                    thread.join();
                }

                if (ctx.error_flag.load(.monotonic)) {
                    return error.TreeBuildFailed;
                }
            } else {
                // Sequential processing
                for (0..next_len) |i| {
                    const left_idx = i * 2;
                    const right_idx = left_idx + 1;

                    if (right_idx < current_len) {
                        const left = level[left_idx];
                        const right = level[right_idx];

                        var input = [2]FieldElement{ left, right };

                        const tweak = PoseidonTweak{ .tree_tweak = .{
                            .level = @intCast(level_num + 1),
                            .pos_in_level = @intCast(i),
                        } };

                        const result = try self.hash.hashFieldElements(
                            allocator,
                            &input,
                            tweak,
                            1, // tree_hash_output_len_fe
                        );
                        defer allocator.free(result);

                        next_level[i] = result[0];
                    } else {
                        next_level[i] = level[left_idx];
                    }
                }
            }

            // Move to next level
            allocator.free(level);
            level = next_level;
            current_len = next_len;
            level_num += 1;
        }

        // Save root and free the final level array
        const root = level[0];
        allocator.free(level);
        return root;
    }

    /// Build full tree structure with all intermediate nodes
    /// Returns all tree nodes level by level (for authentication paths)
    pub fn buildFullTree(
        self: *MerkleTreeNative,
        allocator: Allocator,
        leaves: []const []FieldElement,
    ) ![][][]FieldElement {
        if (leaves.len == 0) return error.EmptyLeaves;

        // Calculate number of levels
        const num_leaves = leaves.len;
        var levels_needed: usize = 1;
        var tmp = num_leaves;
        while (tmp > 1) {
            tmp = (tmp + 1) / 2;
            levels_needed += 1;
        }

        // Allocate for all levels (3D: levels → nodes → elements)
        var tree_levels = try allocator.alloc([][]FieldElement, levels_needed);
        errdefer {
            for (tree_levels) |level| {
                for (level) |node| {
                    allocator.free(node);
                }
                allocator.free(level);
            }
            allocator.free(tree_levels);
        }

        // Copy leaves (each leaf is already a []FieldElement)
        tree_levels[0] = try allocator.alloc([]FieldElement, num_leaves);
        for (leaves, 0..) |leaf, i| {
            tree_levels[0][i] = try allocator.dupe(FieldElement, leaf);
        }

        var current_len = num_leaves;
        var level_num: u32 = 0;

        // Build each level
        for (1..levels_needed) |level_idx| {
            const next_len = (current_len + 1) / 2;
            tree_levels[level_idx] = try allocator.alloc([]FieldElement, next_len);

            const current_level = tree_levels[level_idx - 1];

            for (0..next_len) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                if (right_idx < current_len) {
                    // Have both children - hash them
                    const left = current_level[left_idx];
                    const right = current_level[right_idx];

                    // Combine left and right (each is 7 FEs, total 14 FEs)
                    var combined = try allocator.alloc(FieldElement, left.len + right.len);
                    defer allocator.free(combined);
                    @memcpy(combined[0..left.len], left);
                    @memcpy(combined[left.len..], right);

                    const tweak = PoseidonTweak{ .tree_tweak = .{
                        .level = @intCast(level_num + 1),
                        .pos_in_level = @intCast(i),
                    } };

                    const parent = try self.hash.hashFieldElements(
                        allocator,
                        combined,
                        tweak,
                        7, // 7 field elements output (HASH_LEN_FE)
                    );
                    // Removed debug print for performance
                    // Don't defer - ownership transfers to tree
                    tree_levels[level_idx][i] = parent;
                } else if (left_idx < current_len) {
                    // Odd node, copy up
                    tree_levels[level_idx][i] = try allocator.dupe(FieldElement, current_level[left_idx]);
                } else {
                    // Shouldn't happen, but handle gracefully
                    tree_levels[level_idx][i] = try allocator.alloc(FieldElement, 7);
                    @memset(tree_levels[level_idx][i], FieldElement.zero());
                }
            }

            current_len = next_len;
            level_num += 1;
        }

        return tree_levels;
    }

    /// Get authentication path for a specific leaf index
    pub fn getAuthPath(
        self: *MerkleTreeNative,
        allocator: Allocator,
        tree_levels: [][][]const FieldElement,
        leaf_index: usize,
    ) ![][]FieldElement {
        _ = self;

        if (tree_levels.len == 0) return error.EmptyTree;
        if (leaf_index >= tree_levels[0].len) return error.InvalidLeafIndex;

        const height = tree_levels.len - 1; // Exclude root level
        var auth_path = try allocator.alloc([]FieldElement, height);
        errdefer {
            for (auth_path) |node| {
                allocator.free(node);
            }
            allocator.free(auth_path);
        }

        var current_idx = leaf_index;

        for (0..height) |level| {
            const sibling_idx = current_idx ^ 1; // XOR with 1 to get sibling
            const current_level = tree_levels[level];

            if (sibling_idx < current_level.len) {
                // Copy all field elements for the sibling node
                auth_path[level] = try allocator.dupe(FieldElement, current_level[sibling_idx]);
            } else {
                // No sibling (odd node), use the node itself
                auth_path[level] = try allocator.dupe(FieldElement, current_level[current_idx]);
            }

            current_idx /= 2;
        }

        return auth_path;
    }

    /// Verify a leaf value with its authentication path
    pub fn verifyAuthPath(
        self: *MerkleTreeNative,
        allocator: Allocator,
        leaf: []const FieldElement,
        leaf_index: usize,
        auth_path: []const []FieldElement,
        expected_root: []const FieldElement,
    ) !bool {
        if (auth_path.len == 0) {
            // Compare single field element
            if (leaf.len != 1) return false;
            if (expected_root.len != 1) return false;
            return leaf[0].toU32() == expected_root[0].toU32();
        }

        var current = try allocator.dupe(FieldElement, leaf);
        defer allocator.free(current);
        var current_idx = leaf_index;
        var level_num: u32 = 0;

        for (auth_path) |sibling| {
            const is_left = (current_idx & 1) == 0;
            const pos_in_level = current_idx / 2;

            // Combine current and sibling (each contains 7 field elements)
            var combined = try allocator.alloc(FieldElement, current.len + sibling.len);
            defer allocator.free(combined);

            if (is_left) {
                @memcpy(combined[0..current.len], current);
                @memcpy(combined[current.len..], sibling);
            } else {
                @memcpy(combined[0..sibling.len], sibling);
                @memcpy(combined[sibling.len..], current);
            }

            // Rust uses parent level index for the hash tweak. Our level_num starts at 0 for leaves,
            // so parent level is (level_num + 1), which matches Rust's convention.
            const tweak = PoseidonTweak{ .tree_tweak = .{
                .level = @intCast(level_num + 1),
                .pos_in_level = @intCast(pos_in_level),
            } };

            const result = try self.hash.hashFieldElements(
                allocator,
                combined,
                tweak,
                7, // 7 field elements output for Poseidon2
            );
            // Removed debug print for performance

            // Update current for next iteration
            allocator.free(current);
            current = result;
            current_idx = pos_in_level;
            level_num += 1;
        }

        // Compare final result with expected root
        if (current.len != expected_root.len) {
            return false;
        }

        // Compare all field elements
        for (current, expected_root) |current_fe, expected_fe| {
            if (current_fe.toU32() != expected_fe.toU32()) {
                return false;
            }
        }
        return true;
    }
};

test "merkle native: build tree from leaves" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_8);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 4 leaves (each leaf is 7 FEs)
    var leaves = try allocator.alloc([]FieldElement, 4);
    defer {
        for (leaves) |leaf| allocator.free(leaf);
        allocator.free(leaves);
    }

    for (0..4) |i| {
        leaves[i] = try allocator.alloc(FieldElement, 7);
        for (0..7) |j| {
            leaves[i][j] = FieldElement.fromU32(@intCast(i * 7 + j + 1));
        }
    }

    const tree_levels = try tree.buildFullTree(allocator, leaves);
    defer {
        for (tree_levels) |level| {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }
        allocator.free(tree_levels);
    }

    const root = tree_levels[tree_levels.len - 1][0];

    // Root should be non-zero (check first element)
    try std.testing.expect(root.len > 0);
    try std.testing.expect(root[0].toU32() != 0);
}

test "merkle native: build full tree" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_8);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 8 leaves (each leaf is 7 FEs)
    var leaves = try allocator.alloc([]FieldElement, 8);
    defer {
        for (leaves) |leaf| allocator.free(leaf);
        allocator.free(leaves);
    }

    for (0..8) |i| {
        leaves[i] = try allocator.alloc(FieldElement, 7);
        for (0..7) |j| {
            leaves[i][j] = FieldElement.fromU32(@intCast(i * 7 + j + 1));
        }
    }

    const tree_levels = try tree.buildFullTree(allocator, leaves);
    defer {
        for (tree_levels) |level| {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }
        allocator.free(tree_levels);
    }

    // Should have 4 levels: 8 -> 4 -> 2 -> 1
    try std.testing.expectEqual(@as(usize, 4), tree_levels.len);
    try std.testing.expectEqual(@as(usize, 8), tree_levels[0].len);
    try std.testing.expectEqual(@as(usize, 4), tree_levels[1].len);
    try std.testing.expectEqual(@as(usize, 2), tree_levels[2].len);
    try std.testing.expectEqual(@as(usize, 1), tree_levels[3].len);
}

test "merkle native: auth path verification" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_8);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 8 leaves (each leaf is 7 FEs)
    var leaves = try allocator.alloc([]FieldElement, 8);
    defer {
        for (leaves) |leaf| allocator.free(leaf);
        allocator.free(leaves);
    }

    for (0..8) |i| {
        leaves[i] = try allocator.alloc(FieldElement, 7);
        for (0..7) |j| {
            leaves[i][j] = FieldElement.fromU32(@intCast(i * 7 + j + 1));
        }
    }

    const tree_levels = try tree.buildFullTree(allocator, leaves);
    defer {
        for (tree_levels) |level| {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }
        allocator.free(tree_levels);
    }

    const root = tree_levels[tree_levels.len - 1][0];

    // Get auth path for leaf 3
    const leaf_idx: usize = 3;
    const auth_path = try tree.getAuthPath(allocator, tree_levels, leaf_idx);
    defer {
        for (auth_path) |node| allocator.free(node);
        allocator.free(auth_path);
    }

    // Verify the leaf
    const is_valid = try tree.verifyAuthPath(
        allocator,
        leaves[leaf_idx],
        leaf_idx,
        auth_path,
        root,
    );
    try std.testing.expect(is_valid);

    // Verify with wrong leaf should fail
    const wrong_leaf = try allocator.alloc(FieldElement, 7);
    defer allocator.free(wrong_leaf);
    @memset(wrong_leaf, FieldElement.fromU32(999));

    const is_invalid = try tree.verifyAuthPath(
        allocator,
        wrong_leaf,
        leaf_idx,
        auth_path,
        root,
    );
    try std.testing.expect(!is_invalid);
}

test "merkle native: deterministic" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_8);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create same leaves twice (each leaf is 7 FEs)
    var leaves = try allocator.alloc([]FieldElement, 8);
    defer {
        for (leaves) |leaf| allocator.free(leaf);
        allocator.free(leaves);
    }

    for (0..8) |i| {
        leaves[i] = try allocator.alloc(FieldElement, 7);
        for (0..7) |j| {
            leaves[i][j] = FieldElement.fromU32(@intCast(i * 7 + j + 42));
        }
    }

    const tree_levels1 = try tree.buildFullTree(allocator, leaves);
    defer {
        for (tree_levels1) |level| {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }
        allocator.free(tree_levels1);
    }

    const tree_levels2 = try tree.buildFullTree(allocator, leaves);
    defer {
        for (tree_levels2) |level| {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }
        allocator.free(tree_levels2);
    }

    const root1 = tree_levels1[tree_levels1.len - 1][0];
    const root2 = tree_levels2[tree_levels2.len - 1][0];

    // Roots should be identical
    try std.testing.expect(root1.len == root2.len);
    for (root1, root2) |r1, r2| {
        try std.testing.expect(r1.toU32() == r2.toU32());
    }
}
