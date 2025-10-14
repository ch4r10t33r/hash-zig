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
const tweakable_hash = @import("tweakable_hash.zig");
const field_types = @import("field.zig");
const tweak_types = @import("tweak.zig");
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
                // Hash two children nodes
                const left = ctx.current_level[left_idx];
                const right = ctx.current_level[right_idx];

                // Create input: [left, right]
                var input = [2]FieldElement{ left, right };

                // Create tree tweak
                const tweak = PoseidonTweak{
                    .tree_tweak = .{
                        .level = @intCast(ctx.level_num + 1), // Parent level
                        .pos_in_level = @intCast(i), // Position in parent level
                    },
                };

                // Hash to single field element (tree_hash_output_len_fe = 1)
                const result = ctx.tree.hash.hashFieldElements(
                    ctx.allocator,
                    &input,
                    tweak,
                    1, // tree_hash_output_len_fe for KoalaBear
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
    /// Returns the root as a single FieldElement
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
        leaves: []const FieldElement,
    ) ![][]FieldElement {
        if (leaves.len == 0) return error.EmptyLeaves;

        // Calculate number of levels
        const num_leaves = leaves.len;
        var levels_needed: usize = 1;
        var tmp = num_leaves;
        while (tmp > 1) {
            tmp = (tmp + 1) / 2;
            levels_needed += 1;
        }

        // Allocate for all levels
        var tree_levels = try allocator.alloc([]FieldElement, levels_needed);
        errdefer {
            for (tree_levels) |level| {
                if (level.len > 0) allocator.free(level);
            }
            allocator.free(tree_levels);
        }

        // Copy leaves
        tree_levels[0] = try allocator.alloc(FieldElement, num_leaves);
        @memcpy(tree_levels[0], leaves);

        var current_len = num_leaves;
        var level_num: u32 = 0;

        // Build each level
        for (1..levels_needed) |level_idx| {
            const next_len = (current_len + 1) / 2;
            tree_levels[level_idx] = try allocator.alloc(FieldElement, next_len);
            @memset(tree_levels[level_idx], FieldElement.zero());

            const current_level = tree_levels[level_idx - 1];
            const next_level = tree_levels[level_idx];

            for (0..next_len) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                if (right_idx < current_len) {
                    const left = current_level[left_idx];
                    const right = current_level[right_idx];

                    var input = [2]FieldElement{ left, right };

                    const tweak = PoseidonTweak{ .tree_tweak = .{
                        .level = @intCast(level_num + 1),
                        .pos_in_level = @intCast(i),
                    } };

                    const result = try self.hash.hashFieldElements(
                        allocator,
                        &input,
                        tweak,
                        1,
                    );
                    defer allocator.free(result);

                    next_level[i] = result[0];
                } else {
                    next_level[i] = current_level[left_idx];
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
        tree_levels: [][]const FieldElement,
        leaf_index: usize,
    ) ![]FieldElement {
        _ = self;

        if (tree_levels.len == 0) return error.EmptyTree;
        if (leaf_index >= tree_levels[0].len) return error.InvalidLeafIndex;

        const height = tree_levels.len - 1; // Exclude root level
        var auth_path = try allocator.alloc(FieldElement, height);
        errdefer allocator.free(auth_path);

        var current_idx = leaf_index;

        for (0..height) |level| {
            const sibling_idx = current_idx ^ 1; // XOR with 1 to get sibling
            const current_level = tree_levels[level];

            if (sibling_idx < current_level.len) {
                auth_path[level] = current_level[sibling_idx];
            } else {
                // No sibling (odd node), use the node itself
                auth_path[level] = current_level[current_idx];
            }

            current_idx /= 2;
        }

        return auth_path;
    }

    /// Verify a leaf value with its authentication path
    pub fn verifyAuthPath(
        self: *MerkleTreeNative,
        allocator: Allocator,
        leaf: FieldElement,
        leaf_index: usize,
        auth_path: []const FieldElement,
        expected_root: FieldElement,
    ) !bool {
        if (auth_path.len == 0) return leaf.value == expected_root.value;

        var current = leaf;
        var current_idx = leaf_index;
        var level_num: u32 = 0;

        for (auth_path) |sibling| {
            const is_left = (current_idx & 1) == 0;
            const pos_in_level = current_idx / 2;

            var input: [2]FieldElement = undefined;
            if (is_left) {
                input[0] = current;
                input[1] = sibling;
            } else {
                input[0] = sibling;
                input[1] = current;
            }

            const tweak = PoseidonTweak{ .tree_tweak = .{
                .level = @intCast(level_num + 1),
                .pos_in_level = @intCast(pos_in_level),
            } };

            const result = try self.hash.hashFieldElements(
                allocator,
                &input,
                tweak,
                1,
            );
            defer allocator.free(result);

            current = result[0];
            current_idx = pos_in_level;
            level_num += 1;
        }

        return current.value == expected_root.value;
    }
};

test "merkle native: build tree from leaves" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_10);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 4 leaves
    var leaves: [4]FieldElement = undefined;
    for (0..4) |i| {
        leaves[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    const root = try tree.buildTree(allocator, &leaves);

    // Root should be non-zero
    try std.testing.expect(root.value != 0);
}

test "merkle native: build full tree" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_10);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 8 leaves
    var leaves: [8]FieldElement = undefined;
    for (0..8) |i| {
        leaves[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    const tree_levels = try tree.buildFullTree(allocator, &leaves);
    defer {
        for (tree_levels) |level| allocator.free(level);
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
    const parameters = Parameters.init(.lifetime_2_10);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create 8 leaves
    var leaves: [8]FieldElement = undefined;
    for (0..8) |i| {
        leaves[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    const tree_levels = try tree.buildFullTree(allocator, &leaves);
    defer {
        for (tree_levels) |level| allocator.free(level);
        allocator.free(tree_levels);
    }

    const root = tree_levels[tree_levels.len - 1][0];

    // Get auth path for leaf 3
    const leaf_idx: usize = 3;
    const auth_path = try tree.getAuthPath(allocator, @ptrCast(tree_levels), leaf_idx);
    defer allocator.free(auth_path);

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
    const wrong_leaf = FieldElement.fromU32(999);
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
    const parameters = Parameters.init(.lifetime_2_10);

    var tree = try MerkleTreeNative.init(allocator, parameters);
    defer tree.deinit();

    // Create same leaves twice
    var leaves: [8]FieldElement = undefined;
    for (0..8) |i| {
        leaves[i] = FieldElement.fromU32(@intCast(i + 42));
    }

    const root1 = try tree.buildTree(allocator, &leaves);
    const root2 = try tree.buildTree(allocator, &leaves);

    // Roots should be identical
    try std.testing.expectEqual(root1.value, root2.value);
}
