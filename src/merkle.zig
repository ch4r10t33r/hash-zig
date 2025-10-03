//! Merkle tree for hash-based signatures

const std = @import("std");
const params = @import("params.zig");
const tweakable_hash = @import("tweakable_hash.zig");
const Parameters = params.Parameters;
const TweakableHash = tweakable_hash.TweakableHash;
const Allocator = std.mem.Allocator;

pub const MerkleTree = struct {
    params: Parameters,
    hash: TweakableHash,
    height: u32,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !MerkleTree {
        return .{
            .params = parameters,
            .hash = try TweakableHash.init(allocator, parameters),
            .height = parameters.tree_height,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.hash.deinit();
    }

    const NodeWorkerCtx = struct {
        tree: *MerkleTree,
        current_level: [][]u8,
        next_level: [][]u8,
        current_len: usize,
        allocator: Allocator,
        index: std.atomic.Value(usize),
        error_flag: std.atomic.Value(bool),
        combined_len: usize,
    };

    fn nodeWorker(ctx: *NodeWorkerCtx) void {
        // Allocate a per-thread scratch buffer once
        var scratch = ctx.allocator.alloc(u8, ctx.combined_len) catch {
            ctx.error_flag.store(true, .monotonic);
            return;
        };
        defer ctx.allocator.free(scratch);

        const total = ctx.next_level.len;
        while (!ctx.error_flag.load(.monotonic)) {
            const i = ctx.index.fetchAdd(1, .monotonic);
            if (i >= total) break;
            const left_idx = i * 2;
            const right_idx = left_idx + 1;
            if (right_idx < ctx.current_len) {
                const left = ctx.current_level[left_idx];
                const right = ctx.current_level[right_idx];
                @memcpy(scratch[0..left.len], left);
                @memcpy(scratch[left.len..][0..right.len], right);
                ctx.next_level[i] = ctx.tree.hash.hash(ctx.allocator, scratch, i) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };
            } else {
                ctx.next_level[i] = ctx.allocator.dupe(u8, ctx.current_level[left_idx]) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };
            }
        }
    }

    pub fn buildTree(self: *MerkleTree, allocator: Allocator, leaves: [][]const u8) ![]u8 {
        if (leaves.len == 0) return error.EmptyLeaves;
        if (leaves.len == 1) {
            return allocator.dupe(u8, leaves[0]);
        }

        var level = try allocator.alloc([]u8, leaves.len);

        for (leaves, 0..) |leaf, i| {
            level[i] = try allocator.dupe(u8, leaf);
        }

        var current_len = leaves.len;

        const num_cpus = std.Thread.getCpuCount() catch 8;

        while (current_len > 1) {
            const next_len = (current_len + 1) / 2;
            var next_level = try allocator.alloc([]u8, next_len);

            // Initialize to empty slices
            for (next_level) |*node| {
                node.* = &[_]u8{};
            }

            const num_threads = @min(num_cpus, next_len);

            if (num_threads <= 1 or next_len < 32) {
                // Sequential for small workloads
                for (0..next_len) |i| {
                    const left_idx = i * 2;
                    const right_idx = left_idx + 1;

                    if (right_idx < current_len) {
                        const combined = try allocator.alloc(u8, level[left_idx].len + level[right_idx].len);
                        defer allocator.free(combined);
                        @memcpy(combined[0..level[left_idx].len], level[left_idx]);
                        @memcpy(combined[level[left_idx].len..], level[right_idx]);
                        next_level[i] = try self.hash.hash(allocator, combined, i);
                    } else {
                        next_level[i] = try allocator.dupe(u8, level[left_idx]);
                    }
                }
            } else {
                // Parallel node hashing with atomic index and thread-local scratch
                const error_flag = std.atomic.Value(bool).init(false);
                const idx = std.atomic.Value(usize).init(0);
                const node_len = level[0].len; // hash output len
                var ctx = NodeWorkerCtx{
                    .tree = self,
                    .current_level = level,
                    .next_level = next_level,
                    .current_len = current_len,
                    .allocator = allocator,
                    .index = idx,
                    .error_flag = error_flag,
                    .combined_len = node_len * 2,
                };

                var threads = try allocator.alloc(std.Thread, num_threads);
                defer allocator.free(threads);
                // Spawn workers
                for (0..num_threads) |t| {
                    threads[t] = try std.Thread.spawn(.{}, nodeWorker, .{&ctx});
                }
                // Join
                for (threads) |th| th.join();
                if (ctx.error_flag.load(.monotonic)) {
                    // Cleanup on error
                    for (next_level) |node| {
                        if (node.len > 0) allocator.free(node);
                    }
                    allocator.free(next_level);
                    for (level[0..current_len]) |node| allocator.free(node);
                    allocator.free(level);
                    return error.InternalError;
                }
            }

            // Free the current level
            for (level[0..current_len]) |node| allocator.free(node);
            allocator.free(level);

            level = next_level;
            current_len = next_len;
        }

        // Return the root (move ownership to caller)
        const root = level[0];
        allocator.free(level);

        return root;
    }

    pub fn generateAuthPath(self: *MerkleTree, allocator: Allocator, leaves: [][]const u8, leaf_idx: usize) ![][]u8 {
        if (leaves.len == 0) return error.EmptyLeaves;
        if (leaf_idx >= leaves.len) return error.InvalidIndex;

        const tree_height = @ctz(@as(u64, leaves.len));
        var auth_path = try allocator.alloc([]u8, tree_height);
        errdefer {
            for (auth_path) |node| allocator.free(node);
            allocator.free(auth_path);
        }

        // Build the tree level by level and collect sibling nodes
        var level = try allocator.alloc([]u8, leaves.len);
        defer {
            for (level) |node| allocator.free(node);
            allocator.free(level);
        }

        for (leaves, 0..) |leaf, i| {
            level[i] = try allocator.dupe(u8, leaf);
        }

        var current_idx = leaf_idx;
        var current_len = leaves.len;
        var path_idx: usize = 0;

        while (current_len > 1) {
            // Get sibling index
            const sibling_idx = if (current_idx % 2 == 0) current_idx + 1 else current_idx - 1;

            // Save sibling to auth path (if it exists)
            if (sibling_idx < current_len) {
                auth_path[path_idx] = try allocator.dupe(u8, level[sibling_idx]);
                path_idx += 1;
            }

            // Build next level
            const next_len = (current_len + 1) / 2;
            var next_level = try allocator.alloc([]u8, next_len);

            for (0..next_len) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                if (right_idx < current_len) {
                    const combined = try allocator.alloc(u8, level[left_idx].len + level[right_idx].len);
                    defer allocator.free(combined);
                    @memcpy(combined[0..level[left_idx].len], level[left_idx]);
                    @memcpy(combined[level[left_idx].len..], level[right_idx]);
                    next_level[i] = try self.hash.hash(allocator, combined, i);
                } else {
                    next_level[i] = try allocator.dupe(u8, level[left_idx]);
                }
            }

            // Free current level
            for (level[0..current_len]) |node| allocator.free(node);
            allocator.free(level);

            level = next_level;
            current_idx = current_idx / 2;
            current_len = next_len;
        }

        // Resize auth_path to actual size (may be less than tree_height)
        if (path_idx < tree_height) {
            const resized = try allocator.alloc([]u8, path_idx);
            for (0..path_idx) |i| {
                resized[i] = auth_path[i];
            }
            allocator.free(auth_path);
            return resized;
        }

        return auth_path;
    }
};
