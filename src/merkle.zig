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

        while (current_len > 1) {
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
        _ = self;
        _ = allocator;
        _ = leaves;
        _ = leaf_idx;
        return error.NotImplemented;
    }
};
