//! Incremental Merkle Tree Builder
//!
//! This module provides an efficient incremental tree builder that computes
//! the root hash without storing the entire tree in memory. It uses a
//! streaming approach similar to the Rust implementation.

const std = @import("std");
const field_types = @import("../core/field.zig");
const tweakable_hash = @import("../hash/tweakable_hash.zig");

const FieldElement = field_types.FieldElement;
const TweakableHash = tweakable_hash.TweakableHash;
const Allocator = std.mem.Allocator;

/// Incremental tree builder that computes root without storing full tree
pub const IncrementalTreeBuilder = struct {
    allocator: Allocator,
    hash: *TweakableHash,
    tree_height: u8,
    leaf_count: usize,
    max_leaves: usize,

    // Stack-based approach: only store the current level being computed
    current_level: []FieldElement,
    current_level_size: usize,

    pub fn init(allocator: Allocator, tree_height: u8, hash: *TweakableHash) !IncrementalTreeBuilder {
        const max_leaves = @as(usize, 1) << @intCast(tree_height);

        // Start with a small buffer for the current level
        const initial_buffer_size = @min(1024, max_leaves);
        const current_level = try allocator.alloc(FieldElement, initial_buffer_size);

        return IncrementalTreeBuilder{
            .allocator = allocator,
            .hash = hash,
            .tree_height = tree_height,
            .leaf_count = 0,
            .max_leaves = max_leaves,
            .current_level = current_level,
            .current_level_size = initial_buffer_size,
        };
    }

    pub fn deinit(self: *IncrementalTreeBuilder) void {
        self.allocator.free(self.current_level);
    }

    /// Add a leaf hash and incrementally build the tree
    pub fn addLeaf(self: *IncrementalTreeBuilder, leaf_hash: FieldElement) !void {
        if (self.leaf_count >= self.max_leaves) {
            return error.TooManyLeaves;
        }

        // Ensure we have enough space
        if (self.leaf_count >= self.current_level_size) {
            try self.expandBuffer();
        }

        self.current_level[self.leaf_count] = leaf_hash;
        self.leaf_count += 1;

        // If we've completed a level, compute the next level
        if (self.leaf_count == self.current_level_size) {
            try self.computeNextLevel();
        }
    }

    /// Get the current root (may be intermediate if tree is not complete)
    pub fn getCurrentRoot(self: *IncrementalTreeBuilder) ?FieldElement {
        if (self.leaf_count == 0) return null;
        return self.current_level[0];
    }

    /// Complete the tree and return the final root
    pub fn finalize(self: *IncrementalTreeBuilder) !FieldElement {
        if (self.leaf_count == 0) return error.EmptyTree;

        // Complete any remaining levels
        while (self.current_level_size > 1) {
            try self.computeNextLevel();
        }

        return self.current_level[0];
    }

    /// Generate authentication path for a given leaf index (placeholder implementation)
    /// TODO: Implement proper authentication path generation
    pub fn generateAuthPath(self: *IncrementalTreeBuilder, leaf_index: usize) ![][]FieldElement {
        _ = self;
        _ = leaf_index;

        // For now, return an empty auth path - this is a placeholder
        // In a real implementation, we would need to store intermediate nodes
        // or recompute them on demand
        return error.NotImplemented;
    }

    fn expandBuffer(self: *IncrementalTreeBuilder) !void {
        const new_size = self.current_level_size * 2;
        const new_level = try self.allocator.realloc(self.current_level, new_size);
        self.current_level = new_level;
        self.current_level_size = new_size;
    }

    fn computeNextLevel(self: *IncrementalTreeBuilder) !void {
        const current_count = self.leaf_count;
        const next_count = (current_count + 1) / 2;

        // Compute pairs of nodes to form the next level
        var next_idx: usize = 0;
        var i: usize = 0;

        while (i < current_count) {
            const left = self.current_level[i];
            var combined: [2]FieldElement = undefined;
            combined[0] = left;

            if (i + 1 < current_count) {
                // Both left and right nodes exist
                combined[1] = self.current_level[i + 1];
                i += 2;
            } else {
                // Only left node exists (odd number of nodes)
                combined[1] = FieldElement.zero();
                i += 1;
            }

            // Hash the combined nodes
            const tweak = @import("../hash/tweak.zig").PoseidonTweak{
                .tree_tweak = .{
                    .level = @intCast(self.tree_height - @ctz(@as(u64, current_count))),
                    .pos_in_level = @intCast(next_idx),
                },
            };

            const hash_result = try self.hash.hashFieldElements(
                self.allocator,
                &combined,
                tweak,
                1,
            );
            defer self.allocator.free(hash_result);

            self.current_level[next_idx] = hash_result[0];
            next_idx += 1;
        }

        // Update state for next level
        self.leaf_count = next_idx;
        self.current_level_size = next_count;
    }
};
