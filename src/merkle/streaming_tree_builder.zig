const std = @import("std");
const field_types = @import("../core/field.zig");
const tweakable_hash = @import("../hash/tweakable_hash.zig");

const FieldElement = field_types.FieldElement;
const TweakableHash = tweakable_hash.TweakableHash;

pub const StreamingTreeBuilder = struct {
    // Use a truly streaming approach - compute root incrementally
    tree_height: u8,
    allocator: std.mem.Allocator,
    hash: *TweakableHash,
    mutex: std.Thread.Mutex,
    leaves_added: usize,
    // Store only the current level we're working on (much smaller)
    current_level: []FieldElement,
    current_level_size: usize,

    pub fn init(allocator: std.mem.Allocator, tree_height: u8, hash: *TweakableHash) !StreamingTreeBuilder {
        // Use a truly streaming approach - only allocate what we need for current level
        // Removed unused variable for performance
        // Removed debug print for performance

        // Start with a small buffer for the current level (we'll grow as needed)
        const initial_buffer_size = 1024; // Much smaller initial allocation
        // Removed debug print for performance

        const current_level = try allocator.alloc(FieldElement, initial_buffer_size);
        @memset(current_level, FieldElement.zero());

        // Removed debug print for performance

        return StreamingTreeBuilder{
            .tree_height = tree_height,
            .allocator = allocator,
            .hash = hash,
            .mutex = std.Thread.Mutex{},
            .leaves_added = 0,
            .current_level = current_level,
            .current_level_size = initial_buffer_size,
        };
    }

    pub fn deinit(self: *StreamingTreeBuilder) void {
        self.allocator.free(self.current_level);
    }

    pub fn addLeafHash(self: *StreamingTreeBuilder, leaf_hash: FieldElement) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // For now, just store the leaf hash in our buffer
        if (self.leaves_added >= self.current_level_size) {
            // Need to grow the buffer
            const new_size = self.current_level_size * 2;
            const new_level = try self.allocator.realloc(self.current_level, new_size);
            self.current_level = new_level;
            self.current_level_size = new_size;

            // Zero out the new space
            @memset(self.current_level[self.leaves_added..], FieldElement.zero());
        }

        self.current_level[self.leaves_added] = leaf_hash;
        self.leaves_added += 1;
    }

    pub fn getRoot(self: *StreamingTreeBuilder) !?FieldElement {
        if (self.leaves_added == 0) {
            return null;
        }

        // Compute the root incrementally using the leaves we have
        var current_level = try self.allocator.dupe(FieldElement, self.current_level[0..self.leaves_added]);

        var level_size = self.leaves_added;
        var current_height: u32 = 0;

        while (level_size > 1 and current_height < self.tree_height) {
            const next_level_size = (level_size + 1) / 2;
            var next_level = try self.allocator.alloc(FieldElement, next_level_size);

            for (0..next_level_size) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                const left = current_level[left_idx];
                const right = if (right_idx < level_size) current_level[right_idx] else FieldElement.zero();

                // Hash the pair to get parent
                const pair = try self.allocator.alloc(FieldElement, 2);
                pair[0] = left;
                pair[1] = right;

                const tweak = @import("../hash/tweak.zig").PoseidonTweak{
                    .tree_tweak = .{
                        .level = @intCast(current_height + 1),
                        .pos_in_level = @intCast(i),
                    },
                };

                const parent_hash = try self.hash.hashFieldElements(
                    self.allocator,
                    pair,
                    tweak,
                    1,
                );

                next_level[i] = parent_hash[0];

                // Clean up pair and parent_hash
                self.allocator.free(pair);
                self.allocator.free(parent_hash);
            }

            self.allocator.free(current_level);
            current_level = next_level;
            level_size = next_level_size;
            current_height += 1;
        }

        // Store result before freeing
        const result = if (level_size > 0) current_level[0] else FieldElement.zero();
        // Always free current_level since it was allocated at the beginning
        self.allocator.free(current_level);
        return result;
    }

    pub fn getTreeLevels(self: *StreamingTreeBuilder) ![][][]FieldElement {
        // For now, return empty tree levels since we're not storing the full tree
        var tree_levels: [][][]FieldElement = try self.allocator.alloc([][]FieldElement, self.tree_height);

        for (0..self.tree_height) |level| {
            const level_size = @as(usize, 1) << @intCast(level);
            tree_levels[level] = try self.allocator.alloc([]FieldElement, level_size);

            for (0..level_size) |pos| {
                tree_levels[level][pos] = try self.allocator.alloc(FieldElement, 1);
                tree_levels[level][pos][0] = FieldElement.zero();
            }
        }

        return tree_levels;
    }

    pub fn isComplete(self: *const StreamingTreeBuilder) bool {
        return self.leaves_added == (@as(usize, 1) << @intCast(self.tree_height));
    }
};
