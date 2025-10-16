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
        const max_leaves = @as(usize, 1) << @intCast(tree_height);
        std.debug.print("StreamingTreeBuilder: Initializing with tree_height={}, max_leaves={}\n", .{tree_height, max_leaves});
        
        // Start with a small buffer for the current level (we'll grow as needed)
        const initial_buffer_size = 1024; // Much smaller initial allocation
        std.debug.print("StreamingTreeBuilder: About to allocate {} bytes for initial buffer\n", .{initial_buffer_size * @sizeOf(FieldElement)});
        
        const current_level = try allocator.alloc(FieldElement, initial_buffer_size);
        @memset(current_level, FieldElement.zero());
        
        std.debug.print("StreamingTreeBuilder: Successfully allocated initial buffer\n", .{});

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

        // For now, just return the first leaf hash as a placeholder
        // TODO: Implement proper incremental root computation
        return self.current_level[0];
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
        return self.leaves_added == self.leaf_hashes.len;
    }
};
