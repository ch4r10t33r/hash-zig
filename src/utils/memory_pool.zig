//! Memory Pool Allocator for High-Performance Operations
//!
//! This module provides a custom memory pool allocator optimized for
//! frequent allocations and deallocations of similar-sized objects.

const std = @import("std");

/// Memory pool allocator for high-performance operations
pub const MemoryPool = struct {
    const Block = struct {
        data: []u8,
        used: bool,
        next: ?*Block,
    };

    parent_allocator: std.mem.Allocator,
    block_size: usize,
    blocks: std.ArrayList(*Block),
    free_blocks: ?*Block,
    mutex: std.Thread.Mutex,

    pub fn init(parent_allocator: std.mem.Allocator, block_size: usize) MemoryPool {
        return MemoryPool{
            .parent_allocator = parent_allocator,
            .block_size = block_size,
            .blocks = std.ArrayList(*Block).init(parent_allocator),
            .free_blocks = null,
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *MemoryPool) void {
        // Free all blocks
        for (self.blocks.items) |block| {
            self.parent_allocator.free(block.data);
            self.parent_allocator.destroy(block);
        }
        self.blocks.deinit();
    }

    pub fn allocator(self: *MemoryPool) std.mem.Allocator {
        return std.mem.Allocator{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, _: u8, _: usize) ?[*]u8 {
        const self: *MemoryPool = @ptrCast(@alignCast(ctx));

        // Only handle exact block size allocations for now
        if (len != self.block_size) {
            return null;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        // Try to reuse a free block
        if (self.free_blocks) |block| {
            self.free_blocks = block.next;
            block.used = true;
            return block.data.ptr;
        }

        // Allocate a new block
        const data = self.parent_allocator.alloc(u8, len) catch return null;
        const block = self.parent_allocator.create(Block) catch {
            self.parent_allocator.free(data);
            return null;
        };

        block.* = Block{
            .data = data,
            .used = true,
            .next = null,
        };

        self.blocks.append(block) catch {
            self.allocator.destroy(block);
            self.allocator.free(data);
            return null;
        };

        return data.ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = ret_addr;
        return false; // No resize support
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        const self: *MemoryPool = @ptrCast(@alignCast(ctx));
        _ = buf_align;
        _ = ret_addr;

        if (buf.len != self.block_size) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        // Find the block and mark it as free
        for (self.blocks.items) |block| {
            if (block.data.ptr == buf.ptr) {
                block.used = false;
                block.next = self.free_blocks;
                self.free_blocks = block;
                return;
            }
        }
    }
};
