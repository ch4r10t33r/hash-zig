//! Arena allocator for high-performance memory management
//! Reduces allocation overhead in hot paths by pre-allocating large blocks

const std = @import("std");

pub const ArenaAllocator = struct {
    const Block = struct {
        data: []u8,
        used: usize,
        next: ?*Block,
    };

    const DEFAULT_BLOCK_SIZE = 1024 * 1024; // 1MB blocks
    const alignment = 8;

    Gpa: std.heap.DebugAllocator,
    current_block: ?*Block,
    block_size: usize,

    pub fn init(block_size: usize) ArenaAllocator {
        var gpa = std.heap.DebugAllocator.init(.{});
        return .{
            .Gpa = gpa,
            .current_block = null,
            .block_size = block_size,
        };
    }

    pub fn deinit(self: *ArenaAllocator) void {
        var block = self.current_block;
        while (block) |b| {
            const next = b.next;
            self.Gpa.allocator().free(b.data);
            self.Gpa.allocator().destroy(b);
            block = next;
        }
        self.Gpa.deinit();
    }

    pub fn allocator(self: *ArenaAllocator) std.mem.Allocator {
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

    fn alloc(ctx: *anyopaque, len: usize, log2_ptr_align: u8, ret_addr: usize) ?[*]u8 {
        const self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        return self.allocImpl(len, log2_ptr_align, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, new_len: usize, ret_addr: usize) bool {
        _ = ctx;
        _ = buf;
        _ = log2_buf_align;
        _ = new_len;
        _ = ret_addr;
        return false; // Arena allocator doesn't support resizing
    }

    fn free(ctx: *anyopaque, buf: []u8, log2_buf_align: u8, ret_addr: usize) void {
        _ = ctx;
        _ = buf;
        _ = log2_buf_align;
        _ = ret_addr;
        // Arena allocator doesn't free individual allocations
    }

    fn allocImpl(self: *ArenaAllocator, len: usize, log2_ptr_align: u8, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;

        const alignment_value = @as(usize, 1) << @intCast(log2_ptr_align);
        const aligned_len = std.mem.alignForward(usize, len, alignment_value);

        // Check if current block has enough space
        if (self.current_block) |block| {
            const aligned_offset = std.mem.alignForward(usize, block.used, alignment_value);
            if (aligned_offset + aligned_len <= block.data.len) {
                const result = block.data.ptr + aligned_offset;
                block.used = aligned_offset + aligned_len;
                return result;
            }
        }

        // Need a new block
        const block_size = @max(self.block_size, aligned_len);
        const block_data = self.Gpa.allocator().alloc(u8, block_size) catch return null;

        const block = self.Gpa.allocator().create(Block) catch {
            self.Gpa.allocator().free(block_data);
            return null;
        };

        block.* = .{
            .data = block_data,
            .used = 0,
            .next = self.current_block,
        };

        self.current_block = block;

        // Allocate from the new block
        const aligned_offset = std.mem.alignForward(usize, 0, alignment_value);
        const result = block.data.ptr + aligned_offset;
        block.used = aligned_offset + aligned_len;
        return result;
    }

    /// Reset the arena, freeing all allocations but keeping the blocks
    pub fn reset(self: *ArenaAllocator) void {
        var block = self.current_block;
        while (block) |b| {
            b.used = 0;
            block = b.next;
        }
    }
};

test "arena allocator basic functionality" {
    var arena = ArenaAllocator.init(1024);
    defer arena.deinit();

    const allocator = arena.allocator();

    // Test basic allocation
    const data = allocator.alloc(u8, 100) orelse return;
    try std.testing.expect(data.len == 100);

    // Test alignment
    const aligned = allocator.alloc(u8, 1) orelse return;
    try std.testing.expect(@intFromPtr(aligned.ptr) % 8 == 0);

    // Test reset
    arena.reset();

    // Should be able to allocate again
    const data2 = allocator.alloc(u8, 200) orelse return;
    try std.testing.expect(data2.len == 200);
}
