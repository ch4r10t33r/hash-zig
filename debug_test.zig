const std = @import("std");

// Test the parallel chain generation logic
pub fn main() !void {
    const num_chains: usize = 64;
    const num_threads: usize = 8;
    
    std.debug.print("Testing thread distribution for {} chains across {} threads\n", .{num_chains, num_threads});
    
    const chains_per_thread = num_chains / num_threads;
    const remainder = num_chains % num_threads;
    
    std.debug.print("  chains_per_thread: {}\n", .{chains_per_thread});
    std.debug.print("  remainder: {}\n", .{remainder});
    std.debug.print("\n", .{});
    
    for (0..num_threads) |t| {
        const start = t * chains_per_thread + @min(t, remainder);
        const end = start + chains_per_thread + (if (t < remainder) @as(usize, 1) else 0);
        std.debug.print("Thread {}: chains {} to {} (exclusive) = {} chains\n", .{t, start, end, end - start});
    }
}
