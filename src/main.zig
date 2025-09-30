const std = @import("std");
const hash_zig = @import("hash_zig_lib");

pub fn main() !void {
    _ = hash_zig;
    std.debug.print("hash-zig library built successfully.\n", .{});
    std.debug.print("Run 'zig build example' to see usage examples.\n", .{});
    std.debug.print("Run 'zig build test' to run tests.\n", .{});
}
