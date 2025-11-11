const std = @import("std");
const build_options = @import("build_options");

pub inline fn print(comptime fmt: []const u8, args: anytype) void {
    if (!build_options.enable_debug_logs) return;
    std.debug.print(fmt, args);
}
