const std = @import("std");
const build_options = @import("build_options");

pub inline fn print(comptime fmt: []const u8, args: anytype) void {
    if (!build_options.enable_debug_logs) return;
    std.debug.print(fmt, args);
}

/// Feature-flagged version of std.debug.print
/// Only prints if build_options.enable_debug_logs is true
pub inline fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (!build_options.enable_debug_logs) return;
    std.debug.print(fmt, args);
}

pub inline fn emit(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}
