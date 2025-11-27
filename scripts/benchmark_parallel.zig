const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("========================================\n", .{});
    std.debug.print("Parallel Tree Generation Benchmark\n", .{});
    std.debug.print("========================================\n", .{});
    std.debug.print("Lifetime: 2^32\n", .{});
    std.debug.print("Active Epochs: 1024\n", .{});
    std.debug.print("Previous baseline: ~96.6 seconds\n", .{});
    std.debug.print("Expected improvement: 35-48%%\n", .{});
    std.debug.print("========================================\n\n", .{});

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_32);
    defer scheme.deinit();

    const num_active_epochs: usize = 1024;
    std.debug.print("Generating keypair...\n", .{});

    var timer = try std.time.Timer.start();
    const keypair = try scheme.keyGen(0, num_active_epochs);
    const elapsed_ns = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

    std.debug.print("\n✅ Key generation completed!\n", .{});
    std.debug.print("⏱️  Time: {d:.3} seconds\n", .{elapsed_s});
    std.debug.print("📊 Improvement: {d:.1}%% faster\n", .{(96.6 - elapsed_s) / 96.6 * 100.0});
    std.debug.print("   Baseline: 96.6s → Current: {d:.3}s\n", .{elapsed_s});
    std.debug.print("   Speedup: {d:.2}x\n", .{96.6 / elapsed_s});

    keypair.secret_key.deinit();
}
