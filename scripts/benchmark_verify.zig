const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var lifetime_power: u8 = 8; // Default to 2^8
    var iterations: usize = 1000; // Default iterations
    if (args.len > 1) {
        lifetime_power = std.fmt.parseInt(u8, args[1], 10) catch 8;
    }
    if (args.len > 2) {
        iterations = std.fmt.parseInt(usize, args[2], 10) catch 1000;
    }

    std.debug.print("Verification Performance Benchmark\n", .{});
    std.debug.print("==================================\n", .{});
    std.debug.print("Lifetime: 2^{d}\n", .{lifetime_power});
    std.debug.print("Iterations: {d}\n\n", .{iterations});

    const lifetime: hash_zig.KeyLifetimeRustCompat = switch (lifetime_power) {
        8 => .lifetime_2_8,
        18 => .lifetime_2_18,
        32 => .lifetime_2_32,
        else => .lifetime_2_8,
    };

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();

    // Generate keypair
    std.debug.print("Generating keypair...\n", .{});
    const keypair = try scheme.keyGen(0, 256);
    defer {
        keypair.secret_key.deinit();
    }

    // Sign a message
    const message = [_]u8{0x42} ** 32;
    const signature = try scheme.sign(keypair.secret_key, 0, message);
    defer signature.deinit();

    // Warm up
    _ = try scheme.verify(&keypair.public_key, 0, message, signature);

    // Benchmark verification
    std.debug.print("Benchmarking verification ({d} iterations)...\n", .{iterations});
    var timer = try std.time.Timer.start();
    const start_ns = timer.read();

    for (0..iterations) |_| {
        const is_valid = try scheme.verify(&keypair.public_key, 0, message, signature);
        if (!is_valid) {
            std.debug.print("ERROR: Verification failed!\n", .{});
            return;
        }
    }

    const end_ns = timer.read();
    const duration_ns = end_ns - start_ns;
    const duration_ms = @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0;
    const duration_s = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;
    const avg_ms = duration_ms / @as(f64, @floatFromInt(iterations));
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / duration_s;

    std.debug.print("\n📊 VERIFICATION BENCHMARK RESULTS:\n", .{});
    std.debug.print("  Total time: {d:.3}ms ({d:.6}s)\n", .{ duration_ms, duration_s });
    std.debug.print("  Iterations: {d}\n", .{iterations});
    std.debug.print("  Average per verify: {d:.3}ms\n", .{avg_ms});
    std.debug.print("  Throughput: {d:.0} verifications/sec\n", .{ops_per_sec});
    std.debug.print("  Lifetime: 2^{d}\n", .{lifetime_power});
}

