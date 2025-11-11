const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Parse command line arguments
    var include_2_32 = false;
    var num_iterations: u32 = 3;
    var help_requested = false;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--include-2-32") or std.mem.eql(u8, arg, "-32")) {
            include_2_32 = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            help_requested = true;
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            const iterations_str = arg[13..];
            num_iterations = std.fmt.parseInt(u32, iterations_str, 10) catch {
                log.print("Error: Invalid iterations value: {s}\n", .{iterations_str});
                return;
            };
        } else if (std.mem.startsWith(u8, arg, "-i")) {
            const iterations_str = arg[2..];
            num_iterations = std.fmt.parseInt(u32, iterations_str, 10) catch {
                log.print("Error: Invalid iterations value: {s}\n", .{iterations_str});
                return;
            };
        } else {
            log.print("Unknown argument: {s}\n", .{arg});
            log.print("Use --help for usage information\n", .{});
            return;
        }
    }

    if (help_requested) {
        printUsage();
        return;
    }

    log.print("hash-zig Key Generation Benchmark (Multiple Lifetimes)\n", .{});
    log.print("=======================================================\n", .{});
    log.print("Iterations per configuration: {}\n", .{num_iterations});
    log.print("Include 2^32 lifetime: {}\n", .{include_2_32});
    log.print("Note: All tests generate 256 keys to compare lifetime performance\n", .{});
    log.print("\n", .{});

    // Benchmark configurations - test different lifetimes but only generate 256 keys each
    var benchmarks = std.ArrayList(BenchmarkConfig).init(allocator);
    defer benchmarks.deinit();

    try benchmarks.append(.{
        .name = "2^8",
        .lifetime = .lifetime_2_8,
        .epochs = 256,
        .description = "Short-term keys (256 signatures max)",
    });

    try benchmarks.append(.{
        .name = "2^18",
        .lifetime = .lifetime_2_18,
        .epochs = 256,
        .description = "Medium-term keys (256 signatures max)",
    });

    if (include_2_32) {
        log.print("⚠️  Warning: 2^32 lifetime test will take longer due to larger tree structures!\n", .{});
        log.print("   This is recommended only for comprehensive benchmarking.\n\n", .{});

        try benchmarks.append(.{
            .name = "2^32",
            .lifetime = .lifetime_2_32,
            .epochs = 256,
            .description = "Long-term keys (256 signatures max)",
        });
    }

    // Run benchmarks
    for (benchmarks.items) |config| {
        try runBenchmark(allocator, config, num_iterations);
        log.print("\n", .{});
    }

    log.print("🎉 Benchmark completed!\n", .{});
    log.print("💡 Tip: Use 'zig build -Doptimize=ReleaseFast' for production builds\n", .{});
}

const BenchmarkConfig = struct {
    name: []const u8,
    lifetime: hash_zig.KeyLifetimeRustCompat,
    epochs: u64,
    description: []const u8,
};

fn runBenchmark(allocator: std.mem.Allocator, config: BenchmarkConfig, num_iterations: u32) !void {
    log.print("Benchmarking lifetime {s} (generating {} keys)\n", .{ config.name, config.epochs });
    log.print("Description: {s}\n", .{config.description});
    log.print("{s}\n", .{"=" ** 60});

    var times = std.ArrayList(f64).init(allocator);
    defer times.deinit();

    for (0..num_iterations) |i| {
        log.print("Iteration {}/{}... ", .{ i + 1, num_iterations });
        log.print("\x1b[2K\r", .{}); // Clear line

        // Initialize scheme
        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, config.lifetime);
        defer scheme.deinit();

        // Measure key generation time
        var timer = try std.time.Timer.start();
        const keypair = try scheme.keyGen(0, @intCast(config.epochs));
        const elapsed_ns = timer.read();
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

        // Store timing
        try times.append(elapsed_s);

        // Clean up
        keypair.secret_key.deinit();

        log.print("✅ {d:.2}s", .{elapsed_s});
        if (i < num_iterations - 1) {
            log.print(" | ", .{});
        }
    }

    log.print("\n", .{});

    // Calculate statistics
    const stats = calculateStats(times.items);

    log.print("📊 Results for lifetime {s} ({} keys):\n", .{ config.name, config.epochs });
    log.print("  Average time: {d:.2} seconds\n", .{stats.average});
    log.print("  Min time:     {d:.2} seconds\n", .{stats.min});
    log.print("  Max time:     {d:.2} seconds\n", .{stats.max});
    log.print("  Std deviation: {d:.2} seconds\n", .{stats.std_dev});
    log.print("  Generation rate: {d:.1} keys/second\n", .{@as(f64, @floatFromInt(config.epochs)) / stats.average});

    if (stats.average < 1.0) {
        log.print("  Generation rate: {d:.0} keys/second\n", .{@as(f64, @floatFromInt(config.epochs)) / stats.average});
    }
}

const Stats = struct {
    average: f64,
    min: f64,
    max: f64,
    std_dev: f64,
};

fn calculateStats(times: []f64) Stats {
    var sum: f64 = 0;
    var min: f64 = times[0];
    var max: f64 = times[0];

    for (times) |time| {
        sum += time;
        min = @min(min, time);
        max = @max(max, time);
    }

    const average = sum / @as(f64, @floatFromInt(times.len));

    var variance_sum: f64 = 0;
    for (times) |time| {
        const diff = time - average;
        variance_sum += diff * diff;
    }
    const variance = variance_sum / @as(f64, @floatFromInt(times.len));
    const std_dev = @sqrt(variance);

    return Stats{
        .average = average,
        .min = min,
        .max = max,
        .std_dev = std_dev,
    };
}

fn printUsage() void {
    log.print("hash-zig Key Generation Benchmark (Multiple Lifetimes)\n", .{});
    log.print("Usage: zig run benchmark_keygen.zig [options]\n\n", .{});
    log.print("Options:\n", .{});
    log.print("  --include-2-32, -32    Include 2^32 lifetime test (slower due to larger trees)\n", .{});
    log.print("  --iterations=N, -iN     Number of iterations per configuration (default: 3)\n", .{});
    log.print("  --help, -h              Show this help message\n\n", .{});
    log.print("Note: All tests generate 256 keys to compare performance across different lifetimes\n", .{});
    log.print("      Tests: 2^8, 2^18, and optionally 2^32 lifetimes\n\n", .{});
    log.print("Examples:\n", .{});
    log.print("  zig run benchmark_keygen.zig                    # Basic benchmark (2^8, 2^18)\n", .{});
    log.print("  zig run benchmark_keygen.zig --include-2-32     # Include 2^32 lifetime test\n", .{});
    log.print("  zig run benchmark_keygen.zig -i5                # 5 iterations\n", .{});
    log.print("  zig run benchmark_keygen.zig -32 -i10           # Full benchmark\n\n", .{});
    log.print("Performance Tips:\n", .{});
    log.print("  - Use optimized builds for production: -Doptimize=ReleaseFast\n", .{});
    log.print("  - 2^32 lifetime tests take longer due to larger tree structures\n", .{});
}
