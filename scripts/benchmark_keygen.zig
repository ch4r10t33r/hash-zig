const std = @import("std");
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
                std.debug.print("Error: Invalid iterations value: {s}\n", .{iterations_str});
                return;
            };
        } else if (std.mem.startsWith(u8, arg, "-i")) {
            const iterations_str = arg[2..];
            num_iterations = std.fmt.parseInt(u32, iterations_str, 10) catch {
                std.debug.print("Error: Invalid iterations value: {s}\n", .{iterations_str});
                return;
            };
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            std.debug.print("Use --help for usage information\n", .{});
            return;
        }
    }

    if (help_requested) {
        printUsage();
        return;
    }

    std.debug.print("hash-zig Key Generation Benchmark\n", .{});
    std.debug.print("==================================\n", .{});
    std.debug.print("Iterations per lifetime: {}\n", .{num_iterations});
    std.debug.print("Include 2^32 lifetime: {}\n", .{include_2_32});
    std.debug.print("\n", .{});

    // Benchmark configurations
    var benchmarks = std.ArrayList(BenchmarkConfig).init(allocator);
    defer benchmarks.deinit();

    try benchmarks.append(.{
        .name = "2^8",
        .lifetime = .lifetime_2_8,
        .epochs = 256,
        .description = "Testing, short-term keys",
    });

    try benchmarks.append(.{
        .name = "2^18",
        .lifetime = .lifetime_2_18,
        .epochs = 262144,
        .description = "Medium-term applications",
    });

    if (include_2_32) {
        std.debug.print("⚠️  Warning: 2^32 key generation will take a very long time!\n", .{});
        std.debug.print("   This is recommended only for comprehensive benchmarking.\n\n", .{});

        try benchmarks.append(.{
            .name = "2^32",
            .lifetime = .lifetime_2_32,
            .epochs = 4294967296,
            .description = "Long-term, high-volume",
        });
    }

    // Run benchmarks
    for (benchmarks.items) |config| {
        try runBenchmark(allocator, config, num_iterations);
        std.debug.print("\n", .{});
    }

    std.debug.print("🎉 Benchmark completed!\n", .{});
    std.debug.print("💡 Tip: Use 'zig build -Doptimize=ReleaseFast' for production builds\n", .{});
}

const BenchmarkConfig = struct {
    name: []const u8,
    lifetime: hash_zig.KeyLifetimeRustCompat,
    epochs: u64,
    description: []const u8,
};

fn runBenchmark(allocator: std.mem.Allocator, config: BenchmarkConfig, num_iterations: u32) !void {
    std.debug.print("Benchmarking lifetime {s} ({} signatures)\n", .{ config.name, config.epochs });
    std.debug.print("Description: {s}\n", .{config.description});
    std.debug.print("{s}\n", .{"=" ** 60});

    var times = std.ArrayList(f64).init(allocator);
    defer times.deinit();

    for (0..num_iterations) |i| {
        std.debug.print("Iteration {}/{}... ", .{ i + 1, num_iterations });
        std.debug.print("\x1b[2K\r", .{}); // Clear line

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

        std.debug.print("✅ {d:.2}s", .{elapsed_s});
        if (i < num_iterations - 1) {
            std.debug.print(" | ", .{});
        }
    }

    std.debug.print("\n", .{});

    // Calculate statistics
    const stats = calculateStats(times.items);

    std.debug.print("📊 Results for lifetime {s}:\n", .{config.name});
    std.debug.print("  Average time: {d:.2} seconds\n", .{stats.average});
    std.debug.print("  Min time:     {d:.2} seconds\n", .{stats.min});
    std.debug.print("  Max time:     {d:.2} seconds\n", .{stats.max});
    std.debug.print("  Std deviation: {d:.2} seconds\n", .{stats.std_dev});
    std.debug.print("  Generation rate: {d:.1} signatures/second\n", .{@as(f64, @floatFromInt(config.epochs)) / stats.average});

    if (stats.average < 1.0) {
        std.debug.print("  Generation rate: {d:.0} signatures/second\n", .{@as(f64, @floatFromInt(config.epochs)) / stats.average});
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
    std.debug.print("hash-zig Key Generation Benchmark\n", .{});
    std.debug.print("Usage: zig run benchmark_keygen.zig [options]\n\n", .{});
    std.debug.print("Options:\n", .{});
    std.debug.print("  --include-2-32, -32    Include 2^32 lifetime benchmark (very slow!)\n", .{});
    std.debug.print("  --iterations=N, -iN     Number of iterations per lifetime (default: 3)\n", .{});
    std.debug.print("  --help, -h              Show this help message\n\n", .{});
    std.debug.print("Examples:\n", .{});
    std.debug.print("  zig run benchmark_keygen.zig                    # Basic benchmark\n", .{});
    std.debug.print("  zig run benchmark_keygen.zig --include-2-32     # Include 2^32\n", .{});
    std.debug.print("  zig run benchmark_keygen.zig -i5                # 5 iterations\n", .{});
    std.debug.print("  zig run benchmark_keygen.zig -32 -i10           # Full benchmark\n\n", .{});
    std.debug.print("Performance Tips:\n", .{});
    std.debug.print("  - Use optimized builds for production: -Doptimize=ReleaseFast\n", .{});
    std.debug.print("  - 2^32 benchmarks can take hours - use with caution!\n", .{});
}
