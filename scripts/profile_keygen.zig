//! Performance profiling script for key generation
//! Measures time spent in different phases of key generation

const std = @import("std");
const hash_zig = @import("hash-zig");
const Allocator = std.mem.Allocator;
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const lifetime_power: u8 = 32;
    const num_active_epochs: u32 = 1024;

    print("========================================\n", .{});
    print("Key Generation Performance Profiling\n", .{});
    print("========================================\n", .{});
    print("Lifetime: 2^{}\n", .{lifetime_power});
    print("Active Epochs: {}\n", .{num_active_epochs});
    print("========================================\n\n", .{});

    // Initialize scheme
    const timer = try std.time.Timer.start();
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(
        allocator,
        hash_zig.KeyLifetimeRustCompat.lifetime_2_32,
    );
    defer scheme.deinit();

    const init_time = timer.lap();
    print("Scheme initialization: {d:.3}s\n", .{@as(f64, @floatFromInt(init_time)) / 1_000_000_000.0});

    // Generate seed
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    
    // Generate keypair with timing
    print("\nGenerating keypair...\n", .{});
    const keygen_start = timer.lap();
    
    const keypair = try scheme.keyGen(seed);
    defer keypair.deinit(allocator);
    
    const keygen_total = timer.lap();
    const keygen_time = @as(f64, @floatFromInt(keygen_total)) / 1_000_000_000.0;
    
    print("\n✅ Key generation completed!\n", .{});
    print("⏱️  Total Time: {d:.3}s\n\n", .{keygen_time});
    
    print("Breakdown:\n", .{});
    print("  - Initialization: {d:.3}s\n", .{@as(f64, @floatFromInt(init_time)) / 1_000_000_000.0});
    print("  - Key Generation: {d:.3}s\n", .{keygen_time});
    print("  - Total: {d:.3}s\n", .{(@as(f64, @floatFromInt(init_time)) + keygen_time) / 1_000_000_000.0});
}

