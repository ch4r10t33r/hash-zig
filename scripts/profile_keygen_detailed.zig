//! Detailed performance profiling script for key generation
//! Measures time spent in different phases: chain computation, tree hashing, etc.

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
    print("Detailed Key Generation Performance Profiling\n", .{});
    print("========================================\n", .{});
    print("Lifetime: 2^{}\n", .{lifetime_power});
    print("Active Epochs: {}\n", .{num_active_epochs});
    print("========================================\n\n", .{});

    // Initialize scheme
    var timer = try std.time.Timer.start();
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(
        allocator,
        hash_zig.KeyLifetimeRustCompat.lifetime_2_32,
    );
    defer scheme.deinit();

    const init_time = timer.read();
    timer.reset();
    print("Scheme initialization: {d:.3}s\n", .{@as(f64, @floatFromInt(init_time)) / 1_000_000_000.0});

    // Generate keypair with timing
    print("\nGenerating keypair...\n", .{});
    timer.reset();
    
    const activation_epoch: usize = 0;
    const keypair = try scheme.keyGen(activation_epoch, num_active_epochs);
    // KeyGenResult contains public_key and secret_key which are managed by the scheme
    _ = keypair;
    
    const keygen_time = @as(f64, @floatFromInt(timer.read())) / 1_000_000_000.0;
    
    print("\n✅ Key generation completed!\n", .{});
    print("⏱️  Total Time: {d:.3}s\n\n", .{keygen_time});
    
    const init_time_sec = @as(f64, @floatFromInt(init_time)) / 1_000_000_000.0;
    const total_time = init_time_sec + keygen_time;
    
    print("Performance Breakdown:\n", .{});
    print("  - Initialization: {d:.3}s ({d:.1}%)\n", .{ 
        init_time_sec,
        if (total_time > 0) (init_time_sec / total_time) * 100.0 else 0.0
    });
    print("  - Key Generation: {d:.3}s ({d:.1}%)\n", .{ 
        keygen_time,
        if (total_time > 0) (keygen_time / total_time) * 100.0 else 0.0
    });
    print("  - Total: {d:.3}s\n", .{total_time});
    
    print("\nNote: For detailed breakdown of chain computation vs tree hashing,\n", .{});
    print("      instrumentation needs to be added to the key generation code.\n", .{});
}

