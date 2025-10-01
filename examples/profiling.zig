const std = @import("std");
const hash_sig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Hash-zig Performance Profiling ===\n\n", .{});

    const params = hash_sig.Parameters.init(.lifetime_2_10);
    std.debug.print("Configuration: 2^10 = 1,024 signatures\n", .{});
    std.debug.print("  Winternitz w: {}\n", .{params.winternitz_w});
    std.debug.print("  Num chains: {}\n", .{params.num_chains});
    std.debug.print("  Hash output: {} bytes\n\n", .{params.hash_output_len});

    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    const seed: [32]u8 = .{42} ** 32;

    // Profile individual WOTS operations
    std.debug.print("--- Single WOTS Operation Profile ---\n", .{});
    
    const t1 = std.time.nanoTimestamp();
    const priv_key = try sig_scheme.wots.generatePrivateKey(allocator, &seed, 0);
    const t2 = std.time.nanoTimestamp();
    
    const pub_key = try sig_scheme.wots.generatePublicKey(allocator, priv_key);
    const t3 = std.time.nanoTimestamp();
    
    const priv_time = @as(f64, @floatFromInt(t2 - t1)) / 1_000_000.0;
    const pub_time = @as(f64, @floatFromInt(t3 - t2)) / 1_000_000.0;
    
    std.debug.print("  generatePrivateKey: {d:.3} ms\n", .{priv_time});
    std.debug.print("  generatePublicKey:  {d:.3} ms\n", .{pub_time});
    std.debug.print("  Total per leaf:     {d:.3} ms\n\n", .{priv_time + pub_time});
    
    for (priv_key) |k| allocator.free(k);
    allocator.free(priv_key);
    allocator.free(pub_key);

    // Profile hash operations
    std.debug.print("--- Hash Operation Profile ---\n", .{});
    const test_data = "test data for hashing";
    
    const h1 = std.time.nanoTimestamp();
    const hash_result = try sig_scheme.wots.hash.hash(allocator, test_data, 0);
    const h2 = std.time.nanoTimestamp();
    allocator.free(hash_result);
    
    const hash_time = @as(f64, @floatFromInt(h2 - h1)) / 1_000_000.0;
    std.debug.print("  Single hash call: {d:.3} ms\n\n", .{hash_time});

    // Calculate expected times
    const num_leaves = @as(usize, 1) << @intCast(params.tree_height);
    const chain_length = @as(u32, 1) << @intCast(@ctz(params.winternitz_w));
    
    std.debug.print("--- Theoretical Breakdown for 1,024 leaves ---\n", .{});
    std.debug.print("  Chain length: {}\n", .{chain_length});
    std.debug.print("  Chains per leaf: ~86\n", .{});
    std.debug.print("  Hashes per leaf: ~86 * {} = ~{}\n", .{ chain_length, 86 * chain_length });
    std.debug.print("  Total hashes: 1024 * {} = ~{}\n", .{ 86 * chain_length, 1024 * 86 * chain_length });
    std.debug.print("  Expected hash time: {d:.1} seconds\n", .{
        @as(f64, @floatFromInt(1024 * 86 * chain_length)) * hash_time / 1000.0
    });
    std.debug.print("  Expected leaf gen: {d:.1} seconds\n\n", .{
        @as(f64, @floatFromInt(num_leaves)) * (priv_time + pub_time) / 1000.0
    });

    // Now do full keygen with timing
    std.debug.print("--- Full Key Generation ---\n", .{});
    const start = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    const end = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const total_time = @as(f64, @floatFromInt(end - start)) / 1_000_000_000.0;
    std.debug.print("  TOTAL TIME: {d:.3} seconds\n\n", .{total_time});

    // Breakdown estimate
    const leaf_gen_percent = ((priv_time + pub_time) * @as(f64, @floatFromInt(num_leaves)) / 1000.0) / total_time * 100.0;
    std.debug.print("--- Estimated Breakdown ---\n", .{});
    std.debug.print("  Leaf generation: ~{d:.1}%\n", .{leaf_gen_percent});
    std.debug.print("  Merkle tree: ~{d:.1}%\n", .{100.0 - leaf_gen_percent});
    std.debug.print("  Other overhead: ~{d:.1}%\n", .{@max(0.0, 100.0 - leaf_gen_percent - 10.0)});
}

