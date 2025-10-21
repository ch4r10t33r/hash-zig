const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig hash-zig Key Generation Benchmark\n", .{});
    std.debug.print("=====================================\n", .{});

    // Use a fixed seed for reproducibility
    const seed = [_]u8{0x42} ** 32;
    std.debug.print("SEED: ", .{});
    for (seed) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    // Initialize the signature scheme for lifetime 2^8
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    std.debug.print("Generating keypair for lifetime 2^8 (256 signatures)...\n", .{});

    // Measure key generation time
    var timer = try std.time.Timer.start();
    const keypair = try scheme.keyGen(0, 256); // activation_epoch=0, num_active_epochs=256
    const elapsed_ns = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

    std.debug.print("Key generation completed in {d:.6} seconds\n", .{elapsed_s});
    std.debug.print("BENCHMARK_RESULT: {d:.6}\n", .{elapsed_s});

    // Generate public key hash for comparison
    const public_key_bytes = std.mem.asBytes(&keypair.public_key.root.value);
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(public_key_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    std.debug.print("PUBLIC_SHA3: ", .{});
    for (digest) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    // Test signing and verification
    const message = [_]u8{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21} ++ [_]u8{0x00} ** 20; // "Hello World!" + padding
    const epoch: u32 = 0;

    std.debug.print("Testing signing...\n", .{});
    var sign_timer = try std.time.Timer.start();
    const signature = try scheme.sign(keypair.secret_key, epoch, message);
    const sign_elapsed_ns = sign_timer.read();
    const sign_elapsed_s = @as(f64, @floatFromInt(sign_elapsed_ns)) / 1_000_000_000.0;
    std.debug.print("Signing completed in {d:.6} seconds\n", .{sign_elapsed_s});

    std.debug.print("Testing verification...\n", .{});
    var verify_timer = try std.time.Timer.start();
    const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
    const verify_elapsed_ns = verify_timer.read();
    const verify_elapsed_s = @as(f64, @floatFromInt(verify_elapsed_ns)) / 1_000_000_000.0;
    std.debug.print("Verification completed in {d:.6} seconds\n", .{verify_elapsed_s});

    std.debug.print("VERIFY_OK: {}\n", .{is_valid});

    // Clean up
    signature.deinit();
    keypair.secret_key.deinit();

    std.debug.print("✅ Benchmark completed successfully!\n", .{});
}
