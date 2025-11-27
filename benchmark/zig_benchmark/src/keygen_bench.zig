const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("Zig hash-zig Key Generation Benchmark\n", .{});
    log.print("=====================================\n", .{});

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var lifetime: hash_zig.KeyLifetimeRustCompat = .lifetime_2_8;
    var num_active_epochs: usize = 256;
    var activation_epoch: usize = 0;

    if (args.len > 1) {
        lifetime = try parseLifetime(args[1]);
    }
    if (args.len > 2) {
        num_active_epochs = try std.fmt.parseInt(usize, args[2], 10);
    }
    if (args.len > 3) {
        activation_epoch = try std.fmt.parseInt(usize, args[3], 10);
    }

    const seed = [_]u8{0x42} ** 32;
    log.print("SEED: ", .{});
    for (seed) |b| log.print("{x:0>2}", .{b});
    log.print("\n", .{});

    log.print("CONFIG: lifetime={s}, activation_epoch={}, active_epochs={}\n", .{
        lifetimeToString(lifetime),
        activation_epoch,
        num_active_epochs,
    });

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, seed);
    defer scheme.deinit();

    log.print("Generating keypair...\n", .{});

    // Measure key generation time
    var timer = try std.time.Timer.start();
    const keypair = try scheme.keyGen(activation_epoch, num_active_epochs);
    const elapsed_ns = timer.read();
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;

    log.print("Key generation completed in {d:.6} seconds\n", .{elapsed_s});
    log.print("BENCHMARK_RESULT: {d:.6}\n", .{elapsed_s});

    // Generate public key hash for comparison
    const public_key_bytes = std.mem.asBytes(&keypair.public_key.root);
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(public_key_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    log.print("PUBLIC_SHA3: ", .{});
    for (digest) |b| log.print("{x:0>2}", .{b});
    log.print("\n", .{});

    // Test signing and verification
    const message = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 } ++ [_]u8{0x00} ** 20; // "Hello World!" + padding
    const epoch: u32 = 0;

    log.print("Testing signing...\n", .{});
    var sign_timer = try std.time.Timer.start();
    const signature = try scheme.sign(keypair.secret_key, epoch, message);
    const sign_elapsed_ns = sign_timer.read();
    const sign_elapsed_s = @as(f64, @floatFromInt(sign_elapsed_ns)) / 1_000_000_000.0;
    log.print("Signing completed in {d:.6} seconds\n", .{sign_elapsed_s});

    log.print("Testing verification...\n", .{});
    var verify_timer = try std.time.Timer.start();
    const is_valid = try scheme.verify(&keypair.public_key, epoch, message, signature);
    const verify_elapsed_ns = verify_timer.read();
    const verify_elapsed_s = @as(f64, @floatFromInt(verify_elapsed_ns)) / 1_000_000_000.0;
    log.print("Verification completed in {d:.6} seconds\n", .{verify_elapsed_s});

    log.print("VERIFY_OK: {}\n", .{is_valid});

    // Clean up
    signature.deinit();
    keypair.secret_key.deinit();

    log.print("✅ Benchmark completed successfully!\n", .{});
}

fn parseLifetime(value: []const u8) !hash_zig.KeyLifetimeRustCompat {
    if (std.mem.eql(u8, value, "2^8") or std.mem.eql(u8, value, "8")) {
        return .lifetime_2_8;
    } else if (std.mem.eql(u8, value, "2^18") or std.mem.eql(u8, value, "18")) {
        return .lifetime_2_18;
    } else if (std.mem.eql(u8, value, "2^32") or std.mem.eql(u8, value, "32")) {
        return .lifetime_2_32;
    }
    return error.UnknownLifetime;
}

fn lifetimeToString(lifetime: hash_zig.KeyLifetimeRustCompat) []const u8 {
    return switch (lifetime) {
        .lifetime_2_8 => "2^8",
        .lifetime_2_18 => "2^18",
        .lifetime_2_32 => "2^32",
    };
}
