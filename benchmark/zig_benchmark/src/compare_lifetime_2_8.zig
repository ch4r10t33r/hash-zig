const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("Zig hash-zig Determinism Check (lifetime 2^8)\n", .{});
    log.print("================================================\n", .{});

    // Read seed from environment variable or use default
    var seed: [32]u8 = undefined;
    if (std.process.getEnvVarOwned(allocator, "SEED_HEX")) |seed_hex| {
        defer allocator.free(seed_hex);
        if (seed_hex.len == 64) { // 32 bytes = 64 hex chars
            for (0..32) |i| {
                const hex_pair = seed_hex[i * 2 .. i * 2 + 2];
                seed[i] = std.fmt.parseInt(u8, hex_pair, 16) catch 0x42;
            }
        } else {
            @memset(&seed, 0x42); // fallback to default
        }
    } else |_| {
        @memset(&seed, 0x42); // fallback to default
    }

    log.print("SEED: {s}\n", .{std.fmt.fmtSliceHexLower(&seed)});
    log.print("SEED (bytes): {any}\n", .{seed});

    var scheme1 = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed);
    defer scheme1.deinit();

    var scheme2 = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, seed);
    defer scheme2.deinit();

    // Add debug output for RNG state
    log.print("Scheme1 RNG state after creation: {any}\n", .{scheme1.getRngState()});
    log.print("Scheme2 RNG state after creation: {any}\n", .{scheme2.getRngState()});

    const kp1 = try scheme1.keyGen(0, 256);
    defer kp1.secret_key.deinit();

    const kp2 = try scheme2.keyGen(0, 256);
    defer kp2.secret_key.deinit();

    const root1 = kp1.public_key.getRoot();
    const root2 = kp2.public_key.getRoot();

    const param1 = kp1.public_key.getParameter();
    const param2 = kp2.public_key.getParameter();

    var roots_equal = true;
    for (root1, 0..) |fe1, i| {
        if (fe1.value != root2[i].value) {
            roots_equal = false;
            break;
        }
    }
    var params_equal = true;
    inline for (param1, 0..) |fe, i| {
        if (fe.value != param2[i].value) {
            params_equal = false;
            break;
        }
    }

    const equal = roots_equal and params_equal;
    log.print("Public keys equal: {}\n", .{equal});
    if (equal) {
        log.print("✅ Deterministic: same seed -> identical public keys (2^8)\n", .{});
    } else {
        log.print("❌ Different public keys (2^8).\n", .{});
    }

    // Print the public key for inspection (JSON format to match Rust)
    const pk1_json = try kp1.public_key.serialize(allocator);
    defer allocator.free(pk1_json);

    log.print("\nPublic Key (JSON):\n", .{});
    log.print("{s}\n", .{pk1_json});

    log.print("\nPublic Key (JSON bytes):\n", .{});
    const display_len = @min(32, pk1_json.len);
    log.print("{any}", .{pk1_json[0..display_len]});
    if (pk1_json.len > 32) {
        log.print("... (total {} bytes)", .{pk1_json.len});
    }
    log.print("\n", .{});
}
