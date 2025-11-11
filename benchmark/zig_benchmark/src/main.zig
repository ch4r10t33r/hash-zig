const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    log.print("Zig hash-zig Standard Implementation Benchmark\n", .{});
    log.print("===============================================\n", .{});
    log.print("Lifetime: 2^10 = 1,024 signatures\n", .{});
    log.print("Architecture: Rust-compatible (Generalized XMSS)\n", .{});
    log.print("Parameters: Winternitz (22 chains of length 256, w=8)\n", .{});
    log.print("Hash: Poseidon2 (width=16, KoalaBear field)\n", .{});
    log.print("\n", .{});

    // Initialize parameters with lifetime 2^18 (matching Rust benchmark config)
    const params = hash_zig.Parameters.init(.lifetime_2_8);

    // Read SEED_HEX env var (64 hex chars => 32 bytes). Default to 0x42 repeated
    var seed: [32]u8 = undefined;
    if (std.process.getEnvVarOwned(allocator, "SEED_HEX")) |seed_hex| {
        defer allocator.free(seed_hex);
        if (seed_hex.len >= 64) {
            for (0..32) |i| {
                const hi = std.fmt.parseInt(u4, seed_hex[i * 2 .. i * 2 + 1], 16) catch 0;
                const lo = std.fmt.parseInt(u4, seed_hex[i * 2 + 1 .. i * 2 + 2], 16) catch 0;
                seed[i] = @as(u8, @intCast((@as(u8, hi) << 4) | @as(u8, lo)));
            }
        } else {
            @memset(&seed, 0x42);
        }
    } else |_| {
        @memset(&seed, 0x42);
    }

    // Emit seed for reproducibility
    log.print("SEED: ", .{});
    for (seed) |b| log.print("{x:0>2}", .{b});
    log.print("\n", .{});

    // Debug: Print actual parameters being used
    log.print("DEBUG: Tree height: {}\n", .{params.tree_height});
    log.print("DEBUG: Winternitz w: {}\n", .{params.winternitz_w});
    log.print("DEBUG: Num chains: {}\n", .{params.num_chains});
    log.print("DEBUG: Hash output len: {}\n", .{params.hash_output_len});
    log.print("DEBUG: Chain length: {}\n", .{@as(u32, 1) << @intCast(params.winternitz_w)});

    log.print("\nGenerating keypair (Rust-compatible implementation)...\n", .{});

    // Initialize signature scheme
    var sig_scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, params);
    defer sig_scheme.deinit();

    // Key generation benchmark
    log.print("BENCHMARK: About to call generateKeyPair with lifetime 2^10\n", .{});
    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 1024);
    const end_time = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const duration_ns = end_time - start_time;
    const keygen_time = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    // Display key information
    log.print("Key generation completed in {d:.3} seconds\n\n", .{keygen_time});

    log.print("Key Structure (Rust-compatible):\n", .{});
    log.print("  Public Key:\n", .{});
    log.print("    Root: {d} bytes\n", .{keypair.public_key.root.len});
    log.print("  Secret Key:\n", .{});
    log.print("    PRF key: {d} bytes\n", .{keypair.secret_key.prf_key.len});
    log.print("    Tree nodes: {d}\n", .{keypair.secret_key.tree.len});
    log.print("    Activation epoch: {d}\n", .{keypair.secret_key.activation_epoch});
    log.print("    Active epochs: {d}\n\n", .{keypair.secret_key.num_active_epochs});

    // Self-verify: sign and verify a message
    const msg = "benchmark-message";

    log.print("Testing sign/verify operations...\n", .{});

    // Generate RNG seed for encoding randomness
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);

    // Prepare message and hash to required length (32 bytes)
    var msg_hash: [32]u8 = undefined;
    std.crypto.hash.sha3.Sha3_256.hash(msg, &msg_hash, .{});

    // Sign
    const sign_start = std.time.nanoTimestamp();
    var signature = try sig_scheme.sign(allocator, &keypair.secret_key, &msg_hash, 0);
    const sign_end = std.time.nanoTimestamp();
    defer signature.deinit(allocator);

    const sign_duration_ms = @as(f64, @floatFromInt(sign_end - sign_start)) / 1_000_000.0;
    const sign_time = sign_duration_ms / 1000.0; // Convert to seconds

    // Verify
    const verify_start = std.time.nanoTimestamp();
    const verify_ok = try sig_scheme.verify(allocator, &keypair.public_key, &msg_hash, &signature);
    const verify_end = std.time.nanoTimestamp();

    const verify_duration_ms = @as(f64, @floatFromInt(verify_end - verify_start)) / 1_000_000.0;
    const verify_time = verify_duration_ms / 1000.0; // Convert to seconds

    log.print("  Sign: {d:.2} ms\n", .{sign_duration_ms});
    log.print("  Verify: {d:.2} ms\n", .{verify_duration_ms});
    log.print("  Signature valid: {}\n\n", .{verify_ok});

    // For compatibility testing, compare just the root (28 bytes from 7 field elements)
    // This avoids serialization format differences
    const root_fe = keypair.public_key.root;

    // Convert field elements to bytes (7 FEs × 4 bytes = 28 bytes)
    var root_bytes = try allocator.alloc(u8, root_fe.len * 4);
    defer allocator.free(root_bytes);
    for (root_fe, 0..) |fe, i| {
        const val = fe.toU32();
        var slice = root_bytes[i * 4 .. i * 4 + 4];
        std.mem.writeInt(u32, slice[0..4], val, .little);
    }

    log.print("DEBUG: Public key root size: {} bytes\n", .{root_bytes.len});

    // Hash just the root for comparison (matching Rust approach)
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(root_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // Output public key root (28 bytes, matching Rust)
    log.print("PUBLIC_KEY_STRUCT_ZIG:\n", .{});
    log.print("  Root size: {} bytes\n", .{root_bytes.len});
    log.print("  Root hex: ", .{});
    for (root_bytes) |b| log.print("{x:0>2}", .{b});
    log.print("\n", .{});

    // Convert seed to hex string
    var seed_hex_buf: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&seed_hex_buf, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        seed[0],  seed[1],  seed[2],  seed[3],  seed[4],  seed[5],  seed[6],  seed[7],
        seed[8],  seed[9],  seed[10], seed[11], seed[12], seed[13], seed[14], seed[15],
        seed[16], seed[17], seed[18], seed[19], seed[20], seed[21], seed[22], seed[23],
        seed[24], seed[25], seed[26], seed[27], seed[28], seed[29], seed[30], seed[31],
    });

    // Convert root to hex string (32 bytes, matching Rust)
    var pk_hex = try allocator.alloc(u8, root_bytes.len * 2);
    defer allocator.free(pk_hex);
    for (root_bytes, 0..) |b, i| {
        _ = try std.fmt.bufPrint(pk_hex[i * 2 .. i * 2 + 2], "{x:0>2}", .{b});
    }

    // Convert digest to hex string
    var digest_hex_buf: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&digest_hex_buf, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        digest[0],  digest[1],  digest[2],  digest[3],  digest[4],  digest[5],  digest[6],  digest[7],
        digest[8],  digest[9],  digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
        digest[16], digest[17], digest[18], digest[19], digest[20], digest[21], digest[22], digest[23],
        digest[24], digest[25], digest[26], digest[27], digest[28], digest[29], digest[30], digest[31],
    });

    // Create JSON output
    var json_buffer = std.ArrayList(u8).init(allocator);
    defer json_buffer.deinit();

    try json_buffer.writer().print(
        \\{{
        \\  "implementation": "zig-hash-zig",
        \\  "type": "SIGWinternitzLifetime10W8",
        \\  "parameters": {{
        \\    "winternitz_w": {d},
        \\    "num_chains": {d},
        \\    "chain_length": {d},
        \\    "tree_height": {d},
        \\    "lifetime": {d},
        \\    "hash_function": "Poseidon2KoalaBear"
        \\  }},
        \\  "timing": {{
        \\    "keygen_seconds": {d:.6},
        \\    "sign_seconds": {d:.6},
        \\    "verify_seconds": {d:.6}
        \\  }},
        \\  "keys": {{
        \\    "seed": "{s}",
        \\    "public_key_hex": "{s}",
        \\    "public_key_sha3": "{s}",
        \\    "public_key_size_bytes": {d}
        \\  }},
        \\  "verification": {{
        \\    "signature_valid": {any}
        \\  }}
        \\}}
        \\
    , .{
        params.winternitz_w,
        params.num_chains,
        @as(u32, 1) << @intCast(params.winternitz_w),
        params.tree_height,
        (@as(u32, 1) << @intCast(params.tree_height)),
        keygen_time,
        sign_time,
        verify_time,
        seed_hex_buf,
        pk_hex,
        digest_hex_buf,
        root_bytes.len, // Use root size (32 bytes, matching Rust)
        verify_ok,
    });

    // Save to JSON file
    const json_filename = "zig_public_key.json";
    const file = try std.fs.cwd().createFile(json_filename, .{});
    defer file.close();

    try file.writeAll(json_buffer.items);
    log.print("✅ Saved public key to {s}\n\n", .{json_filename});

    // Output results (using root for comparison, matching Rust)
    log.print("PUBLIC_SHA3: ", .{});
    for (digest) |b| log.print("{x:0>2}", .{b});
    log.print("\nPUBLIC_KEY_HEX: ", .{});
    for (root_bytes) |b| log.print("{x:0>2}", .{b});
    log.print("\nVERIFY_OK: {}\n", .{verify_ok});
    log.print("BENCHMARK_RESULT: {d:.6}\n", .{keygen_time});

    log.print("\n✅ Benchmark completed successfully!\n", .{});
    log.print("Implementation: Standard Rust-compatible (GeneralizedXMSSSignatureScheme)\n", .{});
    log.print("Parameters: Winternitz (22 chains × 256 length, w=8)\n", .{});
}
