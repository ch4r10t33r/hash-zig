const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig hash-zig Standard Implementation Benchmark\n", .{});
    std.debug.print("===============================================\n", .{});
    std.debug.print("Lifetime: 2^10 = 1,024 signatures\n", .{});
    std.debug.print("Architecture: Rust-compatible (Generalized XMSS)\n", .{});
    std.debug.print("Parameters: Winternitz (22 chains of length 256, w=8)\n", .{});
    std.debug.print("Hash: Poseidon2 (width=16, KoalaBear field)\n", .{});
    std.debug.print("\n", .{});

    // Initialize parameters with lifetime 2^18 (matching Rust benchmark config)
    const params = hash_zig.Parameters.init(.lifetime_2_10);

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
    std.debug.print("SEED: ", .{});
    for (seed) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    // Debug: Print actual parameters being used
    std.debug.print("DEBUG: Tree height: {}\n", .{params.tree_height});
    std.debug.print("DEBUG: Winternitz w: {}\n", .{params.winternitz_w});
    std.debug.print("DEBUG: Num chains: {}\n", .{params.num_chains});
    std.debug.print("DEBUG: Hash output len: {}\n", .{params.hash_output_len});
    std.debug.print("DEBUG: Chain length: {}\n", .{@as(u32, 1) << @intCast(params.winternitz_w)});

    std.debug.print("\nGenerating keypair (Rust-compatible implementation)...\n", .{});

    // Initialize signature scheme
    var sig_scheme = try hash_zig.HashSignatureNative.init(allocator, params);
    defer sig_scheme.deinit();

    // Key generation benchmark
    std.debug.print("BENCHMARK: About to call generateKeyPair with lifetime 2^10\n", .{});
    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 1024);
    const end_time = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const duration_ns = end_time - start_time;
    const keygen_time = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    // Display key information
    std.debug.print("Key generation completed in {d:.3} seconds\n\n", .{keygen_time});

    std.debug.print("Key Structure (Rust-compatible):\n", .{});
    std.debug.print("  Public Key:\n", .{});
    std.debug.print("    Root: {d} bytes\n", .{keypair.public_key.root.len});
    std.debug.print("  Secret Key:\n", .{});
    std.debug.print("    PRF key: {d} bytes\n", .{keypair.secret_key.prf_key.len});
    std.debug.print("    Tree nodes: {d}\n", .{keypair.secret_key.tree.len});
    std.debug.print("    Activation epoch: {d}\n", .{keypair.secret_key.activation_epoch});
    std.debug.print("    Active epochs: {d}\n\n", .{keypair.secret_key.num_active_epochs});

    // Self-verify: sign and verify a message
    const msg = "benchmark-message";

    std.debug.print("Testing sign/verify operations...\n", .{});

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

    std.debug.print("  Sign: {d:.2} ms\n", .{sign_duration_ms});
    std.debug.print("  Verify: {d:.2} ms\n", .{verify_duration_ms});
    std.debug.print("  Signature valid: {}\n\n", .{verify_ok});

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

    std.debug.print("DEBUG: Public key root size: {} bytes\n", .{root_bytes.len});

    // Hash just the root for comparison (matching Rust approach)
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(root_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // Output public key root (28 bytes, matching Rust)
    std.debug.print("PUBLIC_KEY_STRUCT_ZIG:\n", .{});
    std.debug.print("  Root size: {} bytes\n", .{root_bytes.len});
    std.debug.print("  Root hex: ", .{});
    for (root_bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

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
    std.debug.print("✅ Saved public key to {s}\n\n", .{json_filename});

    // Output results (using root for comparison, matching Rust)
    std.debug.print("PUBLIC_SHA3: ", .{});
    for (digest) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\nPUBLIC_KEY_HEX: ", .{});
    for (root_bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\nVERIFY_OK: {}\n", .{verify_ok});
    std.debug.print("BENCHMARK_RESULT: {d:.6}\n", .{keygen_time});

    std.debug.print("\n✅ Benchmark completed successfully!\n", .{});
    std.debug.print("Implementation: Standard Rust-compatible (HashSignature)\n", .{});
    std.debug.print("Parameters: Winternitz (22 chains × 256 length, w=8)\n", .{});
}
