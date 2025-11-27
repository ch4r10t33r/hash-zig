//! Zig tool for cross-language compatibility testing
//! 
//! This tool provides:
//! - Key generation (supports lifetime 2^8, 2^18, 2^32)
//! - Serialization of secret/public keys to bincode JSON
//! - Signing messages
//! - Verifying signatures from Rust

const std = @import("std");
const hash_zig = @import("hash-zig");
const Allocator = std.mem.Allocator;
const KeyLifetime = hash_zig.KeyLifetimeRustCompat;
const log = hash_zig.utils.log;

fn parseLifetime(lifetime_str: []const u8) !KeyLifetime {
    if (std.mem.eql(u8, lifetime_str, "2^8")) {
        return .lifetime_2_8;
    } else if (std.mem.eql(u8, lifetime_str, "2^18")) {
        return .lifetime_2_18;
    } else if (std.mem.eql(u8, lifetime_str, "2^32")) {
        return .lifetime_2_32;
    } else {
        return error.InvalidLifetime;
    }
}

fn readLifetimeFromFile(allocator: Allocator) !KeyLifetime {
    const lifetime_json = std.fs.cwd().readFileAlloc(allocator, "tmp/zig_lifetime.txt", std.math.maxInt(usize)) catch |err| {
        if (err == error.FileNotFound) {
            // Default to 2^8 for backward compatibility
            return .lifetime_2_8;
        }
        return err;
    };
    defer allocator.free(lifetime_json);
    
    // Remove trailing newline if present
    var lifetime_str = lifetime_json;
    if (lifetime_str.len > 0 and lifetime_str[lifetime_str.len - 1] == '\n') {
        lifetime_str = lifetime_str[0..lifetime_str.len - 1];
    }
    
    return parseLifetime(lifetime_str);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage:\n", .{});
        std.debug.print("  {s} keygen [seed_hex] [lifetime]        - Generate keypair (lifetime: 2^8, 2^18, or 2^32, default: 2^8)\n", .{args[0]});
        std.debug.print("  {s} sign <message> <epoch>               - Sign message using tmp/zig_sk.json, save to tmp/zig_sig.bin\n", .{args[0]});
        std.debug.print("  {s} verify <rust_sig.bin> <rust_pk.json> <message> <epoch> - Verify Rust signature\n", .{args[0]});
        std.process.exit(1);
    }

    if (std.mem.eql(u8, args[1], "keygen")) {
        const seed_hex = if (args.len > 2) args[2] else null;
        const lifetime_str = if (args.len > 3) args[3] else "2^8";
        const lifetime = parseLifetime(lifetime_str) catch {
            std.debug.print("Error: Invalid lifetime '{s}'. Must be one of: 2^8, 2^18, 2^32\n", .{lifetime_str});
            std.process.exit(1);
        };
        keygenCommand(allocator, seed_hex, lifetime) catch |err| {
            log.print("ZIG_MAIN_ERROR: keygenCommand failed with error {s}\n", .{@errorName(err)});
            return err;
        };
    } else if (std.mem.eql(u8, args[1], "sign")) {
        if (args.len < 4) {
            std.debug.print("Usage: {s} sign <message> <epoch>\n", .{args[0]});
            std.process.exit(1);
        }
        const message = args[2];
        const epoch = try std.fmt.parseUnsigned(u32, args[3], 10);
        const lifetime = try readLifetimeFromFile(allocator);
        try signCommand(allocator, message, epoch, lifetime);
    } else if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len < 6) {
            std.debug.print("Usage: {s} verify <rust_sig.bin> <rust_pk.json> <message> <epoch>\n", .{args[0]});
            std.process.exit(1);
        }
        const sig_path = args[2];
        const pk_path = args[3];
        const message = args[4];
        const epoch = try std.fmt.parseUnsigned(u32, args[5], 10);
        const lifetime = try readLifetimeFromFile(allocator);
        try verifyCommand(allocator, sig_path, pk_path, message, epoch, lifetime);
    } else {
        std.debug.print("Unknown command: {s}\n", .{args[1]});
        std.process.exit(1);
    }
}

fn keygenCommand(allocator: Allocator, seed_hex: ?[]const u8, lifetime: KeyLifetime) !void {
    const lifetime_str = switch (lifetime) {
        .lifetime_2_8 => "2^8",
        .lifetime_2_18 => "2^18",
        .lifetime_2_32 => "2^32",
    };
    std.debug.print("Generating keypair with lifetime {s}...\n", .{lifetime_str});

    // Create tmp directory if it doesn't exist
    std.fs.cwd().makePath("tmp") catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Save lifetime to file for sign/verify commands
    {
        var lifetime_file = try std.fs.cwd().createFile("tmp/zig_lifetime.txt", .{});
        defer lifetime_file.close();
        try lifetime_file.writeAll(lifetime_str);
    }

    var seed: [32]u8 = undefined;
    var seed_str: []const u8 = undefined;
    if (seed_hex) |hex| {
        // Parse hex seed provided by caller
        if (hex.len != 64) {
            std.debug.print("Error: Seed must be 64 hex characters (32 bytes)\n", .{});
            std.process.exit(1);
        }
        _ = try std.fmt.hexToBytes(&seed, hex);
        seed_str = hex;
    } else {
        // Generate random seed
        try std.posix.getrandom(&seed);
        // Convert generated seed to hex string so we can persist it
        const seed_hex_alloc = try std.fmt.allocPrint(allocator, "{x:0>64}", .{std.fmt.fmtSliceHexLower(&seed)});
        defer allocator.free(seed_hex_alloc);
        seed_str = seed_hex_alloc;
    }

    // Initialize signature scheme with seed
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, seed);
    defer scheme.deinit();

    // Persist seed so that signing can reconstruct the exact same keypair
    // and follow the same in-memory path as initial key generation.
    {
        var seed_file = try std.fs.cwd().createFile("tmp/zig_seed.hex", .{});
        defer seed_file.close();
        try seed_file.writeAll(seed_str);
        std.debug.print("✅ Seed saved to tmp/zig_seed.hex\n", .{});
    }

    // Read active epochs from file (default to 256 if not found)
    const num_active_epochs = blk: {
        const active_epochs_file = std.fs.cwd().readFileAlloc(allocator, "tmp/zig_active_epochs.txt", 32) catch |err| {
            if (err == error.FileNotFound) {
                break :blk 256; // Default to 256 for backward compatibility
            }
            return err;
        };
        defer allocator.free(active_epochs_file);
        // Remove trailing newline if present
        var active_epochs_str = active_epochs_file;
        if (active_epochs_str.len > 0 and active_epochs_str[active_epochs_str.len - 1] == '\n') {
            active_epochs_str = active_epochs_str[0..active_epochs_str.len - 1];
        }
        break :blk try std.fmt.parseUnsigned(u32, active_epochs_str, 10);
    };

    // Generate keypair
    var keypair = scheme.keyGen(0, num_active_epochs) catch |err| {
        log.print("ZIG_KEYGEN_ERROR: keyGen failed with error {s}\n", .{@errorName(err)});
        return err;
    };
    defer keypair.secret_key.deinit();

    // Serialize secret key to JSON
    const sk_json = try hash_zig.serialization.serializeSecretKey(allocator, keypair.secret_key);
    defer allocator.free(sk_json);
    var sk_file = try std.fs.cwd().createFile("tmp/zig_sk.json", .{});
    defer sk_file.close();
    try sk_file.writeAll(sk_json);
    std.debug.print("✅ Secret key saved to tmp/zig_sk.json\n", .{});

    // Serialize public key to JSON
    const pk_json = try hash_zig.serialization.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(pk_json);
    
    // Debug: print parameter that will be written to public key file
    log.print("ZIG_KEYGEN_DEBUG: parameter to be written to public key file (canonical): ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{keypair.public_key.parameter[i].toCanonical()});
    }
    log.print("(Montgomery: ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{keypair.public_key.parameter[i].toMontgomery()});
    }
    log.print(")\n", .{});
    
    var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.json", .{});
    defer pk_file.close();
    try pk_file.writeAll(pk_json);
    std.debug.print("✅ Public key saved to tmp/zig_pk.json\n", .{});

    std.debug.print("Keypair generated successfully!\n", .{});
}

fn signCommand(allocator: Allocator, message: []const u8, epoch: u32, lifetime: KeyLifetime) !void {
    std.debug.print("Signing message: '{s}' (epoch: {})\n", .{ message, epoch });

    // Prefer deterministic reconstruction from the original seed so that
    // signing follows the exact same path as in-memory key generation.
    const seed_file = std.fs.cwd().openFile("tmp/zig_seed.hex", .{}) catch null;
    
    var scheme: *hash_zig.GeneralizedXMSSSignatureScheme = undefined;
    const keypair: hash_zig.GeneralizedXMSSSignatureScheme.KeyGenResult = if (seed_file) |file| blk: {
        defer file.close();

        // Read seed hex string
        var buf: [64]u8 = undefined;
        const read_len = try file.readAll(&buf);
        const hex_slice = buf[0..read_len];

        var seed: [32]u8 = undefined;
        if (hex_slice.len != 64) {
            log.print("ZIG_SIGN_DEBUG: Invalid seed length in tmp/zig_seed.hex (got {}, expected 64)\n", .{hex_slice.len});
            return error.InvalidSeed;
        }
        _ = try std.fmt.hexToBytes(&seed, hex_slice);

        // Rebuild scheme and keypair exactly as in keygenCommand
        scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, seed);

        // Read active epochs from file (default to 256 if not found)
        const num_active_epochs = blk2: {
            const active_epochs_file = std.fs.cwd().readFileAlloc(allocator, "tmp/zig_active_epochs.txt", 32) catch |err| {
                if (err == error.FileNotFound) {
                    break :blk2 256; // Default to 256 for backward compatibility
                }
                return err;
            };
            defer allocator.free(active_epochs_file);
            // Remove trailing newline if present
            var active_epochs_str = active_epochs_file;
            if (active_epochs_str.len > 0 and active_epochs_str[active_epochs_str.len - 1] == '\n') {
                active_epochs_str = active_epochs_str[0..active_epochs_str.len - 1];
            }
            break :blk2 try std.fmt.parseUnsigned(u32, active_epochs_str, 10);
        };

        const kp = try scheme.keyGen(0, num_active_epochs);
        log.print("ZIG_SIGN_DEBUG: Reconstructed keypair from seed (deterministic path)\n", .{});
        break :blk kp;
    } else blk: {
        // Fallback: use legacy deserialization path (PRF key + parameter).
        // This path may not perfectly match original RNG state, but keeps
        // compatibility if seed file is missing.
        const sk_json = try std.fs.cwd().readFileAlloc(allocator, "tmp/zig_sk.json", std.math.maxInt(usize));
        defer allocator.free(sk_json);

        const sk_data = try hash_zig.serialization.deserializeSecretKeyData(allocator, sk_json);

        scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, sk_data.prf_key);

        const kp = try scheme.keyGenWithParameter(sk_data.activation_epoch, sk_data.num_active_epochs, sk_data.parameter, sk_data.prf_key);
        log.print("ZIG_SIGN_DEBUG: Reconstructed keypair from PRF key + parameter (fallback path)\n", .{});
        break :blk kp;
    };
    
    // Keep scheme alive for signing - it's needed for the sign() call
    defer scheme.deinit();
    defer keypair.secret_key.deinit();
    
    const secret_key = keypair.secret_key;
    
    // CRITICAL DEBUG: Verify the secret key has the correct parameter
    log.print("ZIG_SIGN_DEBUG_STEP4: Secret key parameter after keyGenWithParameter (canonical): ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{secret_key.getParameter()[i].toCanonical()});
    }
    log.print("(Montgomery: ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{secret_key.getParameter()[i].toMontgomery()});
    }
    log.print(")\n", .{});

    // Convert message to 32 bytes
    var msg_bytes: [32]u8 = undefined;
    const len = @min(message.len, 32);
    @memset(msg_bytes[0..], 0);
    @memcpy(msg_bytes[0..len], message[0..len]);

    // Sign the message
    var signature = try scheme.sign(secret_key, epoch, msg_bytes);
    defer signature.deinit();

    // In-memory self-check: verify immediately using the same keypair and message.
    const in_memory_valid = try scheme.verify(&keypair.public_key, epoch, msg_bytes, signature);
    if (in_memory_valid) {
        std.debug.print("ZIG_SIGN_DEBUG: In-memory sign→verify PASSED for epoch {}\n", .{epoch});
    } else {
        std.debug.print("ZIG_SIGN_DEBUG: In-memory sign→verify FAILED for epoch {}\n", .{epoch});
    }

    // IMPORTANT: Also update the public key JSON to match the regenerated keypair.
    // This ensures that verification (in both Zig and Rust) uses a public key that
    // is consistent with the trees/roots used during signing.
    const pk_json = try hash_zig.serialization.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(pk_json);
    var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.json", .{});
    defer pk_file.close();
    try pk_file.writeAll(pk_json);
    std.debug.print("✅ Public key updated to tmp/zig_pk.json (from regenerated keypair)\n", .{});

    // Serialize signature to bincode binary format (3116 bytes per leanSignature spec)
    // Import bincode functions from remote_hash_tool
    const remote_hash_tool = @import("remote_hash_tool.zig");
    const rand_len = scheme.lifetime_params.rand_len_fe;
    const hash_len = scheme.lifetime_params.hash_len_fe;
    try remote_hash_tool.writeSignatureBincode("tmp/zig_sig.bin", signature, rand_len, hash_len);
    
    // Pad to exactly 3116 bytes as per leanSignature spec
    const SIG_LEN: usize = 3116;
    var sig_file = try std.fs.cwd().openFile("tmp/zig_sig.bin", .{ .mode = .read_write });
    defer sig_file.close();
    const current_size = try sig_file.getEndPos();
    if (current_size > SIG_LEN) {
        return error.SignatureTooLarge;
    }
    // Pad with zeros to reach 3116 bytes
    try sig_file.seekTo(current_size);
    const padding_needed = SIG_LEN - @as(usize, @intCast(current_size));
    if (padding_needed > 0) {
        const zeros = [_]u8{0} ** 1024;
        var remaining = padding_needed;
        while (remaining > 0) {
            const to_write = @min(remaining, zeros.len);
            try sig_file.writeAll(zeros[0..to_write]);
            remaining -= to_write;
        }
    }
    std.debug.print("✅ Signature saved to tmp/zig_sig.bin ({} bytes)\n", .{SIG_LEN});

    std.debug.print("Message signed successfully!\n", .{});
}

fn verifyCommand(allocator: Allocator, sig_path: []const u8, pk_path: []const u8, message: []const u8, epoch: u32, lifetime: KeyLifetime) !void {
    std.debug.print("Verifying signature from Rust...\n", .{});
    std.debug.print("  Signature: {s}\n", .{sig_path});
    std.debug.print("  Public key: {s}\n", .{pk_path});
    std.debug.print("  Message: '{s}'\n", .{message});
    std.debug.print("  Epoch: {}\n", .{epoch});

    // Debug: print file path to verify we're reading from the correct file
    log.print("ZIG_VERIFY_DEBUG: Reading signature from file: {s}\n", .{sig_path});

    // Load signature from binary format (bincode)
    // Import bincode functions from remote_hash_tool
    const remote_hash_tool = @import("remote_hash_tool.zig");
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();
    
    const rand_len = scheme.lifetime_params.rand_len_fe;
    const max_path_len: usize = scheme.lifetime_params.final_layer;
    const hash_len = scheme.lifetime_params.hash_len_fe;
    const max_hashes: usize = scheme.lifetime_params.dimension;
    
    // Read signature from binary format (bincode)
    // The readSignatureBincode function reads from file path directly
    var signature = try remote_hash_tool.readSignatureBincode(sig_path, allocator, rand_len, max_path_len, hash_len, max_hashes);
    defer signature.deinit();
    
    // Debug: print rho from signature right after reading (before verify)
    const rho_after_read = signature.getRho();
    log.print("ZIG_VERIFY_DEBUG: rho from signature.getRho() RIGHT AFTER READ (Montgomery): ", .{});
    for (0..rand_len) |i| {
        log.print("0x{x:0>8} ", .{rho_after_read[i].toMontgomery()});
    }
    log.print("\n", .{});

    // Debug: print which public key file we're reading from
    log.print("ZIG_VERIFY_DEBUG: Reading public key from file: {s}\n", .{pk_path});
    
    // Load public key from Rust
    const pk_json = try std.fs.cwd().readFileAlloc(allocator, pk_path, std.math.maxInt(usize));
    defer allocator.free(pk_json);
    const public_key = try hash_zig.serialization.deserializePublicKey(pk_json);
    
    // Debug: print parameter from public key right after reading
    log.print("ZIG_VERIFY_DEBUG: parameter from public key file (canonical): ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{public_key.parameter[i].toCanonical()});
    }
    log.print("(Montgomery: ", .{});
    for (0..5) |i| {
        log.print("0x{x:0>8} ", .{public_key.parameter[i].toMontgomery()});
    }
    log.print(")\n", .{});

    // Scheme already initialized above

    // Convert message to 32 bytes
    var msg_bytes: [32]u8 = undefined;
    const len = @min(message.len, 32);
    @memset(msg_bytes[0..], 0);
    @memcpy(msg_bytes[0..len], message[0..len]);

    // Verify the signature
    const is_valid = try scheme.verify(&public_key, epoch, msg_bytes, signature);

    if (is_valid) {
        std.debug.print("✅ Signature verification PASSED!\n", .{});
    } else {
        std.debug.print("❌ Signature verification FAILED!\n", .{});
        std.process.exit(1);
    }
}

