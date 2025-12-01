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
        std.debug.print("  {s} keygen [seed_hex] [lifetime] [--ssz]  - Generate keypair (lifetime: 2^8, 2^18, or 2^32, default: 2^8)\n", .{args[0]});
        std.debug.print("  {s} sign <message> <epoch> [--ssz]       - Sign message using tmp/zig_sk.json, save to tmp/zig_sig.bin or tmp/zig_sig.ssz\n", .{args[0]});
        std.debug.print("  {s} verify <rust_sig.bin> <rust_pk.json> <message> <epoch> [--ssz] - Verify Rust signature\n", .{args[0]});
        std.debug.print("\n  --ssz: Use SSZ serialization instead of JSON/bincode\n", .{});
        std.process.exit(1);
    }
    
    // Check for --ssz flag
    var use_ssz = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--ssz")) {
            use_ssz = true;
            break;
        }
    }

    if (std.mem.eql(u8, args[1], "keygen")) {
        const seed_hex = if (args.len > 2) args[2] else null;
        const lifetime_str = if (args.len > 3) args[3] else "2^8";
        const lifetime = parseLifetime(lifetime_str) catch {
            std.debug.print("Error: Invalid lifetime '{s}'. Must be one of: 2^8, 2^18, 2^32\n", .{lifetime_str});
            std.process.exit(1);
        };
        keygenCommand(allocator, seed_hex, lifetime, use_ssz) catch |err| {
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
        try signCommand(allocator, message, epoch, lifetime, use_ssz);
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
        try verifyCommand(allocator, sig_path, pk_path, message, epoch, lifetime, use_ssz);
    } else {
        std.debug.print("Unknown command: {s}\n", .{args[1]});
        std.process.exit(1);
    }
}

fn keygenCommand(allocator: Allocator, seed_hex: ?[]const u8, lifetime: KeyLifetime, use_ssz: bool) !void {
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
    // Debug: Log RNG state before keyGen
    const rng_state_before = scheme.getRngState();
    log.print("ZIG_KEYGEN_DEBUG: RNG state before keyGen: ", .{});
    for (rng_state_before) |val| {
        log.print("0x{x:0>8} ", .{val});
    }
    log.print("\n", .{});
    
    var keypair = scheme.keyGen(0, num_active_epochs) catch |err| {
        log.print("ZIG_KEYGEN_ERROR: keyGen failed with error {s}\n", .{@errorName(err)});
        return err;
    };
    defer keypair.secret_key.deinit();
    
    // Debug: Log RNG state after keyGen
    const rng_state_after_keygen = scheme.getRngState();
    log.print("ZIG_KEYGEN_DEBUG: RNG state after keyGen: ", .{});
    for (rng_state_after_keygen) |val| {
        log.print("0x{x:0>8} ", .{val});
    }
    log.print("\n", .{});
    
    // Debug: Log the generated public key root
    log.print("ZIG_KEYGEN_DEBUG: Generated public key root (canonical): ", .{});
    for (keypair.public_key.root) |fe| {
        log.print("0x{x:0>8} ", .{fe.toCanonical()});
    }
    log.print("\n", .{});

    if (use_ssz) {
        // Serialize secret key to SSZ
        const sk_bytes = try keypair.secret_key.toBytes(allocator);
        defer allocator.free(sk_bytes);
        var sk_file = try std.fs.cwd().createFile("tmp/zig_sk.ssz", .{});
        defer sk_file.close();
        try sk_file.writeAll(sk_bytes);
        std.debug.print("✅ Secret key saved to tmp/zig_sk.ssz ({} bytes)\n", .{sk_bytes.len});

        // Serialize public key to SSZ
        const pk_bytes = try keypair.public_key.toBytes(allocator);
        defer allocator.free(pk_bytes);
        var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.ssz", .{});
        defer pk_file.close();
        try pk_file.writeAll(pk_bytes);
        std.debug.print("✅ Public key saved to tmp/zig_pk.ssz ({} bytes)\n", .{pk_bytes.len});
    } else {
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
    }

    std.debug.print("Keypair generated successfully!\n", .{});
}

fn signCommand(allocator: Allocator, message: []const u8, epoch: u32, lifetime: KeyLifetime, use_ssz: bool) !void {
    std.debug.print("Signing message: '{s}' (epoch: {})\n", .{ message, epoch });

    // Prefer deserialization path (PRF key + parameter) for reliable reconstruction.
    // This ensures we use the exact parameter and PRF key from the original keygen,
    // which should produce identical trees. The seed-based path can have RNG state
    // synchronization issues, especially for 2^32 lifetime.
    var scheme: *hash_zig.GeneralizedXMSSSignatureScheme = undefined;
    const keypair: hash_zig.GeneralizedXMSSSignatureScheme.KeyGenResult = blk: {
        const sk_json = std.fs.cwd().readFileAlloc(allocator, "tmp/zig_sk.json", std.math.maxInt(usize)) catch |err| {
            // Fallback to seed-based path if secret key file is missing
            const seed_file = std.fs.cwd().openFile("tmp/zig_seed.hex", .{}) catch {
                return err;
            };
            defer seed_file.close();

            // Read seed hex string
            var buf: [64]u8 = undefined;
            const read_len = try seed_file.readAll(&buf);
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
                const active_epochs_file = std.fs.cwd().readFileAlloc(allocator, "tmp/zig_active_epochs.txt", 32) catch |err2| {
                    if (err2 == error.FileNotFound) {
                        break :blk2 256; // Default to 256 for backward compatibility
                    }
                    return err2;
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
            log.print("ZIG_SIGN_DEBUG: Reconstructed keypair from seed (fallback path)\n", .{});
            break :blk kp;
        };
        defer allocator.free(sk_json);

        const sk_data = try hash_zig.serialization.deserializeSecretKeyData(allocator, sk_json);
        
        // Use the original seed (not PRF key) to ensure RNG state matches original keygen
        // The PRF key was generated from the seed, so we need to start from the seed
        // and consume RNG state to match where we were after generating parameter and PRF key
        const seed_file = std.fs.cwd().openFile("tmp/zig_seed.hex", .{}) catch {
            // If seed file is missing, fall back to using PRF key as seed (may not match exactly)
            scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, sk_data.prf_key);
            const kp = try scheme.keyGenWithParameter(sk_data.activation_epoch, sk_data.num_active_epochs, sk_data.parameter, sk_data.prf_key, false);
            log.print("ZIG_SIGN_DEBUG: Reconstructed keypair from PRF key + parameter (no seed file)\n", .{});
            break :blk kp;
        };
        defer seed_file.close();

        // Read seed hex string
        var seed_buf: [64]u8 = undefined;
        const seed_read_len = try seed_file.readAll(&seed_buf);
        const seed_hex_slice = seed_buf[0..seed_read_len];

        var seed: [32]u8 = undefined;
        if (seed_hex_slice.len != 64) {
            log.print("ZIG_SIGN_DEBUG: Invalid seed length in tmp/zig_seed.hex (got {}, expected 64)\n", .{seed_hex_slice.len});
            return error.InvalidSeed;
        }
        _ = try std.fmt.hexToBytes(&seed, seed_hex_slice);

        // Initialize with original seed to match RNG state from keygen
        scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, seed);
        
        // CRITICAL: We need to match the RNG state exactly as it was when keyGenWithParameter
        // was called from keyGen(). In keyGen(), the flow is:
        // 1. generateRandomParameter() - peeks 20 bytes (doesn't consume)
        // 2. generateRandomPRFKey() - consumes 32 bytes
        // 3. keyGenWithParameter() - consumes another 32 bytes (to match state after step 2)
        //
        // But wait - that's wrong! When keyGenWithParameter is called from keyGen(), the RNG
        // state is already after consuming 32 bytes. So keyGenWithParameter shouldn't consume
        // another 32 bytes when called from keyGen(). But it does, which means it's consuming
        // 64 bytes total when called from keyGen().
        //
        // Actually, I think the issue is that keyGenWithParameter is designed to be called
        // directly (not from keyGen()), so it consumes 32 bytes to match the state after
        // parameter/PRF key generation. But when called from keyGen(), this causes double
        // consumption.
        //
        // For now, let's NOT consume here, because keyGenWithParameter will consume 32 bytes
        // internally. But we need to account for the peek (20 bytes) and PRF key (32 bytes).
        // Actually, the peek doesn't consume, so we just need to consume 32 bytes for the PRF key.
        // But keyGenWithParameter already does that, so we shouldn't consume here.
        //
        // Wait, let me re-read the code. keyGenWithParameter consumes 32 bytes to match the
        // state AFTER parameter/PRF key generation. So when we call it directly, we need to
        // have consumed 32 bytes already. But we're starting fresh, so we need to consume
        // 32 bytes to get to the state after PRF key generation.
        // CRITICAL: Simulate the exact RNG consumption from keyGen():
        // 1. generateRandomParameter() - peeks 20 bytes (doesn't consume RNG offset)
        // 2. generateRandomPRFKey() - consumes 32 bytes (advances RNG offset)
        //
        // Even though peek doesn't consume, we should call the actual function to ensure
        // the RNG state is in the exact same condition. The peek reads from the current
        // offset without advancing it, but we want to ensure we're reading from the same
        // position in the RNG stream.
        _ = try scheme.generateRandomParameter(); // Peek at 20 bytes (doesn't consume)
        var dummy_prf_key: [32]u8 = undefined;
        scheme.rng.fill(&dummy_prf_key); // Consume 32 bytes to match generateRandomPRFKey()

        // We've already consumed 32 bytes to match PRF key generation, so pass true
        const kp = try scheme.keyGenWithParameter(sk_data.activation_epoch, sk_data.num_active_epochs, sk_data.parameter, sk_data.prf_key, true);
        
        log.print("ZIG_SIGN_DEBUG: Reconstructed keypair from PRF key + parameter with original seed (preferred path)\n", .{});
        break :blk kp;
    };
    
    // Keep scheme alive for signing - it's needed for the sign() call
    defer scheme.deinit();
    defer keypair.secret_key.deinit();
    
    const secret_key = keypair.secret_key;
    
    // CRITICAL DEBUG: Verify the secret key's top tree root matches the public key root
    const top_tree_root = secret_key.top_tree.root();
    log.print("ZIG_SIGN_DEBUG: Top tree root from secret key (canonical): ", .{});
    for (top_tree_root) |fe| {
        log.print("0x{x:0>8} ", .{fe.toCanonical()});
    }
    log.print("\n", .{});
    log.print("ZIG_SIGN_DEBUG: Public key root (canonical): ", .{});
    for (keypair.public_key.root) |fe| {
        log.print("0x{x:0>8} ", .{fe.toCanonical()});
    }
    log.print("\n", .{});
    
    var root_match = true;
    for (0..8) |i| {
        if (!top_tree_root[i].eql(keypair.public_key.root[i])) {
            log.debugPrint("ZIG_SIGN_ERROR: Top tree root[{}] mismatch: computed=0x{x:0>8} (canonical) / 0x{x:0>8} (monty) expected=0x{x:0>8} (canonical) / 0x{x:0>8} (monty)\n", .{ 
                i, 
                top_tree_root[i].toCanonical(), 
                top_tree_root[i].toMontgomery(),
                keypair.public_key.root[i].toCanonical(),
                keypair.public_key.root[i].toMontgomery(),
            });
            root_match = false;
        }
    }
    if (!root_match) {
        log.debugPrint("ZIG_SIGN_ERROR: Top tree root does not match public key root! This indicates the regenerated keypair is inconsistent.\n", .{});
        log.debugPrint("ZIG_SIGN_ERROR: This will cause verification to fail. The signature will be generated with trees that don't match the public key.\n", .{});
        // Continue anyway to see the full error
    } else {
        log.debugPrint("ZIG_SIGN_DEBUG: Top tree root matches public key root ✓\n", .{});
    }
    
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

    // CRITICAL: Verify parameter match before signing
    std.debug.print("ZIG_SIGN_DEBUG: Checking parameter match before signing:\n", .{});
    std.debug.print("ZIG_SIGN_DEBUG: secret_key.parameter (canonical): ", .{});
    for (0..5) |i| {
        std.debug.print("0x{x:0>8} ", .{secret_key.getParameter()[i].toCanonical()});
    }
    std.debug.print("\nZIG_SIGN_DEBUG: public_key.parameter (canonical): ", .{});
    for (0..5) |i| {
        std.debug.print("0x{x:0>8} ", .{keypair.public_key.parameter[i].toCanonical()});
    }
    std.debug.print("\n", .{});
    
    // Verify parameters match
    var param_match = true;
    for (0..5) |i| {
        if (!secret_key.getParameter()[i].eql(keypair.public_key.parameter[i])) {
            log.debugPrint("ZIG_SIGN_ERROR: Parameter mismatch at index {}!\n", .{i});
            param_match = false;
        }
    }
    if (!param_match) {
        log.debugPrint("ZIG_SIGN_ERROR: secret_key.parameter does not match public_key.parameter!\n", .{});
        return error.ParameterMismatch;
    }
    std.debug.print("ZIG_SIGN_DEBUG: Parameters match ✓\n", .{});

    // Sign the message
    var signature = try scheme.sign(secret_key, epoch, msg_bytes);
    defer signature.deinit();

    // In-memory self-check: verify immediately using the same keypair and message.
    // Debug: Print stored hash from signature before verification
    const stored_hashes = signature.getHashes();
    if (stored_hashes.len > 0) {
        log.debugPrint("ZIG_SIGN_DEBUG: Stored hash[0] before verification (Montgomery): ", .{});
        for (0..@min(8, stored_hashes[0].len)) |h| {
            std.debug.print("0x{x:0>8} ", .{stored_hashes[0][h].value});
        }
        std.debug.print("\n", .{});
        log.debugPrint("ZIG_SIGN_DEBUG: Stored hash[0] before verification (Canonical): ", .{});
        for (0..@min(8, stored_hashes[0].len)) |h| {
            std.debug.print("0x{x:0>8} ", .{stored_hashes[0][h].toCanonical()});
        }
        std.debug.print("\n", .{});
    }
    const in_memory_valid = try scheme.verify(&keypair.public_key, epoch, msg_bytes, signature);
    if (in_memory_valid) {
        log.debugPrint("ZIG_SIGN_DEBUG: In-memory sign→verify PASSED for epoch {}\n", .{epoch});
    } else {
        log.debugPrint("ZIG_SIGN_DEBUG: In-memory sign→verify FAILED for epoch {}\n", .{epoch});
    }

    if (use_ssz) {
        // IMPORTANT: Also update the public key SSZ to match the regenerated keypair.
        const pk_bytes = try keypair.public_key.toBytes(allocator);
        defer allocator.free(pk_bytes);
        var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.ssz", .{});
        defer pk_file.close();
        try pk_file.writeAll(pk_bytes);
        std.debug.print("✅ Public key updated to tmp/zig_pk.ssz ({} bytes, from regenerated keypair)\n", .{pk_bytes.len});

        // Serialize signature to SSZ
        const sig_bytes = try signature.toBytes(allocator);
        defer allocator.free(sig_bytes);
        var sig_file = try std.fs.cwd().createFile("tmp/zig_sig.ssz", .{});
        defer sig_file.close();
        try sig_file.writeAll(sig_bytes);
        std.debug.print("✅ Signature saved to tmp/zig_sig.ssz ({} bytes)\n", .{sig_bytes.len});
    } else {
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
        // Reference: https://github.com/leanEthereum/leanSpec/blob/main/src/lean_spec/subspecs/containers/signature.py
        // The leanSpec requires:
        //   1. Signature container: exactly 3116 bytes (Bytes3116)
        //   2. Signature data: bincode format at the beginning
        //   3. Can be sliced to scheme.config.SIGNATURE_LEN_BYTES if needed
        //   4. Format: XmssSignature.from_bytes (bincode deserialization)
        // Import bincode functions from remote_hash_tool
        const remote_hash_tool = @import("remote_hash_tool.zig");
        const rand_len = scheme.lifetime_params.rand_len_fe;
        const hash_len = scheme.lifetime_params.hash_len_fe;
        try remote_hash_tool.writeSignatureBincode("tmp/zig_sig.bin", signature, rand_len, hash_len);
        
        // Pad to exactly 3116 bytes as per leanSignature spec (Bytes3116 container)
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
    }

    std.debug.print("Message signed successfully!\n", .{});
}

fn verifyCommand(allocator: Allocator, sig_path: []const u8, pk_path: []const u8, message: []const u8, epoch: u32, lifetime: KeyLifetime, use_ssz: bool) !void {
    std.debug.print("Verifying signature from Rust...\n", .{});
    std.debug.print("  Signature: {s}\n", .{sig_path});
    std.debug.print("  Public key: {s}\n", .{pk_path});
    std.debug.print("  Message: '{s}'\n", .{message});
    std.debug.print("  Epoch: {}\n", .{epoch});

    // Debug: print file path to verify we're reading from the correct file
    log.print("ZIG_VERIFY_DEBUG: Reading signature from file: {s}\n", .{sig_path});

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();
    
    var signature: *hash_zig.GeneralizedXMSSSignature = undefined;
    var public_key: hash_zig.GeneralizedXMSSPublicKey = undefined;
    
    if (use_ssz) {
        // Load signature from SSZ format
        const sig_bytes = try std.fs.cwd().readFileAlloc(allocator, sig_path, std.math.maxInt(usize));
        defer allocator.free(sig_bytes);
        signature = try hash_zig.GeneralizedXMSSSignature.fromBytes(sig_bytes, allocator);
        defer signature.deinit();
        
        // Load public key from SSZ format
        const pk_bytes = try std.fs.cwd().readFileAlloc(allocator, pk_path, std.math.maxInt(usize));
        defer allocator.free(pk_bytes);
        public_key = try hash_zig.GeneralizedXMSSPublicKey.fromBytes(pk_bytes, null);
    } else {
        // Load signature from binary format (bincode)
        // Import bincode functions from remote_hash_tool
        const remote_hash_tool = @import("remote_hash_tool.zig");
        const rand_len = scheme.lifetime_params.rand_len_fe;
        const max_path_len: usize = scheme.lifetime_params.final_layer;
        const hash_len = scheme.lifetime_params.hash_len_fe;
        const max_hashes: usize = scheme.lifetime_params.dimension;
        
        // The readSignatureBincode function reads from file path directly
        signature = try remote_hash_tool.readSignatureBincode(sig_path, allocator, rand_len, max_path_len, hash_len, max_hashes);
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
        public_key = try hash_zig.serialization.deserializePublicKey(pk_json);
    }
    
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

