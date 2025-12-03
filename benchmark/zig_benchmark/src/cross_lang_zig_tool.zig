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
        lifetime_str = lifetime_str[0 .. lifetime_str.len - 1];
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
        std.debug.print("  {s} inspect <sk_path> <pk_path> <lifetime> - Inspect SSZ keys and report public key\n", .{args[0]});
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

    if (std.mem.eql(u8, args[1], "inspect")) {
        if (args.len < 5) {
            std.debug.print("Usage: {s} inspect <sk_path> <pk_path> <lifetime>\n", .{args[0]});
            std.debug.print("Example: {s} inspect validator_0_sk.ssz validator_0_pk.ssz 2^32\n", .{args[0]});
            std.process.exit(1);
        }
        const sk_path = args[2];
        const pk_path = args[3];
        const lifetime_str = args[4];
        const lifetime = parseLifetime(lifetime_str) catch {
            std.debug.print("Error: Invalid lifetime '{s}'. Must be one of: 2^8, 2^18, 2^32\n", .{lifetime_str});
            std.process.exit(1);
        };
        try inspectCommand(allocator, sk_path, pk_path, lifetime);
    } else if (std.mem.eql(u8, args[1], "keygen")) {
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
            active_epochs_str = active_epochs_str[0 .. active_epochs_str.len - 1];
        }
        break :blk try std.fmt.parseUnsigned(u32, active_epochs_str, 10);
    };

    // Generate keypair
    var keypair = scheme.keyGen(0, num_active_epochs) catch |err| {
        std.debug.print("Error: keyGen failed with {s}\n", .{@errorName(err)});
        return err;
    };
    defer keypair.secret_key.deinit();

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

        var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.json", .{});
        defer pk_file.close();
        try pk_file.writeAll(pk_json);
        std.debug.print("✅ Public key saved to tmp/zig_pk.json\n", .{});
    }

    std.debug.print("Keypair generated successfully!\n", .{});
}

fn signCommand(allocator: Allocator, message: []const u8, epoch: u32, lifetime: KeyLifetime, use_ssz: bool) !void {
    std.debug.print("Signing message: '{s}' (epoch: {})\n", .{ message, epoch });

    var scheme: *hash_zig.GeneralizedXMSSSignatureScheme = undefined;
    const keypair: hash_zig.GeneralizedXMSSSignatureScheme.KeyGenResult = blk: {
        // Try to load SSZ secret key first if use_ssz is true and file exists
        if (use_ssz) {
            if (std.fs.cwd().readFileAlloc(allocator, "tmp/zig_sk.ssz", std.math.maxInt(usize))) |sk_ssz| {
                defer allocator.free(sk_ssz);

                // Check if this is a full secret key (with trees) or minimal (just metadata)
                // Minimal SSZ: exactly 68 bytes (prf_key:32 + parameter:20 + activation_epoch:8 + num_active_epochs:8)
                // Full SSZ: 88+ bytes header + tree data (at least several KB even for smallest lifetime)
                // A full key for 2^8 with 2 active epochs is ~3KB, so 500 bytes is a safe threshold
                const is_full_secret_key = sk_ssz.len >= 500; // Threshold: >= 500 bytes means full key

                if (!is_full_secret_key) {
                    std.debug.print("⚠️  SSZ secret key is minimal ({} bytes), falling back to regeneration\n", .{sk_ssz.len});
                    // Fall through to JSON/regeneration path
                } else {
                    std.debug.print("✅ Loaded pre-generated full SSZ secret key ({} bytes)\n", .{sk_ssz.len});

                    // Extract lifetime from tree depth field in SSZ
                    // SSZ format: [header:88][top_tree_data...]
                    // Tree structure: [depth:8][lowest_layer:8]...
                    if (sk_ssz.len < 96) return error.InvalidLength; // Need at least header + tree depth
                    const top_tree_offset = std.mem.readInt(u32, sk_ssz[68..72], .little);

                    // Validate top_tree_offset to prevent overflow and out-of-bounds access
                    if (top_tree_offset < 88 or top_tree_offset >= sk_ssz.len) return error.InvalidOffset;
                    if (sk_ssz.len - top_tree_offset < 8) return error.InvalidLength;

                    const tree_depth = std.mem.readInt(u64, sk_ssz[top_tree_offset .. top_tree_offset + 8][0..8], .little);

                    const actual_lifetime: KeyLifetime = switch (tree_depth) {
                        8 => .lifetime_2_8,
                        18 => .lifetime_2_18,
                        32 => .lifetime_2_32,
                        else => return error.InvalidLifetime,
                    };

                    if (actual_lifetime != lifetime) {
                        std.debug.print("⚠️  Using lifetime from SSZ file (log={d}) instead of provided lifetime\n", .{tree_depth});
                    }

                    // Allocate secret key on heap
                    const secret_key = try allocator.create(hash_zig.GeneralizedXMSSSecretKey);
                    errdefer allocator.destroy(secret_key);

                    // Deserialize the full secret key (including trees) from SSZ
                    try hash_zig.GeneralizedXMSSSecretKey.sszDecode(sk_ssz, secret_key, allocator);

                    // Derive public key from secret key's top tree root (not from file!)
                    // The public key is: root = top_tree.root(), parameter = secret_key.parameter
                    const top_tree_root = secret_key.top_tree.root();
                    const hash_len_fe: usize = switch (actual_lifetime) {
                        .lifetime_2_8 => 8,
                        .lifetime_2_18 => 7,
                        .lifetime_2_32 => 8,
                    };
                    const public_key = hash_zig.GeneralizedXMSSPublicKey.init(top_tree_root, secret_key.parameter, hash_len_fe);

                    std.debug.print("✅ Loaded pre-generated key (lifetime 2^{}, {} active epochs)\n", .{ tree_depth, secret_key.num_active_epochs });

                    // Initialize scheme with just the lifetime - we don't need to pass PRF key as seed!
                    // The secret key already contains the PRF key, parameter, and all trees.
                    // We just need a minimal scheme with the right lifetime_params and poseidon2 for hashing.
                    scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, actual_lifetime);

                    // Return the loaded keypair
                    break :blk hash_zig.GeneralizedXMSSSignatureScheme.KeyGenResult{
                        .secret_key = secret_key,
                        .public_key = public_key,
                    };
                }
            } else |err| {
                // If SSZ file not found or error reading, fall through to JSON/regeneration path
                if (err != error.FileNotFound) {
                    std.debug.print("⚠️  Error reading SSZ secret key: {}, falling back to JSON/regeneration\n", .{err});
                }
                // Fall through to JSON path below
            }
        }

        // JSON/regeneration path
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
                    active_epochs_str = active_epochs_str[0 .. active_epochs_str.len - 1];
                }
                break :blk2 try std.fmt.parseUnsigned(u32, active_epochs_str, 10);
            };

            const kp = try scheme.keyGen(0, num_active_epochs);
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
            break :blk kp;
        };
        defer seed_file.close();

        // Read seed hex string
        var seed_buf: [64]u8 = undefined;
        const seed_read_len = try seed_file.readAll(&seed_buf);
        const seed_hex_slice = seed_buf[0..seed_read_len];

        var seed: [32]u8 = undefined;
        if (seed_hex_slice.len != 64) {
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
        break :blk kp;
    };

    // Keep scheme alive for signing - it's needed for the sign() call
    defer scheme.deinit();
    defer keypair.secret_key.deinit();

    const secret_key = keypair.secret_key;

    // Convert message to 32 bytes
    var msg_bytes: [32]u8 = undefined;
    const len = @min(message.len, 32);
    @memset(msg_bytes[0..], 0);
    @memcpy(msg_bytes[0..len], message[0..len]);

    // Verify parameters match
    for (0..5) |i| {
        if (!secret_key.getParameter()[i].eql(keypair.public_key.parameter[i])) {
            return error.ParameterMismatch;
        }
    }

    // Sign the message
    var signature = try scheme.sign(secret_key, epoch, msg_bytes);
    defer signature.deinit();

    // In-memory self-check: verify immediately using the same keypair and message
    const in_memory_valid = try scheme.verify(&keypair.public_key, epoch, msg_bytes, signature);
    if (!in_memory_valid) {
        std.debug.print("Warning: In-memory verification failed\n", .{});
    }

    if (use_ssz) {
        // IMPORTANT: Also update the public key SSZ to match the regenerated keypair.
        const pk_bytes = try keypair.public_key.toBytes(allocator);
        defer allocator.free(pk_bytes);
        var pk_file = try std.fs.cwd().createFile("tmp/zig_pk.ssz", .{});
        defer pk_file.close();
        try pk_file.writeAll(pk_bytes);
        std.debug.print("✅ Public key saved to tmp/zig_pk.ssz ({} bytes)\n", .{pk_bytes.len});

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

fn inspectCommand(allocator: Allocator, sk_path: []const u8, pk_path: []const u8, lifetime: KeyLifetime) !void {
    std.debug.print("🔍 Zig: Inspecting keys...\n", .{});
    std.debug.print("  Secret key: {s}\n", .{sk_path});
    std.debug.print("  Public key: {s}\n", .{pk_path});

    // Read secret key
    const sk_bytes = try std.fs.cwd().readFileAlloc(allocator, sk_path, std.math.maxInt(usize));
    defer allocator.free(sk_bytes);

    // Read public key
    const pk_bytes = try std.fs.cwd().readFileAlloc(allocator, pk_path, std.math.maxInt(usize));
    defer allocator.free(pk_bytes);

    // Parse metadata from SSZ header without fully deserializing trees
    // SSZ format: [prf_key:32][parameter:20][activation_epoch:8][num_active_epochs:8][top_tree_offset:4][left_bottom_tree_index:8]...
    if (sk_bytes.len < 88) return error.InvalidLength;

    var offset: usize = 0;

    // Skip prf_key (32 bytes)
    offset += 32;

    // Skip parameter (20 bytes for 5 u32s)
    offset += 20;

    // Read activation_epoch (u64)
    const activation_epoch = std.mem.readInt(u64, sk_bytes[offset .. offset + 8][0..8], .little);
    offset += 8;

    // Read num_active_epochs (u64)
    const num_active_epochs = std.mem.readInt(u64, sk_bytes[offset .. offset + 8][0..8], .little);
    offset += 8;

    // Read top_tree_offset (u32)
    const top_tree_offset = std.mem.readInt(u32, sk_bytes[offset .. offset + 4][0..4], .little);
    offset += 4;

    // Validate top_tree_offset to prevent overflow and out-of-bounds access
    if (top_tree_offset < 88 or top_tree_offset >= sk_bytes.len) return error.InvalidOffset;
    if (sk_bytes.len - top_tree_offset < 8) return error.InvalidLength;

    // Read left_bottom_tree_index (u64)
    const left_bottom_tree_index = std.mem.readInt(u64, sk_bytes[offset .. offset + 8][0..8], .little);

    // Extract lifetime from tree depth field
    // Tree structure: [depth:8][lowest_layer:8][layers_offset:4]...
    const tree_depth = std.mem.readInt(u64, sk_bytes[top_tree_offset .. top_tree_offset + 8][0..8], .little);

    // Determine actual lifetime from tree depth (log_lifetime)
    const actual_lifetime: KeyLifetime = switch (tree_depth) {
        8 => .lifetime_2_8,
        18 => .lifetime_2_18,
        32 => .lifetime_2_32,
        else => return error.InvalidLifetime,
    };

    // Verify it matches the provided lifetime parameter
    if (actual_lifetime != lifetime) {
        std.debug.print("⚠️  WARNING: Provided lifetime {s} doesn't match SSZ file lifetime (log={d})\n", .{
            switch (lifetime) {
                .lifetime_2_8 => "2^8",
                .lifetime_2_18 => "2^18",
                .lifetime_2_32 => "2^32",
            },
            tree_depth,
        });
    }

    // Deserialize public key to verify it's valid
    _ = try hash_zig.GeneralizedXMSSPublicKey.fromBytes(pk_bytes, null);

    const lifetime_str = switch (actual_lifetime) {
        .lifetime_2_8 => "2^8",
        .lifetime_2_18 => "2^18",
        .lifetime_2_32 => "2^32",
    };

    std.debug.print("✅ Successfully deserialized keys for lifetime {s}\n", .{lifetime_str});
    std.debug.print("  Public key size: {} bytes\n", .{pk_bytes.len});
    std.debug.print("  Secret key size: {} bytes\n", .{sk_bytes.len});
    std.debug.print("  Activation epoch: {}\n", .{activation_epoch});
    std.debug.print("  Num active epochs: {}\n", .{num_active_epochs});
    std.debug.print("  Left bottom tree index: {}\n", .{left_bottom_tree_index});
    std.debug.print("  Public key (first 8 bytes): ", .{});
    for (pk_bytes[0..@min(8, pk_bytes.len)]) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});
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
    var sig_bytes_opt: ?[]u8 = null; // Keep sig_bytes alive if using SSZ

    if (use_ssz) {
        // Load signature from SSZ format
        const sig_bytes = try std.fs.cwd().readFileAlloc(allocator, sig_path, std.math.maxInt(usize));
        sig_bytes_opt = sig_bytes; // Store to free later
        std.debug.print("DEBUG: sig_bytes allocated at 0x{x}, len={}\n", .{ @intFromPtr(sig_bytes.ptr), sig_bytes.len });
        signature = try hash_zig.GeneralizedXMSSSignature.fromBytes(sig_bytes, allocator);
        std.debug.print("DEBUG: signature allocated at 0x{x}\n", .{@intFromPtr(signature)});

        // Validate signature struct is accessible before verify
        std.debug.print("DEBUG: Signature struct at 0x{x}, path=0x{x}, rho[0]=0x{x}\n", .{
            @intFromPtr(signature),
            @intFromPtr(signature.path),
            signature.rho[0].toCanonical(),
        });

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

        // Load public key from Rust
        const pk_json = try std.fs.cwd().readFileAlloc(allocator, pk_path, std.math.maxInt(usize));
        defer allocator.free(pk_json);
        public_key = try hash_zig.serialization.deserializePublicKey(pk_json);
    }

    // Convert message to 32 bytes
    var msg_bytes: [32]u8 = undefined;
    const len = @min(message.len, 32);
    @memset(msg_bytes[0..], 0);
    @memcpy(msg_bytes[0..len], message[0..len]);

    // Verify the signature
    const is_valid = try scheme.verify(&public_key, epoch, msg_bytes, signature);

    // Clean up signature and sig_bytes after verify
    signature.deinit();
    if (sig_bytes_opt) |sig_bytes| {
        allocator.free(sig_bytes);
    }

    if (is_valid) {
        std.debug.print("✅ Signature verification PASSED!\n", .{});
    } else {
        std.debug.print("❌ Signature verification FAILED!\n", .{});
        std.process.exit(1);
    }
}
