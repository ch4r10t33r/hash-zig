const std = @import("std");
const hash_zig = @import("hash-zig");
const HashTreeOpening = hash_zig.signature.HashTreeOpening;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 5) {
        std.debug.print("Usage: {s} <pk_json> <sig_bin> <message> <epoch> <lifetime>\n", .{args[0]});
        std.debug.print("Example: {s} /tmp/rust_public_2pow8.key.json /tmp/rust_signature_2pow8.bin \"Cross-language benchmark message\" 0 2^8\n", .{args[0]});
        std.process.exit(1);
    }

    const pk_path = args[1];
    const sig_path = args[2];
    const message = args[3];
    const epoch = try std.fmt.parseInt(u32, args[4], 10);
    const lifetime_tag = args[5];

    // Parse lifetime - use KeyLifetimeRustCompat enum (matches remote_hash_tool.zig)
    const lifetime = if (std.mem.eql(u8, lifetime_tag, "2^8"))
        hash_zig.KeyLifetimeRustCompat.lifetime_2_8
    else if (std.mem.eql(u8, lifetime_tag, "2^18"))
        hash_zig.KeyLifetimeRustCompat.lifetime_2_18
    else if (std.mem.eql(u8, lifetime_tag, "2^32"))
        hash_zig.KeyLifetimeRustCompat.lifetime_2_32
    else {
        std.debug.print("Unsupported lifetime: {s}\n", .{lifetime_tag});
        std.process.exit(1);
    };

    // Read public key
    const pk_file = try std.fs.cwd().openFile(pk_path, .{});
    defer pk_file.close();
    const pk_bytes = try pk_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(pk_bytes);
    const pk = try hash_zig.serialization.deserializePublicKey(pk_bytes);

    // Read signature binary
    const sig_file = try std.fs.cwd().openFile(sig_path, .{});
    defer sig_file.close();
    const sig_bytes = try sig_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(sig_bytes);

    // Initialize scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();

    // Read signature
    const signature = try readSignatureBincode(
        sig_bytes,
        allocator,
        scheme.lifetime_params.rand_len_fe,
        scheme.lifetime_params.final_layer,
        scheme.lifetime_params.hash_len_fe,
        scheme.lifetime_params.dimension,
    );
    defer signature.deinit();

    // Get rho and parameter
    const rho = signature.getRho();
    const parameter = pk.parameter;

    // Encode message and epoch
    const message_bytes = try messageToBytes(message);
    const message_fe = try scheme.encodeMessage(scheme.lifetime_params.msg_len_fe, message_bytes);
    defer allocator.free(message_fe);
    const epoch_fe = try scheme.encodeEpoch(scheme.lifetime_params.tweak_len_fe, epoch);
    defer allocator.free(epoch_fe);

    // Build combined input: randomness + parameter + epoch + message + iteration
    const RAND_LEN = scheme.lifetime_params.rand_len_fe;
    const PARAMETER_LEN = scheme.lifetime_params.parameter_len;
    const TWEAK_LEN_FE = scheme.lifetime_params.tweak_len_fe;
    const MSG_LEN_FE = scheme.lifetime_params.msg_len_fe;
    const ITER_INPUT_LEN = RAND_LEN + PARAMETER_LEN + TWEAK_LEN_FE + MSG_LEN_FE + 1;

    var combined_input = try allocator.alloc(hash_zig.FieldElement, ITER_INPUT_LEN);
    defer allocator.free(combined_input);

    var input_idx: usize = 0;
    for (0..RAND_LEN) |j| {
        combined_input[input_idx] = rho[j];
        input_idx += 1;
    }
    for (0..PARAMETER_LEN) |j| {
        combined_input[input_idx] = parameter[j];
        input_idx += 1;
    }
    for (0..TWEAK_LEN_FE) |j| {
        combined_input[input_idx] = epoch_fe[j];
        input_idx += 1;
    }
    for (0..MSG_LEN_FE) |j| {
        combined_input[input_idx] = message_fe[j];
        input_idx += 1;
    }
    combined_input[input_idx] = hash_zig.FieldElement.fromCanonical(0);
    input_idx += 1;

    // Pad to 24
    var padded_input: [24]hash_zig.FieldElement = undefined;
    for (0..ITER_INPUT_LEN) |j| {
        padded_input[j] = combined_input[j];
    }
    for (ITER_INPUT_LEN..24) |j| {
        padded_input[j] = hash_zig.FieldElement.zero();
    }

    // Print input (canonical form)
    std.debug.print("ZIG_COMPARE_INPUT (canonical, 24 values):\n", .{});
    for (0..24) |i| {
        std.debug.print("0x{x:0>8} ", .{padded_input[i].toCanonical()});
        if ((i + 1) % 8 == 0) {
            std.debug.print("\nZIG_COMPARE_INPUT (canonical): ", .{});
        }
    }
    std.debug.print("\n", .{});

    // Run poseidon compress
    const pos_outputs = try scheme.poseidon2.compress(padded_input, 15);

    // Print output (canonical form)
    std.debug.print("ZIG_COMPARE_OUTPUT (canonical, 15 values):\n", .{});
    for (0..15) |i| {
        std.debug.print("0x{x:0>8} ", .{pos_outputs[i].toCanonical()});
        if ((i + 1) % 8 == 0 and i < 14) {
            std.debug.print("\nZIG_COMPARE_OUTPUT (canonical): ", .{});
        }
    }
    std.debug.print("\n", .{});
}

fn messageToBytes(msg: []const u8) ![32]u8 {
    var bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(msg.len, 32);
    @memcpy(bytes[0..copy_len], msg[0..copy_len]);
    return bytes;
}

fn readSignatureBincode(
    bytes: []const u8,
    allocator: std.mem.Allocator,
    rand_len: usize,
    max_path_len: usize,
    hash_len: usize,
    max_hashes: usize,
) !*hash_zig.GeneralizedXMSSSignature {
    var offset: usize = 0;

    // Read path_len
    if (bytes.len < offset + 8) return error.InvalidSignature;
    const path_len = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;
    if (path_len == 0 or path_len > max_path_len) return error.InvalidSignature;

    // Read path nodes
    var path_nodes = try allocator.alloc([8]hash_zig.FieldElement, path_len);
    errdefer allocator.free(path_nodes);
    for (0..path_len) |i| {
        if (bytes.len < offset + hash_len * 4) {
            allocator.free(path_nodes);
            return error.InvalidSignature;
        }
        for (0..hash_len) |j| {
            const montgomery = std.mem.readInt(u32, bytes[offset + j * 4 ..][0..4], .little);
            path_nodes[i][j] = hash_zig.FieldElement.fromMontgomery(montgomery);
        }
        // Pad with zeros if hash_len < 8
        for (hash_len..8) |j| {
            path_nodes[i][j] = hash_zig.FieldElement.zero();
        }
        offset += hash_len * 4;
    }

    // Read rho
    if (bytes.len < offset + rand_len * 4) {
        allocator.free(path_nodes);
        return error.InvalidSignature;
    }
    var rho: [7]hash_zig.FieldElement = undefined;
    for (0..rand_len) |i| {
        const montgomery = std.mem.readInt(u32, bytes[offset + i * 4 ..][0..4], .little);
        rho[i] = hash_zig.FieldElement.fromMontgomery(montgomery);
    }
    offset += rand_len * 4;

    // Read hashes_len
    if (bytes.len < offset + 8) {
        allocator.free(path_nodes);
        return error.InvalidSignature;
    }
    const hashes_len = std.mem.readInt(u64, bytes[offset..][0..8], .little);
    offset += 8;

    if (hashes_len == 0 or hashes_len > max_hashes) {
        allocator.free(path_nodes);
        return error.InvalidSignature;
    }
    var hashes = try allocator.alloc([8]hash_zig.FieldElement, hashes_len);
    errdefer allocator.free(hashes);

    for (0..hashes_len) |i| {
        if (bytes.len < offset + hash_len * 4) {
            allocator.free(path_nodes);
            allocator.free(hashes);
            return error.InvalidSignature;
        }
        for (0..hash_len) |j| {
            const montgomery = std.mem.readInt(u32, bytes[offset + j * 4 ..][0..4], .little);
            hashes[i][j] = hash_zig.FieldElement.fromMontgomery(montgomery);
        }
        // Pad with zeros if hash_len < 8
        for (hash_len..8) |j| {
            hashes[i][j] = hash_zig.FieldElement.zero();
        }
        offset += hash_len * 4;
    }

    // Create path
    const path = HashTreeOpening.init(allocator, path_nodes) catch |err| {
        allocator.free(path_nodes);
        allocator.free(hashes);
        return err;
    };
    allocator.free(path_nodes);

    // Note: hashes array will be freed by signature when it's deinitialized
    return hash_zig.GeneralizedXMSSSignature.init(allocator, path, rho, hashes) catch |err| {
        path.deinit();
        allocator.free(hashes);
        return err;
    };
}

