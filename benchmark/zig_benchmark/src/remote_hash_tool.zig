const std = @import("std");
const hash_zig = @import("hash-zig");
const log = hash_zig.utils.log;

const Command = enum {
    sign,
    verify,
};

const UsageError = error{InvalidArguments};
const BincodeError = error{ LengthOverflow, InvalidRandLength, InvalidPathLength, InvalidHashesLength };
const LifetimeError = error{UnsupportedLifetime};

const FieldElement = hash_zig.core.FieldElement;
const HashTreeOpening = hash_zig.signature.HashTreeOpening;

fn parseLifetimeTag(tag: []const u8) LifetimeError!hash_zig.KeyLifetimeRustCompat {
    const cleaned = std.mem.trim(u8, tag, " \t\r\n");
    if (std.mem.eql(u8, cleaned, "2^8") or std.mem.eql(u8, cleaned, "256") or std.ascii.eqlIgnoreCase(cleaned, "lifetime_2_8")) {
        return hash_zig.KeyLifetimeRustCompat.lifetime_2_8;
    }
    if (std.mem.eql(u8, cleaned, "2^18") or std.mem.eql(u8, cleaned, "262144") or std.ascii.eqlIgnoreCase(cleaned, "lifetime_2_18")) {
        return hash_zig.KeyLifetimeRustCompat.lifetime_2_18;
    }
    if (std.mem.eql(u8, cleaned, "2^32") or std.mem.eql(u8, cleaned, "4294967296") or std.ascii.eqlIgnoreCase(cleaned, "lifetime_2_32")) {
        return hash_zig.KeyLifetimeRustCompat.lifetime_2_32;
    }
    return LifetimeError.UnsupportedLifetime;
}

fn writeLength(writer: anytype, value: usize) !void {
    try writer.writeInt(u64, @as(u64, value), .little);
}

fn readLength(reader: anytype) !usize {
    const raw = try reader.readInt(u64, .little);
    if (raw > std.math.maxInt(usize)) return BincodeError.LengthOverflow;
    return @intCast(raw);
}

fn writeFieldElement(writer: anytype, value: FieldElement) !void {
    try writer.writeInt(u32, value.toMontgomery(), .little);
}

fn readFieldElement(reader: anytype) !FieldElement {
    const mont = try reader.readInt(u32, .little);
    return FieldElement.fromMontgomery(mont);
}

fn writeDomain(writer: anytype, domain: [8]FieldElement, active_len: usize) !void {
    for (domain[0..active_len]) |fe| {
        try writeFieldElement(writer, fe);
    }
}

fn readDomain(reader: anytype, active_len: usize) ![8]FieldElement {
    var domain: [8]FieldElement = .{ FieldElement.zero(), FieldElement.zero(), FieldElement.zero(), FieldElement.zero(), FieldElement.zero(), FieldElement.zero(), FieldElement.zero(), FieldElement.zero() };
    for (0..active_len) |i| {
        domain[i] = try readFieldElement(reader);
    }
    return domain;
}

fn printUsage(writer: anytype) !void {
    try writer.print(
        \\Usage:
        \\  zig-remote-hash-tool sign <message> <pk_json_out> <sig_bin_out> [seed_hex] [epoch] [num_active_epochs] [start_epoch] [lifetime]
        \\  zig-remote-hash-tool verify <message> <pk_json_path> <sig_bin_path> [epoch] [lifetime]
        \\
    , .{});
}

fn parseSeedHex(arg: []const u8) ![32]u8 {
    var cleaned = std.mem.trim(u8, arg, " \t\r\n");
    if (cleaned.len >= 2 and cleaned[0] == '0' and (cleaned[1] == 'x' or cleaned[1] == 'X')) {
        cleaned = cleaned[2..];
    }
    if (cleaned.len < 64)
        return error.InvalidSeedHex;
    var seed: [32]u8 = [_]u8{0} ** 32;
    var i: usize = 0;
    var idx: usize = 0;
    while (i < seed.len and idx + 1 < cleaned.len) : (i += 1) {
        const hi = std.fmt.charToDigit(cleaned[idx], 16) catch return error.InvalidSeedHex;
        const lo = std.fmt.charToDigit(cleaned[idx + 1], 16) catch return error.InvalidSeedHex;
        seed[i] = @as(u8, hi) << 4 | @as(u8, lo);
        idx += 2;
    }
    if (idx != cleaned.len) return error.InvalidSeedHex;
    return seed;
}

fn messageToBytes(msg: []const u8) [32]u8 {
    var bytes = [_]u8{0} ** 32;
    const copy_len = @min(msg.len, bytes.len);
    @memcpy(bytes[0..copy_len], msg[0..copy_len]);
    return bytes;
}

fn writePublicKeyToJson(path: []const u8, pk: *const hash_zig.GeneralizedXMSSPublicKey) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const json_str = try hash_zig.serialization.serializePublicKey(allocator, pk);
    defer allocator.free(json_str);

    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(json_str);
}

fn readPublicKeyFromJson(path: []const u8, allocator: std.mem.Allocator) !hash_zig.GeneralizedXMSSPublicKey {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return try hash_zig.serialization.deserializePublicKey(bytes);
}

fn writeSignatureBincode(path: []const u8, signature: *const hash_zig.GeneralizedXMSSSignature, rand_len: usize, hash_len: usize) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();

    const writer = file.writer();
    const path_nodes = signature.getPath().getNodes();
    try writeLength(writer, path_nodes.len);
    for (path_nodes) |node| {
        try writeDomain(writer, node, hash_len);
    }

    const rho = signature.getRho();
    if (rand_len > rho.len) return BincodeError.InvalidRandLength;
    for (rho[0..rand_len]) |fe| {
        try writeFieldElement(writer, fe);
    }

    const hashes = signature.getHashes();
    try writeLength(writer, hashes.len);
    for (hashes) |domain| {
        try writeDomain(writer, domain, hash_len);
    }
}

fn readSignatureBincode(path: []const u8, allocator: std.mem.Allocator, rand_len: usize, max_path_len: usize, hash_len: usize, max_hashes: usize) !*hash_zig.GeneralizedXMSSSignature {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const reader = file.reader();

    const path_len = try readLength(reader);
    if (path_len == 0 or path_len > max_path_len) return BincodeError.InvalidPathLength;
    var path_nodes = try allocator.alloc([8]FieldElement, path_len);
    errdefer allocator.free(path_nodes);
    for (0..path_len) |i| {
        path_nodes[i] = try readDomain(reader, hash_len);
    }

    var path_ptr = HashTreeOpening.init(allocator, path_nodes) catch |err| {
        allocator.free(path_nodes);
        return err;
    };
    allocator.free(path_nodes);

    if (rand_len > 7) {
        path_ptr.deinit();
        return BincodeError.InvalidRandLength;
    }
    var rho = [_]FieldElement{FieldElement.zero()} ** 7;
    for (0..rand_len) |i| {
        rho[i] = try readFieldElement(reader);
    }

    const hashes_len = try readLength(reader);
    if (hashes_len == 0 or hashes_len > max_hashes) {
        path_ptr.deinit();
        return BincodeError.InvalidHashesLength;
    }
    var hashes_tmp = try allocator.alloc([8]FieldElement, hashes_len);
    errdefer allocator.free(hashes_tmp);
    for (0..hashes_len) |i| {
        hashes_tmp[i] = try readDomain(reader, hash_len);
    }

    const signature_ptr = hash_zig.GeneralizedXMSSSignature.initDeserialized(allocator, path_ptr, rho, hashes_tmp) catch |err| {
        allocator.free(hashes_tmp);
        path_ptr.deinit();
        return err;
    };
    allocator.free(hashes_tmp);
    return signature_ptr;
}

fn signCommand(
    allocator: std.mem.Allocator,
    message: []const u8,
    pk_path: []const u8,
    sig_path: []const u8,
    seed_hex: ?[]const u8,
    epoch: u32,
    start_epoch: usize,
    num_active_epochs: usize,
    lifetime_tag: []const u8,
) !void {
    const lifetime = parseLifetimeTag(lifetime_tag) catch {
        log.emit("Unsupported lifetime tag. Expected 2^8, 2^18, or 2^32\n", .{});
        std.process.exit(1);
    };

    const scheme_ptr = try blk: {
        if (seed_hex) |hex| {
            const seed = parseSeedHex(hex) catch {
                log.emit("Invalid SEED_HEX provided; expected at least 64 hex characters\n", .{});
                std.process.exit(1);
            };
            break :blk hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, lifetime, seed);
        } else {
            break :blk hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
        }
    };

    var scheme = scheme_ptr;
    defer scheme.deinit();

    const keypair = try scheme.keyGen(start_epoch, num_active_epochs);
    defer keypair.secret_key.deinit();

    const message_bytes = messageToBytes(message);
    const signature_ptr = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature_ptr.deinit();

    const verify_ok = try scheme.verify(&keypair.public_key, epoch, message_bytes, signature_ptr);
    log.print("ZIG_REMOTE_DEBUG: internal verify result: {}\n", .{verify_ok});

    try writePublicKeyToJson(pk_path, &keypair.public_key);
    try writeSignatureBincode(sig_path, signature_ptr, scheme.lifetime_params.rand_len_fe, scheme.lifetime_params.hash_len_fe);
}

fn verifyCommand(
    allocator: std.mem.Allocator,
    message: []const u8,
    pk_path: []const u8,
    sig_path: []const u8,
    epoch: u32,
    lifetime_tag: []const u8,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const lifetime = parseLifetimeTag(lifetime_tag) catch {
        log.emit("Unsupported lifetime tag. Expected 2^8, 2^18, or 2^32\n", .{});
        std.process.exit(1);
    };

    var pk = try readPublicKeyFromJson(pk_path, arena_allocator);

    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(arena_allocator, lifetime);
    defer scheme.deinit();

    var signature_ptr = try readSignatureBincode(
        sig_path,
        arena_allocator,
        scheme.lifetime_params.rand_len_fe,
        scheme.lifetime_params.final_layer,
        scheme.lifetime_params.hash_len_fe,
        scheme.lifetime_params.dimension,
    );
    defer signature_ptr.deinit();

    const msg_bytes = messageToBytes(message);
    const ok = try scheme.verify(&pk, epoch, msg_bytes, signature_ptr);
    log.emit("VERIFY_RESULT:{}\n", .{ok});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage(std.io.getStdErr().writer());
        std.process.exit(1);
    }

    const cmd_str = args[1];
    const command = if (std.mem.eql(u8, cmd_str, "sign"))
        Command.sign
    else if (std.mem.eql(u8, cmd_str, "verify"))
        Command.verify
    else {
        try printUsage(std.io.getStdErr().writer());
        std.process.exit(1);
    };

    switch (command) {
        .sign => {
            if (args.len < 5) {
                try printUsage(std.io.getStdErr().writer());
                std.process.exit(1);
            }
            const message = args[2];
            const pk_path = args[3];
            const sig_path = args[4];
            const seed_hex = if (args.len >= 6) args[5] else null;
            const epoch: u32 = if (args.len >= 7) std.fmt.parseInt(u32, args[6], 10) catch 0 else 0;
            const num_active_epochs: usize = if (args.len >= 8)
                std.fmt.parseInt(usize, args[7], 10) catch 256
            else
                256;
            const start_epoch: usize = if (args.len >= 9)
                std.fmt.parseInt(usize, args[8], 10) catch 0
            else
                0;
            const lifetime_tag = if (args.len >= 10) args[9] else "2^8";

            try signCommand(allocator, message, pk_path, sig_path, seed_hex, epoch, start_epoch, num_active_epochs, lifetime_tag);
        },
        .verify => {
            if (args.len < 5) {
                try printUsage(std.io.getStdErr().writer());
                std.process.exit(1);
            }
            const message = args[2];
            const pk_path = args[3];
            const sig_path = args[4];
            const epoch: u32 = if (args.len >= 6) std.fmt.parseInt(u32, args[5], 10) catch 0 else 0;
            const lifetime_tag = if (args.len >= 7) args[6] else "2^8";

            try verifyCommand(allocator, message, pk_path, sig_path, epoch, lifetime_tag);
        },
    }
}
