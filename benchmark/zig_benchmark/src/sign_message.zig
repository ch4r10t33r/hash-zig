const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const ascii = std.ascii;
const json = std.json;

fn valueIsZero(val: json.Value) bool {
    return switch (val) {
        .string => blk: {
            const raw = std.mem.trim(u8, val.string, " \t\r\n\"");
            if (raw.len == 0) break :blk true;
            var normalized = raw;
            if (normalized.len >= 2 and ascii.toLower(normalized[0]) == '0' and ascii.toLower(normalized[1]) == 'x') {
                normalized = normalized[2..];
            }
            var idx: usize = 0;
            while (idx < normalized.len and normalized[idx] == '0') : (idx += 1) {}
            break :blk idx == normalized.len;
        },
        .integer => val.integer == 0,
        .float => val.float == 0.0,
        else => false,
    };
}

fn trimSignatureJson(
    allocator: std.mem.Allocator,
    original: []const u8,
    rand_len_fe: usize,
    hash_len_fe: usize,
) ![]u8 {
    var doc = try json.parseFromSlice(json.Value, allocator, original, .{});
    defer doc.deinit();

    if (doc.value == .object) {
        if (doc.value.object.getPtr("rho")) |rho_val| {
            if (rho_val.* == .array and rho_val.array.items.len > 0) {
                const desired = @min(rand_len_fe, rho_val.array.items.len);
                rho_val.array.items = rho_val.array.items[0..desired];
            }
        }
        if (doc.value.object.getPtr("hashes")) |hashes_val| {
            if (hashes_val.* == .array) {
                for (hashes_val.array.items) |*domain_val| {
                    if (domain_val.* == .array and domain_val.array.items.len > 0) {
                        const desired = @min(hash_len_fe, domain_val.array.items.len);
                        domain_val.array.items = domain_val.array.items[0..desired];
                    }
                }
            }
        }
        if (doc.value.object.getPtr("path")) |path_val| {
            if (path_val.* == .object) {
                if (path_val.object.getPtr("nodes")) |nodes_val| {
                    if (nodes_val.* == .array) {
                        for (nodes_val.array.items) |*node_val| {
                            if (node_val.* == .array and node_val.array.items.len > 0) {
                                const desired = @min(hash_len_fe, node_val.array.items.len);
                                node_val.array.items = node_val.array.items[0..desired];
                            }
                        }
                    }
                }
            }
        }
    }

    return json.stringifyAlloc(allocator, doc.value, .{});
}

fn trimPublicKeyJson(
    allocator: std.mem.Allocator,
    original: []const u8,
    hash_len_fe: usize,
) ![]u8 {
    var doc = try json.parseFromSlice(json.Value, allocator, original, .{});
    defer doc.deinit();

    if (doc.value == .object) {
        if (doc.value.object.getPtr("root")) |root_val| {
            if (root_val.* == .array and root_val.array.items.len > 0) {
                const desired = @min(hash_len_fe, root_val.array.items.len);
                root_val.array.items = root_val.array.items[0..desired];
            }
        }
    }

    return json.stringifyAlloc(allocator, doc.value, .{});
}

fn parseLifetimeTag(raw: []const u8) hash_zig.KeyLifetimeRustCompat {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (ascii.eqlIgnoreCase(trimmed, "2^18") or
        ascii.eqlIgnoreCase(trimmed, "2_18") or
        ascii.eqlIgnoreCase(trimmed, "218") or
        ascii.eqlIgnoreCase(trimmed, "lifetime_2_18"))
    {
        return .lifetime_2_18;
    }
    if (ascii.eqlIgnoreCase(trimmed, "2^32") or
        ascii.eqlIgnoreCase(trimmed, "2_32") or
        ascii.eqlIgnoreCase(trimmed, "232") or
        ascii.eqlIgnoreCase(trimmed, "lifetime_2_32"))
    {
        return .lifetime_2_32;
    }
    return .lifetime_2_8;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const message = std.process.getEnvVarOwned(allocator, "MESSAGE") catch {
        log.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

    const epoch_str = std.process.getEnvVarOwned(allocator, "EPOCH") catch "0";
    defer allocator.free(epoch_str);
    const epoch = std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    const lifetime_env = std.process.getEnvVarOwned(allocator, "LIFETIME") catch null;
    const lifetime_tag = if (lifetime_env) |value| value else "2^8";
    defer if (lifetime_env) |value| allocator.free(value);
    const lifetime = parseLifetimeTag(lifetime_tag);

    const num_active_epochs_env = std.process.getEnvVarOwned(allocator, "NUM_ACTIVE_EPOCHS") catch null;
    const num_active_epochs: usize = blk: {
        if (num_active_epochs_env) |value| {
            defer allocator.free(value);
            break :blk std.fmt.parseInt(usize, value, 10) catch 256;
        } else break :blk 256;
    };

    // Initialize the scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
    defer scheme.deinit();

    log.print("ZIG_SIGN_DEBUG: lifetime={s} num_active_epochs={d}\n", .{
        switch (lifetime) {
            .lifetime_2_18 => "2^18",
            .lifetime_2_32 => "2^32",
            else => "2^8",
        },
        num_active_epochs,
    });

    // Generate a keypair
    const keypair = try scheme.keyGen(0, num_active_epochs);
    defer keypair.secret_key.deinit();

    // Convert message to bytes (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message.len, 32);
    @memcpy(message_bytes[0..copy_len], message[0..copy_len]);

    // Sign the message
    const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature.deinit();

    const verify_ok = try scheme.verify(&keypair.public_key, epoch, message_bytes, signature);
    log.print("ZIG_SIGN_DEBUG: internal verify result: {}\n", .{verify_ok});

    // Serialize signature using proper serialization
    const signature_json = try hash_zig.serialization.serializeSignature(allocator, signature);
    defer allocator.free(signature_json);

    if (std.process.getEnvVarOwned(allocator, "DEBUG_SAVE_RAW_SIGNATURE") catch null) |path| {
        defer allocator.free(path);
        log.print("ZIG_SIGN_DEBUG: writing raw signature to {s}\n", .{path});
        var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(signature_json);
    }

    // Serialize public key for verification
    const public_key_json = try hash_zig.serialization.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(public_key_json);

    if (std.process.getEnvVarOwned(allocator, "DEBUG_SAVE_RAW_PUBLIC_KEY") catch null) |path| {
        defer allocator.free(path);
        log.print("ZIG_SIGN_DEBUG: writing raw public key to {s}\n", .{path});
        var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(public_key_json);
    }

    const rand_len_fe: usize = switch (lifetime) {
        .lifetime_2_18 => 6,
        else => 7,
    };
    const hash_len_fe: usize = switch (lifetime) {
        .lifetime_2_18 => 7,
        else => 8,
    };
    log.print("ZIG_SIGN_DEBUG: hash_len_fe={d} rand_len_fe={d}\n", .{ hash_len_fe, rand_len_fe });

    const trimmed_signature = try trimSignatureJson(allocator, signature_json, rand_len_fe, hash_len_fe);
    defer allocator.free(trimmed_signature);
    const trimmed_public_key = try trimPublicKeyJson(allocator, public_key_json, hash_len_fe);
    defer allocator.free(trimmed_public_key);

    // Serialize secret key for signing
    const secret_key_json = try hash_zig.serialization.serializeSecretKey(allocator, keypair.secret_key);
    defer allocator.free(secret_key_json);

    // Output the serialized data
    log.print("SIGNATURE:{s}\n", .{trimmed_signature});
    log.print("PUBLIC_KEY:{s}\n", .{trimmed_public_key});
    log.print("SECRET_KEY:{s}\n", .{secret_key_json});
}
