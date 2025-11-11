const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");
const ascii = std.ascii;

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

    // Get environment variables
    const public_key_data = std.process.getEnvVarOwned(allocator, "PUBLIC_KEY") catch {
        log.print("Missing PUBLIC_KEY environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(public_key_data);

    const signature_data = std.process.getEnvVarOwned(allocator, "SIGNATURE") catch {
        log.print("Missing SIGNATURE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(signature_data);

    const message = std.process.getEnvVarOwned(allocator, "MESSAGE") catch {
        log.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

    const lifetime_env = std.process.getEnvVarOwned(allocator, "LIFETIME") catch null;
    const lifetime_tag = if (lifetime_env) |value| value else "2^8";
    defer if (lifetime_env) |value| allocator.free(value);
    const lifetime = parseLifetimeTag(lifetime_tag);

    const epoch_str = std.process.getEnvVarOwned(allocator, "EPOCH") catch "0";
    defer allocator.free(epoch_str);
    const epoch = std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    // Convert message to bytes (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message.len, 32);
    @memcpy(message_bytes[0..copy_len], message[0..copy_len]);

    // Parse the signature and public key data
    if (std.mem.startsWith(u8, signature_data, "SIGNATURE:")) {
        const signature_json = signature_data[10..]; // Skip "SIGNATURE:" prefix

        // Parse public key
        const public_key_json = if (std.mem.startsWith(u8, public_key_data, "PUBLIC_KEY:"))
            public_key_data[11..] // Skip "PUBLIC_KEY:" prefix
        else
            public_key_data;

        const stdout = std.io.getStdOut().writer();
        try stdout.print("ZIG_VERIFY_DEBUG: Starting deserialization\n", .{});

        // Deserialize public key
        const public_key = hash_zig.serialization.deserializePublicKey(public_key_json) catch |err| {
            try stdout.print("ZIG_VERIFY_DEBUG: Failed to deserialize public key: {}\n", .{err});
            std.process.exit(1);
        };
        try stdout.print("ZIG_VERIFY_DEBUG: Public key deserialized successfully\n", .{});

        // Deserialize signature
        var signature = hash_zig.serialization.deserializeSignature(allocator, signature_json) catch |err| {
            try stdout.print("ZIG_VERIFY_DEBUG: Failed to deserialize signature: {}\n", .{err});
            std.process.exit(1);
        };
        defer signature.deinit();
        try stdout.print("ZIG_VERIFY_DEBUG: Signature deserialized successfully\n", .{});

        try stdout.print("ZIG_VERIFY_DEBUG: Selected lifetime: {s}\n", .{
            switch (lifetime) {
                .lifetime_2_18 => "2^18",
                .lifetime_2_32 => "2^32",
                else => "2^8",
            },
        });

        // Initialize the scheme
        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, lifetime);
        defer scheme.deinit();

        // Debug: log parsed structure lengths
        const path = signature.getPath();
        const rho_dbg = signature.getRho();
        const hashes = signature.getHashes();
        log.print("ZIG_DEBUG: path_nodes_len={} rho_len={} hashes_len={}\n", .{ path.getNodes().len, rho_dbg.len, hashes.len });
        try stdout.print("ZIG_VERIFY_DEBUG: path_nodes_len={} rho_len={} hashes_len={}\n", .{ path.getNodes().len, rho_dbg.len, hashes.len });

        // Verify the signature
        var is_valid = try scheme.verify(&public_key, epoch, message_bytes, signature);
        try stdout.print("ZIG_VERIFY_DEBUG: verification result: {}\n", .{is_valid});

        if (!is_valid) {
            // Attempt alternate path order: reverse path.nodes and re-verify
            var parsed = std.json.parseFromSlice(std.json.Value, allocator, signature_json, .{}) catch null;
            if (parsed) |*doc| {
                defer doc.deinit();
                if (doc.value == .object) {
                    if (doc.value.object.get("path")) |p| {
                        if (p == .object) {
                            if (p.object.get("nodes")) |nodes_val| {
                                if (nodes_val == .array) {
                                    std.mem.reverse(std.json.Value, nodes_val.array.items);
                                    const alt_str = std.json.stringifyAlloc(allocator, doc.value, .{}) catch null;
                                    if (alt_str) |alt_json| {
                                        defer allocator.free(alt_json);
                                        const alt_sig = hash_zig.serialization.deserializeSignature(allocator, alt_json) catch null;
                                        if (alt_sig) |sig2| {
                                            defer sig2.deinit();
                                            const alt_ok = try scheme.verify(&public_key, epoch, message_bytes, sig2);
                                            if (alt_ok) {
                                                is_valid = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        const stdout_final = std.io.getStdOut().writer();
        try stdout_final.print("VERIFY_RESULT:{}\n", .{is_valid});
    } else {
        const stdout_err = std.io.getStdOut().writer();
        try stdout_err.print("VERIFY_RESULT:false (signature_data doesn't start with SIGNATURE:)\n", .{});
    }
}
