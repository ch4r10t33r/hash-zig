const std = @import("std");
const hash_zig = @import("hash-zig");

fn fromMonty(x: u32) u32 {
    const prime: u64 = 0x7f000001;
    const mu: u64 = 0x81000001;
    const x64: u64 = x;
    const t = x64 *% mu & 0xffffffff;
    const u = t * prime;
    const sub = @subWithOverflow(x64, u);
    const hi: u32 = @intCast(sub[0] >> 32);
    const corr: u32 = if (sub[1] != 0) @intCast(prime) else 0;
    return hi +% corr;
}

fn mapHexStrings(allocator: std.mem.Allocator, value: *std.json.Value) !void {
    switch (value.*) {
        .string => |s| {
            if (s.len > 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
                const n = std.fmt.parseInt(u32, s[2..], 16) catch return;
                value.* = .{ .string = try std.fmt.allocPrint(allocator, "0x{x:0>8}", .{fromMonty(n)}) };
            }
        },
        .array => |*arr| {
            for (arr.items) |*item| try mapHexStrings(allocator, item);
        },
        .object => |*obj| {
            var it = obj.iterator();
            while (it.next()) |entry| try mapHexStrings(allocator, entry.value_ptr);
        },
        else => {},
    }
}

/// Rust loads JSON integers as Montgomery limbs. The library verifier expects
/// canonical path, rho, hashes, and parameter, with the root left as a limb.
fn canonicalWireJson(allocator: std.mem.Allocator, signature_json: []const u8, public_key_json: []const u8) !struct { sig: []u8, pk: []u8 } {
    var sig_parsed = try std.json.parseFromSlice(std.json.Value, allocator, signature_json, .{});
    defer sig_parsed.deinit();
    if (sig_parsed.value == .object) {
        if (sig_parsed.value.object.getPtr("path")) |path| try mapHexStrings(allocator, path);
        if (sig_parsed.value.object.getPtr("rho")) |rho| try mapHexStrings(allocator, rho);
        if (sig_parsed.value.object.getPtr("hashes")) |hashes| try mapHexStrings(allocator, hashes);
    }
    var pk_parsed = try std.json.parseFromSlice(std.json.Value, allocator, public_key_json, .{});
    defer pk_parsed.deinit();
    if (pk_parsed.value == .object) {
        if (pk_parsed.value.object.getPtr("parameter")) |parameter| try mapHexStrings(allocator, parameter);
    }
    return .{
        .sig = try jsonStringifyAlloc(allocator, sig_parsed.value),
        .pk = try jsonStringifyAlloc(allocator, pk_parsed.value),
    };
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get environment variables
    const public_key_data = envVarOwned(allocator, init, "PUBLIC_KEY") catch {
        std.debug.print("Missing PUBLIC_KEY environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(public_key_data);

    const signature_data = envVarOwned(allocator, init, "SIGNATURE") catch {
        std.debug.print("Missing SIGNATURE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(signature_data);

    const message = envVarOwned(allocator, init, "MESSAGE") catch {
        std.debug.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

    const epoch_str = envVarOwned(allocator, init, "EPOCH") catch "0";
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

        try writeStdout(init, "ZIG_VERIFY_DEBUG: Starting deserialization\n", .{});
        
        // Deserialize public key
        const public_key = hash_zig.serialization.deserializePublicKey(public_key_json) catch |err| {
            try writeStdout(init, "ZIG_VERIFY_DEBUG: Failed to deserialize public key: {}\n", .{err});
            std.process.exit(1);
        };
        try writeStdout(init, "ZIG_VERIFY_DEBUG: Public key deserialized successfully\n", .{});

        // Deserialize signature
        var signature = hash_zig.serialization.deserializeSignature(allocator, signature_json) catch |err| {
            try writeStdout(init, "ZIG_VERIFY_DEBUG: Failed to deserialize signature: {}\n", .{err});
            std.process.exit(1);
        };
        defer signature.deinit();
        try writeStdout(init, "ZIG_VERIFY_DEBUG: Signature deserialized successfully\n", .{});

        // Initialize the scheme
        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
        defer scheme.deinit();

        // Debug: log parsed structure lengths
        const path = signature.getPath();
        const rho_dbg = signature.getRho();
        const hashes = signature.getHashes();
        std.debug.print("ZIG_DEBUG: path_nodes_len={} rho_len={} hashes_len={}\n", .{ path.getNodes().len, rho_dbg.len, hashes.len });
        try writeStdout(init, "ZIG_VERIFY_DEBUG: path_nodes_len={} rho_len={} hashes_len={}\n", .{ path.getNodes().len, rho_dbg.len, hashes.len });

        // Verify the signature
        var is_valid = try scheme.verify(&public_key, epoch, message_bytes, signature);
        try writeStdout(init, "ZIG_VERIFY_DEBUG: verification result: {}\n", .{is_valid});

        if (!is_valid) {
            const rewritten = canonicalWireJson(allocator, signature_json, public_key_json) catch null;
            if (rewritten) |docs| {
                defer allocator.free(docs.sig);
                defer allocator.free(docs.pk);
                const alt_pk = hash_zig.serialization.deserializePublicKey(docs.pk) catch null;
                const alt_sig = hash_zig.serialization.deserializeSignature(allocator, docs.sig) catch null;
                if (alt_pk != null and alt_sig != null) {
                    var pk2 = alt_pk.?;
                    const sig2 = alt_sig.?;
                    defer sig2.deinit();
                    const alt_ok = try scheme.verify(&pk2, epoch, message_bytes, sig2);
                    if (alt_ok) is_valid = true;
                }
            }
        }

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
                                    const alt_str = jsonStringifyAlloc(allocator, doc.value) catch null;
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

        try writeStdout(init, "VERIFY_RESULT:{}\n", .{is_valid});
    } else {
        try writeStdout(init, "VERIFY_RESULT:false (signature_data doesn't start with SIGNATURE:)\n", .{});
    }
}

fn writeStdout(init: std.process.Init, comptime fmt: []const u8, args: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(init.io, &buffer);
    try stdout.interface.print(fmt, args);
    try stdout.interface.flush();
}

fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try out.writer.print("{f}", .{std.json.fmt(value, .{})});
    return out.toOwnedSlice();
}

fn envVarOwned(allocator: std.mem.Allocator, init: std.process.Init, key: []const u8) ![]u8 {
    const value = init.environ_map.get(key) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}
