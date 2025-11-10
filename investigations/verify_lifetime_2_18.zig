const std = @import("std");
const hash_zig = @import("root.zig");

fn readEnv(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const value = std.process.getEnvVarOwned(allocator, name) catch {
        return error.Missing;
    };
    return value;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const public_key_env = readEnv(allocator, "PUBLIC_KEY") catch {
        std.debug.print("Missing PUBLIC_KEY environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(public_key_env);

    const signature_env = readEnv(allocator, "SIGNATURE") catch {
        std.debug.print("Missing SIGNATURE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(signature_env);

    const message_env = readEnv(allocator, "MESSAGE") catch {
        std.debug.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message_env);

    const epoch_str = readEnv(allocator, "EPOCH") catch allocator.dupe(u8, "0") catch unreachable;
    defer allocator.free(epoch_str);
    const epoch: u32 = std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    // Prepare message bytes (32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message_env.len, message_bytes.len);
    @memcpy(message_bytes[0..copy_len], message_env[0..copy_len]);

    // Deserialize public key / signature
    const public_key_json = if (std.mem.startsWith(u8, public_key_env, "PUBLIC_KEY:"))
        public_key_env[11..]
    else
        public_key_env;

    const signature_json = if (std.mem.startsWith(u8, signature_env, "SIGNATURE:"))
        signature_env[10..]
    else
        signature_env;

    var public_key = hash_zig.serialization.deserializePublicKey(public_key_json) catch |err| {
        std.debug.print("Failed to deserialize public key: {}\n", .{err});
        std.process.exit(1);
    };

    var signature = hash_zig.serialization.deserializeSignature(allocator, signature_json) catch |err| {
        std.debug.print("Failed to deserialize signature: {}\n", .{err});
        std.process.exit(1);
    };
    defer signature.deinit();

    // Initialize scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_18);
    defer scheme.deinit();

    const is_valid = try scheme.verify(&public_key, epoch, message_bytes, signature);
    std.debug.print("VERIFY_RESULT:{s}\n", .{if (is_valid) "true" else "false"});
}

