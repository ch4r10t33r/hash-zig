const std = @import("std");
const hash_zig = @import("root.zig");

fn readEnvOrExit(allocator: std.mem.Allocator, name: []const u8, required: bool) []u8 {
    const value = std.process.getEnvVarOwned(allocator, name) catch {
        if (required) {
            std.debug.print("Missing {s} environment variable\n", .{name});
            std.process.exit(1);
        }
        return allocator.dupe(u8, "") catch unreachable;
    };
    return value;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Read inputs
    const message_env = readEnvOrExit(allocator, "MESSAGE", true);
    defer allocator.free(message_env);

    const epoch_str = readEnvOrExit(allocator, "EPOCH", false);
    defer allocator.free(epoch_str);
    const epoch: u32 = if (epoch_str.len == 0) 0 else std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    // Initialize scheme for lifetime 2^18
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_18);
    defer scheme.deinit();

    // Key generation: activation_epoch=0, num_active_epochs=256 per requirements
    var keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Prepare message (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message_env.len, message_bytes.len);
    @memcpy(message_bytes[0..copy_len], message_env[0..copy_len]);

    // Sign
    const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature.deinit();

    // Serialize
    const signature_json = try hash_zig.serialization.serializeSignature(allocator, signature);
    defer allocator.free(signature_json);

    const public_key_json = try hash_zig.serialization.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(public_key_json);

    const secret_key_json = try hash_zig.serialization.serializeSecretKey(allocator, keypair.secret_key);
    defer allocator.free(secret_key_json);

    std.debug.print("SIGNATURE:{s}\n", .{signature_json});
    std.debug.print("PUBLIC_KEY:{s}\n", .{public_key_json});
    std.debug.print("SECRET_KEY:{s}\n", .{secret_key_json});
}

