const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get environment variables
    const key_data = envVarOwned(allocator, init, "KEY_DATA") catch {
        std.debug.print("Missing KEY_DATA environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(key_data);

    const message = envVarOwned(allocator, init, "MESSAGE") catch {
        std.debug.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

    const epoch_str = envVarOwned(allocator, init, "EPOCH") catch "0";
    defer allocator.free(epoch_str);
    const epoch = std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    // Initialize the scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    // Generate a keypair
    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Convert message to bytes (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message.len, 32);
    @memcpy(message_bytes[0..copy_len], message[0..copy_len]);

    // Sign the message
    const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature.deinit();

    // Serialize signature using proper serialization
    const signature_json = try hash_zig.serialization.serializeSignature(allocator, signature);
    defer allocator.free(signature_json);

    // Serialize public key for verification
    const public_key_json = try hash_zig.serialization.serializePublicKey(allocator, &keypair.public_key);
    defer allocator.free(public_key_json);

    // Serialize secret key for signing
    const secret_key_json = try hash_zig.serialization.serializeSecretKey(allocator, keypair.secret_key);
    defer allocator.free(secret_key_json);

    // Output the serialized data
    std.debug.print("SIGNATURE:{s}\n", .{signature_json});
    std.debug.print("PUBLIC_KEY:{s}\n", .{public_key_json});
    std.debug.print("SECRET_KEY:{s}\n", .{secret_key_json});
}

fn envVarOwned(allocator: std.mem.Allocator, init: std.process.Init, key: []const u8) ![]u8 {
    const value = init.environ_map.get(key) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, value);
}
