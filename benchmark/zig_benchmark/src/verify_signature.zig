const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get environment variables
    const public_key_data = std.process.getEnvVarOwned(allocator, "PUBLIC_KEY") catch {
        std.debug.print("Missing PUBLIC_KEY environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(public_key_data);

    const signature_data = std.process.getEnvVarOwned(allocator, "SIGNATURE") catch {
        std.debug.print("Missing SIGNATURE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(signature_data);

    const message = std.process.getEnvVarOwned(allocator, "MESSAGE") catch {
        std.debug.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

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

        // Deserialize public key
        const public_key = hash_zig.serialization.deserializePublicKey(public_key_json) catch |err| {
            std.debug.print("Failed to deserialize public key: {}\n", .{err});
            std.process.exit(1);
        };

        // Deserialize signature
        const signature = hash_zig.serialization.deserializeSignature(allocator, signature_json) catch |err| {
            std.debug.print("Failed to deserialize signature: {}\n", .{err});
            std.process.exit(1);
        };
        defer signature.deinit();

        // Initialize the scheme
        var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
        defer scheme.deinit();

        // Verify the signature
        const is_valid = try scheme.verify(&public_key, epoch, message_bytes, signature);

        std.debug.print("VERIFY_RESULT:{}\n", .{is_valid});
    } else {
        std.debug.print("VERIFY_RESULT:false\n", .{});
    }
}
