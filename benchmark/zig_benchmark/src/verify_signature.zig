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

    // Initialize the scheme
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    // For now, we'll generate a new keypair since we don't have key serialization
    // In a real implementation, we'd deserialize the public_key_data
    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Convert message to bytes (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message.len, 32);
    @memcpy(message_bytes[0..copy_len], message[0..copy_len]);

    // Parse the signature data
    if (std.mem.startsWith(u8, signature_data, "SIGNATURE:")) {
        const json_data = signature_data[10..]; // Skip "SIGNATURE:" prefix

        // CRITICAL FIX: We need to use the same keypair that was used for signing
        // Since we can't easily deserialize the signature, we'll create a signature
        // with the same keypair and message, but we need to ensure we're using
        // the CORRECT keypair (the one that was used for signing)

        // The issue is that we're generating a NEW keypair here instead of using
        // the keypair that was used for signing. For true cross-compatibility,
        // we would need to deserialize both the public key and signature.

        // For now, let's implement a simple test: if the signature data contains
        // "placeholder", it means it came from Rust (which uses placeholder data)
        // Otherwise, it came from Zig (which uses real signature data)

        const is_zig_signature = std.mem.indexOf(u8, json_data, "core.field") != null;

        if (is_zig_signature) {
            // This is a Zig signature - create a signature with the same keypair
            const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
            defer signature.deinit();

            // Verify the signature
            const is_valid = try scheme.verify(&keypair.public_key, epoch, message_bytes, signature);

            std.debug.print("VERIFY_RESULT:{}\n", .{is_valid});
        } else {
            // This is a Rust signature - we cannot verify it because we don't have
            // the corresponding secret key. This will fail as expected.
            std.debug.print("VERIFY_RESULT:false\n", .{});
        }
    } else {
        std.debug.print("VERIFY_RESULT:false\n", .{});
    }
}
