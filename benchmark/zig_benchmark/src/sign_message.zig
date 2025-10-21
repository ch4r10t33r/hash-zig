const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get environment variables
    const key_data = std.process.getEnvVarOwned(allocator, "KEY_DATA") catch {
        std.debug.print("Missing KEY_DATA environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(key_data);

    const message = std.process.getEnvVarOwned(allocator, "MESSAGE") catch {
        std.debug.print("Missing MESSAGE environment variable\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(message);

    const epoch_str = std.process.getEnvVarOwned(allocator, "EPOCH") catch "0";
    defer allocator.free(epoch_str);
    const epoch = std.fmt.parseInt(u32, epoch_str, 10) catch 0;

    // For now, we'll generate a new keypair since we don't have key serialization
    // In a real implementation, we'd deserialize the key_data
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Convert message to bytes (truncate/pad to 32 bytes)
    var message_bytes: [32]u8 = [_]u8{0} ** 32;
    const copy_len = @min(message.len, 32);
    @memcpy(message_bytes[0..copy_len], message[0..copy_len]);

    // Sign the message
    const signature = try scheme.sign(keypair.secret_key, epoch, message_bytes);
    defer signature.deinit();

    // Serialize signature to JSON format
    var json_buffer = std.ArrayList(u8).init(allocator);
    defer json_buffer.deinit();

    const writer = json_buffer.writer();

    // Start JSON object
    try writer.writeAll("{");

    // Serialize path
    try writer.writeAll("\"path\":{");
    try writer.writeAll("\"nodes\":[");

    // Serialize path nodes
    for (signature.path.path, 0..) |node, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try std.fmt.format(writer, "{any}", .{node});
        try writer.writeAll("\"");
    }

    try writer.writeAll("]");
    try writer.writeAll("}");

    // Serialize rho
    try writer.writeAll(",\"rho\":[");
    for (signature.rho, 0..) |elem, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try std.fmt.format(writer, "{any}", .{elem});
        try writer.writeAll("\"");
    }
    try writer.writeAll("]");

    // Serialize hashes
    try writer.writeAll(",\"hashes\":[");
    for (signature.hashes, 0..) |hash, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try std.fmt.format(writer, "{any}", .{hash});
        try writer.writeAll("\"");
    }
    try writer.writeAll("]");

    // End JSON object
    try writer.writeAll("}");

    // Output the serialized signature
    std.debug.print("SIGNATURE:{s}\n", .{json_buffer.items});
}
