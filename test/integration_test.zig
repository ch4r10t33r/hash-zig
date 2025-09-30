//! Integration tests for hash-sig

const std = @import("std");
const hash_sig = @import("hash-sig");

test "full signature workflow" {
    const allocator = std.testing.allocator;

    const params = hash_sig.Parameters.init(.Level128);
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    var keypair = try sig_scheme.generateKeyPair(allocator);
    defer keypair.deinit(allocator);

    const message = "Test message";
    var signature = try sig_scheme.sign(allocator, message, keypair.secret_key, 0);
    defer signature.deinit(allocator);

    const is_valid = try sig_scheme.verify(allocator, message, signature, keypair.public_key);
    try std.testing.expect(is_valid);
}

test "all security levels" {
    const allocator = std.testing.allocator;

    inline for ([_]hash_sig.SecurityLevel{ .Level128, .Level192, .Level256 }) |level| {
        const params = hash_sig.Parameters.init(level);
        var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
        defer sig_scheme.deinit();

        var keypair = try sig_scheme.generateKeyPair(allocator);
        defer keypair.deinit(allocator);

        try std.testing.expect(keypair.public_key.len > 0);
        try std.testing.expect(keypair.secret_key.len > 0);
    }
}
