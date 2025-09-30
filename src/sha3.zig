//! SHA3 hash function implementation using Zig standard library

const std = @import("std");
const params = @import("params.zig");
const SecurityLevel = params.SecurityLevel;
const Allocator = std.mem.Allocator;

pub const Sha3 = struct {
    security_level: SecurityLevel,

    pub fn init(allocator: Allocator, security_level: SecurityLevel) !Sha3 {
        _ = allocator;
        return .{
            .security_level = security_level,
        };
    }

    pub fn deinit(self: *Sha3, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    /// Hash arbitrary bytes and return the hash output (SHA3-256 for 128-bit security)
    pub fn hashBytes(self: *Sha3, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;
        const output_len = 32; // SHA3-256

        const output = try allocator.alloc(u8, output_len);

        // SHA3-256 for 128-bit security
        var hash_state = std.crypto.hash.sha3.Sha3_256.init(.{});
        hash_state.update(data);
        var digest: [32]u8 = undefined;
        hash_state.final(&digest);
        @memcpy(output, &digest);

        return output;
    }
};

test "sha3 256 basic hash" {
    const allocator = std.testing.allocator;

    var sha3 = try Sha3.init(allocator, .level_128);
    defer sha3.deinit(allocator);

    const data = "test data";
    const hash = try sha3.hashBytes(allocator, data);
    defer allocator.free(hash);

    try std.testing.expect(hash.len == 32); // SHA3-256 for 128-bit security
}

test "sha3 produces different hashes for different inputs" {
    const allocator = std.testing.allocator;

    var sha3 = try Sha3.init(allocator, .level_128);
    defer sha3.deinit(allocator);

    const data1 = "test data 1";
    const hash1 = try sha3.hashBytes(allocator, data1);
    defer allocator.free(hash1);

    const data2 = "test data 2";
    const hash2 = try sha3.hashBytes(allocator, data2);
    defer allocator.free(hash2);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}
