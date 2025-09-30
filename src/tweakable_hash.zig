//! Tweakable hash wrapper for multiple hash functions (Poseidon2 and SHA3)

const std = @import("std");
const params = @import("params.zig");
const poseidon2 = @import("poseidon2/hash.zig");
const sha3_mod = @import("sha3.zig");
const Parameters = params.Parameters;
const HashFunction = params.HashFunction;
const Poseidon2 = poseidon2.Poseidon2;
const Sha3 = sha3_mod.Sha3;
const Allocator = std.mem.Allocator;

const HashImpl = union(enum) {
    poseidon2: Poseidon2,
    sha3: Sha3,
};

pub const TweakableHash = struct {
    params: Parameters,
    hash_impl: HashImpl,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !TweakableHash {
        const hash_impl = switch (parameters.hash_function) {
            .poseidon2 => blk: {
                const poseidon_instance = try Poseidon2.init(allocator, parameters.security_level);
                break :blk HashImpl{ .poseidon2 = poseidon_instance };
            },
            .sha3 => blk: {
                const sha3_instance = try Sha3.init(allocator, parameters.security_level);
                break :blk HashImpl{ .sha3 = sha3_instance };
            },
        };

        return .{
            .params = parameters,
            .hash_impl = hash_impl,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TweakableHash) void {
        switch (self.hash_impl) {
            .poseidon2 => |*p| p.deinit(self.allocator),
            .sha3 => |*s| s.deinit(self.allocator),
        }
    }

    pub fn hash(self: *TweakableHash, allocator: Allocator, data: []const u8, tweak: u64) ![]u8 {
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        @memcpy(tweaked_data[8..], data);

        return switch (self.hash_impl) {
            .poseidon2 => |*p| try p.hashBytes(allocator, tweaked_data),
            .sha3 => |*s| try s.hashBytes(allocator, tweaked_data),
        };
    }

    pub fn prfHash(self: *TweakableHash, allocator: Allocator, key: []const u8, index: u64) ![]u8 {
        return self.hash(allocator, key, index);
    }
};

test "tweakable hash different tweaks poseidon2" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const data = "test";
    const hash1 = try hash.hash(allocator, data, 0);
    defer allocator.free(hash1);
    const hash2 = try hash.hash(allocator, data, 1);
    defer allocator.free(hash2);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}

test "tweakable hash different tweaks sha3" {
    const allocator = std.testing.allocator;

    // Create parameters with SHA3
    const parameters = Parameters.initWithSha3(.lifetime_2_16);

    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const data = "test";
    const hash1 = try hash.hash(allocator, data, 0);
    defer allocator.free(hash1);
    const hash2 = try hash.hash(allocator, data, 1);
    defer allocator.free(hash2);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}
