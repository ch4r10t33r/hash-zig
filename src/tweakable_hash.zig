//! Tweakable hash wrapper for multiple hash functions (Poseidon2 and SHA3)

const std = @import("std");
const params = @import("params.zig");
const poseidon2_mod = @import("poseidon2_hash.zig");
const sha3_mod = @import("sha3.zig");
const Parameters = params.Parameters;
const HashFunction = params.HashFunction;
const Poseidon2 = poseidon2_mod.Poseidon2;
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
                const poseidon_instance = try Poseidon2.init(allocator);
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
            .poseidon2 => |*p| p.deinit(),
            .sha3 => |*s| s.deinit(self.allocator),
        }
    }

    pub fn hash(self: *TweakableHash, allocator: Allocator, data: []const u8, tweak: u64) ![]u8 {
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        for (data, 0..) |byte, i| {
            tweaked_data[8 + i] = byte;
        }

        return switch (self.hash_impl) {
            .poseidon2 => |*p| try p.hashBytes(allocator, tweaked_data),
            .sha3 => |*s| try s.hashBytes(allocator, tweaked_data),
        };
    }

    pub fn prfHash(self: *TweakableHash, allocator: Allocator, key: []const u8, index: u64) ![]u8 {
        return self.hash(allocator, key, index);
    }

    /// Batch hash multiple inputs with corresponding tweaks
    /// This is optimized for Winternitz chain generation where we process
    /// all chains at the same iteration step simultaneously
    pub fn hashBatch(self: *TweakableHash, allocator: Allocator, data_array: []const []const u8, tweaks: []const u64) ![][]u8 {
        if (data_array.len != tweaks.len) return error.MismatchedArrayLengths;

        // Prepare tweaked inputs
        var tweaked_inputs = try allocator.alloc([]u8, data_array.len);
        defer {
            for (tweaked_inputs) |input| allocator.free(input);
            allocator.free(tweaked_inputs);
        }

        for (data_array, tweaks, 0..) |data, tweak, i| {
            tweaked_inputs[i] = try allocator.alloc(u8, 8 + data.len);
            std.mem.writeInt(u64, tweaked_inputs[i][0..8], tweak, .big);
            @memcpy(tweaked_inputs[i][8..], data);
        }

        // Batch hash using underlying implementation
        return switch (self.hash_impl) {
            .poseidon2 => |*p| try p.hashBatch(allocator, tweaked_inputs),
            .sha3 => |*s| {
                // SHA3 doesn't have batch optimization, process sequentially
                var results = try allocator.alloc([]u8, tweaked_inputs.len);
                errdefer {
                    for (results) |r| {
                        if (r.len > 0) allocator.free(r);
                    }
                    allocator.free(results);
                }
                for (tweaked_inputs, 0..) |input, i| {
                    results[i] = try s.hashBytes(allocator, input);
                }
                return results;
            },
        };
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
