//! Tweakable hash wrapper for Poseidon2

const std = @import("std");
const params = @import("params.zig");
const poseidon2 = @import("poseidon2/hash.zig");
const Parameters = params.Parameters;
const Poseidon2 = poseidon2.Poseidon2;
const Allocator = std.mem.Allocator;

pub const TweakableHash = struct {
    params: Parameters,
    poseidon: Poseidon2,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !TweakableHash {
        const p2 = try Poseidon2.init(allocator, parameters.security_level);
        return .{
            .params = parameters,
            .poseidon = p2,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TweakableHash) void {
        self.poseidon.deinit(self.allocator);
    }

    pub fn hash(self: *TweakableHash, allocator: Allocator, data: []const u8, tweak: u64) ![]u8 {
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        @memcpy(tweaked_data[8..], data);

        return self.poseidon.hashBytes(allocator, tweaked_data);
    }

    pub fn prfHash(self: *TweakableHash, allocator: Allocator, key: []const u8, index: u64) ![]u8 {
        return self.hash(allocator, key, index);
    }
};

test "tweakable hash different tweaks" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.level_128, .lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const data = "test";
    const h1 = try hash.hash(allocator, data, 0);
    defer allocator.free(h1);
    const h2 = try hash.hash(allocator, data, 1);
    defer allocator.free(h2);

    try std.testing.expect(!std.mem.eql(u8, h1, h2));
}
