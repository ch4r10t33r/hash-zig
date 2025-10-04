//! Optimized hash implementation for Rust-compatible signatures
//! Version 2 - focuses on performance without caching complexity

const std = @import("std");
const params = @import("params.zig");
const koalabear16 = @import("poseidon2/instances/koalabear16.zig");
const Parameters = params.Parameters;
const Allocator = std.mem.Allocator;

/// Optimized hash implementation without caching for simplicity
pub const OptimizedHashV2 = struct {
    params: Parameters,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !OptimizedHashV2 {
        return .{
            .params = parameters,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *OptimizedHashV2) void {
        _ = self;
    }

    pub fn hash(self: *OptimizedHashV2, allocator: Allocator, data: []const u8, tweak: u64) ![]u8 {
        _ = self;

        // Create tweaked input: tweak (8 bytes) + data
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        @memcpy(tweaked_data[8..], data);

        // Use Rust-compatible KoalaBear16 Poseidon2 (width=16, ext_rounds=8, int_rounds=20, sbox=3)
        const hash_result = koalabear16.hash(tweaked_data);

        // Return a copy
        const result = try allocator.dupe(u8, &hash_result);
        return result;
    }

    pub fn prfHash(self: *OptimizedHashV2, allocator: Allocator, key: []const u8, index: u64) ![]u8 {
        return self.hash(allocator, key, index);
    }
};
