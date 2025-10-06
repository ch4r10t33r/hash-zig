const std = @import("std");
const simd_poseidon2 = @import("simd_poseidon2");

// SIMD-optimized hash function using Poseidon2
// Uses SIMD Poseidon2 with width=16 to match the Rust implementation
// but with SIMD optimizations for better performance

pub const SimdHash = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) SimdHash {
        return SimdHash{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SimdHash) void {
        _ = self;
        // No cleanup needed
    }

    // Hash function using SIMD Poseidon2
    pub fn hash(self: *SimdHash, allocator: std.mem.Allocator, data: []const u8, tweak: u64) ![]u8 {
        _ = self;

        // Create tweaked input: tweak (8 bytes) + data
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        @memcpy(tweaked_data[8..], data);

        // Use SIMD-optimized Poseidon2 with Rust-compatible parameters
        const hash_result = simd_poseidon2.simd_poseidon2.hash(tweaked_data);

        // Return a copy
        const result = try allocator.dupe(u8, &hash_result);
        return result;
    }

    // PRF hash function using SIMD Poseidon2
    pub fn prfHash(self: *SimdHash, allocator: std.mem.Allocator, key: []const u8, index: u64) ![]u8 {
        return self.hash(allocator, key, index);
    }

    // Batch hash function for multiple inputs
    pub fn batchHash(self: *SimdHash, allocator: std.mem.Allocator, inputs: []const []const u8) ![][]u8 {
        _ = self;

        var outputs = std.ArrayList([]u8).init(allocator);
        try outputs.ensureTotalCapacity(inputs.len);

        for (inputs) |input| {
            const hash_result = simd_poseidon2.simd_poseidon2.hash(input);
            const result = try allocator.dupe(u8, &hash_result);
            try outputs.append(result);
        }

        return outputs.toOwnedSlice();
    }

    // Batch PRF hash function
    pub fn batchPrfHash(self: *SimdHash, allocator: std.mem.Allocator, keys: []const []const u8, indices: []const u64) ![][]u8 {
        if (keys.len != indices.len) {
            return error.InvalidInput;
        }

        var outputs = std.ArrayList([]u8).init(allocator);
        try outputs.ensureTotalCapacity(keys.len);

        for (keys, indices) |key, index| {
            const hash_result = try self.prfHash(allocator, key, index);
            try outputs.append(hash_result);
        }

        return outputs.toOwnedSlice();
    }
};
