///! Poseidon2 hash using KoalaBear field
///! Compatible with plonky3's implementation for hash-based signatures
const std = @import("std");
const Allocator = std.mem.Allocator;
const poseidon2_core = @import("poseidon2/root.zig");

const WIDTH = 16;
const OUTPUT_LEN = 8; // 8 field elements = 32 bytes (8 * 4 bytes)

pub const Poseidon2 = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) !Poseidon2 {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Poseidon2) void {
        _ = self;
        // No cleanup needed - stateless
    }

    /// Hash arbitrary bytes to a 32-byte output using Poseidon2
    pub fn hashBytes(self: *Poseidon2, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;

        const F = poseidon2_core.KoalaBearField;
        const Poseidon2Core = poseidon2_core.Poseidon2KoalaBear16;

        // Initialize state in Montgomery form
        var state: [WIDTH]F.MontFieldElem = undefined;
        for (0..WIDTH) |i| {
            F.toMontgomery(&state[i], 0);
        }

        // Process data in 64-byte chunks (WIDTH * 4 bytes)
        var offset: usize = 0;
        const chunk_size = WIDTH * 4; // 64 bytes per chunk

        while (offset < data.len) {
            // Pack bytes into field elements and XOR into state
            const remaining = data.len - offset;
            const to_process = @min(remaining, chunk_size);

            var chunk: [WIDTH]u32 = std.mem.zeroes([WIDTH]u32);
            for (0..to_process) |i| {
                const elem_idx = i / 4;
                const byte_idx = i % 4;
                chunk[elem_idx] |= @as(u32, data[offset + i]) << @intCast(byte_idx * 8);
            }

            // XOR chunk into state (in Montgomery form)
            for (0..WIDTH) |i| {
                var chunk_mont: F.MontFieldElem = undefined;
                F.toMontgomery(&chunk_mont, chunk[i]);
                F.add(&state[i], state[i], chunk_mont);
            }

            // Apply permutation
            Poseidon2Core.permutation(&state);

            offset += chunk_size;
        }

        // Convert OUTPUT_LEN elements back from Montgomery form
        var output = try allocator.alloc(u8, 32);
        for (0..OUTPUT_LEN) |i| {
            const val = F.toNormal(state[i]);
            output[i * 4 + 0] = @truncate(val);
            output[i * 4 + 1] = @truncate(val >> 8);
            output[i * 4 + 2] = @truncate(val >> 16);
            output[i * 4 + 3] = @truncate(val >> 24);
        }

        return output;
    }
};

test "poseidon2 basic" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    const data = "test data";
    const hash1 = try hasher.hashBytes(allocator, data);
    defer allocator.free(hash1);

    const hash2 = try hasher.hashBytes(allocator, data);
    defer allocator.free(hash2);

    // Same input should produce same output
    try std.testing.expectEqualSlices(u8, hash1, hash2);

    // Different input should produce different output
    const data2 = "different";
    const hash3 = try hasher.hashBytes(allocator, data2);
    defer allocator.free(hash3);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash3));
}
