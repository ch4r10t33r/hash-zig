//! Pseudorandom Function (PRF) implementation using SHAKE-128
//! Matches the Rust hash-sig implementation: ShakePRFtoF

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

// Domain separators (matching Rust implementation)
const PRF_DOMAIN_SEP: [16]u8 = .{
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff,
    0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
};
const PRF_DOMAIN_SEP_DOMAIN_ELEMENT: [1]u8 = .{0x00};

const PRF_BYTES_PER_FE: usize = 8; // 8 bytes per field element
const KEY_LENGTH: usize = 32; // 32 bytes

/// KoalaBear field prime: p = 2^31 - 2^24 + 1
const KOALABEAR_PRIME: u64 = (1 << 31) - (1 << 24) + 1;

pub const ShakePRF = struct {
    /// Generate a pseudorandom field element for a given epoch and index
    /// This matches Rust's ShakePRFtoF::get_domain_element
    ///
    /// For num_domain_elements = 7 (HASH_LEN_FE in Rust):
    /// Returns 7 field elements (7 * 4 bytes = 28 bytes, rounded to 32 for hash output)
    pub fn getDomainElements(
        allocator: Allocator,
        key: []const u8,
        epoch: u32,
        index: u64,
        num_elements: usize,
    ) ![]u8 {
        // Initialize SHAKE-128
        var hasher = crypto.hash.sha3.Shake128.init(.{});

        // Hash the domain separator
        hasher.update(&PRF_DOMAIN_SEP);

        // Hash the domain element separator
        hasher.update(&PRF_DOMAIN_SEP_DOMAIN_ELEMENT);

        // Hash the key (should be 32 bytes)
        hasher.update(key);

        // Hash the epoch (big-endian)
        var epoch_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &epoch_bytes, epoch, .big);
        hasher.update(&epoch_bytes);

        // Hash the index (big-endian)
        var index_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &index_bytes, index, .big);
        hasher.update(&index_bytes);

        // Read extended output
        const output_bytes = num_elements * PRF_BYTES_PER_FE;
        var prf_output = try allocator.alloc(u8, output_bytes);
        errdefer allocator.free(prf_output);

        // Finalize and read output
        hasher.squeeze(prf_output);

        // Convert bytes to field elements (reduce modulo KoalaBear prime)
        // Then pack field elements back to bytes (4 bytes per element)
        var result = try allocator.alloc(u8, num_elements * 4);
        errdefer allocator.free(result);

        for (0..num_elements) |i| {
            const chunk_start = i * PRF_BYTES_PER_FE;
            const chunk_end = chunk_start + PRF_BYTES_PER_FE;

            // Read 8 bytes as big-endian u64
            const value_u64 = std.mem.readInt(u64, prf_output[chunk_start..chunk_end][0..8], .big);

            // Reduce modulo KoalaBear prime
            const field_element = @as(u32, @intCast(value_u64 % KOALABEAR_PRIME));

            // Write as little-endian u32 (4 bytes per field element)
            std.mem.writeInt(u32, result[i * 4 ..][0..4], field_element, .little);
        }

        allocator.free(prf_output);
        return result;
    }

    /// Generate hash output for Winternitz chain starts
    /// Returns 7 field elements (28 bytes) matching Rust's HASH_LEN_FE = 7
    pub fn getHashOutput(
        allocator: Allocator,
        key: []const u8,
        epoch: u64,
        chain_index: u64,
    ) ![]u8 {
        // Use 7 field elements (matching HASH_LEN_FE = 7 in Rust)
        // Each field element is 4 bytes (little-endian u32), total 28 bytes
        const field_elements = try getDomainElements(allocator, key, @intCast(epoch), chain_index, 7);
        // field_elements is already 28 bytes (7 * 4), return it directly
        return field_elements;
    }
};

test "shake prf basic" {
    const allocator = std.testing.allocator;

    // Test key (32 bytes of 0x42)
    var key: [32]u8 = undefined;
    @memset(&key, 0x42);

    // Generate domain elements
    const output = try ShakePRF.getDomainElements(allocator, &key, 0, 0, 7);
    defer allocator.free(output);

    // Should produce 7 field elements * 4 bytes = 28 bytes
    try std.testing.expectEqual(@as(usize, 28), output.len);

    // All bytes should be within the field (when interpreted as u32 little-endian)
    for (0..7) |i| {
        const fe_bytes = output[i * 4 ..][0..4];
        const fe_value = std.mem.readInt(u32, fe_bytes, .little);
        try std.testing.expect(fe_value < KOALABEAR_PRIME);
    }
}

test "shake prf deterministic" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    @memset(&key, 0x42);

    const output1 = try ShakePRF.getDomainElements(allocator, &key, 0, 0, 7);
    defer allocator.free(output1);

    const output2 = try ShakePRF.getDomainElements(allocator, &key, 0, 0, 7);
    defer allocator.free(output2);

    // Same inputs should produce same outputs
    try std.testing.expectEqualSlices(u8, output1, output2);
}

test "shake prf different indices" {
    const allocator = std.testing.allocator;

    var key: [32]u8 = undefined;
    @memset(&key, 0x42);

    const output1 = try ShakePRF.getDomainElements(allocator, &key, 0, 0, 7);
    defer allocator.free(output1);

    const output2 = try ShakePRF.getDomainElements(allocator, &key, 0, 1, 7);
    defer allocator.free(output2);

    // Different indices should produce different outputs
    try std.testing.expect(!std.mem.eql(u8, output1, output2));
}
