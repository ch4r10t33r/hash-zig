//! Winternitz One-Time Signature encoding with checksum
//! Based on the Rust hash-sig implementation

const std = @import("std");
const params = @import("params.zig");
const Parameters = params.Parameters;
const EncodingType = params.EncodingType;
const Allocator = std.mem.Allocator;

pub const IncomparableEncoding = struct {
    params: Parameters,

    pub fn init(parameters: Parameters) IncomparableEncoding {
        return .{ .params = parameters };
    }

    /// Encode message hash into Winternitz chunks with checksum
    /// Returns: array of chunk values (num_message_chains + num_checksum_chains)
    /// For w=8: returns 22 values (20 message + 2 checksum), each in range [0, 255]
    pub fn encodeWinternitz(self: IncomparableEncoding, allocator: Allocator, message_hash: []const u8) ![]u8 {
        // Step 1: Take only the first num_message_chains bytes from the message hash
        // For w=8: 20 bytes produce 20 chunks (1 byte per chunk)
        const bytes_needed = self.params.num_message_chains * self.params.winternitz_w / 8;
        if (message_hash.len < bytes_needed) {
            return error.InsufficientMessageHashLength;
        }
        const hash_slice = message_hash[0..bytes_needed];

        // Step 2: Convert message hash bytes to chunks
        const message_chunks = try self.bytesToChunks(allocator, hash_slice, self.params.winternitz_w);
        defer allocator.free(message_chunks);

        // Verify we got the expected number of chunks
        if (message_chunks.len != self.params.num_message_chains) {
            return error.UnexpectedChunkCount;
        }

        // Step 2: Compute Winternitz checksum
        const base: u64 = @as(u64, 1) << @intCast(self.params.winternitz_w); // 256 for w=8
        var checksum: u64 = 0;
        for (message_chunks[0..self.params.num_message_chains]) |chunk| {
            checksum += (base - 1) - @as(u64, chunk);
        }

        // Step 3: Convert checksum to little-endian bytes
        var checksum_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &checksum_bytes, checksum, .little);

        // Step 4: Convert checksum bytes to chunks
        const checksum_chunks = try self.bytesToChunks(allocator, &checksum_bytes, self.params.winternitz_w);
        defer allocator.free(checksum_chunks);

        // Step 5: Combine message chunks + checksum chunks
        const total_chains = self.params.num_chains;
        var result = try allocator.alloc(u8, total_chains);

        // Copy message chunks
        @memcpy(result[0..self.params.num_message_chains], message_chunks[0..self.params.num_message_chains]);

        // Copy checksum chunks (only first num_checksum_chains)
        const checksum_count = @min(checksum_chunks.len, self.params.num_checksum_chains);
        @memcpy(result[self.params.num_message_chains..][0..checksum_count], checksum_chunks[0..checksum_count]);

        // Zero remaining checksum chunks if needed
        if (checksum_count < self.params.num_checksum_chains) {
            @memset(result[self.params.num_message_chains + checksum_count ..][0 .. self.params.num_checksum_chains - checksum_count], 0);
        }

        return result;
    }

    /// Convert bytes to chunks based on chunk_size (supports 1, 2, 4, 8 bits per chunk)
    /// Matches Rust's bytes_to_chunks function
    fn bytesToChunks(self: IncomparableEncoding, allocator: Allocator, bytes: []const u8, chunk_size: u32) ![]u8 {
        _ = self;

        // Only chunk sizes 1, 2, 4, or 8 are valid
        if (chunk_size != 1 and chunk_size != 2 and chunk_size != 4 and chunk_size != 8) {
            return error.InvalidChunkSize;
        }

        const chunks_per_byte = 8 / chunk_size;
        const num_chunks = bytes.len * chunks_per_byte;
        var chunks = try allocator.alloc(u8, num_chunks);

        switch (chunk_size) {
            8 => {
                // Each byte is one chunk (copy as-is)
                @memcpy(chunks, bytes);
            },
            4 => {
                // Each byte produces 2 chunks (low nibble, then high nibble)
                for (bytes, 0..) |byte, i| {
                    chunks[i * 2] = byte & 0x0F; // Low nibble
                    chunks[i * 2 + 1] = byte >> 4; // High nibble
                }
            },
            2 => {
                // Each byte produces 4 chunks (2 bits each)
                for (bytes, 0..) |byte, i| {
                    chunks[i * 4] = byte & 0x03;
                    chunks[i * 4 + 1] = (byte >> 2) & 0x03;
                    chunks[i * 4 + 2] = (byte >> 4) & 0x03;
                    chunks[i * 4 + 3] = (byte >> 6) & 0x03;
                }
            },
            1 => {
                // Each byte produces 8 chunks (1 bit each)
                for (bytes, 0..) |byte, i| {
                    for (0..8) |bit| {
                        chunks[i * 8 + bit] = @intCast((byte >> @intCast(bit)) & 1);
                    }
                }
            },
            else => unreachable,
        }

        return chunks;
    }

    /// Legacy binary encoding (kept for backwards compatibility)
    pub fn encode(self: IncomparableEncoding, allocator: Allocator, data: []const u8) ![]u8 {
        return self.encodeWinternitz(allocator, data);
    }

    pub fn isIncomparable(self: IncomparableEncoding, enc1: []const u8, enc2: []const u8) bool {
        _ = self;
        if (enc1.len != enc2.len) return false;

        var greater_count: usize = 0;
        var less_count: usize = 0;

        for (enc1, enc2) |e1, e2| {
            if (e1 > e2) greater_count += 1;
            if (e1 < e2) less_count += 1;
        }

        return greater_count > 0 and less_count > 0;
    }
};

test "winternitz encoding with checksum" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_8);
    const encoding = IncomparableEncoding.init(parameters);

    // Test with a 20-byte message hash (for w=8, this produces 20 message chunks)
    var message_hash: [20]u8 = undefined;
    for (&message_hash, 0..) |*byte, i| {
        byte.* = @intCast(i); // Simple test pattern: 0, 1, 2, ..., 19
    }

    const chunks = try encoding.encodeWinternitz(allocator, &message_hash);
    defer allocator.free(chunks);

    // Should produce 22 chunks total (20 message + 2 checksum)
    try std.testing.expectEqual(@as(usize, 22), chunks.len);

    // Message chunks should match input bytes (for w=8)
    for (message_hash, 0..) |byte, i| {
        try std.testing.expectEqual(byte, chunks[i]);
    }

    // Verify checksum is non-zero (sum of (255 - chunk[i]) for i=0..19)
    // For pattern 0,1,2,...,19: checksum = (255-0) + (255-1) + ... + (255-19)
    // = 20*255 - (0+1+2+...+19) = 5100 - 190 = 4910
    const expected_checksum: u64 = 4910;
    const checksum_chunk0 = @as(u64, chunks[20]);
    const checksum_chunk1 = @as(u64, chunks[21]);
    const actual_checksum = checksum_chunk0 | (checksum_chunk1 << 8);
    try std.testing.expectEqual(expected_checksum, actual_checksum);
}
