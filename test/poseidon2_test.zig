//! Tests for Poseidon2 hash function
//! These tests ensure the hash function produces diverse outputs

const std = @import("std");
const hash_zig = @import("hash-zig");

test "poseidon2: no repeating patterns in output" {
    const allocator = std.testing.allocator;
    
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const test_data = "test";
    const result = try tweakable_hash.hash(allocator, test_data, 0);
    defer allocator.free(result);

    // Check that we have 32 bytes
    try std.testing.expectEqual(@as(usize, 32), result.len);

    // Check for repeating 4-byte patterns
    // If all 4-byte chunks are identical, that's a bug
    const num_chunks = result.len / 4;
    var first_chunk: [4]u8 = undefined;
    @memcpy(&first_chunk, result[0..4]);

    var all_same = true;
    var i: usize = 1;
    while (i < num_chunks) : (i += 1) {
        const chunk_offset = i * 4;
        if (!std.mem.eql(u8, &first_chunk, result[chunk_offset..chunk_offset + 4])) {
            all_same = false;
            break;
        }
    }

    // Output should NOT be all the same pattern
    try std.testing.expect(!all_same);
}

test "poseidon2: different inputs produce different outputs" {
    const allocator = std.testing.allocator;
    
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const result1 = try tweakable_hash.hash(allocator, "test1", 0);
    defer allocator.free(result1);

    const result2 = try tweakable_hash.hash(allocator, "test2", 0);
    defer allocator.free(result2);

    // Different inputs should produce different outputs
    try std.testing.expect(!std.mem.eql(u8, result1, result2));
}

test "poseidon2: different tweaks produce different outputs" {
    const allocator = std.testing.allocator;
    
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const test_data = "test";
    const result1 = try tweakable_hash.hash(allocator, test_data, 0);
    defer allocator.free(result1);

    const result2 = try tweakable_hash.hash(allocator, test_data, 1);
    defer allocator.free(result2);

    // Different tweaks should produce different outputs
    try std.testing.expect(!std.mem.eql(u8, result1, result2));
}

test "poseidon2: output has good entropy" {
    const allocator = std.testing.allocator;
    
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const result = try tweakable_hash.hash(allocator, "test", 0);
    defer allocator.free(result);

    // Count bit diversity
    var bit_counts: [8]usize = .{0} ** 8;
    for (result) |byte| {
        var b = byte;
        var bit_pos: usize = 0;
        while (bit_pos < 8) : (bit_pos += 1) {
            if (b & 1 == 1) bit_counts[bit_pos] += 1;
            b >>= 1;
        }
    }

    // Each bit position should appear in roughly 40-60% of bytes (not all 0s or all 1s)
    for (bit_counts) |count| {
        const percent = (count * 100) / result.len;
        try std.testing.expect(percent >= 30 and percent <= 70);
    }
}

test "poseidon2: zero input produces non-zero output" {
    const allocator = std.testing.allocator;
    
    const params = hash_zig.Parameters.init(.lifetime_2_10);
    var tweakable_hash = try hash_zig.TweakableHash.init(allocator, params);
    defer tweakable_hash.deinit();

    const zero_input = &[_]u8{0} ** 32;
    const result = try tweakable_hash.hash(allocator, zero_input, 0);
    defer allocator.free(result);

    // Output should not be all zeros
    var all_zero = true;
    for (result) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }

    try std.testing.expect(!all_zero);
}

