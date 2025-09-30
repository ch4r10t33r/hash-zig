//! Incomparable encodings for hash-based signatures

const std = @import("std");
const params = @import("params.zig");
const EncodingType = params.EncodingType;
const Allocator = std.mem.Allocator;

pub const IncomparableEncoding = struct {
    encoding_type: EncodingType,

    pub fn init(encoding_type: EncodingType) IncomparableEncoding {
        return .{ .encoding_type = encoding_type };
    }

    pub fn encode(self: IncomparableEncoding, allocator: Allocator, data: []const u8) ![]u8 {
        // Only binary encoding supported for 128-bit security
        return self.encodeBinary(allocator, data);
    }

    fn encodeBinary(self: IncomparableEncoding, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;
        const encoded = try allocator.alloc(u8, data.len * 8);
        for (data, 0..) |byte, i| {
            for (0..8) |bit| {
                encoded[i * 8 + bit] = @intCast((byte >> @intCast(7 - bit)) & 1);
            }
        }
        return encoded;
    }

    fn encodeTernary(self: IncomparableEncoding, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;
        const encoded = try allocator.alloc(u8, data.len * 6);
        for (data, 0..) |byte, i| {
            var val = byte;
            for (0..6) |j| {
                encoded[i * 6 + j] = @intCast(val % 3);
                val /= 3;
            }
        }
        return encoded;
    }

    fn encodeQuaternary(self: IncomparableEncoding, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;
        const encoded = try allocator.alloc(u8, data.len * 4);
        for (data, 0..) |byte, i| {
            for (0..4) |j| {
                encoded[i * 4 + j] = @intCast((byte >> @intCast(j * 2)) & 3);
            }
        }
        return encoded;
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

test "binary encoding" {
    const allocator = std.testing.allocator;
    const encoding = IncomparableEncoding.init(.binary);
    const data = "test";
    const encoded = try encoding.encode(allocator, data);
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len == data.len * 8);
}
