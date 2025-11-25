//! KoalaBear finite field implementation
//! Prime: p = 2^31 - 2^24 + 1 = 2,130,706,433
//!
//! This field is used in the Poseidon2 hash function and throughout
//! the hash-based signature scheme for field-native operations.

const std = @import("std");
const Allocator = std.mem.Allocator;
const plonky3_field = @import("../poseidon2/plonky3_field.zig");

pub const KOALABEAR_PRIME: u64 = 0x7f000001;
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

const MontyField = plonky3_field.KoalaBearField;

pub const FieldElement = struct {
    /// Field element stored in Montgomery form (matching Rust hash-sig).
    value: u32,

    pub const PRIME: u64 = KOALABEAR_PRIME;

    pub fn zero() FieldElement {
        return .{ .value = MontyField.zero.value };
    }

    pub fn one() FieldElement {
        return .{ .value = MontyField.one.value };
    }

    pub fn fromCanonical(val: u32) FieldElement {
        return .{ .value = MontyField.fromU32(val).value };
    }

    pub fn fromCanonicalU64(val: u64) FieldElement {
        return fromCanonical(@intCast(val % KOALABEAR_PRIME));
    }

    pub fn fromU32(val: u32) FieldElement {
        return fromCanonical(val);
    }

    pub fn fromU64(val: u64) FieldElement {
        return fromCanonicalU64(val);
    }

    pub fn fromMontgomery(val: u32) FieldElement {
        return .{ .value = val };
    }

    pub fn fromKoala(value: MontyField) FieldElement {
        return .{ .value = value.value };
    }

    pub fn toKoala(self: FieldElement) MontyField {
        return MontyField{ .value = self.value };
    }

    pub fn toMontgomery(self: FieldElement) u32 {
        return self.value;
    }

    pub fn toCanonical(self: FieldElement) u32 {
        return self.toKoala().toU32();
    }

    pub fn toU32(self: FieldElement) u32 {
        return self.toCanonical();
    }

    pub fn toU64(self: FieldElement) u64 {
        return self.toCanonical();
    }

    pub fn add(self: FieldElement, other: FieldElement) FieldElement {
        return fromKoala(self.toKoala().add(other.toKoala()));
    }

    pub fn sub(self: FieldElement, other: FieldElement) FieldElement {
        return fromKoala(self.toKoala().sub(other.toKoala()));
    }

    pub fn mul(self: FieldElement, other: FieldElement) FieldElement {
        return fromKoala(self.toKoala().mul(other.toKoala()));
    }

    pub fn neg(self: FieldElement) FieldElement {
        return fromKoala(self.toKoala().neg());
    }

    pub fn square(self: FieldElement) FieldElement {
        return self.mul(self);
    }

    pub fn eql(self: FieldElement, other: FieldElement) bool {
        return self.value == other.value;
    }

    pub fn isZero(self: FieldElement) bool {
        return self.value == 0;
    }

    pub fn isOne(self: FieldElement) bool {
        return self.toKoala().isOne();
    }

    pub fn toBytes(self: FieldElement) [4]u8 {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, self.toCanonical(), .little);
        return bytes;
    }

    pub fn fromBytes(bytes: [4]u8) FieldElement {
        const val = std.mem.readInt(u32, &bytes, .little);
        return fromCanonical(val);
    }

    pub fn fromBytesSlice(bytes: []const u8) !FieldElement {
        if (bytes.len < 4) return error.InsufficientBytes;
        var arr: [4]u8 = undefined;
        @memcpy(&arr, bytes[0..4]);
        return fromBytes(arr);
    }

    pub fn arrayToBytes(allocator: Allocator, elements: []const FieldElement) ![]u8 {
        const result = try allocator.alloc(u8, elements.len * 4);
        for (elements, 0..) |elem, i| {
            const bytes = elem.toBytes();
            @memcpy(result[i * 4 ..][0..4], &bytes);
        }
        return result;
    }

    pub fn arrayFromBytes(allocator: Allocator, bytes: []const u8) ![]FieldElement {
        if (bytes.len % 4 != 0) return error.InvalidByteLength;
        const num_elements = bytes.len / 4;

        const result = try allocator.alloc(FieldElement, num_elements);
        for (0..num_elements) |i| {
            var chunk: [4]u8 = undefined;
            @memcpy(&chunk, bytes[i * 4 ..][0..4]);
            result[i] = fromBytes(chunk);
        }
        return result;
    }
};

pub const KoalaBearField = FieldElement;

// ============================================================================
// Tests
// ============================================================================

test "field element: zero and one" {
    const zero = FieldElement.zero();
    const one = FieldElement.one();

    try std.testing.expect(zero.isZero());
    try std.testing.expect(!zero.isOne());
    try std.testing.expect(one.isOne());
    try std.testing.expect(!one.isZero());
    try std.testing.expectEqual(@as(u32, 0), zero.toCanonical());
    try std.testing.expectEqual(@as(u32, 1), one.toCanonical());
}

test "field element: canonical conversions" {
    const val_u32: u32 = 12345;
    const val_u64: u64 = 98765432;

    const fe1 = FieldElement.fromU32(val_u32);
    const fe2 = FieldElement.fromU64(val_u64);

    try std.testing.expectEqual(val_u32, fe1.toCanonical());
    try std.testing.expectEqual(@as(u32, @intCast(val_u64 % KOALABEAR_PRIME)), fe2.toCanonical());
}

test "field element: modular reduction" {
    const large_val = KOALABEAR_PRIME + 42;
    const fe = FieldElement.fromU64(large_val);
    try std.testing.expectEqual(@as(u32, 42), fe.toCanonical());

    const fe_prime = FieldElement.fromU64(KOALABEAR_PRIME);
    try std.testing.expect(fe_prime.isZero());
}

test "field element: addition and subtraction" {
    const a = FieldElement.fromU32(100);
    const b = FieldElement.fromU32(200);
    const c = a.add(b);
    try std.testing.expectEqual(@as(u32, 300), c.toCanonical());

    const max_val = @as(u32, @intCast(KOALABEAR_PRIME)) - 1;
    const fe_max = FieldElement.fromU32(max_val);
    const wrapped = fe_max.add(FieldElement.one());
    try std.testing.expect(wrapped.isZero());

    const d = b.sub(a);
    try std.testing.expectEqual(@as(u32, 100), d.toCanonical());

    const neg = a.sub(b);
    const expected = @as(u32, @intCast(KOALABEAR_PRIME)) - 100;
    try std.testing.expectEqual(expected, neg.toCanonical());
}

test "field element: multiplication and negation" {
    const a = FieldElement.fromU32(12345);
    const b = FieldElement.fromU32(6789);
    const c = a.mul(b);
    const expected = @as(u32, @intCast((@as(u64, 12345) * 6789) % KOALABEAR_PRIME));
    try std.testing.expectEqual(expected, c.toCanonical());

    const neg_a = a.neg();
    try std.testing.expect(a.add(neg_a).isZero());
}

test "field element: square matches multiplication" {
    const a = FieldElement.fromU32(42);
    try std.testing.expect(a.square().eql(a.mul(a)));
}

test "field element: serialization round trip" {
    const allocator = std.testing.allocator;

    const original = FieldElement.fromU32(0x12345678);
    const bytes = original.toBytes();
    const restored = FieldElement.fromBytes(bytes);
    try std.testing.expect(original.eql(restored));

    const array = [_]FieldElement{
        FieldElement.fromU32(1),
        FieldElement.fromU32(2),
        FieldElement.fromU32(3),
        FieldElement.fromU32(4),
    };

    const serialized = try FieldElement.arrayToBytes(allocator, &array);
    defer allocator.free(serialized);

    const deserialized = try FieldElement.arrayFromBytes(allocator, serialized);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(array.len, deserialized.len);
    for (array, deserialized) |expected, actual| {
        try std.testing.expect(expected.eql(actual));
    }
}
