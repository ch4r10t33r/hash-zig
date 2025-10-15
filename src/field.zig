//! KoalaBear finite field implementation
//! Prime: p = 2^31 - 2^24 + 1 = 2,130,706,433
//!
//! This field is used in the Poseidon2 hash function and throughout
//! the hash-based signature scheme for field-native operations.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// KoalaBear prime field
/// p = 2^31 - 2^24 + 1 = 2,130,706,433
pub const KOALABEAR_PRIME: u64 = (1 << 31) - (1 << 24) + 1;

/// Tweak separators for domain separation in Poseidon hashing
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x00;
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x01;

pub const KoalaBearField = struct {
    value: u32,

    pub const PRIME: u64 = KOALABEAR_PRIME;
    pub const ZERO = KoalaBearField{ .value = 0 };
    pub const ONE = KoalaBearField{ .value = 1 };

    /// Create the zero element
    pub fn zero() KoalaBearField {
        return ZERO;
    }

    /// Create the one element (multiplicative identity)
    pub fn one() KoalaBearField {
        return ONE;
    }

    /// Create field element from u32 (with modular reduction)
    pub fn fromU32(val: u32) KoalaBearField {
        return .{ .value = @intCast(val % @as(u32, @intCast(PRIME))) };
    }

    /// Create field element from u64 (with modular reduction)
    pub fn fromU64(val: u64) KoalaBearField {
        return .{ .value = @intCast(val % PRIME) };
    }

    /// Convert to u32
    pub fn toU32(self: KoalaBearField) u32 {
        return self.value;
    }

    /// Convert to u64
    pub fn toU64(self: KoalaBearField) u64 {
        return @as(u64, self.value);
    }

    /// Addition in the field
    pub fn add(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        const sum = @as(u64, self.value) + @as(u64, other.value);
        return fromU64(sum);
    }

    /// Subtraction in the field
    pub fn sub(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        if (self.value >= other.value) {
            return .{ .value = self.value - other.value };
        } else {
            const prime_u32 = @as(u32, @intCast(PRIME));
            return .{ .value = prime_u32 - (other.value - self.value) };
        }
    }

    /// Multiplication in the field
    pub fn mul(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        const product = @as(u64, self.value) * @as(u64, other.value);
        return fromU64(product);
    }

    /// Negation in the field
    pub fn neg(self: KoalaBearField) KoalaBearField {
        if (self.value == 0) return zero();
        return .{ .value = @as(u32, @intCast(PRIME)) - self.value };
    }

    /// Square in the field
    pub fn square(self: KoalaBearField) KoalaBearField {
        return self.mul(self);
    }

    /// Equality check
    pub fn eql(self: KoalaBearField, other: KoalaBearField) bool {
        return self.value == other.value;
    }

    /// Check if zero
    pub fn isZero(self: KoalaBearField) bool {
        return self.value == 0;
    }

    /// Check if one
    pub fn isOne(self: KoalaBearField) bool {
        return self.value == 1;
    }

    /// Serialize to bytes (little-endian u32)
    pub fn toBytes(self: KoalaBearField) [4]u8 {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, self.value, .little);
        return bytes;
    }

    /// Deserialize from bytes (little-endian u32)
    pub fn fromBytes(bytes: [4]u8) KoalaBearField {
        const val = std.mem.readInt(u32, &bytes, .little);
        return fromU32(val);
    }

    /// Deserialize from byte slice (little-endian u32)
    pub fn fromBytesSlice(bytes: []const u8) !KoalaBearField {
        if (bytes.len < 4) return error.InsufficientBytes;
        var arr: [4]u8 = undefined;
        @memcpy(&arr, bytes[0..4]);
        return fromBytes(arr);
    }

    /// Serialize array of field elements to bytes
    pub fn arrayToBytes(allocator: Allocator, elements: []const KoalaBearField) ![]u8 {
        const result = try allocator.alloc(u8, elements.len * 4);
        for (elements, 0..) |elem, i| {
            const bytes = elem.toBytes();
            @memcpy(result[i * 4 ..][0..4], &bytes);
        }
        return result;
    }

    /// Deserialize array of field elements from bytes
    pub fn arrayFromBytes(allocator: Allocator, bytes: []const u8) ![]KoalaBearField {
        if (bytes.len % 4 != 0) return error.InvalidByteLength;
        const num_elements = bytes.len / 4;

        const result = try allocator.alloc(KoalaBearField, num_elements);
        for (0..num_elements) |i| {
            var chunk: [4]u8 = undefined;
            @memcpy(&chunk, bytes[i * 4 ..][0..4]);
            result[i] = fromBytes(chunk);
        }
        return result;
    }
};

/// Type alias for convenience
pub const FieldElement = KoalaBearField;

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
    try std.testing.expectEqual(@as(u32, 0), zero.value);
    try std.testing.expectEqual(@as(u32, 1), one.value);
}

test "field element: from/to conversions" {
    const val_u32: u32 = 12345;
    const val_u64: u64 = 98765432;

    const fe1 = FieldElement.fromU32(val_u32);
    const fe2 = FieldElement.fromU64(val_u64);

    try std.testing.expectEqual(val_u32, fe1.toU32());
    try std.testing.expectEqual(@as(u32, @intCast(val_u64 % KOALABEAR_PRIME)), fe2.toU32());
}

test "field element: modular reduction" {
    // Value larger than prime should be reduced
    const large_val = KOALABEAR_PRIME + 42;
    const fe = FieldElement.fromU64(large_val);

    try std.testing.expectEqual(@as(u32, 42), fe.value);

    // Value equal to prime should become 0
    const fe_prime = FieldElement.fromU64(KOALABEAR_PRIME);
    try std.testing.expect(fe_prime.isZero());
}

test "field element: addition" {
    const a = FieldElement.fromU32(100);
    const b = FieldElement.fromU32(200);
    const c = a.add(b);

    try std.testing.expectEqual(@as(u32, 300), c.value);

    // Test wraparound
    const max_val = @as(u32, @intCast(KOALABEAR_PRIME)) - 1;
    const fe_max = FieldElement.fromU32(max_val);
    const fe_two = FieldElement.fromU32(2);
    const wrapped = fe_max.add(fe_two);

    try std.testing.expectEqual(@as(u32, 1), wrapped.value);
}

test "field element: subtraction" {
    const a = FieldElement.fromU32(200);
    const b = FieldElement.fromU32(100);
    const c = a.sub(b);

    try std.testing.expectEqual(@as(u32, 100), c.value);

    // Test wraparound (negative result)
    const d = b.sub(a); // 100 - 200 = -100 mod p
    const expected = @as(u32, @intCast(KOALABEAR_PRIME)) - 100;
    try std.testing.expectEqual(expected, d.value);
}

test "field element: multiplication" {
    const a = FieldElement.fromU32(123);
    const b = FieldElement.fromU32(456);
    const c = a.mul(b);

    const expected = @as(u32, @intCast((123 * 456) % KOALABEAR_PRIME));
    try std.testing.expectEqual(expected, c.value);

    // Test with large values
    const large1 = FieldElement.fromU32(1000000);
    const large2 = FieldElement.fromU32(2000000);
    const product = large1.mul(large2);

    const expected_large = @as(u32, @intCast((1000000 * 2000000) % KOALABEAR_PRIME));
    try std.testing.expectEqual(expected_large, product.value);
}

test "field element: negation" {
    const a = FieldElement.fromU32(42);
    const neg_a = a.neg();

    const sum = a.add(neg_a);
    try std.testing.expect(sum.isZero());

    // Negation of zero is zero
    const zero = FieldElement.zero();
    const neg_zero = zero.neg();
    try std.testing.expect(neg_zero.isZero());
}

test "field element: square" {
    const a = FieldElement.fromU32(123);
    const a_squared = a.square();
    const a_mul_a = a.mul(a);

    try std.testing.expect(a_squared.eql(a_mul_a));
}

test "field element: equality" {
    const a = FieldElement.fromU32(42);
    const b = FieldElement.fromU32(42);
    const c = FieldElement.fromU32(43);

    try std.testing.expect(a.eql(b));
    try std.testing.expect(!a.eql(c));
}

test "field element: byte serialization" {
    const original = FieldElement.fromU32(0x12345678);
    const bytes = original.toBytes();

    // Little-endian: 78 56 34 12
    try std.testing.expectEqual(@as(u8, 0x78), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x56), bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x34), bytes[2]);
    try std.testing.expectEqual(@as(u8, 0x12), bytes[3]);

    const deserialized = FieldElement.fromBytes(bytes);
    try std.testing.expect(original.eql(deserialized));

    // Test slice deserialization
    const from_slice = try FieldElement.fromBytesSlice(&bytes);
    try std.testing.expect(original.eql(from_slice));
}

test "field element: array serialization" {
    const allocator = std.testing.allocator;

    // Create array of field elements
    var elements = [_]FieldElement{
        FieldElement.fromU32(1),
        FieldElement.fromU32(2),
        FieldElement.fromU32(3),
        FieldElement.fromU32(4),
        FieldElement.fromU32(5),
    };

    // Serialize to bytes
    const bytes = try FieldElement.arrayToBytes(allocator, &elements);
    defer allocator.free(bytes);

    try std.testing.expectEqual(@as(usize, 20), bytes.len); // 5 elements × 4 bytes

    // Deserialize back
    const deserialized = try FieldElement.arrayFromBytes(allocator, bytes);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(@as(usize, 5), deserialized.len);
    for (elements, deserialized) |orig, deser| {
        try std.testing.expect(orig.eql(deser));
    }
}

test "field element: arithmetic properties" {
    // Additive identity: a + 0 = a
    const a = FieldElement.fromU32(42);
    const zero = FieldElement.zero();
    try std.testing.expect(a.add(zero).eql(a));

    // Multiplicative identity: a * 1 = a
    const one = FieldElement.one();
    try std.testing.expect(a.mul(one).eql(a));

    // Additive inverse: a + (-a) = 0
    const neg_a = a.neg();
    try std.testing.expect(a.add(neg_a).eql(zero));

    // Commutativity: a + b = b + a
    const b = FieldElement.fromU32(123);
    try std.testing.expect(a.add(b).eql(b.add(a)));

    // Commutativity: a * b = b * a
    try std.testing.expect(a.mul(b).eql(b.mul(a)));

    // Associativity: (a + b) + c = a + (b + c)
    const c = FieldElement.fromU32(456);
    const left = a.add(b).add(c);
    const right = a.add(b.add(c));
    try std.testing.expect(left.eql(right));

    // Associativity: (a * b) * c = a * (b * c)
    const left_mul = a.mul(b).mul(c);
    const right_mul = a.mul(b.mul(c));
    try std.testing.expect(left_mul.eql(right_mul));

    // Distributivity: a * (b + c) = a * b + a * c
    const left_dist = a.mul(b.add(c));
    const right_dist = a.mul(b).add(a.mul(c));
    try std.testing.expect(left_dist.eql(right_dist));
}

test "field element: boundary values" {
    // Test with values near the prime
    const prime_minus_1 = FieldElement.fromU64(KOALABEAR_PRIME - 1);
    const prime_minus_2 = FieldElement.fromU64(KOALABEAR_PRIME - 2);

    // (p-1) + 1 should equal 0
    const one = FieldElement.one();
    try std.testing.expect(prime_minus_1.add(one).isZero());

    // (p-1) + 2 should equal 1
    const two = FieldElement.fromU32(2);
    try std.testing.expect(prime_minus_1.add(two).eql(one));

    // (p-2) + 2 should equal 0
    try std.testing.expect(prime_minus_2.add(two).isZero());
}

test "field element: zero multiplication" {
    const zero = FieldElement.zero();
    const a = FieldElement.fromU32(42);

    // 0 * a = 0
    try std.testing.expect(zero.mul(a).isZero());
    try std.testing.expect(a.mul(zero).isZero());

    // 0 * 0 = 0
    try std.testing.expect(zero.mul(zero).isZero());
}

test "field element: invalid byte slice" {
    const short_bytes = [_]u8{ 0x01, 0x02 }; // Only 2 bytes
    const result = FieldElement.fromBytesSlice(&short_bytes);
    try std.testing.expectError(error.InsufficientBytes, result);
}

test "field element: array from invalid bytes" {
    const allocator = std.testing.allocator;

    const odd_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 }; // 5 bytes (not divisible by 4)
    const result = FieldElement.arrayFromBytes(allocator, &odd_bytes);
    try std.testing.expectError(error.InvalidByteLength, result);
}

test "field element: round-trip serialization" {
    const allocator = std.testing.allocator;

    // Test multiple values
    const test_values = [_]u32{ 0, 1, 42, 255, 256, 65535, 1000000, @as(u32, @intCast(KOALABEAR_PRIME)) - 1 };

    for (test_values) |val| {
        const original = FieldElement.fromU32(val);
        const bytes = original.toBytes();
        const restored = FieldElement.fromBytes(bytes);

        try std.testing.expect(original.eql(restored));
    }

    // Test array round-trip
    var elements: [7]FieldElement = undefined;
    for (0..7) |i| {
        elements[i] = FieldElement.fromU32(@intCast(i * 1000));
    }

    const bytes = try FieldElement.arrayToBytes(allocator, &elements);
    defer allocator.free(bytes);

    const restored = try FieldElement.arrayFromBytes(allocator, bytes);
    defer allocator.free(restored);

    for (elements, restored) |orig, rest| {
        try std.testing.expect(orig.eql(rest));
    }
}

test "field element: prime modulus" {
    // Verify the prime value is correct
    try std.testing.expectEqual(@as(u64, 2130706433), KOALABEAR_PRIME);
    try std.testing.expectEqual(@as(u64, (1 << 31) - (1 << 24) + 1), KOALABEAR_PRIME);

    // Verify it fits in u32
    try std.testing.expect(KOALABEAR_PRIME < (1 << 32));

    // Verify reduction works correctly
    const exactly_prime = FieldElement.fromU64(KOALABEAR_PRIME);
    try std.testing.expect(exactly_prime.isZero());

    const twice_prime = FieldElement.fromU64(KOALABEAR_PRIME * 2);
    try std.testing.expect(twice_prime.isZero());
}
