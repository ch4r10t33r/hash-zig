//! Field element operations for Poseidon2 over BN254 scalar field

const std = @import("std");

pub const FieldElement = struct {
    value: u256,

    /// BN254 scalar field modulus
    pub const modulus: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    pub fn init(val: u256) FieldElement {
        return .{ .value = @mod(val, modulus) };
    }

    pub fn add(self: FieldElement, other: FieldElement) FieldElement {
        return init(@mod(self.value + other.value, modulus));
    }

    pub fn mul(self: FieldElement, other: FieldElement) FieldElement {
        return init(@mod(self.value *% other.value, modulus));
    }

    pub fn pow(self: FieldElement, exp: u64) FieldElement {
        var result = init(1);
        var base = self;
        var e = exp;

        while (e > 0) {
            if (e & 1 == 1) {
                result = result.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }

        return result;
    }

    pub fn toBytes(self: FieldElement, out: []u8) void {
        var val = self.value;
        for (0..out.len) |i| {
            out[i] = @truncate(val);
            val >>= 8;
        }
    }

    pub fn fromBytes(bytes: []const u8) FieldElement {
        var val: u256 = 0;
        for (bytes, 0..) |byte, i| {
            val |= @as(u256, byte) << @intCast(i * 8);
        }
        return init(val);
    }
};

test "field element operations" {
    const a = FieldElement.init(100);
    const b = FieldElement.init(200);

    const sum = a.add(b);
    const product = a.mul(b);

    try std.testing.expect(sum.value == 300);
    try std.testing.expect(product.value == 20000);
}
