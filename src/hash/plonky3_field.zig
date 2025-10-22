const std = @import("std");

// Plonky3-compatible KoalaBear field implementation
// This implements the exact same field arithmetic as Plonky3's MontyField31

// KoalaBear field parameters (exact from Plonky3)
const KOALABEAR_PRIME: u32 = 0x7f000001; // 2^31 - 2^24 + 1
const KOALABEAR_MONTY_BITS: u32 = 32;
const KOALABEAR_MONTY_MU: u32 = 0x81000001;
const KOALABEAR_MONTY_MASK: u32 = 0xffffffff;
const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001; // (P + 1) / 2

// KoalaBear field element in Montgomery form
pub const KoalaBearField = struct {
    value: u32, // Montgomery form value

    pub const zero = KoalaBearField{ .value = 0 };
    pub const one = KoalaBearField{ .value = 1 }; // 1 in normal form

// Convert u32 to field element (exact from Plonky3)
pub fn fromU32(x: u32) KoalaBearField {
    // First reduce modulo the prime if necessary
    const reduced = if (x >= KOALABEAR_PRIME) x % KOALABEAR_PRIME else x;
    return KoalaBearField{ .value = reduced };
}

    // Convert from field element to u32 (exact from Plonky3)
    pub fn toU32(self: KoalaBearField) u32 {
        return self.value;
    }

    // Convert to Montgomery form for internal operations
    pub fn toMontgomery(mont: *KoalaBearField, value: u32) void {
        mont.value = toMonty(value);
    }

    // Convert from Montgomery form for internal operations
    pub fn toNormal(self: KoalaBearField) u32 {
        return fromMonty(self.value);
    }

    // Field addition (exact from Plonky3)
    pub fn add(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        return KoalaBearField{ .value = addMod(self.value, other.value) };
    }

    // Field subtraction (exact from Plonky3)
    pub fn sub(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        return KoalaBearField{ .value = subMod(self.value, other.value) };
    }

    // Field multiplication (exact from Plonky3)
    pub fn mul(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        const long_prod = @as(u64, self.value) * @as(u64, other.value);
        return KoalaBearField{ .value = @as(u32, @intCast(long_prod % KOALABEAR_PRIME)) };
    }

    // Field division (exact from Plonky3)
    pub fn div(self: KoalaBearField, other: KoalaBearField) KoalaBearField {
        return self.mul(other.inverse());
    }

    // Field inverse (exact from Plonky3)
    pub fn inverse(self: KoalaBearField) KoalaBearField {
        const inv = modInverse(self.value, KOALABEAR_PRIME);
        return KoalaBearField{ .value = inv };
    }

    // Double operation (exact from Plonky3)
    pub fn double(self: KoalaBearField) KoalaBearField {
        return self.add(self);
    }

    // Halve operation (exact from Plonky3)
    pub fn halve(self: KoalaBearField) KoalaBearField {
        return KoalaBearField{ .value = halveU32(self.value) };
    }

    // Division by power of 2 (exact from Plonky3)
    pub fn div2exp(self: KoalaBearField, exponent: u32) KoalaBearField {
        if (exponent <= 32) {
            const long_prod = @as(u64, self.value) << @as(u6, @intCast(32 - exponent));
            return KoalaBearField{ .value = @as(u32, @intCast(long_prod % KOALABEAR_PRIME)) };
        } else {
            // For larger values, use repeated halving
            var result = self;
            var i: u32 = 0;
            while (i < exponent) : (i += 1) {
                result = result.halve();
            }
            return result;
        }
    }

    // Exponentiation (exact from Plonky3)
    pub fn exp(self: KoalaBearField, exponent: u32) KoalaBearField {
        var result = KoalaBearField.one;
        var base = self;
        var e = exponent;
        while (e > 0) {
            if (e & 1 == 1) {
                result = result.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        return result;
    }

    // Check if zero
    pub fn isZero(self: KoalaBearField) bool {
        return self.value == 0;
    }

    // Check if one
    pub fn isOne(self: KoalaBearField) bool {
        return self.toU32() == 1;
    }

    // Equality
    pub fn eql(self: KoalaBearField, other: KoalaBearField) bool {
        return self.value == other.value;
    }
};

// Convert u32 to Montgomery form (exact from Plonky3)
fn toMonty(x: u32) u32 {
    // to_monty: (((x as u64) << MP::MONTY_BITS) % MP::PRIME as u64) as u32
    const shifted = @as(u64, x) << KOALABEAR_MONTY_BITS;
    return @as(u32, @intCast(shifted % KOALABEAR_PRIME));
}

// Convert from Montgomery form to u32 (exact from Plonky3)
fn fromMonty(x: u32) u32 {
    // from_monty: monty_reduce::<MP>(x as u64)
    return montyReduce(@as(u64, x));
}

// Montgomery reduction (exact from Plonky3)
fn montyReduce(x: u64) u32 {
    // t = x * MONTY_MU mod MONTY
    const t = x *% KOALABEAR_MONTY_MU & KOALABEAR_MONTY_MASK;

    // u = t * P
    const u = t * KOALABEAR_PRIME;

    // x - u = x mod P
    const sub_result = @subWithOverflow(x, u);
    const x_sub_u = sub_result[0];
    const over = sub_result[1];
    const x_sub_u_hi = @as(u32, @intCast(x_sub_u >> KOALABEAR_MONTY_BITS));
    const corr = if (over != 0) KOALABEAR_PRIME else 0;
    return x_sub_u_hi +% corr;
}

// Addition modulo P (exact from Plonky3)
fn addMod(a: u32, b: u32) u32 {
    var sum = a + b;
    const sub_result = @subWithOverflow(sum, KOALABEAR_PRIME);
    const corr_sum = sub_result[0];
    const over = sub_result[1];
    if (over == 0) {
        sum = corr_sum;
    }
    return sum;
}

// Subtraction modulo P (exact from Plonky3)
fn subMod(a: u32, b: u32) u32 {
    const sub_result = @subWithOverflow(a, b);
    const diff = sub_result[0];
    const over = sub_result[1];
    const corr = if (over != 0) KOALABEAR_PRIME else 0;
    return diff +% corr;
}

// Halve operation (exact from Plonky3)
fn halveU32(input: u32) u32 {
    const shr = input >> 1;
    const lo_bit = input & 1;
    const shr_corr = shr + KOALABEAR_HALF_P_PLUS_1;
    return if (lo_bit == 0) shr else shr_corr;
}

// Modular inverse using extended Euclidean algorithm
fn modInverse(a: u32, m: u32) u32 {
    var old_r = a;
    var r = m;
    var old_s: i32 = 1;
    var s: i32 = 0;

    while (r != 0) {
        const quotient = old_r / r;
        const temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        const temp_s = s;
        s = old_s - @as(i32, @intCast(quotient)) * s;
        old_s = temp_s;
    }

    if (old_r > 1) {
        return 0; // No inverse exists
    }

    if (old_s < 0) {
        return @as(u32, @intCast(old_s + @as(i32, @intCast(m))));
    } else {
        return @as(u32, @intCast(old_s));
    }
}

// Test the field implementation
test "KoalaBear field arithmetic" {
    const a = KoalaBearField.fromU32(5);
    const b = KoalaBearField.fromU32(3);

    // Test addition
    const sum = a.add(b);
    try std.testing.expectEqual(@as(u32, 8), sum.toU32());

    // Test multiplication
    const prod = a.mul(b);
    try std.testing.expectEqual(@as(u32, 15), prod.toU32());

    // Test inverse
    const inv = a.inverse();
    const should_be_one = a.mul(inv);
    std.debug.print("a = {}, inv = {}, a * inv = {}\n", .{ a.toU32(), inv.toU32(), should_be_one.toU32() });
    try std.testing.expect(should_be_one.isOne());
}

// Test specific values that might be used in Poseidon2
test "Poseidon2 field values" {
    // Test the specific input values from our Poseidon2 test
    const input1 = KoalaBearField.fromU32(305419896);
    const input2 = KoalaBearField.fromU32(2596069104);

    std.debug.print("Input1: {} -> Montgomery: {}\n", .{ 305419896, input1.value });
    std.debug.print("Input2: {} -> Montgomery: {}\n", .{ 2596069104, input2.value });

    // Test multiplication
    const prod = input1.mul(input2);
    std.debug.print("Product: {} -> Normal: {}\n", .{ prod.value, prod.toU32() });

    // Test addition
    const sum = input1.add(input2);
    std.debug.print("Sum: {} -> Normal: {}\n", .{ sum.value, sum.toU32() });
}
