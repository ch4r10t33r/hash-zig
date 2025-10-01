const std = @import("std");

// MontgomeryField31 is a generic implementation of a field with modulus with at most 31 bits.
pub fn MontgomeryField31(comptime modulus: u32) type {
    const mont_r: u64 = 1 << 32;
    const r_square_mod_modulus: u64 = @intCast((@as(u128, mont_r) * @as(u128, mont_r)) % modulus);

    // modulus_prime = -modulus^-1 mod mont_r
    const modulus_prime = mont_r - euclideanAlgorithm(modulus, mont_r) % mont_r;
    std.debug.assert(modulus * modulus_prime % mont_r == mont_r - 1);

    return struct {
        pub const FieldElem = u32;
        pub const MontFieldElem = struct {
            value: u32,
        };

        pub fn toMontgomery(out: *MontFieldElem, value: FieldElem) void {
            out.* = .{ .value = montReduce(@as(u64, value) * r_square_mod_modulus) };
        }

        pub fn square(out1: *MontFieldElem, value: MontFieldElem) void {
            mul(out1, value, value);
        }

        pub fn mul(out1: *MontFieldElem, value: MontFieldElem, arg2: MontFieldElem) void {
            out1.* = .{ .value = montReduce(@as(u64, value.value) * @as(u64, arg2.value)) };
        }

        pub fn add(out1: *MontFieldElem, value: MontFieldElem, arg2: MontFieldElem) void {
            var tmp = value.value + arg2.value;
            if (tmp > modulus) {
                tmp -= modulus;
            }
            out1.* = .{ .value = tmp };
        }

        pub fn toNormal(self: MontFieldElem) FieldElem {
            return montReduce(@as(u64, self.value));
        }

        fn montReduce(mont_value: u64) FieldElem {
            const tmp = mont_value + (((mont_value & 0xFFFFFFFF) * modulus_prime) & 0xFFFFFFFF) * modulus;
            std.debug.assert(tmp % mont_r == 0);
            const t = tmp >> 32;
            if (t >= modulus) {
                return @intCast(t - modulus);
            }
            return @intCast(t);
        }
    };
}

fn euclideanAlgorithm(a: u64, b: u64) u64 {
    var t_coef: i64 = 0;
    var new_t: i64 = 1;
    var r_val: i64 = @intCast(b);
    var new_r: i64 = @intCast(a);

    while (new_r != 0) {
        const quotient = r_val / new_r;

        const temp_t = t_coef;
        t_coef = new_t;
        new_t = temp_t - quotient * new_t;

        const temp_r = r_val;
        r_val = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (r_val != 1) {
        @compileError("modular inverse does not exist");
    }

    if (t_coef < 0) {
        t_coef += @intCast(b);
    }
    return @intCast(t_coef);
}
