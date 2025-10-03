//! Generic Poseidon2 implementation
//! This provides a generic constructor for creating Poseidon2 instances with different parameters

const std = @import("std");

/// Generic Poseidon2 constructor function
/// Takes field type, width, internal_rounds, external_rounds, sbox_degree, diagonal, external_rcs, and internal_rcs
pub fn Poseidon2(
    comptime Field: type,
    comptime width: comptime_int,
    comptime internal_rounds: comptime_int,
    comptime external_rounds: comptime_int,
    comptime sbox_degree: comptime_int,
    comptime diagonal: [width]Field.FieldElem,
    comptime external_rcs: [external_rounds][width]Field.FieldElem,
    comptime internal_rcs: [internal_rounds]Field.FieldElem,
) type {
    return struct {
        const Self = @This();

        pub const field = Field;
        pub const WIDTH = width;
        pub const INTERNAL_ROUNDS = internal_rounds;
        pub const EXTERNAL_ROUNDS = external_rounds;
        pub const SBOX_DEGREE = sbox_degree;

        // State type
        pub const State = [width]Field.MontFieldElem;

        /// Permutation function implementation
        pub fn permutation(state: *[width]Field.MontFieldElem) void {
            // Apply external rounds
            for (0..external_rounds) |round| {
                // Add round constants
                for (0..width) |i| {
                    var rc_mont: Field.MontFieldElem = undefined;
                    Field.toMontgomery(&rc_mont, external_rcs[round][i]);
                    Field.add(&state[i], state[i], rc_mont);
                }

                // Apply S-box (exponentiation by repeated squaring)
                for (0..width) |i| {
                    var result: Field.MontFieldElem = undefined;
                    Field.toMontgomery(&result, 1); // Start with 1
                    var base = state[i];
                    var exp: u32 = @intCast(sbox_degree);

                    while (exp > 0) {
                        if (exp & 1 == 1) {
                            Field.mul(&result, result, base);
                        }
                        Field.square(&base, base);
                        exp >>= 1;
                    }
                    state[i] = result;
                }

                // Apply MDS matrix (simplified - in practice this would be a proper MDS matrix)
                var new_state: State = undefined;
                for (0..width) |i| {
                    var sum: Field.MontFieldElem = undefined;
                    Field.toMontgomery(&sum, 0); // Initialize to zero
                    for (0..width) |j| {
                        var diag_mont: Field.MontFieldElem = undefined;
                        Field.toMontgomery(&diag_mont, diagonal[j]);
                        var tmp: Field.MontFieldElem = undefined;
                        Field.mul(&tmp, state[j], diag_mont);
                        Field.add(&sum, sum, tmp);
                    }
                    new_state[i] = sum;
                }
                state.* = new_state;
            }

            // Apply internal rounds
            for (0..internal_rounds) |round| {
                // Add round constants (same constant applied to all elements)
                var rc_mont: Field.MontFieldElem = undefined;
                Field.toMontgomery(&rc_mont, internal_rcs[round]);
                for (0..width) |i| {
                    Field.add(&state[i], state[i], rc_mont);
                }

                // Apply S-box (exponentiation by repeated squaring)
                for (0..width) |i| {
                    var result: Field.MontFieldElem = undefined;
                    Field.toMontgomery(&result, 1); // Start with 1
                    var base = state[i];
                    var exp: u32 = @intCast(sbox_degree);

                    while (exp > 0) {
                        if (exp & 1 == 1) {
                            Field.mul(&result, result, base);
                        }
                        Field.square(&base, base);
                        exp >>= 1;
                    }
                    state[i] = result;
                }

                // Apply MDS matrix
                var new_state: State = undefined;
                for (0..width) |i| {
                    var sum: Field.MontFieldElem = undefined;
                    Field.toMontgomery(&sum, 0); // Initialize to zero
                    for (0..width) |j| {
                        var diag_mont: Field.MontFieldElem = undefined;
                        Field.toMontgomery(&diag_mont, diagonal[j]);
                        var tmp: Field.MontFieldElem = undefined;
                        Field.mul(&tmp, state[j], diag_mont);
                        Field.add(&sum, sum, tmp);
                    }
                    new_state[i] = sum;
                }
                state.* = new_state;
            }
        }
    };
}
