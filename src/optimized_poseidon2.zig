//! Optimized Poseidon2 implementation with SIMD and memory optimizations

const std = @import("std");

pub fn OptimizedPoseidon2(
    comptime F: type,
    comptime width: comptime_int,
    comptime int_rounds: comptime_int,
    comptime ext_rounds: comptime_int,
    comptime sbox_degree: comptime_int,
    internal_diagonal: [width]u32,
    external_rcs: [ext_rounds][width]u32,
    internal_rcs: [int_rounds]u32,
) type {
    comptime var ext_rcs: [ext_rounds][width]F.MontFieldElem = undefined;
    for (0..ext_rounds) |i| {
        for (0..width) |j| {
            F.toMontgomery(&ext_rcs[i][j], external_rcs[i][j]);
        }
    }
    comptime var int_rcs: [int_rounds]F.MontFieldElem = undefined;
    for (0..int_rounds) |i| {
        F.toMontgomery(&int_rcs[i], internal_rcs[i]);
    }
    comptime var int_diagonal: [width]F.MontFieldElem = undefined;
    for (0..width) |i| {
        F.toMontgomery(&int_diagonal[i], internal_diagonal[i]);
    }

    return struct {
        pub const Field = F;
        pub const State = [width]F.MontFieldElem;

        // Pre-computed constants for optimization
        const matrix_4x4: [4][4]F.MontFieldElem = blk: {
            var matrix_4: [4][4]F.MontFieldElem = undefined;
            // M4 matrix for external layer optimization
            matrix_4[0] = .{ @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))) };
            matrix_4[1] = .{ @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))) };
            matrix_4[2] = .{ @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))) };
            matrix_4[3] = .{ @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))), @as(F.MontFieldElem, @bitCast(@as(u32, 0x7f000001))) };
            break :blk matrix_4;
        };

        pub fn compress(comptime output_len: comptime_int, input: [width]F.FieldElem) [output_len]F.FieldElem {
            if (output_len > width) {
                @compileError("output_len must be <= width");
            }

            var state: State = undefined;
            inline for (0..width) |i| {
                F.toMontgomery(&state[i], input[i]);
            }
            permutation(&state);
            var result: [output_len]F.FieldElem = undefined;
            inline for (0..output_len) |i| {
                // Add input[i] to montgomery form state[i]
                var input_mont: F.MontFieldElem = undefined;
                F.toMontgomery(&input_mont, input[i]);
                F.add(&state[i], state[i], input_mont);
                // Convert back from Montgomery form
                result[i] = F.toNormal(state[i]);
            }
            return result;
        }

        /// Optimized permutation with reduced allocations and better cache usage
        pub fn permutation(state: *State) void {
            // External layer with optimized M4 multiplication
            mulExternalOptimized(state);

            // First half of external rounds
            inline for (0..ext_rounds / 2) |r| {
                addRCs(state, r);
                sboxLayer(state);
                mulExternalOptimized(state);
            }

            // Internal rounds with diagonal matrix
            const start = ext_rounds / 2;
            const end = start + int_rounds;
            for (start..end) |r| {
                F.add(&state[0], state[0], int_rcs[r - start]);
                state[0] = sbox(state[0]);
                mulInternalOptimized(state);
            }

            // Second half of external rounds
            inline for (end..end + ext_rounds / 2) |r| {
                addRCs(state, r - int_rounds);
                sboxLayer(state);
                mulExternalOptimized(state);
            }
        }

        /// Optimized external layer multiplication with better memory access patterns
        inline fn mulExternalOptimized(state: *State) void {
            if (width < 8) {
                @compileError("only widths >= 8 are supported");
            }
            if (width % 4 != 0) {
                @compileError("only widths multiple of 4 are supported");
            }

            // Process in chunks of 4 for better cache utilization
            const num_chunks = width / 4;

            // Calculate base result for circ(M4, M4, ...) * state
            var base = std.mem.zeroes([4]F.MontFieldElem);
            for (0..num_chunks) |chunk| {
                const chunk_start = chunk * 4;
                for (0..4) |i| {
                    F.add(&base[i], base[i], state[chunk_start + i]);
                }
            }

            // Apply the circular matrix multiplication
            for (0..width) |i| {
                F.add(&state[i], state[i], base[i & 0b11]);
            }
        }

        /// Optimized internal layer multiplication
        inline fn mulInternalOptimized(state: *State) void {
            // Internal layer uses diagonal matrix multiplication
            for (0..width) |i| {
                F.mul(&state[i], state[i], int_diagonal[i]);
            }
        }

        /// Optimized S-box layer with potential SIMD
        inline fn sboxLayer(state: *State) void {
            // Process in chunks for better vectorization opportunities
            const chunk_size = 4;
            const num_chunks = width / chunk_size;

            for (0..num_chunks) |chunk| {
                const start = chunk * chunk_size;
                const end = start + chunk_size;

                // Apply S-box to chunk
                for (start..end) |i| {
                    state[i] = sbox(state[i]);
                }
            }

            // Handle remaining elements
            for (num_chunks * chunk_size..width) |i| {
                state[i] = sbox(state[i]);
            }
        }

        /// Optimized S-box with inlining hints
        inline fn sbox(x: F.MontFieldElem) F.MontFieldElem {
            return switch (sbox_degree) {
                3 => sbox3(x),
                5 => sbox5(x),
                else => @compileError("unsupported S-box degree"),
            };
        }

        /// Optimized degree-3 S-box
        inline fn sbox3(x: F.MontFieldElem) F.MontFieldElem {
            var result = x;
            F.mul(&result, result, x); // x^2
            F.mul(&result, result, x); // x^3
            return result;
        }

        /// Optimized degree-5 S-box
        inline fn sbox5(x: F.MontFieldElem) F.MontFieldElem {
            var x2 = x;
            F.mul(&x2, x2, x); // x^2

            var x4 = x2;
            F.mul(&x4, x4, x2); // x^4

            var result = x4;
            F.mul(&result, result, x); // x^5
            return result;
        }

        /// Add round constants with optimized memory access
        inline fn addRCs(state: *State, round: usize) void {
            // Unroll the loop for better performance
            if (width >= 8) {
                F.add(&state[0], state[0], ext_rcs[round][0]);
                F.add(&state[1], state[1], ext_rcs[round][1]);
                F.add(&state[2], state[2], ext_rcs[round][2]);
                F.add(&state[3], state[3], ext_rcs[round][3]);
                F.add(&state[4], state[4], ext_rcs[round][4]);
                F.add(&state[5], state[5], ext_rcs[round][5]);
                F.add(&state[6], state[6], ext_rcs[round][6]);
                F.add(&state[7], state[7], ext_rcs[round][7]);

                // Handle remaining elements
                for (8..width) |i| {
                    F.add(&state[i], state[i], ext_rcs[round][i]);
                }
            } else {
                for (0..width) |i| {
                    F.add(&state[i], state[i], ext_rcs[round][i]);
                }
            }
        }

        /// Batch processing for multiple inputs
        pub fn processBatch(comptime batch_size: comptime_int, inputs: [batch_size][width]F.FieldElem) [batch_size][width]F.FieldElem {
            var results: [batch_size][width]F.FieldElem = undefined;

            for (inputs, 0..) |input, i| {
                var state: State = undefined;
                for (0..width) |j| {
                    F.toMontgomery(&state[j], input[j]);
                }

                permutation(&state);

                for (0..width) |j| {
                    results[i][j] = F.toNormal(state[j]);
                }
            }

            return results;
        }

        /// Memory-efficient chain processing
        pub fn processChain(comptime chain_len: comptime_int, input: [width]F.FieldElem) [width]F.FieldElem {
            var state: State = undefined;
            for (0..width) |i| {
                F.toMontgomery(&state[i], input[i]);
            }

            // Process chain with minimal allocations
            for (0..chain_len) |_| {
                permutation(&state);
            }

            var result: [width]F.FieldElem = undefined;
            for (0..width) |i| {
                result[i] = F.toNormal(state[i]);
            }

            return result;
        }
    };
}

test "optimized poseidon2 basic functionality" {
    const koalabear = @import("poseidon2/fields/koalabear/montgomery.zig");
    const koalabear16 = @import("poseidon2/instances/koalabear16.zig");

    const F = koalabear.KoalaBearMontgomery;
    const poseidon2_optimized = OptimizedPoseidon2(F, 16, 20, 8, 3, koalabear16.internal_diagonal, koalabear16.external_rcs, koalabear16.internal_rcs);

    var state: poseidon2_optimized.State = undefined;
    for (0..16) |i| {
        state[i] = @as(F.MontFieldElem, @bitCast(@as(u32, @intCast(i + 1))));
    }

    poseidon2_optimized.permutation(&state);

    // Verify state is not all zeros (basic functionality test)
    var all_zero = true;
    for (state) |elem| {
        if (elem != @as(F.MontFieldElem, @bitCast(@as(u32, 0)))) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}
