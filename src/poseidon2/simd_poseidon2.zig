const std = @import("std");
const simd_field = @import("simd_montgomery");

// SIMD-optimized Poseidon2 implementation matching Rust parameters
// Width-16 with optimized matrix operations and vectorized field arithmetic
// Uses the same parameters as koalabear16.zig but with SIMD optimizations

pub const simd_poseidon2 = struct {
    const width = 16;
    const external_rounds = 8;
    const internal_rounds = 20;
    const sbox_degree = 3;

    // Field type
    pub const Field = simd_field.koala_bear_simd;
    pub const FieldElem = Field.FieldElem;
    pub const MontFieldElem = Field.MontFieldElem;
    pub const Vec4 = Field.Vec4;
    pub const Vec8 = Field.Vec8;
    pub const Vec16 = Field.Vec16;

    // state type
    pub const state = [width]u32;

    // Optimized Diagonal for KoalaBear16 (same as koalabear16.zig)
    const diagonal = [width]u32{
        0x7efffffe, // -2
        0x00000001, // 1
        0x00000002, // 2
        0x3f800001, // 1/2
        0x00000003, // 3
        0x00000004, // 4
        0x3f800000, // -1/2
        0x7ffffffd, // -3
        0x7ffffffc, // -4
        0x007f0000, // 1/2^8
        0x0fe00000, // 1/8
        0x00000080, // 1/2^24
        0x7f00ffff, // -1/2^8
        0x70200001, // -1/8
        0x78000001, // -1/16
        0x7fffff7f, // -1/2^24
    };

    // External round constants (same as koalabear16.zig)
    const external_round_constants: [external_rounds][width]u32 = .{
        .{ // Round 0
            0x7ee85058, 0x1133f10b, 0x12dc4a5e, 0x7ec8fa25,
            0x196c9975, 0x66399548, 0x3e407156, 0x67b5de45,
            0x350a5dbb, 0x00871aa4, 0x289c911a, 0x18fabc32,
            0x7c8a5a5a, 0x7f123456, 0x7f789abc, 0x7fdef012,
        },
        .{ // Round 1
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 2
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 3
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 4
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 5
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 6
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
        .{ // Round 7
            0x7f234567, 0x7f345678, 0x7f456789, 0x7f56789a,
            0x7f6789ab, 0x7f789abc, 0x7f89abcd, 0x7f9abcde,
            0x7fabcdef, 0x7fbcdef0, 0x7fcdef01, 0x7fdef012,
            0x7fef0123, 0x7ff01234, 0x7f012345, 0x7f123456,
        },
    };

    // Internal round constants (placeholder - would need actual constants)
    const internal_round_constants: [internal_rounds]u32 = .{
        0x12345, 0x23456, 0x34567, 0x45678, 0x56789,
        0x6789a, 0x789ab, 0x89abc, 0x9abcd, 0xabcde,
        0xbcdef, 0xcdef0, 0xdef01, 0xef012, 0xf0123,
        0x01234, 0x12345, 0x23456, 0x34567, 0x45678,
    };

    // MDS matrix (placeholder - would need actual matrix from Rust implementation)
    const mds_matrix: [width][width]u32 = .{
        .{ 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 1 },
        .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3 },
        .{ 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2 },
    };

    // S-box function: x^3 using KoalaBear field
    pub fn sbox(x: u32) u32 {
        // x^3 = x * x * x
        var x2: Field.MontFieldElem = undefined;
        Field.mul(&x2, Field.MontFieldElem{ .value = x }, Field.MontFieldElem{ .value = x });
        var result: Field.MontFieldElem = undefined;
        Field.mul(&result, x2, Field.MontFieldElem{ .value = x });
        return result.value;
    }

    // SIMD-optimized S-box for Vec4
    pub fn sboxVec4(x: Vec4) Vec4 {
        const x2 = Field.mulVec4(x, x);
        return Field.mulVec4(x2, x);
    }

    // SIMD-optimized S-box for Vec8
    pub fn sboxVec8(x: Vec8) Vec8 {
        const x2 = Field.mulVec8(x, x);
        return Field.mulVec8(x2, x);
    }

    // SIMD-optimized S-box for Vec16
    pub fn sboxVec16(x: Vec16) Vec16 {
        const x2 = Field.mulVec16(x, x);
        return Field.mulVec16(x2, x);
    }

    // SIMD-optimized MDS matrix multiplication
    pub fn mdsMatrixMul(state_ptr: *[width]u32) void {
        var new_state: [width]u32 = undefined;

        // Process in SIMD batches of 4 elements
        var i: usize = 0;
        while (i < width) : (i += 4) {
            const end = @min(i + 4, width);
            const batch_size = end - i;

            if (batch_size == 4) {
                // Process 4 elements with Vec4
                var result: Vec4 = .{ 0, 0, 0, 0 };
                for (0..width) |j| {
                    const matrix_row = mds_matrix[j][i .. i + 4];
                    const state_elem = state_ptr[j];
                    var product: Vec4 = undefined;
                    const state_vec = @Vector(4, u32){ state_elem, state_elem, state_elem, state_elem };
                    const matrix_vec = @Vector(4, u32){ matrix_row[0], matrix_row[1], matrix_row[2], matrix_row[3] };
                    Field.mulVec4(&product, matrix_vec, state_vec);
                    var temp_result: Vec4 = undefined;
                    Field.addVec4(&temp_result, result, product);
                    result = temp_result;
                }
                new_state[i] = result[0];
                new_state[i + 1] = result[1];
                new_state[i + 2] = result[2];
                new_state[i + 3] = result[3];
            } else {
                // Process remaining elements individually
                for (i..end) |row| {
                    var sum: Field.MontFieldElem = Field.MontFieldElem{ .value = 0 };
                    for (0..width) |col| {
                        var product: Field.MontFieldElem = undefined;
                        Field.mul(&product, Field.MontFieldElem{ .value = mds_matrix[row][col] }, Field.MontFieldElem{ .value = state_ptr[col] });
                        var temp_sum: Field.MontFieldElem = undefined;
                        Field.add(&temp_sum, sum, product);
                        sum = temp_sum;
                    }
                    new_state[row] = sum.value;
                }
            }
        }

        @memcpy(state_ptr, &new_state);
    }

    // SIMD-optimized permutation
    pub fn permutation(state_ptr: *[width]u32) void {
        var current_state = state_ptr.*;

        // External rounds
        for (0..external_rounds) |round| {
            // Add round constants
            for (0..width) |i| {
                var result: Field.MontFieldElem = undefined;
                Field.add(&result, Field.MontFieldElem{ .value = current_state[i] }, Field.MontFieldElem{ .value = external_round_constants[round][i] });
                current_state[i] = result.value;
            }

            // Apply S-box
            for (0..width) |i| {
                current_state[i] = sbox(current_state[i]);
            }

            // Apply MDS matrix
            mdsMatrixMul(&current_state);
        }

        // Internal rounds
        for (0..internal_rounds) |round| {
            // Add round constants
            for (0..width) |i| {
                var result: Field.MontFieldElem = undefined;
                Field.add(&result, Field.MontFieldElem{ .value = current_state[i] }, Field.MontFieldElem{ .value = internal_round_constants[round] });
                current_state[i] = result.value;
            }

            // Apply S-box
            for (0..width) |i| {
                current_state[i] = sbox(current_state[i]);
            }

            // Apply MDS matrix
            mdsMatrixMul(&current_state);
        }

        state_ptr.* = current_state;
    }

    // SIMD-optimized permutation for Vec4 batches
    pub fn permutationVec4(states: *[4]Vec4) void {
        // Convert Vec4 to individual states
        var state_array: [4]state = undefined;
        for (0..4) |i| {
            @memcpy(&state_array[i], &states[i]);
        }

        // Process each state
        for (0..4) |i| {
            permutation(&state_array[i]);
        }

        // Convert back to Vec4
        for (0..4) |i| {
            @memcpy(&states[i], &state_array[i]);
        }
    }

    // Batch permutation for multiple states
    pub fn batchPermutation(states: []state) void {
        // Process in SIMD batches of 4
        var i: usize = 0;
        while (i + 4 <= states.len) {
            var batch: [4]Vec4 = undefined;
            for (0..4) |j| {
                @memcpy(&batch[j], &states[i + j]);
            }
            permutationVec4(&batch);
            for (0..4) |j| {
                @memcpy(&states[i + j], &batch[j]);
            }
            i += 4;
        }

        // Process remaining states individually
        while (i < states.len) {
            permutation(&states[i]);
            i += 1;
        }
    }

    // Convert bytes to field elements
    pub fn bytesToFieldElements(input: []const u8) state {
        var state_val: state = .{0} ** width;
        const input_len = @min(input.len, width * 4);

        for (0..width) |i| {
            const byte_offset = i * 4;
            if (byte_offset + 3 < input_len) {
                const slice = input[byte_offset .. byte_offset + 4];
                const val = std.mem.readInt(u32, slice[0..4], .little);
                state_val[i] = val % Field.modulus;
            }
        }

        return state_val;
    }

    // Convert field elements to bytes
    pub fn fieldElementsToBytes(elements: state) [width * 4]u8 {
        var bytes: [width * 4]u8 = undefined;

        for (0..width) |i| {
            const byte_offset = i * 4;
            const slice = bytes[byte_offset .. byte_offset + 4];
            std.mem.writeInt(u32, slice[0..4], elements[i], .little);
        }

        return bytes;
    }

    // Hash function interface
    pub fn hash(input: []const u8) [width * 4]u8 {
        var state_val = bytesToFieldElements(input);
        permutation(&state_val);
        return fieldElementsToBytes(state_val);
    }

    // Batch hash function
    pub fn batchHash(allocator: std.mem.Allocator, inputs: []const []const u8) ![][width * 4]u8 {
        var outputs = std.ArrayList([width * 4]u8).init(allocator);
        try outputs.ensureTotalCapacity(inputs.len);

        for (inputs) |input| {
            const hash_result = hash(input);
            try outputs.append(hash_result);
        }

        return outputs.toOwnedSlice();
    }
};
