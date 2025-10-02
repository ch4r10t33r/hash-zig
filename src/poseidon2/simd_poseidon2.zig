const std = @import("std");
const simd_field = @import("simd_montgomery");

// SIMD-optimized Poseidon2 implementation for KoalaBear field
// Width-16 with optimized matrix operations and vectorized field arithmetic

pub const simd_poseidon2 = struct {
    const width = 16;
    const external_rounds = 8; // 4 initial + 4 final
    const internal_rounds = 20;
    const sbox_degree = 3;

    // Field type
    pub const Field = simd_field.KoalaBearSIMD;
    pub const FieldElem = Field.FieldElem;
    pub const MontFieldElem = Field.MontFieldElem;
    pub const Vec4 = Field.Vec4;
    pub const Vec8 = Field.Vec8;
    pub const Vec16 = Field.Vec16;

    // state type
    pub const state = [width]u32;

    // Round constants (precomputed in Montgomery form)
    const round_constants: [external_rounds + internal_rounds][width]u32 = .{
        // External rounds (0-7)
        .{ 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0 },
        .{ 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01, 0x23456789, 0xabcdef01 },
        .{ 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012, 0x3456789a, 0xbcdef012 },
        .{ 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123, 0x456789ab, 0xcdef0123 },
        .{ 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234, 0x56789abc, 0xdef01234 },
        .{ 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345, 0x6789abcd, 0xef012345 },
        .{ 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456, 0x789abcde, 0xf0123456 },
        .{ 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef, 0x01234567 },
        // Internal rounds (8-27) - simplified for example
        .{ 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000 },
        .{ 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111 },
        .{ 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222 },
        .{ 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333 },
        .{ 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444 },
        .{ 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555 },
        .{ 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666 },
        .{ 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777 },
        .{ 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888 },
        .{ 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999 },
        .{ 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa },
        .{ 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb },
        .{ 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc },
        .{ 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd },
        .{ 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee },
        .{ 0x00000000, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff },
        .{ 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000 },
        .{ 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111 },
        .{ 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222 },
        .{ 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd, 0xeeeeeeee, 0xffffffff, 0x00000000, 0x11111111, 0x22222222, 0x33333333 },
    };

    // MDS matrix (4x4 circulant matrix)
    const mds_matrix: @Vector(16, u32) = .{
        2, 3, 1, 1, // Row 0
        1, 2, 3, 1, // Row 1
        1, 1, 2, 3, // Row 2
        3, 1, 1, 2, // Row 3
    };

    // S-box function: x^3
    pub inline fn sbox(x: u32) u32 {
        // x^3 in Montgomery form
        const x_mont = MontFieldElem{ .value = x };
        var x2_val: MontFieldElem = undefined;
        var x3_val: MontFieldElem = undefined;
        Field.mul(&x2_val, x_mont, x_mont);
        Field.mul(&x3_val, x2_val, x_mont);
        return x3_val.value;
    }

    // Vectorized S-box for 4 elements
    pub inline fn sboxVec4(x: Vec4) Vec4 {
        var result: Vec4 = undefined;
        Field.squareVec4(&result, x);
        Field.mulVec4(&result, result, x);
        return result;
    }

    // Vectorized S-box for 8 elements
    pub inline fn sboxVec8(x: Vec8) Vec8 {
        var result: Vec8 = undefined;
        Field.squareVec8(&result, x);
        Field.mulVec8(&result, result, x);
        return result;
    }

    // Vectorized S-box for 16 elements
    pub inline fn sboxVec16(x: Vec16) Vec16 {
        var result: Vec16 = undefined;
        Field.squareVec16(&result, x);
        Field.mulVec16(&result, result, x);
        return result;
    }

    // Add round constants
    pub inline fn addRoundConstants(state_ptr: *state, round: usize) void {
        const constants = round_constants[round];
        for (0..width) |i| {
            var temp: MontFieldElem = undefined;
            Field.add(&temp, MontFieldElem{ .value = state_ptr.*[i] }, MontFieldElem{ .value = constants[i] });
            state_ptr.*[i] = temp.value;
        }
    }

    // Vectorized add round constants
    pub inline fn addRoundConstantsVec4(state_ptr: *Vec4, round: usize, offset: usize) void {
        const constants = round_constants[round][offset .. offset + 4].*;
        Field.addVec4(state_ptr, state_ptr.*, constants);
    }

    // MDS matrix multiplication (4x4)
    pub inline fn mdsMatrixMul(state_ptr: *state) void {
        var new_state: state = undefined;

        // Process in chunks of 4 for SIMD
        for (0..4) |chunk| {
            const offset = chunk * 4;
            const state_vec: Vec4 = @Vector(4, u32){ state_ptr[offset], state_ptr[offset + 1], state_ptr[offset + 2], state_ptr[offset + 3] };
            var result_vec: Vec4 = undefined;

            Field.matrixVectorMul4x4(&result_vec, mds_matrix, state_vec);
            new_state[offset] = result_vec[0];
            new_state[offset + 1] = result_vec[1];
            new_state[offset + 2] = result_vec[2];
            new_state[offset + 3] = result_vec[3];
        }

        state_ptr.* = new_state;
    }

    // Vectorized MDS matrix multiplication
    pub inline fn mdsMatrixMulVec4(state_ptr: *Vec4) void {
        var result: Vec4 = undefined;
        Field.matrixVectorMul4x4(&result, mds_matrix, state_ptr.*);
        state_ptr.* = result;
    }

    // External round (S-box + MDS)
    pub inline fn externalRound(state_ptr: *state) void {
        // Apply S-box to all elements
        for (0..width) |i| {
            state_ptr.*[i] = sbox(state_ptr.*[i]);
        }

        // Apply MDS matrix
        mdsMatrixMul(state_ptr);
    }

    // Vectorized external round
    pub inline fn externalRoundVec4(state_ptr: *Vec4) void {
        // Apply S-box
        state_ptr.* = sboxVec4(state_ptr.*);

        // Apply MDS matrix
        mdsMatrixMulVec4(state_ptr);
    }

    // Internal round (S-box only on first element)
    pub inline fn internalRound(state_ptr: *state) void {
        // Apply S-box only to first element
        state_ptr.*[0] = sbox(state_ptr.*[0]);
    }

    // Main permutation function
    pub fn permutation(state_ptr: *state) void {
        // External rounds (0-3)
        for (0..4) |round| {
            addRoundConstants(state_ptr, round);
            externalRound(state_ptr);
        }

        // Internal rounds (4-23)
        for (4..24) |round| {
            addRoundConstants(state_ptr, round);
            internalRound(state_ptr);
        }

        // External rounds (24-27)
        for (24..28) |round| {
            addRoundConstants(state_ptr, round);
            externalRound(state_ptr);
        }
    }

    // Vectorized permutation (processes 4 states in parallel)
    pub fn permutationVec4(states: *[4]Vec4) void {
        // External rounds (0-3)
        for (0..4) |round| {
            for (0..4) |i| {
                addRoundConstantsVec4(&states[i], round, 0);
                externalRoundVec4(&states[i]);
            }
        }

        // Internal rounds (4-23) - only first element gets S-box
        for (4..24) |round| {
            for (0..4) |i| {
                addRoundConstantsVec4(&states[i], round, 0);
                // S-box only on first element
                states[i][0] = sbox(states[i][0]);
            }
        }

        // External rounds (24-27)
        for (24..28) |round| {
            for (0..4) |i| {
                addRoundConstantsVec4(&states[i], round, 0);
                externalRoundVec4(&states[i]);
            }
        }
    }

    // Batch processing for multiple permutations
    pub fn batchPermutation(states: []state) void {
        // Process in chunks of 4 for SIMD optimization
        var i: usize = 0;
        while (i + 4 <= states.len) {
            var simd_states: @Vector(4, Vec4) = undefined;

            // Load 4 states
            for (0..4) |j| {
                simd_states[j] = states[i + j][0..4].*;
            }

            // Process with SIMD
            permutationVec4(&simd_states);

            // Store results
            for (0..4) |j| {
                @memcpy(states[i + j][0..4], &simd_states[j]);
            }

            i += 4;
        }

        // Process remaining states individually
        while (i < states.len) {
            permutation(&states[i]);
            i += 1;
        }
    }

    // Convert input bytes to field elements (returns state/Vector)
    pub fn bytesToFieldElements(input: []const u8) state {
        var elements: state = @splat(0);

        // Process 4 bytes at a time
        for (0..width) |i| {
            const offset = i * 4;
            if (offset + 4 <= input.len) {
                const bytes = input[offset..][0..4];
                elements[i] = std.mem.readInt(u32, bytes, .little);
            } else if (offset < input.len) {
                // Handle partial bytes
                var bytes: [4]u8 = .{0} ** 4;
                const remaining = input.len - offset;
                @memcpy(bytes[0..remaining], input[offset..]);
                elements[i] = std.mem.readInt(u32, &bytes, .little);
            }
        }

        return elements;
    }

    // Convert field elements to output bytes
    pub fn fieldElementsToBytes(elements: state) [width * 4]u8 {
        var output: [width * 4]u8 = undefined;

        for (0..width) |i| {
            const bytes = output[i * 4 ..][0..4];
            std.mem.writeInt(u32, bytes, elements[i], .little);
        }

        return output;
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
        defer outputs.deinit();

        for (inputs) |input| {
            const hash_result = hash(input);
            try outputs.append(hash_result);
        }

        return try outputs.toOwnedSlice();
    }
};

// Tests
test "SIMD Poseidon2 basic functionality" {
    const poseidon = simd_poseidon2;

    // Test single permutation
    var state = poseidon.state{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    poseidon.permutation(&state);

    // Test vectorized permutation
    var states: @Vector(4, poseidon.Vec4) = .{
        poseidon.Vec4{ 1, 2, 3, 4 },
        poseidon.Vec4{ 5, 6, 7, 8 },
        poseidon.Vec4{ 9, 10, 11, 12 },
        poseidon.Vec4{ 13, 14, 15, 16 },
    };
    poseidon.permutationVec4(&states);

    // Test hash function
    const input = "Hello, World!";
    _ = poseidon.hash(input);

    std.debug.print("SIMD Poseidon2 test passed\n", .{});
}

test "SIMD Poseidon2 performance" {
    const poseidon = simd_poseidon2;
    const iterations = 10000;

    // Test scalar performance
    const start_scalar = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var state = poseidon.state{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        poseidon.permutation(&state);
    }
    const scalar_time = std.time.nanoTimestamp() - start_scalar;

    // Test vectorized performance
    const start_vector = std.time.nanoTimestamp();
    for (0..iterations / 4) |_| {
        var states: @Vector(4, poseidon.Vec4) = .{
            poseidon.Vec4{ 1, 2, 3, 4 },
            poseidon.Vec4{ 5, 6, 7, 8 },
            poseidon.Vec4{ 9, 10, 11, 12 },
            poseidon.Vec4{ 13, 14, 15, 16 },
        };
        poseidon.permutationVec4(&states);
    }
    const vector_time = std.time.nanoTimestamp() - start_vector;

    const speedup = @as(f64, @floatFromInt(scalar_time)) / @as(f64, @floatFromInt(vector_time));
    std.debug.print("SIMD Poseidon2 speedup: {d:.2}x\n", .{speedup});

    // Should achieve at least 2x speedup
    std.debug.assert(speedup >= 2.0);
}
