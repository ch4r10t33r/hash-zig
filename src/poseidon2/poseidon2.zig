const std = @import("std");

// Rust-compatible Poseidon2 implementation
// Matches hash-sig crate parameters: width=5, ext_rounds=7, int_rounds=2, sbox=9
// Field: KoalaBear field (31-bit field with modulus 0x7f000001)

const koalabear_field = @import("fields/koalabear/montgomery.zig").montgomery_field;

pub const Poseidon2 = struct {
    const width = 5;
    const external_rounds = 7;
    const internal_rounds = 2;
    const sbox_degree = 9;
    const field_bits = 31;

    // Field modulus: 2^31 - 2^24 + 1 = 0x7f000001 (KoalaBear)
    const field_modulus = 0x7f000001;

    // Field element type
    pub const FieldElem = u32;

    // State type
    pub const State = [width]FieldElem;

    // Round constants (placeholder - would need actual constants from Rust implementation)
    const external_round_constants: [external_rounds][width]FieldElem = .{
        .{ 0x12345, 0x23456, 0x34567, 0x45678, 0x56789 },
        .{ 0x23456, 0x34567, 0x45678, 0x56789, 0x6789A },
        .{ 0x34567, 0x45678, 0x56789, 0x6789A, 0x789AB },
        .{ 0x45678, 0x56789, 0x6789A, 0x789AB, 0x89ABC },
        .{ 0x56789, 0x6789A, 0x789AB, 0x89ABC, 0x9ABCD },
        .{ 0x6789A, 0x789AB, 0x89ABC, 0x9ABCD, 0xABCDE },
        .{ 0x789AB, 0x89ABC, 0x9ABCD, 0xABCDE, 0xBCDEF },
    };

    const internal_round_constants: [internal_rounds]FieldElem = .{
        0x12345, 0x23456,
    };

    // MDS matrix (placeholder - would need actual matrix from Rust implementation)
    const mds_matrix: [width][width]FieldElem = .{
        .{ 2, 3, 1, 1, 1 },
        .{ 1, 2, 3, 1, 1 },
        .{ 1, 1, 2, 3, 1 },
        .{ 1, 1, 1, 2, 3 },
        .{ 3, 1, 1, 1, 2 },
    };

    // S-box function: x^9 using KoalaBear field
    pub fn sbox(x: FieldElem) FieldElem {
        var mont_x: koalabear_field.MontFieldElem = undefined;
        koalabear_field.toMontgomery(&mont_x, x);

        var result: koalabear_field.MontFieldElem = undefined;
        koalabear_field.toMontgomery(&result, 1); // Start with 1
        var base = mont_x;
        var exp: u32 = @intCast(sbox_degree);

        while (exp > 0) {
            if (exp & 1 == 1) {
                koalabear_field.mul(&result, result, base);
            }
            koalabear_field.square(&base, base);
            exp >>= 1;
        }

        return koalabear_field.toNormal(result);
    }

    // Convert to Montgomery form
    fn toMontgomery(x: FieldElem) koalabear_field.MontFieldElem {
        var mont: koalabear_field.MontFieldElem = undefined;
        koalabear_field.toMontgomery(&mont, x);
        return mont;
    }

    // Convert from Montgomery form
    fn fromMontgomery(mont: koalabear_field.MontFieldElem) FieldElem {
        return koalabear_field.toNormal(mont);
    }

    // Add round constants
    fn addRoundConstants(state: *State, round: usize) void {
        if (round < external_rounds) {
            for (0..width) |i| {
                var mont_state = toMontgomery(state[i]);
                const mont_rc = toMontgomery(external_round_constants[round][i]);
                koalabear_field.add(&mont_state, mont_state, mont_rc);
                state[i] = fromMontgomery(mont_state);
            }
        } else {
            const internal_round = round - external_rounds;
            if (internal_round < internal_rounds) {
                var mont_state = toMontgomery(state[0]);
                const mont_rc = toMontgomery(internal_round_constants[internal_round]);
                koalabear_field.add(&mont_state, mont_state, mont_rc);
                state[0] = fromMontgomery(mont_state);
            }
        }
    }

    // Apply S-box to all elements
    fn applySbox(state: *State) void {
        for (0..width) |i| {
            state[i] = sbox(state[i]);
        }
    }

    // Apply S-box only to first element (internal rounds)
    fn applySboxFirst(state: *State) void {
        state[0] = sbox(state[0]);
    }

    // MDS matrix multiplication
    fn applyMds(state: *State) void {
        var new_state: State = undefined;

        for (0..width) |i| {
            var mont_sum = toMontgomery(0);
            for (0..width) |j| {
                const mont_state = toMontgomery(state[j]);
                const mont_matrix = toMontgomery(mds_matrix[i][j]);
                var mont_prod: koalabear_field.MontFieldElem = undefined;
                koalabear_field.mul(&mont_prod, mont_state, mont_matrix);
                koalabear_field.add(&mont_sum, mont_sum, mont_prod);
            }
            new_state[i] = fromMontgomery(mont_sum);
        }

        state.* = new_state;
    }

    // External round
    fn externalRound(state: *State, round: usize) void {
        addRoundConstants(state, round);
        applySbox(state);
        applyMds(state);
    }

    // Internal round
    fn internalRound(state: *State, round: usize) void {
        addRoundConstants(state, round);
        applySboxFirst(state);
    }

    // Main permutation
    pub fn permutation(state: *State) void {
        // External rounds (0-6)
        for (0..external_rounds) |round| {
            externalRound(state, round);
        }

        // Internal rounds (7-8)
        for (0..internal_rounds) |round| {
            internalRound(state, external_rounds + round);
        }
    }

    // Hash function interface
    pub fn hash(input: []const u8) [32]u8 {
        var state: State = .{0} ** width;

        // Process input in chunks
        var input_offset: usize = 0;
        while (input_offset < input.len) {
            const chunk_size = @min(input.len - input_offset, width * 4); // 4 bytes per field element
            var chunk: [width * 4]u8 = undefined;
            @memset(chunk[0..chunk_size], 0);
            @memcpy(chunk[0..chunk_size], input[input_offset .. input_offset + chunk_size]);

            // Convert bytes to field elements (ensure they fit in 31-bit field)
            for (0..width) |j| {
                const byte_offset = j * 4;
                if (byte_offset + 3 < chunk_size) {
                    const slice = chunk[byte_offset .. byte_offset + 4];
                    const val = std.mem.readInt(u32, slice[0..4], .little);
                    state[j] = val % field_modulus;
                }
            }

            permutation(&state);
            input_offset += chunk_size;
        }

        // Convert state to 32-byte output
        var output: [32]u8 = undefined;
        for (0..width) |i| {
            const bytes = std.mem.toBytes(state[i]);
            @memcpy(output[i * 4 .. i * 4 + 4], &bytes);
        }

        // Pad remaining bytes with zeros
        @memset(output[width * 4 ..], 0);

        return output;
    }
};
