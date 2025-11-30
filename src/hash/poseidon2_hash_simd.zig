//! SIMD-aware Poseidon2 hash implementation
//! This module provides SIMD-optimized Poseidon2 operations that can process
//! multiple field elements simultaneously using @Vector operations.
//!
//! The goal is to match Rust's PackedF-based SIMD implementation where
//! poseidon_compress can process PackedF inputs directly.

const std = @import("std");
const Allocator = std.mem.Allocator;
const FieldElement = @import("../core/field.zig").FieldElement;
const simd_utils = @import("../signature/native/simd_utils.zig");
const Poseidon2RustCompat = @import("poseidon2_hash.zig").Poseidon2RustCompat;
const Poseidon2KoalaBear16 = @import("../poseidon2/root.zig").Poseidon2KoalaBear16;
const Poseidon2KoalaBear24 = @import("../poseidon2/root.zig").Poseidon2KoalaBear24;

const WIDTH_16 = 16;
const SIMD_WIDTH = simd_utils.SIMD_WIDTH;

/// SIMD-aware Poseidon2 compression function
/// Processes multiple states simultaneously using SIMD operations
pub const Poseidon2SIMD = struct {
    allocator: Allocator,
    poseidon2: *Poseidon2RustCompat,

    pub fn init(allocator: Allocator, poseidon2: *Poseidon2RustCompat) Poseidon2SIMD {
        return .{
            .allocator = allocator,
            .poseidon2 = poseidon2,
        };
    }

    /// Compress SIMD-packed inputs using Poseidon2-16
    /// This is the SIMD equivalent of poseidon_compress
    ///
    /// NOTE: True SIMD permutation is ENABLED (USE_TRUE_SIMD = true)
    ///
    /// Input: packed_input is [element][lane] format (vertical packing)
    /// Output: packed_output is [element][lane] format
    ///
    /// CRITICAL OPTIMIZATION: Writes to pre-allocated output buffer instead of allocating.
    /// This matches Rust's approach of returning fixed-size stack arrays, eliminating
    /// 114,688 allocations in chain walking (64 chains × 7 steps × 256 batches).
    pub fn compress16SIMD(
        self: *Poseidon2SIMD,
        packed_input: []const simd_utils.PackedF,
        out_len: usize,
        packed_output: []simd_utils.PackedF, // Pre-allocated output buffer (must be at least out_len)
    ) !void {
        std.debug.assert(packed_output.len >= out_len);
        const input_len = packed_input.len;
        const USE_TRUE_SIMD = true; // Enabled - SIMD permutation verified

        if (USE_TRUE_SIMD) {
            // True SIMD path - select 4-wide or 8-wide based on SIMD_WIDTH
            if (SIMD_WIDTH == 8) {
                // 8-wide SIMD path
                var packed_states: [WIDTH_16]@Vector(8, u32) = undefined;

                // Initialize state from packed input
                for (0..WIDTH_16) |i| {
                    if (i < input_len) {
                        packed_states[i] = packed_input[i].values;
                    } else {
                        packed_states[i] = @splat(@as(u32, 0));
                    }
                }

                const packed_input_states = packed_states;
                permute16SIMD8Impl(self, &packed_states);

                // Feed-forward
                for (0..WIDTH_16) |i| {
                    packed_states[i] = addSIMD8(packed_states[i], packed_input_states[i]);
                }

                // Write directly to output buffer (no allocation!)
                for (0..out_len) |i| {
                    packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
                }
            } else {
                // 4-wide SIMD path
                var packed_states: [WIDTH_16]@Vector(4, u32) = undefined;

                // Initialize state from packed input
                for (0..WIDTH_16) |i| {
                    if (i < input_len) {
                        packed_states[i] = packed_input[i].values;
                    } else {
                        packed_states[i] = @splat(@as(u32, 0));
                    }
                }

                const packed_input_states = packed_states;
                permute16SIMD4Impl(self, &packed_states);

                // Feed-forward
                for (0..WIDTH_16) |i| {
                    packed_states[i] = addSIMD4(packed_states[i], packed_input_states[i]);
                }

                // Write directly to output buffer (no allocation!)
                for (0..out_len) |i| {
                    packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
                }
            }
        } else {
            // Optimized batch processing path (maintains compatibility)
            // Process all lanes in batch for better cache locality
            var lane_states: [SIMD_WIDTH][WIDTH_16]FieldElement = undefined;
            var lane_outputs: [SIMD_WIDTH][]FieldElement = undefined;
            defer {
                for (lane_outputs) |output| {
                    if (output.len > 0) self.allocator.free(output);
                }
            }

            // Unpack inputs for all lanes
            for (0..SIMD_WIDTH) |lane| {
                for (0..@min(input_len, WIDTH_16)) |i| {
                    lane_states[lane][i] = FieldElement{ .value = packed_input[i].values[lane] };
                }
                for (@min(input_len, WIDTH_16)..WIDTH_16) |i| {
                    lane_states[lane][i] = FieldElement.zero();
                }
            }

            // Process all lanes in batch (better cache locality)
            for (0..SIMD_WIDTH) |lane| {
                // Apply Poseidon2-16 compression
                // Use out_len (which is hash_len from lifetime params) to match Rust's poseidon_compress OUT_LEN
                lane_outputs[lane] = try self.poseidon2.hashFieldElements16(self.allocator, lane_states[lane][0..WIDTH_16], out_len);
            }

            // Pack outputs back into SIMD format and write to output buffer
            for (0..out_len) |i| {
                const values: @Vector(SIMD_WIDTH, u32) = .{
                    if (i < lane_outputs[0].len) lane_outputs[0][i].value else 0,
                    if (i < lane_outputs[1].len) lane_outputs[1][i].value else 0,
                    if (i < lane_outputs[2].len) lane_outputs[2][i].value else 0,
                    if (i < lane_outputs[3].len) lane_outputs[3][i].value else 0,
                };
                packed_output[i] = simd_utils.PackedF{ .values = values };
            }
        }
    }

    /// Compress SIMD-packed inputs using Poseidon2-24
    /// This is the SIMD equivalent of poseidon_compress for 24-width
    ///
    /// Input: packed_input is [element][lane] format (vertical packing)
    /// Output: packed_output is [element][lane] format
    ///
    /// CRITICAL OPTIMIZATION: Writes to pre-allocated output buffer instead of allocating.
    /// This matches Rust's approach of returning fixed-size stack arrays.
    pub fn compress24SIMD(
        self: *Poseidon2SIMD,
        packed_input: []const simd_utils.PackedF,
        out_len: usize,
        packed_output: []simd_utils.PackedF, // Pre-allocated output buffer (must be at least out_len)
    ) !void {
        std.debug.assert(packed_output.len >= out_len);
        const WIDTH_24 = 24;
        const input_len = packed_input.len;
        const USE_TRUE_SIMD = true; // Enabled - SIMD permutation verified

        if (USE_TRUE_SIMD) {
            // True SIMD path - select 4-wide or 8-wide based on SIMD_WIDTH
            if (SIMD_WIDTH == 8) {
                // 8-wide SIMD path
                var packed_states: [WIDTH_24]@Vector(8, u32) = undefined;

                for (0..WIDTH_24) |i| {
                    if (i < input_len) {
                        packed_states[i] = packed_input[i].values;
                    } else {
                        packed_states[i] = @splat(@as(u32, 0));
                    }
                }

                var packed_input_states: [WIDTH_24]@Vector(8, u32) = undefined;
                for (0..WIDTH_24) |i| {
                    packed_input_states[i] = packed_states[i];
                }

                permute24SIMD8Impl(self, &packed_states);

                for (0..WIDTH_24) |i| {
                    packed_states[i] = addSIMD8(packed_states[i], packed_input_states[i]);
                }

                for (0..out_len) |i| {
                    packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
                }
            } else {
                // 4-wide SIMD path
                var packed_states: [WIDTH_24]@Vector(4, u32) = undefined;

                for (0..WIDTH_24) |i| {
                    if (i < input_len) {
                        packed_states[i] = packed_input[i].values;
                    } else {
                        packed_states[i] = @splat(@as(u32, 0));
                    }
                }

                var packed_input_states: [WIDTH_24]@Vector(4, u32) = undefined;
                for (0..WIDTH_24) |i| {
                    packed_input_states[i] = packed_states[i];
                }

                permute24SIMD4Impl(self, &packed_states);

                for (0..WIDTH_24) |i| {
                    packed_states[i] = addSIMD4(packed_states[i], packed_input_states[i]);
                }

                for (0..out_len) |i| {
                    packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
                }
            }
        } else {
            // Fallback to batch processing
            var lane_states: [SIMD_WIDTH][WIDTH_24]FieldElement = undefined;
            var lane_outputs: [SIMD_WIDTH][]FieldElement = undefined;
            defer {
                for (lane_outputs) |output| {
                    if (output.len > 0) self.allocator.free(output);
                }
            }

            // Unpack inputs for all lanes
            for (0..SIMD_WIDTH) |lane| {
                for (0..@min(input_len, WIDTH_24)) |i| {
                    lane_states[lane][i] = FieldElement{ .value = packed_input[i].values[lane] };
                }
                for (@min(input_len, WIDTH_24)..WIDTH_24) |i| {
                    lane_states[lane][i] = FieldElement.zero();
                }
            }

            // Process all lanes in batch
            for (0..SIMD_WIDTH) |lane| {
                lane_outputs[lane] = try self.poseidon2.hashFieldElements(self.allocator, lane_states[lane][0..WIDTH_24]);
            }

            // Pack outputs back into SIMD format and write to output buffer
            for (0..out_len) |i| {
                const values: @Vector(SIMD_WIDTH, u32) = .{
                    if (i < lane_outputs[0].len) lane_outputs[0][i].value else 0,
                    if (i < lane_outputs[1].len) lane_outputs[1][i].value else 0,
                    if (i < lane_outputs[2].len) lane_outputs[2][i].value else 0,
                    if (i < lane_outputs[3].len) lane_outputs[3][i].value else 0,
                };
                packed_output[i] = simd_utils.PackedF{ .values = values };
            }
        }
    }

    /// SIMD-aware field addition (Montgomery form) - 4-wide
    fn addSIMD4(a: @Vector(4, u32), b: @Vector(4, u32)) @Vector(4, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        const sum = a +% b;
        var result: @Vector(4, u32) = undefined;
        inline for (0..4) |i| {
            result[i] = if (sum[i] >= KOALABEAR_PRIME) sum[i] -% KOALABEAR_PRIME else sum[i];
        }
        return result;
    }

    /// SIMD-aware field addition (Montgomery form) - 8-wide
    fn addSIMD8(a: @Vector(8, u32), b: @Vector(8, u32)) @Vector(8, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        const sum = a +% b;
        var result: @Vector(8, u32) = undefined;
        inline for (0..8) |i| {
            result[i] = if (sum[i] >= KOALABEAR_PRIME) sum[i] -% KOALABEAR_PRIME else sum[i];
        }
        return result;
    }

    /// SIMD-aware field addition (Montgomery form) - dispatches to 4-wide or 8-wide
    /// This wrapper handles both 4-wide and 8-wide by casting appropriately
    fn addSIMD(a: @Vector(SIMD_WIDTH, u32), b: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        if (SIMD_WIDTH == 8) {
            // Cast to 8-wide vectors
            const a8: @Vector(8, u32) = a;
            const b8: @Vector(8, u32) = b;
            const result8 = addSIMD8(a8, b8);
            return result8;
        } else {
            // Cast to 4-wide vectors
            const a4: @Vector(4, u32) = a;
            const b4: @Vector(4, u32) = b;
            const result4 = addSIMD4(a4, b4);
            return result4;
        }
    }

    /// Convert u32 to Montgomery form (SIMD version of F.fromU32)
    /// Converts canonical u32 values to Montgomery form
    fn toMontySIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_PRIME: u64 = 0x7f000001;
        const KOALABEAR_MONTY_BITS: u32 = 32;
        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            // to_monty: (((x as u64) << MONTY_BITS) % PRIME as u64) as u32
            const shifted = @as(u64, x[i]) << KOALABEAR_MONTY_BITS;
            result[i] = @as(u32, @intCast(shifted % KOALABEAR_PRIME));
        }
        return result;
    }

    /// SIMD-aware field multiplication (Montgomery form) - 4-wide
    fn mulSIMD4(a: @Vector(4, u32), b: @Vector(4, u32)) @Vector(4, u32) {
        const KOALABEAR_PRIME: u64 = 0x7f000001;
        const KOALABEAR_MONTY_MU: u32 = 0x81000001;
        const KOALABEAR_MONTY_MASK: u32 = 0xffffffff;
        const KOALABEAR_MONTY_BITS: u32 = 32;

        var result: @Vector(4, u32) = undefined;
        inline for (0..4) |i| {
            // Montgomery reduction (matching plonky3_field.zig exactly)
            const long_prod = @as(u64, a[i]) * @as(u64, b[i]);
            const t = @as(u32, @truncate(long_prod)) *% KOALABEAR_MONTY_MU & KOALABEAR_MONTY_MASK;
            const u = @as(u64, t) * KOALABEAR_PRIME;
            const sub_result = @subWithOverflow(long_prod, u);
            const x_sub_u = sub_result[0];
            const over = sub_result[1];
            const x_sub_u_hi = @as(u32, @intCast(x_sub_u >> KOALABEAR_MONTY_BITS));
            const corr = if (over != 0) @as(u32, @truncate(KOALABEAR_PRIME)) else 0;
            result[i] = x_sub_u_hi +% corr;
        }
        return result;
    }

    /// SIMD-aware field multiplication (Montgomery form) - 8-wide
    fn mulSIMD8(a: @Vector(8, u32), b: @Vector(8, u32)) @Vector(8, u32) {
        const KOALABEAR_PRIME: u64 = 0x7f000001;
        const KOALABEAR_MONTY_MU: u32 = 0x81000001;
        const KOALABEAR_MONTY_MASK: u32 = 0xffffffff;
        const KOALABEAR_MONTY_BITS: u32 = 32;

        var result: @Vector(8, u32) = undefined;
        inline for (0..8) |i| {
            // Montgomery reduction (matching plonky3_field.zig exactly)
            const long_prod = @as(u64, a[i]) * @as(u64, b[i]);
            const t = @as(u32, @truncate(long_prod)) *% KOALABEAR_MONTY_MU & KOALABEAR_MONTY_MASK;
            const u = @as(u64, t) * KOALABEAR_PRIME;
            const sub_result = @subWithOverflow(long_prod, u);
            const x_sub_u = sub_result[0];
            const over = sub_result[1];
            const x_sub_u_hi = @as(u32, @intCast(x_sub_u >> KOALABEAR_MONTY_BITS));
            const corr = if (over != 0) @as(u32, @truncate(KOALABEAR_PRIME)) else 0;
            result[i] = x_sub_u_hi +% corr;
        }
        return result;
    }

    /// SIMD-aware field multiplication (Montgomery form)
    /// Multiplies two vectors of field elements element-wise using Montgomery reduction
    fn mulSIMD(a: @Vector(SIMD_WIDTH, u32), b: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_PRIME: u64 = 0x7f000001;
        const KOALABEAR_MONTY_MU: u32 = 0x81000001;
        const KOALABEAR_MONTY_MASK: u32 = 0xffffffff;
        const KOALABEAR_MONTY_BITS: u32 = 32;

        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            // Montgomery reduction (matching plonky3_field.zig exactly)
            const long_prod = @as(u64, a[i]) * @as(u64, b[i]);
            const t = @as(u32, @truncate(long_prod)) *% KOALABEAR_MONTY_MU & KOALABEAR_MONTY_MASK;
            const u = @as(u64, t) * KOALABEAR_PRIME;
            const sub_result = @subWithOverflow(long_prod, u);
            const x_sub_u = sub_result[0];
            const over = sub_result[1];
            const x_sub_u_hi = @as(u32, @intCast(x_sub_u >> KOALABEAR_MONTY_BITS));
            const corr = if (over != 0) @as(u32, @truncate(KOALABEAR_PRIME)) else 0;
            result[i] = x_sub_u_hi +% corr;
        }
        return result;
    }

    /// SIMD-aware S-box (x^3 operation) - 4-wide
    inline fn sboxSIMD4(x: @Vector(4, u32)) @Vector(4, u32) {
        const x2 = mulSIMD4(x, x);
        return mulSIMD4(x2, x);
    }

    /// SIMD-aware S-box (x^3 operation) - 8-wide
    inline fn sboxSIMD8(x: @Vector(8, u32)) @Vector(8, u32) {
        const x2 = mulSIMD8(x, x);
        return mulSIMD8(x2, x);
    }

    /// SIMD-aware S-box (x^3 operation)
    /// Applies x^3 to each element in the vector
    /// OPTIMIZATION: Inline to help compiler optimize
    inline fn sboxSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        // x^3 = x * x * x (optimal: 2 multiplications)
        if (SIMD_WIDTH == 8) {
            const x2 = mulSIMD8(x, x);
            return mulSIMD8(x2, x);
        } else {
            const x2 = mulSIMD4(x, x);
            return mulSIMD4(x2, x);
        }
    }

    /// SIMD-aware round constant addition
    /// Adds round constants to all lanes (broadcast constant to all lanes)
    fn addRoundConstantsSIMD(
        state: []@Vector(SIMD_WIDTH, u32),
        rcs: []const u32,
    ) void {
        for (0..state.len) |i| {
            if (i < rcs.len) {
                const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(rcs[i]);
                state[i] = addSIMD(state[i], rc_broadcast);
            }
        }
    }

    /// SIMD-aware MDS matrix application (4x4 block) - 4-wide
    inline fn applyMat4SIMD4Impl(
        state: []@Vector(4, u32),
        start_idx: usize,
    ) void {
        if (start_idx + 4 > state.len) return;

        const x0 = state[start_idx + 0];
        const x1 = state[start_idx + 1];
        const x2 = state[start_idx + 2];
        const x3 = state[start_idx + 3];

        const t01 = addSIMD4(x0, x1);
        const t23 = addSIMD4(x2, x3);
        const t0123 = addSIMD4(t01, t23);
        const t01123 = addSIMD4(t0123, x1);
        const t01233 = addSIMD4(t0123, x3);

        const x0_double = addSIMD4(x0, x0);
        state[start_idx + 3] = addSIMD4(t01233, x0_double);

        const x2_double = addSIMD4(x2, x2);
        state[start_idx + 1] = addSIMD4(t01123, x2_double);

        state[start_idx + 0] = addSIMD4(t01123, t01);
        state[start_idx + 2] = addSIMD4(t01233, t23);
    }

    /// SIMD-aware MDS matrix application (4x4 block) - 8-wide
    inline fn applyMat4SIMD8Impl(
        state: []@Vector(8, u32),
        start_idx: usize,
    ) void {
        if (start_idx + 4 > state.len) return;

        const x0 = state[start_idx + 0];
        const x1 = state[start_idx + 1];
        const x2 = state[start_idx + 2];
        const x3 = state[start_idx + 3];

        const t01 = addSIMD8(x0, x1);
        const t23 = addSIMD8(x2, x3);
        const t0123 = addSIMD8(t01, t23);
        const t01123 = addSIMD8(t0123, x1);
        const t01233 = addSIMD8(t0123, x3);

        const x0_double = addSIMD8(x0, x0);
        state[start_idx + 3] = addSIMD8(t01233, x0_double);

        const x2_double = addSIMD8(x2, x2);
        state[start_idx + 1] = addSIMD8(t01123, x2_double);

        state[start_idx + 0] = addSIMD8(t01123, t01);
        state[start_idx + 2] = addSIMD8(t01233, t23);
    }

    /// SIMD-aware MDS matrix application (4x4 block)
    /// Applies the MDS matrix to 4 elements across all SIMD lanes
    /// OPTIMIZATION: Inline to help compiler optimize
    inline fn applyMat4SIMD(
        state: []@Vector(SIMD_WIDTH, u32),
        start_idx: usize,
    ) void {
        if (SIMD_WIDTH == 8) {
            // Cast to 8-wide and call 8-wide implementation
            const state8 = @as([*]@Vector(8, u32), @ptrCast(state.ptr))[0..state.len];
            applyMat4SIMD8Impl(state8, start_idx);
        } else {
            // Cast to 4-wide and call 4-wide implementation
            const state4 = @as([*]@Vector(4, u32), @ptrCast(state.ptr))[0..state.len];
            applyMat4SIMD4Impl(state4, start_idx);
        }
    }

    /// SIMD-aware MDS light permutation for 16-width - 4-wide
    fn mdsLightPermutation16SIMD4Impl(packed_states: []@Vector(4, u32)) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        for (0..4) |i| {
            applyMat4SIMD4Impl(packed_states, i * 4);
        }

        var sums: [4]@Vector(4, u32) = undefined;
        for (0..4) |k| {
            sums[k] = @splat(@as(u32, 0));
            var j: usize = 0;
            while (j < WIDTH) : (j += 4) {
                sums[k] = addSIMD4(sums[k], packed_states[j + k]);
            }
        }

        for (0..WIDTH) |i| {
            packed_states[i] = addSIMD4(packed_states[i], sums[i % 4]);
        }
    }

    /// SIMD-aware MDS light permutation for 16-width - 8-wide
    fn mdsLightPermutation16SIMD8Impl(packed_states: []@Vector(8, u32)) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        for (0..4) |i| {
            applyMat4SIMD8Impl(packed_states, i * 4);
        }

        var sums: [4]@Vector(8, u32) = undefined;
        for (0..4) |k| {
            sums[k] = @splat(@as(u32, 0));
            var j: usize = 0;
            while (j < WIDTH) : (j += 4) {
                sums[k] = addSIMD8(sums[k], packed_states[j + k]);
            }
        }

        for (0..WIDTH) |i| {
            packed_states[i] = addSIMD8(packed_states[i], sums[i % 4]);
        }
    }

    /// SIMD-aware MDS light permutation for 16-width
    /// Applies MDS light to all lanes simultaneously
    fn mdsLightPermutation16SIMD(packed_states: []@Vector(SIMD_WIDTH, u32)) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            mdsLightPermutation16SIMD8Impl(state8);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            mdsLightPermutation16SIMD4Impl(state4);
        }
    }

    /// SIMD-aware MDS light permutation for 24-width - 4-wide
    fn mdsLightPermutation24SIMD4Impl(packed_states: []@Vector(4, u32)) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        for (0..6) |i| {
            applyMat4SIMD4Impl(packed_states, i * 4);
        }

        var sums: [4]@Vector(4, u32) = undefined;
        for (0..4) |k| {
            sums[k] = @splat(@as(u32, 0));
            var j: usize = 0;
            while (j < WIDTH) : (j += 4) {
                sums[k] = addSIMD4(sums[k], packed_states[j + k]);
            }
        }

        for (0..WIDTH) |i| {
            packed_states[i] = addSIMD4(packed_states[i], sums[i % 4]);
        }
    }

    /// SIMD-aware MDS light permutation for 24-width - 8-wide
    fn mdsLightPermutation24SIMD8Impl(packed_states: []@Vector(8, u32)) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        for (0..6) |i| {
            applyMat4SIMD8Impl(packed_states, i * 4);
        }

        var sums: [4]@Vector(8, u32) = undefined;
        for (0..4) |k| {
            sums[k] = @splat(@as(u32, 0));
            var j: usize = 0;
            while (j < WIDTH) : (j += 4) {
                sums[k] = addSIMD8(sums[k], packed_states[j + k]);
            }
        }

        for (0..WIDTH) |i| {
            packed_states[i] = addSIMD8(packed_states[i], sums[i % 4]);
        }
    }

    /// SIMD-aware MDS light permutation for 24-width
    /// Applies MDS light to all lanes simultaneously
    fn mdsLightPermutation24SIMD(packed_states: []@Vector(SIMD_WIDTH, u32)) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            mdsLightPermutation24SIMD8Impl(state8);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            mdsLightPermutation24SIMD4Impl(state4);
        }
    }

    /// SIMD-aware div2exp (division by power of 2) - 4-wide
    fn div2expSIMD4(x: @Vector(4, u32), exponent: u32) @Vector(4, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        var result: @Vector(4, u32) = undefined;
        inline for (0..4) |i| {
            if (exponent <= 32) {
                const long_prod = @as(u64, x[i]) << @as(u6, @intCast(32 - exponent));
                result[i] = montyReduceSIMD(long_prod);
            } else {
                var val = x[i];
                var exp = exponent;
                while (exp > 0 and exp <= 32) : (exp -= 1) {
                    const shr = val >> 1;
                    const lo_bit = val & 1;
                    const shr_corr = shr +% KOALABEAR_HALF_P_PLUS_1;
                    val = if (lo_bit == 0) shr else shr_corr;
                }
                result[i] = val;
            }
        }
        return result;
    }

    /// SIMD-aware div2exp (division by power of 2) - 8-wide
    fn div2expSIMD8(x: @Vector(8, u32), exponent: u32) @Vector(8, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        var result: @Vector(8, u32) = undefined;
        inline for (0..8) |i| {
            if (exponent <= 32) {
                const long_prod = @as(u64, x[i]) << @as(u6, @intCast(32 - exponent));
                result[i] = montyReduceSIMD(long_prod);
            } else {
                var val = x[i];
                var exp = exponent;
                while (exp > 0 and exp <= 32) : (exp -= 1) {
                    const shr = val >> 1;
                    const lo_bit = val & 1;
                    const shr_corr = shr +% KOALABEAR_HALF_P_PLUS_1;
                    val = if (lo_bit == 0) shr else shr_corr;
                }
                result[i] = val;
            }
        }
        return result;
    }

    /// SIMD-aware div2exp (division by power of 2) - dispatches to 4-wide or 8-wide
    fn div2expSIMD(x: @Vector(SIMD_WIDTH, u32), exponent: u32) @Vector(SIMD_WIDTH, u32) {
        if (SIMD_WIDTH == 8) {
            return div2expSIMD8(x, exponent);
        } else {
            return div2expSIMD4(x, exponent);
        }
    }

    /// SIMD-aware Montgomery reduction
    fn montyReduceSIMD(x: u64) u32 {
        const KOALABEAR_PRIME: u64 = 0x7f000001;
        const KOALABEAR_MONTY_MU: u32 = 0x81000001;
        const KOALABEAR_MONTY_MASK: u32 = 0xffffffff;
        const KOALABEAR_MONTY_BITS: u32 = 32;

        const t = @as(u32, @truncate(x)) *% KOALABEAR_MONTY_MU & KOALABEAR_MONTY_MASK;
        const u = @as(u64, t) * KOALABEAR_PRIME;
        const sub_result = @subWithOverflow(x, u);
        const x_sub_u = sub_result[0];
        const over = sub_result[1];
        const x_sub_u_hi = @as(u32, @intCast(x_sub_u >> KOALABEAR_MONTY_BITS));
        const corr = if (over != 0) @as(u32, @truncate(KOALABEAR_PRIME)) else 0;
        return x_sub_u_hi +% corr;
    }

    /// SIMD-aware double operation - 4-wide
    fn doubleSIMD4(x: @Vector(4, u32)) @Vector(4, u32) {
        return addSIMD4(x, x);
    }

    /// SIMD-aware double operation - 8-wide
    fn doubleSIMD8(x: @Vector(8, u32)) @Vector(8, u32) {
        return addSIMD8(x, x);
    }

    /// SIMD-aware double operation
    fn doubleSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        if (SIMD_WIDTH == 8) {
            return doubleSIMD8(x);
        } else {
            return doubleSIMD4(x);
        }
    }

    /// SIMD-aware halve operation - 4-wide
    fn halveSIMD4(x: @Vector(4, u32)) @Vector(4, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        var result: @Vector(4, u32) = undefined;
        inline for (0..4) |i| {
            const shr = x[i] >> 1;
            const lo_bit = x[i] & 1;
            const shr_corr = shr +% KOALABEAR_HALF_P_PLUS_1;
            result[i] = if (lo_bit == 0) shr else shr_corr;
        }
        return result;
    }

    /// SIMD-aware halve operation - 8-wide
    fn halveSIMD8(x: @Vector(8, u32)) @Vector(8, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        var result: @Vector(8, u32) = undefined;
        inline for (0..8) |i| {
            const shr = x[i] >> 1;
            const lo_bit = x[i] & 1;
            const shr_corr = shr +% KOALABEAR_HALF_P_PLUS_1;
            result[i] = if (lo_bit == 0) shr else shr_corr;
        }
        return result;
    }

    /// SIMD-aware halve operation
    fn halveSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        if (SIMD_WIDTH == 8) {
            return halveSIMD8(x);
        } else {
            return halveSIMD4(x);
        }
    }

    /// SIMD-aware internal layer for 16-width - 4-wide
    fn applyInternalLayer16SIMD4Impl(
        packed_states: []@Vector(4, u32),
        rc: u32,
    ) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        const rc_broadcast: @Vector(4, u32) = @splat(rc);
        packed_states[0] = addSIMD4(packed_states[0], rc_broadcast);
        packed_states[0] = sboxSIMD4(packed_states[0]);

        var part_sum: @Vector(4, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD4(part_sum, packed_states[i]);
        }

        const full_sum = addSIMD4(part_sum, packed_states[0]);
        packed_states[0] = subSIMD4(part_sum, packed_states[0]);

        packed_states[1] = addSIMD4(packed_states[1], full_sum);
        packed_states[2] = addSIMD4(doubleSIMD4(packed_states[2]), full_sum);
        packed_states[3] = addSIMD4(halveSIMD4(packed_states[3]), full_sum);
        packed_states[4] = addSIMD4(addSIMD4(doubleSIMD4(packed_states[4]), packed_states[4]), full_sum);
        packed_states[5] = addSIMD4(doubleSIMD4(doubleSIMD4(packed_states[5])), full_sum);
        packed_states[6] = subSIMD4(full_sum, halveSIMD4(packed_states[6]));
        packed_states[7] = subSIMD4(full_sum, addSIMD4(doubleSIMD4(packed_states[7]), packed_states[7]));
        packed_states[8] = subSIMD4(full_sum, doubleSIMD4(doubleSIMD4(packed_states[8])));
        packed_states[9] = addSIMD4(div2expSIMD4(packed_states[9], 8), full_sum);
        packed_states[10] = addSIMD4(div2expSIMD4(packed_states[10], 3), full_sum);
        packed_states[11] = addSIMD4(div2expSIMD4(packed_states[11], 24), full_sum);
        packed_states[12] = div2expSIMD4(packed_states[12], 8);
        packed_states[12] = subSIMD4(full_sum, packed_states[12]);
        packed_states[13] = div2expSIMD4(packed_states[13], 3);
        packed_states[13] = subSIMD4(full_sum, packed_states[13]);
        packed_states[14] = div2expSIMD4(packed_states[14], 4);
        packed_states[14] = subSIMD4(full_sum, packed_states[14]);
        packed_states[15] = div2expSIMD4(packed_states[15], 24);
        packed_states[15] = subSIMD4(full_sum, packed_states[15]);
    }

    /// SIMD-aware internal layer for 16-width - 8-wide
    fn applyInternalLayer16SIMD8Impl(
        packed_states: []@Vector(8, u32),
        rc: u32,
    ) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        const rc_broadcast: @Vector(8, u32) = @splat(rc);
        packed_states[0] = addSIMD8(packed_states[0], rc_broadcast);
        packed_states[0] = sboxSIMD8(packed_states[0]);

        var part_sum: @Vector(8, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD8(part_sum, packed_states[i]);
        }

        const full_sum = addSIMD8(part_sum, packed_states[0]);
        packed_states[0] = subSIMD8(part_sum, packed_states[0]);

        packed_states[1] = addSIMD8(packed_states[1], full_sum);
        packed_states[2] = addSIMD8(doubleSIMD8(packed_states[2]), full_sum);
        packed_states[3] = addSIMD8(halveSIMD8(packed_states[3]), full_sum);
        packed_states[4] = addSIMD8(addSIMD8(doubleSIMD8(packed_states[4]), packed_states[4]), full_sum);
        packed_states[5] = addSIMD8(doubleSIMD8(doubleSIMD8(packed_states[5])), full_sum);
        packed_states[6] = subSIMD8(full_sum, halveSIMD8(packed_states[6]));
        packed_states[7] = subSIMD8(full_sum, addSIMD8(doubleSIMD8(packed_states[7]), packed_states[7]));
        packed_states[8] = subSIMD8(full_sum, doubleSIMD8(doubleSIMD8(packed_states[8])));
        packed_states[9] = addSIMD8(div2expSIMD8(packed_states[9], 8), full_sum);
        packed_states[10] = addSIMD8(div2expSIMD8(packed_states[10], 3), full_sum);
        packed_states[11] = addSIMD8(div2expSIMD8(packed_states[11], 24), full_sum);
        packed_states[12] = div2expSIMD8(packed_states[12], 8);
        packed_states[12] = subSIMD8(full_sum, packed_states[12]);
        packed_states[13] = div2expSIMD8(packed_states[13], 3);
        packed_states[13] = subSIMD8(full_sum, packed_states[13]);
        packed_states[14] = div2expSIMD8(packed_states[14], 4);
        packed_states[14] = subSIMD8(full_sum, packed_states[14]);
        packed_states[15] = div2expSIMD8(packed_states[15], 24);
        packed_states[15] = subSIMD8(full_sum, packed_states[15]);
    }

    /// SIMD-aware internal layer for 16-width
    /// Applies internal layer operations to all lanes simultaneously
    fn applyInternalLayer16SIMD(
        packed_states: []@Vector(SIMD_WIDTH, u32),
        rc: u32, // rc is already in Montgomery form (pre-computed at compile time)
    ) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            applyInternalLayer16SIMD8Impl(state8, rc);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            applyInternalLayer16SIMD4Impl(state4, rc);
        }
    }

    /// SIMD-aware internal layer for 24-width - 4-wide
    fn applyInternalLayer24SIMD4Impl(
        packed_states: []@Vector(4, u32),
        rc: u32,
    ) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        const rc_broadcast: @Vector(4, u32) = @splat(rc);
        packed_states[0] = addSIMD4(packed_states[0], rc_broadcast);
        packed_states[0] = sboxSIMD4(packed_states[0]);

        var part_sum: @Vector(4, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD4(part_sum, packed_states[i]);
        }

        const full_sum = addSIMD4(part_sum, packed_states[0]);
        packed_states[0] = subSIMD4(part_sum, packed_states[0]);

        packed_states[1] = addSIMD4(packed_states[1], full_sum);
        packed_states[2] = addSIMD4(doubleSIMD4(packed_states[2]), full_sum);
        packed_states[3] = addSIMD4(halveSIMD4(packed_states[3]), full_sum);
        packed_states[4] = addSIMD4(addSIMD4(doubleSIMD4(packed_states[4]), packed_states[4]), full_sum);
        packed_states[5] = addSIMD4(doubleSIMD4(doubleSIMD4(packed_states[5])), full_sum);
        packed_states[6] = subSIMD4(full_sum, halveSIMD4(packed_states[6]));
        packed_states[7] = subSIMD4(full_sum, addSIMD4(doubleSIMD4(packed_states[7]), packed_states[7]));
        packed_states[8] = subSIMD4(full_sum, doubleSIMD4(doubleSIMD4(packed_states[8])));
        packed_states[9] = addSIMD4(div2expSIMD4(packed_states[9], 8), full_sum);
        packed_states[10] = addSIMD4(div2expSIMD4(packed_states[10], 2), full_sum);
        packed_states[11] = addSIMD4(div2expSIMD4(packed_states[11], 3), full_sum);
        packed_states[12] = addSIMD4(div2expSIMD4(packed_states[12], 4), full_sum);
        packed_states[13] = addSIMD4(div2expSIMD4(packed_states[13], 5), full_sum);
        packed_states[14] = addSIMD4(div2expSIMD4(packed_states[14], 6), full_sum);
        packed_states[15] = addSIMD4(div2expSIMD4(packed_states[15], 24), full_sum);
        packed_states[16] = div2expSIMD4(packed_states[16], 8);
        packed_states[16] = subSIMD4(full_sum, packed_states[16]);
        packed_states[17] = div2expSIMD4(packed_states[17], 3);
        packed_states[17] = subSIMD4(full_sum, packed_states[17]);
        packed_states[18] = div2expSIMD4(packed_states[18], 4);
        packed_states[18] = subSIMD4(full_sum, packed_states[18]);
        packed_states[19] = div2expSIMD4(packed_states[19], 5);
        packed_states[19] = subSIMD4(full_sum, packed_states[19]);
        packed_states[20] = div2expSIMD4(packed_states[20], 6);
        packed_states[20] = subSIMD4(full_sum, packed_states[20]);
        packed_states[21] = div2expSIMD4(packed_states[21], 7);
        packed_states[21] = subSIMD4(full_sum, packed_states[21]);
        packed_states[22] = div2expSIMD4(packed_states[22], 9);
        packed_states[22] = subSIMD4(full_sum, packed_states[22]);
        packed_states[23] = div2expSIMD4(packed_states[23], 24);
        packed_states[23] = subSIMD4(full_sum, packed_states[23]);
    }

    /// SIMD-aware internal layer for 24-width - 8-wide
    fn applyInternalLayer24SIMD8Impl(
        packed_states: []@Vector(8, u32),
        rc: u32,
    ) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        const rc_broadcast: @Vector(8, u32) = @splat(rc);
        packed_states[0] = addSIMD8(packed_states[0], rc_broadcast);
        packed_states[0] = sboxSIMD8(packed_states[0]);

        var part_sum: @Vector(8, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD8(part_sum, packed_states[i]);
        }

        const full_sum = addSIMD8(part_sum, packed_states[0]);
        packed_states[0] = subSIMD8(part_sum, packed_states[0]);

        packed_states[1] = addSIMD8(packed_states[1], full_sum);
        packed_states[2] = addSIMD8(doubleSIMD8(packed_states[2]), full_sum);
        packed_states[3] = addSIMD8(halveSIMD8(packed_states[3]), full_sum);
        packed_states[4] = addSIMD8(addSIMD8(doubleSIMD8(packed_states[4]), packed_states[4]), full_sum);
        packed_states[5] = addSIMD8(doubleSIMD8(doubleSIMD8(packed_states[5])), full_sum);
        packed_states[6] = subSIMD8(full_sum, halveSIMD8(packed_states[6]));
        packed_states[7] = subSIMD8(full_sum, addSIMD8(doubleSIMD8(packed_states[7]), packed_states[7]));
        packed_states[8] = subSIMD8(full_sum, doubleSIMD8(doubleSIMD8(packed_states[8])));
        packed_states[9] = addSIMD8(div2expSIMD8(packed_states[9], 8), full_sum);
        packed_states[10] = addSIMD8(div2expSIMD8(packed_states[10], 2), full_sum);
        packed_states[11] = addSIMD8(div2expSIMD8(packed_states[11], 3), full_sum);
        packed_states[12] = addSIMD8(div2expSIMD8(packed_states[12], 4), full_sum);
        packed_states[13] = addSIMD8(div2expSIMD8(packed_states[13], 5), full_sum);
        packed_states[14] = addSIMD8(div2expSIMD8(packed_states[14], 6), full_sum);
        packed_states[15] = addSIMD8(div2expSIMD8(packed_states[15], 24), full_sum);
        packed_states[16] = div2expSIMD8(packed_states[16], 8);
        packed_states[16] = subSIMD8(full_sum, packed_states[16]);
        packed_states[17] = div2expSIMD8(packed_states[17], 3);
        packed_states[17] = subSIMD8(full_sum, packed_states[17]);
        packed_states[18] = div2expSIMD8(packed_states[18], 4);
        packed_states[18] = subSIMD8(full_sum, packed_states[18]);
        packed_states[19] = div2expSIMD8(packed_states[19], 5);
        packed_states[19] = subSIMD8(full_sum, packed_states[19]);
        packed_states[20] = div2expSIMD8(packed_states[20], 6);
        packed_states[20] = subSIMD8(full_sum, packed_states[20]);
        packed_states[21] = div2expSIMD8(packed_states[21], 7);
        packed_states[21] = subSIMD8(full_sum, packed_states[21]);
        packed_states[22] = div2expSIMD8(packed_states[22], 9);
        packed_states[22] = subSIMD8(full_sum, packed_states[22]);
        packed_states[23] = div2expSIMD8(packed_states[23], 24);
        packed_states[23] = subSIMD8(full_sum, packed_states[23]);
    }

    /// SIMD-aware internal layer for 24-width
    /// Applies internal layer operations to all lanes simultaneously
    fn applyInternalLayer24SIMD(
        packed_states: []@Vector(SIMD_WIDTH, u32),
        rc: u32, // rc is already in Montgomery form (pre-computed at compile time)
    ) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            applyInternalLayer24SIMD8Impl(state8, rc);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            applyInternalLayer24SIMD4Impl(state4, rc);
        }
    }

    /// SIMD-aware subtraction (Montgomery form) - 4-wide
    fn subSIMD4(a: @Vector(4, u32), b: @Vector(4, u32)) @Vector(4, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        var result: @Vector(4, u32) = undefined;
        inline for (0..4) |i| {
            const sub_result = @subWithOverflow(a[i], b[i]);
            const diff = sub_result[0];
            const over = sub_result[1];
            const corr = if (over != 0) KOALABEAR_PRIME else 0;
            result[i] = diff +% corr;
        }
        return result;
    }

    /// SIMD-aware subtraction (Montgomery form) - 8-wide
    fn subSIMD8(a: @Vector(8, u32), b: @Vector(8, u32)) @Vector(8, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        var result: @Vector(8, u32) = undefined;
        inline for (0..8) |i| {
            const sub_result = @subWithOverflow(a[i], b[i]);
            const diff = sub_result[0];
            const over = sub_result[1];
            const corr = if (over != 0) KOALABEAR_PRIME else 0;
            result[i] = diff +% corr;
        }
        return result;
    }

    /// SIMD-aware subtraction (Montgomery form)
    fn subSIMD(a: @Vector(SIMD_WIDTH, u32), b: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        if (SIMD_WIDTH == 8) {
            return subSIMD8(a, b);
        } else {
            return subSIMD4(a, b);
        }
    }

    /// True SIMD Poseidon2-16 permutation - 4-wide implementation
    fn permute16SIMD4Impl(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(4, u32),
    ) void {
        _ = self;
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC16_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL_MONTY;
        const RC16_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL_MONTY;
        const RC16_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_INTERNAL_MONTY;

        // Initial MDS light transformation
        mdsLightPermutation16SIMD4Impl(packed_states);

        // Initial external rounds (4 rounds)
        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(4, u32) = @splat(RC16_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD4(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD4(packed_states[i]);
            }
            for (0..4) |i| {
                applyMat4SIMD4Impl(packed_states, i * 4);
            }
            var sums: [4]@Vector(4, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD4(sums[k], packed_states[j + k]);
                }
            }
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD4(packed_states[i], sums[i % 4]);
            }
        }

        // Internal rounds (20 rounds)
        for (0..20) |round| {
            applyInternalLayer16SIMD4Impl(packed_states, RC16_INTERNAL[round]);
        }

        // Final external rounds (4 rounds)
        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(4, u32) = @splat(RC16_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD4(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD4(packed_states[i]);
            }
            for (0..4) |i| {
                applyMat4SIMD4Impl(packed_states, i * 4);
            }
            var sums: [4]@Vector(4, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD4(sums[k], packed_states[j + k]);
                }
            }
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD4(packed_states[i], sums[i % 4]);
            }
        }
    }

    /// True SIMD Poseidon2-16 permutation - 8-wide implementation
    fn permute16SIMD8Impl(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(8, u32),
    ) void {
        _ = self;
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC16_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL_MONTY;
        const RC16_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL_MONTY;
        const RC16_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_INTERNAL_MONTY;

        // Initial MDS light transformation
        mdsLightPermutation16SIMD8Impl(packed_states);

        // Initial external rounds (4 rounds)
        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(8, u32) = @splat(RC16_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD8(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD8(packed_states[i]);
            }
            for (0..4) |i| {
                applyMat4SIMD8Impl(packed_states, i * 4);
            }
            var sums: [4]@Vector(8, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD8(sums[k], packed_states[j + k]);
                }
            }
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD8(packed_states[i], sums[i % 4]);
            }
        }

        // Internal rounds (20 rounds)
        for (0..20) |round| {
            applyInternalLayer16SIMD8Impl(packed_states, RC16_INTERNAL[round]);
        }

        // Final external rounds (4 rounds)
        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(8, u32) = @splat(RC16_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD8(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD8(packed_states[i]);
            }
            for (0..4) |i| {
                applyMat4SIMD8Impl(packed_states, i * 4);
            }
            var sums: [4]@Vector(8, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD8(sums[k], packed_states[j + k]);
                }
            }
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD8(packed_states[i], sums[i % 4]);
            }
        }
    }

    /// True SIMD Poseidon2-16 permutation
    /// Processes multiple states simultaneously using SIMD operations
    /// Wrapper that dispatches to 4-wide or 8-wide based on SIMD_WIDTH
    fn permute16SIMD(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(SIMD_WIDTH, u32),
    ) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            permute16SIMD8Impl(self, state8);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            permute16SIMD4Impl(self, state4);
        }
    }

    /// Legacy permute16SIMD implementation (kept for reference, now unused)
    fn permute16SIMD_legacy(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(SIMD_WIDTH, u32),
    ) void {
        _ = self;
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;

        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC16_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL_MONTY;
        const RC16_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL_MONTY;
        const RC16_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_INTERNAL_MONTY;

        // Initial MDS light transformation (before any rounds)
        mdsLightPermutation16SIMD(packed_states);

        // Initial external rounds (4 rounds)
        for (0..4) |round| {
            // Add round constants (already in Montgomery form - pre-computed at compile time)
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(RC16_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD(packed_states[i], rc_broadcast);
            }

            // Apply S-box to all elements
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD(packed_states[i]);
            }

            // Apply MDS matrix in 4x4 blocks
            for (0..4) |i| {
                applyMat4SIMD(packed_states, i * 4);
            }

            // Apply outer circulant matrix
            var sums: [4]@Vector(SIMD_WIDTH, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD(sums[k], packed_states[j + k]);
                }
            }

            // Add appropriate sum to each element
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD(packed_states[i], sums[i % 4]);
            }
        }

        // Internal rounds (20 rounds)
        for (0..20) |round| {
            applyInternalLayer16SIMD(packed_states, RC16_INTERNAL[round]);
        }

        // Final external rounds (4 rounds)
        for (0..4) |round| {
            // Add round constants (already in Montgomery form - pre-computed at compile time)
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(RC16_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD(packed_states[i], rc_broadcast);
            }

            // Apply S-box to all elements
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD(packed_states[i]);
            }

            // Apply MDS matrix in 4x4 blocks
            for (0..4) |i| {
                applyMat4SIMD(packed_states, i * 4);
            }

            // Apply outer circulant matrix
            var sums: [4]@Vector(SIMD_WIDTH, u32) = undefined;
            for (0..4) |k| {
                sums[k] = @splat(@as(u32, 0));
                var j: usize = 0;
                while (j < WIDTH) : (j += 4) {
                    sums[k] = addSIMD(sums[k], packed_states[j + k]);
                }
            }

            // Add appropriate sum to each element
            for (0..WIDTH) |i| {
                packed_states[i] = addSIMD(packed_states[i], sums[i % 4]);
            }
        }
    }

    /// True SIMD Poseidon2-24 permutation - 4-wide implementation
    fn permute24SIMD4Impl(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(4, u32),
    ) void {
        _ = self;
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC24_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_INITIAL_MONTY;
        const RC24_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_FINAL_MONTY;
        const RC24_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_INTERNAL_MONTY;

        mdsLightPermutation24SIMD4Impl(packed_states);

        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(4, u32) = @splat(RC24_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD4(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD4(packed_states[i]);
            }
            mdsLightPermutation24SIMD4Impl(packed_states);
        }

        for (0..23) |round| {
            applyInternalLayer24SIMD4Impl(packed_states, RC24_INTERNAL[round]);
        }

        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(4, u32) = @splat(RC24_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD4(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD4(packed_states[i]);
            }
            mdsLightPermutation24SIMD4Impl(packed_states);
        }
    }

    /// True SIMD Poseidon2-24 permutation - 8-wide implementation
    fn permute24SIMD8Impl(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(8, u32),
    ) void {
        _ = self;
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;

        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC24_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_INITIAL_MONTY;
        const RC24_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_FINAL_MONTY;
        const RC24_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_INTERNAL_MONTY;

        mdsLightPermutation24SIMD8Impl(packed_states);

        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(8, u32) = @splat(RC24_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD8(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD8(packed_states[i]);
            }
            mdsLightPermutation24SIMD8Impl(packed_states);
        }

        for (0..23) |round| {
            applyInternalLayer24SIMD8Impl(packed_states, RC24_INTERNAL[round]);
        }

        for (0..4) |round| {
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(8, u32) = @splat(RC24_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD8(packed_states[i], rc_broadcast);
            }
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD8(packed_states[i]);
            }
            mdsLightPermutation24SIMD8Impl(packed_states);
        }
    }

    /// True SIMD Poseidon2-24 permutation
    /// Processes multiple states simultaneously using SIMD operations
    /// Wrapper that dispatches to 4-wide or 8-wide based on SIMD_WIDTH
    fn permute24SIMD(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(SIMD_WIDTH, u32),
    ) void {
        if (SIMD_WIDTH == 8) {
            const state8 = @as([*]@Vector(8, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            permute24SIMD8Impl(self, state8);
        } else {
            const state4 = @as([*]@Vector(4, u32), @ptrCast(packed_states.ptr))[0..packed_states.len];
            permute24SIMD4Impl(self, state4);
        }
    }
};
