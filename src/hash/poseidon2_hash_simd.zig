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
    pub fn compress16SIMD(
        self: *Poseidon2SIMD,
        packed_input: []const simd_utils.PackedF,
        out_len: usize,
    ) ![]simd_utils.PackedF {
        const input_len = packed_input.len;
        const USE_TRUE_SIMD = true; // Enabled - SIMD permutation verified
        
        if (USE_TRUE_SIMD) {
            // True SIMD path (currently disabled due to internal layer complexity)
            var packed_states: [WIDTH_16]@Vector(SIMD_WIDTH, u32) = undefined;
            
            // Initialize state from packed input
            for (0..WIDTH_16) |i| {
                if (i < input_len) {
                    packed_states[i] = packed_input[i].values;
                } else {
                    packed_states[i] = @splat(@as(u32, 0));
                }
            }
            
            const packed_input_states = packed_states;
            permute16SIMD(self, &packed_states);
            
            // Feed-forward
            for (0..WIDTH_16) |i| {
                packed_states[i] = addSIMD(packed_states[i], packed_input_states[i]);
            }
            
            var packed_output = try self.allocator.alloc(simd_utils.PackedF, out_len);
            errdefer self.allocator.free(packed_output);
            
            for (0..out_len) |i| {
                packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
            }
            
            return packed_output;
        } else {
            // Optimized batch processing path (maintains compatibility)
            var packed_output = try self.allocator.alloc(simd_utils.PackedF, out_len);
            errdefer self.allocator.free(packed_output);
            
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
                lane_outputs[lane] = try self.poseidon2.hashFieldElements16(self.allocator, lane_states[lane][0..WIDTH_16]);
            }
            
            // Pack outputs back into SIMD format
            for (0..out_len) |i| {
                const values: @Vector(SIMD_WIDTH, u32) = .{
                    if (i < lane_outputs[0].len) lane_outputs[0][i].value else 0,
                    if (i < lane_outputs[1].len) lane_outputs[1][i].value else 0,
                    if (i < lane_outputs[2].len) lane_outputs[2][i].value else 0,
                    if (i < lane_outputs[3].len) lane_outputs[3][i].value else 0,
                };
                packed_output[i] = simd_utils.PackedF{ .values = values };
            }
            
            return packed_output;
        }
    }
    
    /// Compress SIMD-packed inputs using Poseidon2-24
    /// This is the SIMD equivalent of poseidon_compress for 24-width
    /// 
    /// Input: packed_input is [element][lane] format (vertical packing)
    /// Output: packed_output is [element][lane] format
    pub fn compress24SIMD(
        self: *Poseidon2SIMD,
        packed_input: []const simd_utils.PackedF,
        out_len: usize,
    ) ![]simd_utils.PackedF {
        const WIDTH_24 = 24;
        const input_len = packed_input.len;
        const USE_TRUE_SIMD = true; // Enabled - SIMD permutation verified
        
        if (USE_TRUE_SIMD) {
            // True SIMD path
            var packed_states: [WIDTH_24]@Vector(SIMD_WIDTH, u32) = undefined;
            
            // Initialize state from packed input
            for (0..WIDTH_24) |i| {
                if (i < input_len) {
                    packed_states[i] = packed_input[i].values;
                } else {
                    packed_states[i] = @splat(@as(u32, 0));
                }
            }
            
            const packed_input_states = packed_states;
            permute24SIMD(self, &packed_states);
            
            // Feed-forward
            for (0..WIDTH_24) |i| {
                packed_states[i] = addSIMD(packed_states[i], packed_input_states[i]);
            }
            
            var packed_output = try self.allocator.alloc(simd_utils.PackedF, out_len);
            errdefer self.allocator.free(packed_output);
            
            for (0..out_len) |i| {
                packed_output[i] = simd_utils.PackedF{ .values = packed_states[i] };
            }
            
            return packed_output;
        } else {
            // Fallback to batch processing
            var packed_output = try self.allocator.alloc(simd_utils.PackedF, out_len);
            errdefer self.allocator.free(packed_output);
            
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
            
            // Pack outputs back into SIMD format
            for (0..out_len) |i| {
                const values: @Vector(SIMD_WIDTH, u32) = .{
                    if (i < lane_outputs[0].len) lane_outputs[0][i].value else 0,
                    if (i < lane_outputs[1].len) lane_outputs[1][i].value else 0,
                    if (i < lane_outputs[2].len) lane_outputs[2][i].value else 0,
                    if (i < lane_outputs[3].len) lane_outputs[3][i].value else 0,
                };
                packed_output[i] = simd_utils.PackedF{ .values = values };
            }
            
            return packed_output;
        }
    }
    
    /// SIMD-aware field addition (Montgomery form)
    /// Adds two vectors of field elements element-wise
    fn addSIMD(a: @Vector(SIMD_WIDTH, u32), b: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        const sum = a +% b;
        // Reduce mod prime if needed (simple check: if sum >= prime, subtract prime)
        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            result[i] = if (sum[i] >= KOALABEAR_PRIME) sum[i] -% KOALABEAR_PRIME else sum[i];
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
    
    /// SIMD-aware S-box (x^3 operation)
    /// Applies x^3 to each element in the vector
    fn sboxSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        // x^3 = x * x * x
        const x2 = mulSIMD(x, x);
        return mulSIMD(x2, x);
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
    
    /// SIMD-aware MDS matrix application (4x4 block)
    /// Applies the MDS matrix to 4 elements across all SIMD lanes
    fn applyMat4SIMD(
        state: []@Vector(SIMD_WIDTH, u32),
        start_idx: usize,
    ) void {
        if (start_idx + 4 > state.len) return;
        
        // Matrix: [ 2 3 1 1 ]
        //         [ 1 2 3 1 ]
        //         [ 1 1 2 3 ]
        //         [ 3 1 1 2 ]
        
        // Store original values
        const x0 = state[start_idx + 0];
        const x1 = state[start_idx + 1];
        const x2 = state[start_idx + 2];
        const x3 = state[start_idx + 3];
        
        // t01 = x[0] + x[1]
        const t01 = addSIMD(x0, x1);
        
        // t23 = x[2] + x[3]
        const t23 = addSIMD(x2, x3);
        
        // t0123 = t01 + t23
        const t0123 = addSIMD(t01, t23);
        
        // t01123 = t0123 + x[1]
        const t01123 = addSIMD(t0123, x1);
        
        // t01233 = t0123 + x[3]
        const t01233 = addSIMD(t0123, x3);
        
        // x[3] = t01233 + 2*x[0] = t01233 + x[0] + x[0]
        const x0_double = addSIMD(x0, x0);
        state[start_idx + 3] = addSIMD(t01233, x0_double);
        
        // x[1] = t01123 + 2*x[2] = t01123 + x[2] + x[2]
        const x2_double = addSIMD(x2, x2);
        state[start_idx + 1] = addSIMD(t01123, x2_double);
        
        // x[0] = t01123 + t01
        state[start_idx + 0] = addSIMD(t01123, t01);
        
        // x[2] = t01233 + t23
        state[start_idx + 2] = addSIMD(t01233, t23);
    }
    
    /// SIMD-aware MDS light permutation for 16-width
    /// Applies MDS light to all lanes simultaneously
    fn mdsLightPermutation16SIMD(packed_states: []@Vector(SIMD_WIDTH, u32)) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;
        
        // First, apply M_4 to each consecutive four elements
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
    
    /// SIMD-aware MDS light permutation for 24-width
    /// Applies MDS light to all lanes simultaneously
    fn mdsLightPermutation24SIMD(packed_states: []@Vector(SIMD_WIDTH, u32)) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;
        
        // First, apply M_4 to each consecutive four elements (6 blocks for 24-width)
        for (0..6) |i| {
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
    
    /// SIMD-aware div2exp (division by power of 2)
    /// Divides each element by 2^exponent in Montgomery form
    fn div2expSIMD(x: @Vector(SIMD_WIDTH, u32), exponent: u32) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        
        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            if (exponent <= 32) {
                // As the monty form of 2^{-exp} is 2^{32 - exp} mod P
                const long_prod = @as(u64, x[i]) << @as(u6, @intCast(32 - exponent));
                result[i] = montyReduceSIMD(long_prod);
            } else {
                // For larger values, use repeated halving (simplified)
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
    
    /// SIMD-aware double operation
    fn doubleSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        return addSIMD(x, x);
    }
    
    /// SIMD-aware halve operation
    fn halveSIMD(x: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_HALF_P_PLUS_1: u32 = 0x3f800001;
        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            const shr = x[i] >> 1;
            const lo_bit = x[i] & 1;
            const shr_corr = shr +% KOALABEAR_HALF_P_PLUS_1;
            result[i] = if (lo_bit == 0) shr else shr_corr;
        }
        return result;
    }
    
    /// SIMD-aware internal layer for 16-width
    /// Applies internal layer operations to all lanes simultaneously
    fn applyInternalLayer16SIMD(
        packed_states: []@Vector(SIMD_WIDTH, u32),
        rc: u32,
    ) void {
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;
        
        const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(rc);
        
        // Add round constant to first element
        packed_states[0] = addSIMD(packed_states[0], rc_broadcast);
        
        // Apply S-box to first element
        packed_states[0] = sboxSIMD(packed_states[0]);
        
        // Compute partial sum of state[1..]
        var part_sum: @Vector(SIMD_WIDTH, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD(part_sum, packed_states[i]);
        }
        
        // Compute full sum
        const full_sum = addSIMD(part_sum, packed_states[0]);
        
        // Apply internal matrix: state[0] = part_sum - state[0]
        packed_states[0] = subSIMD(part_sum, packed_states[0]);
        
        // Apply V-based operations for i >= 1 (matching Plonky3 exactly)
        // state[1] += sum
        packed_states[1] = addSIMD(packed_states[1], full_sum);
        
        // state[2] = state[2].double() + sum
        packed_states[2] = addSIMD(doubleSIMD(packed_states[2]), full_sum);
        
        // state[3] = state[3].halve() + sum
        packed_states[3] = addSIMD(halveSIMD(packed_states[3]), full_sum);
        
        // state[4] = sum + state[4].double() + state[4]
        packed_states[4] = addSIMD(addSIMD(doubleSIMD(packed_states[4]), packed_states[4]), full_sum);
        
        // state[5] = sum + state[5].double().double()
        packed_states[5] = addSIMD(doubleSIMD(doubleSIMD(packed_states[5])), full_sum);
        
        // state[6] = sum - state[6].halve()
        packed_states[6] = subSIMD(full_sum, halveSIMD(packed_states[6]));
        
        // state[7] = sum - (state[7].double() + state[7])
        packed_states[7] = subSIMD(full_sum, addSIMD(doubleSIMD(packed_states[7]), packed_states[7]));
        
        // state[8] = sum - state[8].double().double()
        packed_states[8] = subSIMD(full_sum, doubleSIMD(doubleSIMD(packed_states[8])));
        
        // state[9] = state[9].div_2exp_u64(8) + sum
        packed_states[9] = addSIMD(div2expSIMD(packed_states[9], 8), full_sum);
        
        // state[10] = state[10].div_2exp_u64(3) + sum
        packed_states[10] = addSIMD(div2expSIMD(packed_states[10], 3), full_sum);
        
        // state[11] = state[11].div_2exp_u64(24) + sum
        packed_states[11] = addSIMD(div2expSIMD(packed_states[11], 24), full_sum);
        
        // state[12] = state[12].div_2exp_u64(8), then sum - state[12]
        packed_states[12] = div2expSIMD(packed_states[12], 8);
        packed_states[12] = subSIMD(full_sum, packed_states[12]);
        
        // state[13] = state[13].div_2exp_u64(3), then sum - state[13]
        packed_states[13] = div2expSIMD(packed_states[13], 3);
        packed_states[13] = subSIMD(full_sum, packed_states[13]);
        
        // state[14] = state[14].div_2exp_u64(4), then sum - state[14]
        packed_states[14] = div2expSIMD(packed_states[14], 4);
        packed_states[14] = subSIMD(full_sum, packed_states[14]);
        
        // state[15] = state[15].div_2exp_u64(24), then sum - state[15]
        packed_states[15] = div2expSIMD(packed_states[15], 24);
        packed_states[15] = subSIMD(full_sum, packed_states[15]);
    }
    
    /// SIMD-aware internal layer for 24-width
    /// Applies internal layer operations to all lanes simultaneously
    fn applyInternalLayer24SIMD(
        packed_states: []@Vector(SIMD_WIDTH, u32),
        rc: u32,
    ) void {
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;
        
        const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(rc);
        
        // Add round constant to first element
        packed_states[0] = addSIMD(packed_states[0], rc_broadcast);
        
        // Apply S-box to first element
        packed_states[0] = sboxSIMD(packed_states[0]);
        
        // Compute partial sum of state[1..]
        var part_sum: @Vector(SIMD_WIDTH, u32) = @splat(@as(u32, 0));
        for (1..WIDTH) |i| {
            part_sum = addSIMD(part_sum, packed_states[i]);
        }
        
        // Compute full sum
        const full_sum = addSIMD(part_sum, packed_states[0]);
        
        // Apply internal matrix: state[0] = part_sum - state[0]
        packed_states[0] = subSIMD(part_sum, packed_states[0]);
        
        // Apply V-based operations for i >= 1 (matching Plonky3 exactly for 24-width)
        // state[1] += sum
        packed_states[1] = addSIMD(packed_states[1], full_sum);
        
        // state[2] = state[2].double() + sum
        packed_states[2] = addSIMD(doubleSIMD(packed_states[2]), full_sum);
        
        // state[3] = state[3].halve() + sum
        packed_states[3] = addSIMD(halveSIMD(packed_states[3]), full_sum);
        
        // state[4] = sum + state[4].double() + state[4]
        packed_states[4] = addSIMD(addSIMD(doubleSIMD(packed_states[4]), packed_states[4]), full_sum);
        
        // state[5] = sum + state[5].double().double()
        packed_states[5] = addSIMD(doubleSIMD(doubleSIMD(packed_states[5])), full_sum);
        
        // state[6] = sum - state[6].halve()
        packed_states[6] = subSIMD(full_sum, halveSIMD(packed_states[6]));
        
        // state[7] = sum - (state[7].double() + state[7])
        packed_states[7] = subSIMD(full_sum, addSIMD(doubleSIMD(packed_states[7]), packed_states[7]));
        
        // state[8] = sum - state[8].double().double()
        packed_states[8] = subSIMD(full_sum, doubleSIMD(doubleSIMD(packed_states[8])));
        
        // state[9] = state[9].div_2exp_u64(8) + sum
        packed_states[9] = addSIMD(div2expSIMD(packed_states[9], 8), full_sum);
        
        // state[10] = state[10].div_2exp_u64(2) + sum
        packed_states[10] = addSIMD(div2expSIMD(packed_states[10], 2), full_sum);
        
        // state[11] = state[11].div_2exp_u64(3) + sum
        packed_states[11] = addSIMD(div2expSIMD(packed_states[11], 3), full_sum);
        
        // state[12] = state[12].div_2exp_u64(4) + sum
        packed_states[12] = addSIMD(div2expSIMD(packed_states[12], 4), full_sum);
        
        // state[13] = state[13].div_2exp_u64(5) + sum
        packed_states[13] = addSIMD(div2expSIMD(packed_states[13], 5), full_sum);
        
        // state[14] = state[14].div_2exp_u64(6) + sum
        packed_states[14] = addSIMD(div2expSIMD(packed_states[14], 6), full_sum);
        
        // state[15] = state[15].div_2exp_u64(24) + sum
        packed_states[15] = addSIMD(div2expSIMD(packed_states[15], 24), full_sum);
        
        // state[16] = state[16].div_2exp_u64(8), then sum - state[16]
        packed_states[16] = div2expSIMD(packed_states[16], 8);
        packed_states[16] = subSIMD(full_sum, packed_states[16]);
        
        // state[17] = state[17].div_2exp_u64(3), then sum - state[17]
        packed_states[17] = div2expSIMD(packed_states[17], 3);
        packed_states[17] = subSIMD(full_sum, packed_states[17]);
        
        // state[18] = state[18].div_2exp_u64(4), then sum - state[18]
        packed_states[18] = div2expSIMD(packed_states[18], 4);
        packed_states[18] = subSIMD(full_sum, packed_states[18]);
        
        // state[19] = state[19].div_2exp_u64(5), then sum - state[19]
        packed_states[19] = div2expSIMD(packed_states[19], 5);
        packed_states[19] = subSIMD(full_sum, packed_states[19]);
        
        // state[20] = state[20].div_2exp_u64(6), then sum - state[20]
        packed_states[20] = div2expSIMD(packed_states[20], 6);
        packed_states[20] = subSIMD(full_sum, packed_states[20]);
        
        // state[21] = state[21].div_2exp_u64(7), then sum - state[21]
        packed_states[21] = div2expSIMD(packed_states[21], 7);
        packed_states[21] = subSIMD(full_sum, packed_states[21]);
        
        // state[22] = state[22].div_2exp_u64(9), then sum - state[22]
        packed_states[22] = div2expSIMD(packed_states[22], 9);
        packed_states[22] = subSIMD(full_sum, packed_states[22]);
        
        // state[23] = state[23].div_2exp_u64(24), then sum - state[23]
        packed_states[23] = div2expSIMD(packed_states[23], 24);
        packed_states[23] = subSIMD(full_sum, packed_states[23]);
    }
    
    /// SIMD-aware subtraction (Montgomery form)
    fn subSIMD(a: @Vector(SIMD_WIDTH, u32), b: @Vector(SIMD_WIDTH, u32)) @Vector(SIMD_WIDTH, u32) {
        const KOALABEAR_PRIME: u32 = 0x7f000001;
        var result: @Vector(SIMD_WIDTH, u32) = undefined;
        inline for (0..SIMD_WIDTH) |i| {
            const sub_result = @subWithOverflow(a[i], b[i]);
            const diff = sub_result[0];
            const over = sub_result[1];
            const corr = if (over != 0) KOALABEAR_PRIME else 0;
            result[i] = diff +% corr;
        }
        return result;
    }
    
    /// True SIMD Poseidon2-16 permutation
    /// Processes multiple states simultaneously using SIMD operations
    fn permute16SIMD(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(SIMD_WIDTH, u32),
    ) void {
        _ = self;
        const WIDTH = 16;
        if (packed_states.len != WIDTH) return;
        
        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC16_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_INITIAL;
        const RC16_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_EXTERNAL_FINAL;
        const RC16_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC16_INTERNAL;
        
        // Initial MDS light transformation (before any rounds)
        mdsLightPermutation16SIMD(packed_states);
        
        // Initial external rounds (4 rounds)
        for (0..4) |round| {
            // Add round constants
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
            // Add round constants
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
    
    /// True SIMD Poseidon2-24 permutation
    /// Processes multiple states simultaneously using SIMD operations
    fn permute24SIMD(
        self: *Poseidon2SIMD,
        packed_states: []@Vector(SIMD_WIDTH, u32),
    ) void {
        _ = self;
        const WIDTH = 24;
        if (packed_states.len != WIDTH) return;
        
        const poseidon2_mod = @import("../poseidon2/poseidon2.zig");
        const RC24_EXTERNAL_INITIAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_INITIAL;
        const RC24_EXTERNAL_FINAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_EXTERNAL_FINAL;
        const RC24_INTERNAL = poseidon2_mod.PLONKY3_KOALABEAR_RC24_INTERNAL;
        
        // Initial MDS light transformation (before any rounds) - matching Rust
        mdsLightPermutation24SIMD(packed_states);
        
        // Initial external rounds (4 rounds)
        // Note: Rust applies MDS light INSIDE each round for 24-width
        for (0..4) |round| {
            // Add round constants
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(RC24_EXTERNAL_INITIAL[round][i]);
                packed_states[i] = addSIMD(packed_states[i], rc_broadcast);
            }
            
            // Apply S-box to all elements
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD(packed_states[i]);
            }
            
            // Apply MDS light (not full MDS matrix) - matching Rust's external_terminal_permute_state
            mdsLightPermutation24SIMD(packed_states);
        }
        
        // Internal rounds (23 rounds)
        for (0..23) |round| {
            applyInternalLayer24SIMD(packed_states, RC24_INTERNAL[round]);
        }
        
        // Final external rounds (4 rounds)
        // Note: Rust applies MDS light INSIDE each round for 24-width
        for (0..4) |round| {
            // Add round constants
            for (0..WIDTH) |i| {
                const rc_broadcast: @Vector(SIMD_WIDTH, u32) = @splat(RC24_EXTERNAL_FINAL[round][i]);
                packed_states[i] = addSIMD(packed_states[i], rc_broadcast);
            }
            
            // Apply S-box to all elements
            for (0..WIDTH) |i| {
                packed_states[i] = sboxSIMD(packed_states[i]);
            }
            
            // Apply MDS light (not full MDS matrix) - matching Rust's external_terminal_permute_state
            mdsLightPermutation24SIMD(packed_states);
        }
    }
};


