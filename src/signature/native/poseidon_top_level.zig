const std = @import("std");
const log = @import("../../utils/log.zig");
const FieldElement = @import("../../core/field.zig").FieldElement;
const KOALABEAR_PRIME = @import("../../core/field.zig").KOALABEAR_PRIME;
const BigInt = std.math.big.int.Managed;

pub const LayerInfo = struct {
    sizes: []BigInt,
    prefix_sums: []BigInt,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *LayerInfo) void {
        for (self.sizes) |*value| {
            value.deinit();
        }
        if (self.sizes.len > 0) self.allocator.free(self.sizes);

        for (self.prefix_sums) |*value| {
            value.deinit();
        }
        if (self.prefix_sums.len > 0) self.allocator.free(self.prefix_sums);
    }
};

pub const AllLayerInfoForBase = struct {
    layers: []LayerInfo,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *AllLayerInfoForBase) void {
        for (self.layers) |*layer| {
            layer.deinit();
        }
        self.allocator.free(self.layers);
    }

    pub fn get(self: *const AllLayerInfoForBase, v: usize) *const LayerInfo {
        return &self.layers[v];
    }
};

fn initBigIntSlice(allocator: std.mem.Allocator, len: usize) ![]BigInt {
    const slice = try allocator.alloc(BigInt, len);
    errdefer allocator.free(slice);
    for (slice) |*item| {
        item.* = try BigInt.init(allocator);
    }
    return slice;
}

fn prepareLayerInfo(allocator: std.mem.Allocator, w: usize) !AllLayerInfoForBase {
    const MAX_DIMENSION: usize = 100;

    var all_info = try allocator.alloc(LayerInfo, MAX_DIMENSION + 1);
    errdefer {
        for (all_info) |*info| {
            info.deinit();
        }
        allocator.free(all_info);
    }

    for (all_info) |*info| {
        info.* = LayerInfo{
            .sizes = &[_]BigInt{},
            .prefix_sums = &[_]BigInt{},
            .allocator = allocator,
        };
    }

    const dim1_sizes = try initBigIntSlice(allocator, w);
    errdefer {
        for (dim1_sizes) |*value| value.deinit();
        allocator.free(dim1_sizes);
    }
    const dim1_prefix_sums = try initBigIntSlice(allocator, w);
    errdefer {
        for (dim1_prefix_sums) |*value| value.deinit();
        allocator.free(dim1_prefix_sums);
    }

    for (dim1_sizes) |*val| {
        try val.set(1);
    }
    var cumulative = try BigInt.initSet(allocator, 0);
    defer cumulative.deinit();
    for (dim1_prefix_sums) |*prefix| {
        try BigInt.addScalar(&cumulative, &cumulative, 1);
        try BigInt.addScalar(prefix, &cumulative, 0);
    }

    all_info[1] = LayerInfo{
        .sizes = dim1_sizes,
        .prefix_sums = dim1_prefix_sums,
        .allocator = allocator,
    };

    for (2..MAX_DIMENSION + 1) |v| {
        const max_d = (w - 1) * v;
        var current_sizes = try initBigIntSlice(allocator, max_d + 1);
        errdefer {
            for (current_sizes) |*value| value.deinit();
            allocator.free(current_sizes);
        }

        const prev_info = all_info[v - 1];
        for (0..max_d + 1) |d| {
            const max_t = @min(d, w - 1);
            for (0..max_t + 1) |t| {
                const idx = d - t;
                if (idx < prev_info.sizes.len) {
                    try BigInt.add(&current_sizes[d], &current_sizes[d], &prev_info.sizes[idx]);
                }
            }
        }

        var current_prefix_sums = try initBigIntSlice(allocator, max_d + 1);
        errdefer {
            for (current_prefix_sums) |*value| value.deinit();
            allocator.free(current_prefix_sums);
        }

        try cumulative.set(0);
        for (0..max_d + 1) |d| {
            try BigInt.add(&cumulative, &cumulative, &current_sizes[d]);
            try BigInt.addScalar(&current_prefix_sums[d], &cumulative, 0);
        }

        all_info[v] = LayerInfo{
            .sizes = current_sizes,
            .prefix_sums = current_prefix_sums,
            .allocator = allocator,
        };
    }

    return AllLayerInfoForBase{
        .layers = all_info,
        .allocator = allocator,
    };
}

pub fn getLayerData(self: anytype, w: usize) !*const AllLayerInfoForBase {
    self.layer_cache_mutex.lock();
    defer self.layer_cache_mutex.unlock();

    if (self.layer_cache.getPtr(w)) |entry| {
        return entry;
    } else {
        try self.layer_cache.put(w, try prepareLayerInfo(self.allocator, w));
        return self.layer_cache.getPtr(w).?;
    }
}

pub fn hypercubeFindLayerBig(
    self: anytype,
    BASE: usize,
    DIMENSION: usize,
    final_layer: usize,
    value: *const BigInt,
    offset_out: *BigInt,
) !usize {
    const layer_data = try getLayerData(self, BASE);
    const info = layer_data.get(DIMENSION);

    if (info.prefix_sums.len == 0) return error.InvalidHypercubeIndex;
    const last_prefix = &info.prefix_sums[info.prefix_sums.len - 1];
    if (value.*.order(last_prefix.*) != .lt) return error.InvalidHypercubeIndex;

    var left: usize = 0;
    var right: usize = info.prefix_sums.len;
    while (left < right) {
        const mid = left + (right - left) / 2;
        const cmp = info.prefix_sums[mid].order(value.*);
        if (cmp == .lt or cmp == .eq) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    const layer = left;
    if (layer > final_layer) return error.InvalidHypercubeIndex;

    try BigInt.addScalar(offset_out, value, 0);
    if (layer > 0) {
        try BigInt.sub(offset_out, offset_out, &info.prefix_sums[layer - 1]);
    }

    return layer;
}

pub fn mapToVertexBig(
    self: anytype,
    BASE: usize,
    DIMENSION: usize,
    layer: usize,
    offset: *const BigInt,
) ![]u8 {
    const layer_data = try getLayerData(self, BASE);
    const info = layer_data.get(DIMENSION);

    if (layer >= info.sizes.len) return error.InvalidHypercubeMapping;
    if (offset.*.order(info.sizes[layer]) != .lt) return error.InvalidHypercubeMapping;

    var result = try self.allocator.alloc(u8, DIMENSION);
    errdefer self.allocator.free(result);

    var x_curr = try offset.*.toConst().toManaged(self.allocator);
    defer x_curr.deinit();
    var d_curr = layer;

    for (1..DIMENSION) |i| {
        // CRITICAL FIX: Initialize ji to a sentinel value matching Rust's usize::MAX
        // Rust: let mut ji = usize::MAX;
        var ji: usize = std.math.maxInt(usize);
        const sub_dim = DIMENSION - i;
        // CRITICAL FIX: Use saturating_sub to match Rust's behavior exactly
        // Rust: range_start = d_curr.saturating_sub((w - 1) * (v - i))
        const range_start = if (d_curr >= (BASE - 1) * sub_dim) d_curr - (BASE - 1) * sub_dim else 0;
        const sub_info = layer_data.get(sub_dim);

        // CRITICAL FIX: Match Rust's loop exactly: for j in range_start..=min(w - 1, d_curr)
        // Rust uses inclusive range: range_start..=min(w - 1, d_curr)
        const limit = @min(BASE - 1, d_curr);
        var j: usize = range_start;
        // CRITICAL: Loop must be inclusive on both ends (j <= limit), matching Rust's ..= operator
        while (j <= limit) : (j += 1) {
            const sub_layer = d_curr - j;
            // CRITICAL FIX: In Rust, accessing out-of-bounds would panic, but for valid inputs
            // this should never happen. However, we need to handle it gracefully.
            // If sub_layer is out of bounds, it means our calculation is wrong or input is invalid.
            // For now, we'll skip this iteration (similar to continue) but this might indicate a bug.
            if (sub_layer >= sub_info.sizes.len) {
                // This shouldn't happen for valid inputs, but if it does, we can't find ji
                // In Rust, this would panic. We'll continue to next j to see if we can find a valid one.
                // However, if we reach the end without finding ji, we'll return an error below.
                continue;
            }
            const count = &sub_info.sizes[sub_layer];
            // CRITICAL FIX: Match Rust's comparison exactly: if x_curr >= *count
            const cmp = x_curr.order(count.*);
            if (cmp == .gt or cmp == .eq) {
                try BigInt.sub(&x_curr, &x_curr, count);
            } else {
                ji = j;
                break;
            }
        }

        // CRITICAL FIX: Match Rust's assertion: assert!(ji < w)
        // If ji is still the sentinel value, it means we never found a valid j
        if (ji >= BASE) return error.InvalidHypercubeMapping;

        const ai = BASE - 1 - ji;
        result[i - 1] = @as(u8, @intCast(ai));
        d_curr -= (BASE - 1) - ai;
    }

    const x_curr_u64 = x_curr.toInt(u64) catch return error.InvalidHypercubeMapping;
    if (x_curr_u64 + d_curr >= BASE) return error.InvalidHypercubeMapping;
    result[DIMENSION - 1] = @as(u8, @intCast(BASE - 1 - x_curr_u64 - d_curr));

    return result;
}

pub fn mapIntoHypercubePart(
    self: anytype,
    DIMENSION: usize,
    BASE: usize,
    final_layer: usize,
    field_elements: []const FieldElement,
) ![]u8 {
    const layer_data = try getLayerData(self, BASE);
    const info = layer_data.get(DIMENSION);
    if (final_layer >= info.prefix_sums.len) return error.InvalidHypercubeIndex;

    var modulus = try BigInt.init(self.allocator);
    defer modulus.deinit();
    try BigInt.addScalar(&modulus, &info.prefix_sums[final_layer], 0);
    const mod_str = try std.fmt.allocPrint(self.allocator, "{}", .{modulus.toConst()});
    defer self.allocator.free(mod_str);
    log.print("ZIG_HYPERCUBE_DEBUG: dom_size {s}\n", .{mod_str});

    // CRITICAL FIX: Match Rust's algorithm exactly
    // Rust: acc = 0; for fe in field_elements: acc = acc * ORDER + fe; acc %= dom_size
    // We must build the full big integer first, then apply modulo (not during combination)
    var acc = try BigInt.initSet(self.allocator, 0);
    defer acc.deinit();

    var multiplier = try BigInt.initSet(self.allocator, KOALABEAR_PRIME);
    defer multiplier.deinit();

    var tmp = try BigInt.init(self.allocator);
    defer tmp.deinit();

    log.print("ZIG_HYPERCUBE_DEBUG: Combining {} field elements (canonical): ", .{field_elements.len});
    var fe_bigint = try BigInt.init(self.allocator);
    defer fe_bigint.deinit();
    for (field_elements, 0..) |fe, i| {
        if (i < 5) {
            log.print("fe[{}]=0x{x:0>8} ", .{ i, fe.toCanonical() });
        }
        // Build big integer: acc = acc * ORDER + fe (matching Rust exactly)
        // CRITICAL FIX: Use BigInt.add with temporary BigInt for field element to match Rust's BigUint addition
        try BigInt.mul(&tmp, &acc, &multiplier);
        // Create BigInt from field element (matching Rust's fe.as_canonical_biguint())
        // CRITICAL: Ensure we use the canonical value as u64 to match Rust's BigUint::from behavior
        const fe_canonical = fe.toCanonical();
        try fe_bigint.set(@as(u64, fe_canonical));
        try BigInt.add(&acc, &tmp, &fe_bigint);
    }
    log.print("\n", .{});

    // Apply modulo AFTER building the full big integer (matching Rust: acc %= dom_size)
    // Use divFloor to get remainder, then replace acc with remainder
    var quotient_mod = try BigInt.init(self.allocator);
    defer quotient_mod.deinit();
    var remainder_mod = try BigInt.init(self.allocator);
    defer remainder_mod.deinit();
    try BigInt.divFloor(&quotient_mod, &remainder_mod, &acc, &modulus);
    // Replace acc with remainder (matching Rust: acc %= dom_size)
    // Swap acc and remainder_mod, then clear the old acc (now in remainder_mod)
    // This effectively sets acc = remainder_mod
    const temp_swap = acc;
    acc = remainder_mod;
    remainder_mod = temp_swap;
    remainder_mod.deinit(); // Free the old acc value
    remainder_mod = try BigInt.init(self.allocator); // Reinitialize for defer

    var offset = try BigInt.init(self.allocator);
    defer offset.deinit();
    const layer = try hypercubeFindLayerBig(self, BASE, DIMENSION, final_layer, &acc, &offset);

    log.print("ZIG_HYPERCUBE_DEBUG: layer={} offset_bitlen={}\n", .{ layer, offset.toConst().bitCountAbs() });

    const chunks = try mapToVertexBig(self, BASE, DIMENSION, layer, &offset);

    var chunk_sum: usize = 0;
    for (chunks) |chunk| chunk_sum += chunk;
    log.print("ZIG_HYPERCUBE_DEBUG: chunks[0..5]: ", .{});
    for (0..@min(5, chunks.len)) |i| {
        log.print("chunks[{}]={} ", .{ i, chunks[i] });
    }
    log.print("sum={}\n", .{chunk_sum});

    return chunks;
}

pub fn applyTopLevelPoseidonMessageHash(
    self: anytype,
    parameter: [5]FieldElement,
    epoch: u32,
    randomness: []const FieldElement,
    message: [32]u8,
) ![]u8 {
    const PARAMETER_LEN: usize = self.lifetime_params.parameter_len;
    const RAND_LEN: usize = self.lifetime_params.rand_len_fe;
    const TWEAK_LEN_FE: usize = self.lifetime_params.tweak_len_fe;
    const MSG_LEN_FE: usize = self.lifetime_params.msg_len_fe;
    const POS_OUTPUT_LEN_PER_INV_FE: usize = 15;
    const POS_INVOCATIONS: usize = 1;
    const POS_OUTPUT_LEN_FE: usize = POS_OUTPUT_LEN_PER_INV_FE * POS_INVOCATIONS;
    const DIMENSION: usize = self.lifetime_params.dimension;
    const BASE: usize = self.lifetime_params.base;
    const FINAL_LAYER: usize = self.lifetime_params.final_layer;

    const message_fe = try self.encodeMessage(MSG_LEN_FE, message);
    defer self.allocator.free(message_fe);
    const epoch_fe = try self.encodeEpoch(TWEAK_LEN_FE, epoch);
    defer self.allocator.free(epoch_fe);

    var pos_outputs: [POS_OUTPUT_LEN_FE]FieldElement = undefined;

    for (0..POS_INVOCATIONS) |i| {
        // Match Rust's behavior: use loop variable i as iteration index
        // Rust: let iteration_index = [F::from_u8(i as u8)];
        const ITER_INPUT_LEN = RAND_LEN + PARAMETER_LEN + TWEAK_LEN_FE + MSG_LEN_FE + 1;
        var combined_input = try self.allocator.alloc(FieldElement, ITER_INPUT_LEN);
        defer self.allocator.free(combined_input);

        var input_idx: usize = 0;
        for (0..RAND_LEN) |j| {
            combined_input[input_idx] = randomness[j];
            input_idx += 1;
        }
        for (0..PARAMETER_LEN) |j| {
            combined_input[input_idx] = parameter[j];
            input_idx += 1;
        }
        for (0..TWEAK_LEN_FE) |j| {
            combined_input[input_idx] = epoch_fe[j];
            input_idx += 1;
        }
        for (0..MSG_LEN_FE) |j| {
            combined_input[input_idx] = message_fe[j];
            input_idx += 1;
        }
        // Use loop variable i as iteration index (matching Rust: F::from_u8(i as u8))
        combined_input[input_idx] = FieldElement.fromU32(@intCast(i));
        input_idx += 1;

        var padded_input: [24]FieldElement = undefined;
        for (0..ITER_INPUT_LEN) |j| {
            padded_input[j] = combined_input[j];
        }
        // Pad remaining elements with zeros (should be none since ITER_INPUT_LEN = 24)
        for (ITER_INPUT_LEN..24) |j| {
            padded_input[j] = FieldElement.zero();
        }

        log.print("ZIG_POS_IN: ", .{});
        for (0..24) |j| {
            log.print("0x{x:0>8} ", .{padded_input[j].value});
        }
        log.print("\n", .{});

        log.print("ZIG_POS_IN:", .{});
        for (0..24) |k| {
            log.print(" 0x{x:0>8}", .{padded_input[k].value});
        }
        log.print("\n", .{});

        const iteration_pos_output = try self.poseidon2.compress(padded_input, POS_OUTPUT_LEN_PER_INV_FE);

        for (0..POS_OUTPUT_LEN_PER_INV_FE) |j| {
            pos_outputs[i * POS_OUTPUT_LEN_PER_INV_FE + j] = iteration_pos_output[j];
        }

        log.print("ZIG_POS_OUT: ", .{});
        for (0..POS_OUTPUT_LEN_PER_INV_FE) |j| {
            log.print("0x{x:0>8} ", .{iteration_pos_output[j].value});
        }
        log.print("\n", .{});

        // Always print to stderr for debugging (bypasses build_options)
        const stderr = std.io.getStdErr().writer();
        stderr.print("ZIG_POS_CONTEXT rand:", .{}) catch {};
        for (randomness[0..RAND_LEN]) |r| {
            stderr.print(" 0x{x:0>8}", .{r.toCanonical()}) catch {};
        }
        stderr.print(" param:", .{}) catch {};
        for (parameter) |p| {
            stderr.print(" 0x{x:0>8}", .{p.toCanonical()}) catch {};
        }
        stderr.print(" epoch:", .{}) catch {};
        for (epoch_fe) |e| {
            stderr.print(" 0x{x:0>8}", .{e.toCanonical()}) catch {};
        }
        stderr.print(" msg:", .{}) catch {};
        for (message_fe) |m| {
            stderr.print(" 0x{x:0>8}", .{m.toCanonical()}) catch {};
        }
        stderr.print(" iter_idx: 0x{x:0>8} (i={})\n", .{ combined_input[ITER_INPUT_LEN - 1].toCanonical(), i }) catch {};
        
        // Also print the combined input in canonical form
        stderr.print("ZIG_POS_INPUT_CANONICAL (24 values):", .{}) catch {};
        for (0..24) |j| {
            stderr.print(" 0x{x:0>8}", .{padded_input[j].toCanonical()}) catch {};
            if ((j + 1) % 8 == 0) {
                stderr.print("\nZIG_POS_INPUT_CANONICAL:", .{}) catch {};
            }
        }
        stderr.print("\n", .{}) catch {};
        
        // Print output in canonical form
        stderr.print("ZIG_POS_OUTPUT_CANONICAL (15 values):", .{}) catch {};
        for (0..POS_OUTPUT_LEN_PER_INV_FE) |j| {
            stderr.print(" 0x{x:0>8}", .{iteration_pos_output[j].toCanonical()}) catch {};
            if ((j + 1) % 8 == 0 and j < POS_OUTPUT_LEN_PER_INV_FE - 1) {
                stderr.print("\nZIG_POS_OUTPUT_CANONICAL:", .{}) catch {};
            }
        }
        stderr.print("\n", .{}) catch {};
    }

    const chunks = try mapIntoHypercubePart(self, DIMENSION, BASE, FINAL_LAYER, &pos_outputs);
    return chunks;
}
