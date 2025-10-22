//! Tweakable hash wrapper for multiple hash functions (Poseidon2 and SHA3)

const std = @import("std");
const params = @import("params.zig");
const poseidon2_mod = @import("poseidon2_hash.zig");
const sha3_mod = @import("sha3.zig");
const prf_mod = @import("prf.zig");
const field_types = @import("field.zig");
const tweak_types = @import("tweak.zig");
const Parameters = params.Parameters;
const HashFunction = params.HashFunction;
const Poseidon2 = poseidon2_mod.Poseidon2RustCompat;
const Sha3 = sha3_mod.Sha3;
const ShakePRF = prf_mod.ShakePRF;
const FieldElement = field_types.FieldElement;
const PoseidonTweak = tweak_types.PoseidonTweak;
const Allocator = std.mem.Allocator;

const HashImpl = union(enum) {
    poseidon2: Poseidon2,
    sha3: Sha3,
};

pub const TweakableHash = struct {
    params: Parameters,
    hash_impl: HashImpl,
    allocator: Allocator,
    parameter: [5]FieldElement, // Random parameter (Rust compatibility)

    pub fn init(allocator: Allocator, parameters: Parameters) !TweakableHash {
        // Default: use zero parameter for backward compatibility
        const zero_param = [_]FieldElement{FieldElement.zero()} ** 5;
        return initWithParameter(allocator, parameters, zero_param);
    }

    pub fn initWithParameter(
        allocator: Allocator,
        parameters: Parameters,
        parameter: [5]FieldElement,
    ) !TweakableHash {
        const hash_impl = switch (parameters.hash_function) {
            .poseidon2 => blk: {
                const poseidon_instance = try Poseidon2.init(allocator);
                break :blk HashImpl{ .poseidon2 = poseidon_instance };
            },
            .sha3 => blk: {
                const sha3_instance = try Sha3.init(allocator, parameters.security_level);
                break :blk HashImpl{ .sha3 = sha3_instance };
            },
        };

        return .{
            .params = parameters,
            .hash_impl = hash_impl,
            .allocator = allocator,
            .parameter = parameter,
        };
    }

    pub fn deinit(self: *TweakableHash) void {
        switch (self.hash_impl) {
            .poseidon2 => |*p| p.deinit(),
            .sha3 => |*s| s.deinit(self.allocator),
        }
    }

    pub fn hash(self: *TweakableHash, allocator: Allocator, data: []const u8, tweak: u64) ![]u8 {
        var tweaked_data = try allocator.alloc(u8, 8 + data.len);
        defer allocator.free(tweaked_data);

        std.mem.writeInt(u64, tweaked_data[0..8], tweak, .big);
        for (data, 0..) |byte, i| {
            tweaked_data[8 + i] = byte;
        }

        return switch (self.hash_impl) {
            .poseidon2 => |*p| {
                // Convert bytes to field elements and hash
                const field_elements = try self.bytesToFieldElements(allocator, tweaked_data);
                defer allocator.free(field_elements);
                const hash_result = try p.hashFieldElements(allocator, field_elements);
                defer allocator.free(hash_result);

                // Convert field elements back to bytes
                const result = try allocator.alloc(u8, hash_result.len * 4);
                for (hash_result, 0..) |fe, i| {
                    const bytes = std.mem.toBytes(fe.value);
                    @memcpy(result[i * 4 .. (i + 1) * 4], &bytes);
                }
                return result;
            },
            .sha3 => |*s| try s.hashBytes(allocator, tweaked_data),
        };
    }

    /// Convert bytes to field elements for Poseidon2 hashing
    fn bytesToFieldElements(_: *TweakableHash, allocator: Allocator, data: []const u8) ![]FieldElement {
        const num_elements = (data.len + 3) / 4; // 4 bytes per field element
        const field_elements = try allocator.alloc(FieldElement, num_elements);

        for (0..num_elements) |i| {
            const start = i * 4;
            const end = @min(start + 4, data.len);

            var value: u32 = 0;
            for (start..end) |j| {
                value |= @as(u32, data[j]) << @intCast((j - start) * 8);
            }

            field_elements[i] = FieldElement{ .value = value % 2130706433 }; // KoalaBear modulus
        }

        return field_elements;
    }

    /// PRF-based hash using SHAKE-128 (matching Rust's ShakePRFtoF)
    /// This generates pseudorandom private keys for Winternitz chains
    /// Parameters match Rust's PRF::get_domain_element(key, epoch, chain_index)
    pub fn prfHash(self: *TweakableHash, allocator: Allocator, key: []const u8, epoch: u32, chain_index: usize) ![]u8 {
        _ = self; // PRF is independent of hash function choice
        return ShakePRF.getHashOutput(allocator, key, epoch, chain_index);
    }

    /// Batch hash multiple inputs with corresponding tweaks
    /// This is optimized for Winternitz chain generation where we process
    /// all chains at the same iteration step simultaneously
    pub fn hashBatch(self: *TweakableHash, allocator: Allocator, data_array: []const []const u8, tweaks: []const u64) ![][]u8 {
        if (data_array.len != tweaks.len) return error.MismatchedArrayLengths;

        // Prepare tweaked inputs
        var tweaked_inputs = try allocator.alloc([]u8, data_array.len);
        defer {
            for (tweaked_inputs) |input| allocator.free(input);
            allocator.free(tweaked_inputs);
        }

        for (data_array, tweaks, 0..) |data, tweak, i| {
            tweaked_inputs[i] = try allocator.alloc(u8, 8 + data.len);
            std.mem.writeInt(u64, tweaked_inputs[i][0..8], tweak, .big);
            @memcpy(tweaked_inputs[i][8..], data);
        }

        // Batch hash using underlying implementation
        return switch (self.hash_impl) {
            .poseidon2 => |*p| try p.hashBatch(allocator, tweaked_inputs),
            .sha3 => |*s| {
                // SHA3 doesn't have batch optimization, process sequentially
                var results = try allocator.alloc([]u8, tweaked_inputs.len);
                errdefer {
                    for (results) |r| {
                        if (r.len > 0) allocator.free(r);
                    }
                    allocator.free(results);
                }
                for (tweaked_inputs, 0..) |input, i| {
                    results[i] = try s.hashBytes(allocator, input);
                }
                return results;
            },
        };
    }

    // ========================================================================
    // Field-Native Operations (for Rust compatibility)
    // ========================================================================

    /// Hash field elements with a Poseidon tweak (field-native version)
    /// This matches Rust's TweakableHash implementation
    /// Only works with Poseidon2 hash function
    pub fn hashFieldElements(
        self: *TweakableHash,
        allocator: Allocator,
        input: []const FieldElement,
        tweak: PoseidonTweak,
        comptime output_len: usize,
    ) ![]FieldElement {
        // Only Poseidon2 supports field-native operations
        if (self.params.hash_function != .poseidon2) {
            return error.FieldNativeNotSupported;
        }

        // Convert tweak to field elements (TWEAK_LEN_FE = 2 in Rust)
        const tweak_fes = tweak.toFieldElements(2);

        // Combine parameter + tweak + input into state (matching Rust)
        // State layout: [param[0..5], tweak[0..2], input[0..N]]
        const state_size = 5 + 2 + input.len; // param_len + tweak_len + input_len
        var state = try allocator.alloc(FieldElement, state_size);
        defer allocator.free(state);

        // Copy parameter (5 elements)
        @memcpy(state[0..5], &self.parameter);

        // Copy tweak field elements (2 elements)
        state[5] = tweak_fes[0];
        state[6] = tweak_fes[1];

        // Copy input field elements (avoid aliasing)
        for (input, 0..) |elem, i| {
            state[7 + i] = elem;
        }

        // Select hash mode based on input length (matching Rust)
        return switch (self.hash_impl) {
            .poseidon2 => |*p| {
                // Rust uses 3 modes:
                // 1. Single element: Poseidon2-16 compress
                // 2. Two elements: Poseidon2-24 compress
                // 3. Many elements (>2): Poseidon2-24 sponge
                if (input.len == 1) {
                    // Mode 1: Chain hashing (single field element array)
                    if (state.len >= 24) {
                        var state_array: [24]FieldElement = undefined;
                        @memcpy(state_array[0..state.len], state);
                        const compress_result = try p.compress(state_array, output_len);

                        // Copy result to a slice and return
                        const result = try allocator.alloc(FieldElement, compress_result.len);
                        @memcpy(result, &compress_result);
                        return result;
                    } else {
                        // Use hashFieldElements for variable length
                        const hash_result = try p.hashFieldElements(allocator, state);
                        defer allocator.free(hash_result);

                        // Return field elements directly (not converted to bytes)
                        return hash_result;
                    }
                } else if (input.len == 2) {
                    // Mode 2: Tree node merging (two field element arrays)
                    if (state.len >= 24) {
                        var state_array: [24]FieldElement = undefined;
                        @memcpy(state_array[0..state.len], state);
                        const compress_result = try p.compress(state_array, output_len);

                        // Copy result to a slice and return
                        const result = try allocator.alloc(FieldElement, compress_result.len);
                        @memcpy(result, &compress_result);
                        return result;
                    } else {
                        // Use hashFieldElements for variable length
                        const hash_result = try p.hashFieldElements(allocator, state);
                        defer allocator.free(hash_result);

                        // Return field elements directly (not converted to bytes)
                        return hash_result;
                    }
                } else {
                    // Mode 3: Leaf generation (many field element arrays)
                    // Simplified implementation - use hashFieldElements for now
                    const full_result = try p.hashFieldElements(allocator, state);
                    defer allocator.free(full_result);

                    // Truncate to requested output length
                    const result = try allocator.alloc(FieldElement, output_len);
                    for (0..@min(output_len, full_result.len)) |i| {
                        result[i] = full_result[i];
                    }

                    return result;
                }
            },
            .sha3 => error.FieldNativeNotSupported,
        };
    }

    /// In-place hash computation without allocations (Rust-style efficiency)
    pub fn hashFieldElementsInPlace(
        self: *TweakableHash,
        input: FieldElement,
        tweak: PoseidonTweak,
    ) !FieldElement {
        // Only Poseidon2 supports field-native operations
        if (self.params.hash_function != .poseidon2) {
            return error.FieldNativeNotSupported;
        }

        // Convert tweak to field elements (TWEAK_LEN_FE = 2 in Rust)
        const tweak_fes = tweak.toFieldElements(2);

        // For single element input, we can optimize the state creation
        const state_size = 5 + 2 + 1; // param_len + tweak_len + input_len
        var state = [_]FieldElement{undefined} ** state_size;

        // Copy parameter (5 elements)
        @memcpy(state[0..5], &self.parameter);

        // Copy tweak field elements (2 elements)
        state[5] = tweak_fes[0];
        state[6] = tweak_fes[1];

        // Copy input field element
        state[7] = input;

        // Use Poseidon2 compress for single element (chain hashing)
        return switch (self.hash_impl) {
            .poseidon2 => |*p| {
                // Zero-allocation fast path
                return p.compress1NoAlloc(&state);
            },
            .sha3 => error.FieldNativeNotSupported,
        };
    }

    /// PRF-based hash using SHAKE-128, returning field elements
    /// This generates pseudorandom field elements for Winternitz chains
    pub fn prfHashFieldElements(
        self: *TweakableHash,
        allocator: Allocator,
        key: []const u8,
        epoch: u32,
        chain_index: usize,
        num_elements: usize,
    ) ![]FieldElement {
        _ = self; // PRF is independent of hash function choice
        return ShakePRF.getDomainElementsNative(allocator, key, epoch, chain_index, num_elements);
    }
};

test "tweakable hash different tweaks poseidon2" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const data = "test";
    const hash1 = try hash.hash(allocator, data, 0);
    defer allocator.free(hash1);
    const hash2 = try hash.hash(allocator, data, 1);
    defer allocator.free(hash2);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}

test "tweakable hash different tweaks sha3" {
    const allocator = std.testing.allocator;

    // Create parameters with SHA3
    const parameters = Parameters.initWithSha3(.lifetime_2_16);

    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const data = "test";
    const hash1 = try hash.hash(allocator, data, 0);
    defer allocator.free(hash1);
    const hash2 = try hash.hash(allocator, data, 1);
    defer allocator.free(hash2);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}

test "tweakable hash field-native: hash field elements" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    // Create test input
    var input: [4]FieldElement = undefined;
    for (0..4) |i| {
        input[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    // Create tree tweak
    const tweak = PoseidonTweak{ .tree_tweak = .{
        .level = 1,
        .pos_in_level = 0,
    } };

    // Hash field elements
    const result = try hash.hashFieldElements(allocator, &input, tweak, 1);
    defer allocator.free(result);

    // Result should have 1 element
    try std.testing.expectEqual(@as(usize, 1), result.len);

    // Result should be non-zero
    try std.testing.expect(result[0].value != 0);
}

test "tweakable hash field-native: different tweaks produce different hashes" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    // Create test input
    var input: [4]FieldElement = undefined;
    for (0..4) |i| {
        input[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    // Create two different tweaks
    const tweak1 = PoseidonTweak{ .tree_tweak = .{
        .level = 1,
        .pos_in_level = 0,
    } };

    const tweak2 = PoseidonTweak{ .tree_tweak = .{
        .level = 1,
        .pos_in_level = 1,
    } };

    // Hash with both tweaks
    const result1 = try hash.hashFieldElements(allocator, &input, tweak1, 1);
    defer allocator.free(result1);
    const result2 = try hash.hashFieldElements(allocator, &input, tweak2, 1);
    defer allocator.free(result2);

    // Results should be different
    try std.testing.expect(result1[0].value != result2[0].value);
}

test "tweakable hash field-native: prf hash field elements" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    const key = "test_key_32_bytes_long_padded";
    const epoch: u32 = 0;
    const chain_index: usize = 0;
    const num_elements: usize = 7;

    const result = try hash.prfHashFieldElements(allocator, key, epoch, chain_index, num_elements);
    defer allocator.free(result);

    // Should have 7 elements
    try std.testing.expectEqual(@as(usize, 7), result.len);

    // All elements should be non-zero
    for (result) |elem| {
        try std.testing.expect(elem.value != 0);
    }
}

test "tweakable hash field-native: sha3 not supported" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.initWithSha3(.lifetime_2_16);
    var hash = try TweakableHash.init(allocator, parameters);
    defer hash.deinit();

    var input: [4]FieldElement = undefined;
    for (0..4) |i| {
        input[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    const tweak = PoseidonTweak{ .tree_tweak = .{
        .level = 1,
        .pos_in_level = 0,
    } };

    // Should return error for SHA3
    const result = hash.hashFieldElements(allocator, &input, tweak, 1);
    try std.testing.expectError(error.FieldNativeNotSupported, result);
}
