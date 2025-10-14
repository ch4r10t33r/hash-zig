///! Poseidon2 hash using KoalaBear field
///! Compatible with plonky3's implementation for hash-based signatures
const std = @import("std");
const Allocator = std.mem.Allocator;

// Import from external zig-poseidon dependency
const poseidon = @import("poseidon");

// Import field types for field-native operations
const field_types = @import("field.zig");
const FieldElement = field_types.FieldElement;

const width = 16; // Default width for byte-based operations
const width16 = 16;
const width24 = 24;
const output_len = 8; // 8 field elements = 32 bytes (8 * 4 bytes)

// Helper aliases for easier access (width-16 for legacy byte-based operations)
const field_mod = poseidon.koalabear16.Poseidon2KoalaBear.Field;
const poseidon2_core_type = poseidon.koalabear16.Poseidon2KoalaBear;

// Width-24 for Rust compatibility
const field_mod24 = poseidon.koalabear24.Poseidon2KoalaBear.Field;
const poseidon2_core_type24 = poseidon.koalabear24.Poseidon2KoalaBear;

pub const Poseidon2 = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) !Poseidon2 {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Poseidon2) void {
        _ = self;
        // No cleanup needed - stateless
    }

    /// Hash arbitrary bytes to a 32-byte output using Poseidon2
    pub fn hashBytes(self: *Poseidon2, allocator: Allocator, data: []const u8) ![]u8 {
        _ = self;

        // Initialize state in Montgomery form
        var state: [width]field_mod.MontFieldElem = undefined;
        for (0..width) |i| {
            field_mod.toMontgomery(&state[i], 0);
        }

        // Process data in 64-byte chunks (WIDTH * 4 bytes)
        var offset: usize = 0;
        const chunk_size = width * 4; // 64 bytes per chunk

        while (offset < data.len) {
            // Pack bytes into field elements and XOR into state
            const remaining = data.len - offset;
            const to_process = @min(remaining, chunk_size);

            var chunk: [width]u32 = std.mem.zeroes([width]u32);
            for (0..to_process) |i| {
                const elem_idx = i / 4;
                const byte_idx = i % 4;
                chunk[elem_idx] |= @as(u32, data[offset + i]) << @intCast(byte_idx * 8);
            }

            // XOR chunk into state (in Montgomery form)
            for (0..width) |i| {
                var chunk_mont: field_mod.MontFieldElem = undefined;
                field_mod.toMontgomery(&chunk_mont, chunk[i]);
                field_mod.add(&state[i], state[i], chunk_mont);
            }

            // Apply permutation
            poseidon2_core_type.permutation(&state);

            offset += chunk_size;
        }

        // Convert OUTPUT_LEN elements back from Montgomery form
        var output = try allocator.alloc(u8, 32);
        for (0..output_len) |i| {
            const val = field_mod.toNormal(state[i]);
            output[i * 4 + 0] = @truncate(val);
            output[i * 4 + 1] = @truncate(val >> 8);
            output[i * 4 + 2] = @truncate(val >> 16);
            output[i * 4 + 3] = @truncate(val >> 24);
        }

        return output;
    }

    /// Batch hash multiple inputs efficiently with interleaved permutations
    /// Returns array of 32-byte hashes
    /// Optimized for Winternitz chain generation where all inputs are same size (32 bytes)
    pub fn hashBatch(self: *Poseidon2, allocator: Allocator, inputs: []const []const u8) ![][]u8 {
        _ = self;

        var results = try allocator.alloc([]u8, inputs.len);
        errdefer {
            for (results) |result| {
                if (result.len > 0) allocator.free(result);
            }
            allocator.free(results);
        }

        // Optimization: Process multiple states with interleaved permutations
        // This improves instruction-level parallelism and reduces pipeline stalls
        const batch_size = 8; // Process 8 hashes simultaneously (tuned for CPU cache/pipeline)
        var i: usize = 0;

        while (i < inputs.len) {
            const batch_end = @min(i + batch_size, inputs.len);
            const current_batch_size = batch_end - i;

            // Allocate states for this batch
            var states = try allocator.alloc([width]field_mod.MontFieldElem, current_batch_size);
            defer allocator.free(states);

            // Initialize all states in the batch
            for (states) |*state| {
                for (0..width) |j| {
                    field_mod.toMontgomery(&state[j], 0);
                }
            }

            // Process all inputs in this batch
            // For Winternitz, inputs are typically 32 bytes (single chunk)
            for (0..current_batch_size) |batch_idx| {
                const input = inputs[i + batch_idx];
                var offset: usize = 0;
                const chunk_size = width * 4; // 64 bytes per chunk

                while (offset < input.len) {
                    const remaining = input.len - offset;
                    const to_process = @min(remaining, chunk_size);

                    var chunk: [width]u32 = std.mem.zeroes([width]u32);
                    for (0..to_process) |j| {
                        const elem_idx = j / 4;
                        const byte_idx = j % 4;
                        chunk[elem_idx] |= @as(u32, input[offset + j]) << @intCast(byte_idx * 8);
                    }

                    // XOR chunk into state (in Montgomery form)
                    for (0..width) |j| {
                        var chunk_mont: field_mod.MontFieldElem = undefined;
                        field_mod.toMontgomery(&chunk_mont, chunk[j]);
                        field_mod.add(&states[batch_idx][j], states[batch_idx][j], chunk_mont);
                    }

                    offset += chunk_size;
                }
            }

            // Apply permutations to all states in batch
            // Optimization: Process permutations together to improve instruction-level parallelism
            // The CPU can pipeline and reorder instructions across multiple permutations

            // Process all permutations in the batch
            // Note: Unrolling didn't provide significant benefit in testing
            // Compiler does a good job optimizing the loop
            for (states) |*state| {
                poseidon2_core_type.permutation(state);
            }

            // Convert outputs
            for (0..current_batch_size) |batch_idx| {
                results[i + batch_idx] = try allocator.alloc(u8, 32);
                for (0..output_len) |j| {
                    const val = field_mod.toNormal(states[batch_idx][j]);
                    results[i + batch_idx][j * 4 + 0] = @truncate(val);
                    results[i + batch_idx][j * 4 + 1] = @truncate(val >> 8);
                    results[i + batch_idx][j * 4 + 2] = @truncate(val >> 16);
                    results[i + batch_idx][j * 4 + 3] = @truncate(val >> 24);
                }
            }

            i = batch_end;
        }

        return results;
    }

    /// Generate a chain of hashes efficiently using batching
    /// This is optimized for Winternitz chain generation
    pub fn generateChain(self: *Poseidon2, allocator: Allocator, start_value: []const u8, chain_length: u32, tweak: u64) ![]u8 {
        _ = tweak; // Tweak not used in current implementation

        // For short chains, do sequential processing
        if (chain_length <= 4) {
            var current = try allocator.dupe(u8, start_value);
            defer allocator.free(current);

            for (0..chain_length) |_| {
                const next = try self.hashBytes(allocator, current);
                allocator.free(current);
                current = next;
            }

            return current;
        }

        // For longer chains, use optimized batch processing
        // Process in batches to balance memory usage and performance
        const batch_size = 8;
        var current = try allocator.dupe(u8, start_value);

        var remaining = chain_length;

        while (remaining > 0) {
            const batch_len = @min(batch_size, remaining);
            var batch_inputs = try allocator.alloc([]const u8, batch_len);
            defer allocator.free(batch_inputs);

            // Prepare batch inputs - build chain sequentially for this batch
            var temp_current = current;
            for (0..batch_len) |i| {
                if (i == 0) {
                    batch_inputs[i] = temp_current;
                } else {
                    // For subsequent iterations, we need to hash the previous result
                    const next = try self.hashBytes(allocator, temp_current);
                    if (i > 1) allocator.free(temp_current);
                    temp_current = next;
                    batch_inputs[i] = temp_current;
                }
            }

            // Process batch
            const batch_results = try self.hashBatch(allocator, batch_inputs);
            defer {
                for (batch_results) |result| allocator.free(result);
                allocator.free(batch_results);
            }

            // Clean up the last temp_current if it wasn't freed
            if (batch_len > 1) {
                allocator.free(temp_current);
            }

            // Update current to the last result
            allocator.free(current);
            current = try allocator.dupe(u8, batch_results[batch_len - 1]);

            remaining -= batch_len;
        }

        return current;
    }

    // ========================================================================
    // Field-Native Operations (for Rust compatibility)
    // ========================================================================

    /// Hash field elements directly, returning field elements
    /// This is the field-native version matching Rust's implementation
    /// Input: array of field elements
    /// Output: array of field elements (default 7 elements for HASH_LEN_FE)
    pub fn hashFieldElements(
        self: *Poseidon2,
        allocator: Allocator,
        input: []const FieldElement,
        comptime output_len_fe: usize,
    ) ![]FieldElement {
        _ = self;

        // Convert field elements to u32 array
        var state: [width]u32 = std.mem.zeroes([width]u32);

        // Copy input field elements to state (up to width)
        const input_len = @min(input.len, width);
        for (0..input_len) |i| {
            state[i] = input[i].toU32();
        }

        // Convert to Montgomery form
        var state_mont: [width]field_mod.MontFieldElem = undefined;
        for (0..width) |i| {
            field_mod.toMontgomery(&state_mont[i], state[i]);
        }

        // Apply permutation
        poseidon2_core_type.permutation(&state_mont);

        // Convert back to field elements (not Montgomery)
        var result = try allocator.alloc(FieldElement, output_len_fe);
        for (0..output_len_fe) |i| {
            const val = field_mod.toNormal(state_mont[i]);
            result[i] = FieldElement.fromU32(val);
        }

        return result;
    }

    /// Poseidon compression function: permute and add original input
    /// Matches Rust's poseidon_compress function
    /// Output length must be <= input length and <= width
    pub fn compress(
        self: *Poseidon2,
        allocator: Allocator,
        input: []const FieldElement,
        comptime output_len_fe: usize,
    ) ![]FieldElement {
        _ = self;

        if (input.len < output_len_fe) return error.InputTooShort;
        if (output_len_fe > width) return error.OutputTooLarge;

        // Save original input (first output_len_fe elements)
        var original: [output_len_fe]u32 = undefined;
        for (0..output_len_fe) |i| {
            original[i] = input[i].toU32();
        }

        // Convert input to state (pad with zeros)
        var state: [width]u32 = std.mem.zeroes([width]u32);
        for (0..@min(input.len, width)) |i| {
            state[i] = input[i].toU32();
        }

        // Convert to Montgomery form
        var state_mont: [width]field_mod.MontFieldElem = undefined;
        for (0..width) |i| {
            field_mod.toMontgomery(&state_mont[i], state[i]);
        }

        // Apply permutation
        poseidon2_core_type.permutation(&state_mont);

        // Convert back and add original (feed-forward)
        var result = try allocator.alloc(FieldElement, output_len_fe);
        for (0..output_len_fe) |i| {
            const permuted = field_mod.toNormal(state_mont[i]);
            // Add original input (mod p)
            const sum = (@as(u64, permuted) + @as(u64, original[i])) % FieldElement.PRIME;
            result[i] = FieldElement.fromU64(sum);
        }

        return result;
    }

    /// Direct permutation on field elements (no compression)
    pub fn permute(
        self: *Poseidon2,
        input: []const FieldElement,
    ) [width]FieldElement {
        _ = self;

        // Convert to u32 state
        var state: [width]u32 = std.mem.zeroes([width]u32);
        for (0..@min(input.len, width)) |i| {
            state[i] = input[i].toU32();
        }

        // Convert to Montgomery and permute
        var state_mont: [width]field_mod.MontFieldElem = undefined;
        for (0..width) |i| {
            field_mod.toMontgomery(&state_mont[i], state[i]);
        }

        poseidon2_core_type.permutation(&state_mont);

        // Convert back to field elements
        var result: [width]FieldElement = undefined;
        for (0..width) |i| {
            const val = field_mod.toNormal(state_mont[i]);
            result[i] = FieldElement.fromU32(val);
        }

        return result;
    }

    /// Compress using Poseidon2-24 (for merging two hashes)
    /// This matches Rust's mode 2: [left_hash, right_hash]
    pub fn compress24(
        self: *Poseidon2,
        allocator: Allocator,
        input: []const FieldElement,
        comptime output_len_fe: usize,
    ) ![]FieldElement {
        _ = self;

        if (input.len < output_len_fe) return error.InputTooShort;
        if (output_len_fe > width24) return error.OutputTooLarge;

        // Save original input
        var original: [output_len_fe]u32 = undefined;
        for (0..output_len_fe) |i| {
            original[i] = input[i].toU32();
        }

        // Pad to width-24
        var state: [width24]u32 = std.mem.zeroes([width24]u32);
        for (0..@min(input.len, width24)) |i| {
            state[i] = input[i].toU32();
        }

        // Permute with width-24
        var state_mont: [width24]field_mod24.MontFieldElem = undefined;
        for (0..width24) |i| {
            field_mod24.toMontgomery(&state_mont[i], state[i]);
        }
        poseidon2_core_type24.permutation(&state_mont);

        // Feed-forward
        var result = try allocator.alloc(FieldElement, output_len_fe);
        for (0..output_len_fe) |i| {
            const permuted = field_mod24.toNormal(state_mont[i]);
            const sum = (@as(u64, permuted) + @as(u64, original[i])) % FieldElement.PRIME;
            result[i] = FieldElement.fromU64(sum);
        }

        return result;
    }

    /// Sponge construction using Poseidon2-24 (for many elements)
    /// This matches Rust's mode 3: hashing 22 chain ends into 1 leaf
    pub fn sponge24(
        self: *Poseidon2,
        allocator: Allocator,
        input: []const FieldElement,
        comptime output_len_fe: usize,
    ) ![]FieldElement {
        _ = self;

        const rate = 16; // Absorb rate for width-24
        // const capacity = 8;  // Capacity (not directly used)

        // Initialize state
        var state: [width24]u32 = std.mem.zeroes([width24]u32);

        // Absorbing phase
        var offset: usize = 0;
        while (offset < input.len) {
            const chunk_len = @min(rate, input.len - offset);

            // XOR/add input into rate portion
            for (0..chunk_len) |i| {
                const val = input[offset + i].toU32();
                state[i] = (state[i] + val) % @as(u32, @intCast(FieldElement.PRIME));
            }

            // Permute
            var state_mont: [width24]field_mod24.MontFieldElem = undefined;
            for (0..width24) |i| {
                field_mod24.toMontgomery(&state_mont[i], state[i]);
            }
            poseidon2_core_type24.permutation(&state_mont);
            for (0..width24) |i| {
                state[i] = field_mod24.toNormal(state_mont[i]);
            }

            offset += chunk_len;
        }

        // Squeezing phase - extract from rate
        var result = try allocator.alloc(FieldElement, output_len_fe);
        for (0..output_len_fe) |i| {
            result[i] = FieldElement.fromU32(state[i]);
        }

        return result;
    }
};

test "poseidon2 basic" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    const data = "test data";
    const hash1 = try hasher.hashBytes(allocator, data);
    defer allocator.free(hash1);

    const hash2 = try hasher.hashBytes(allocator, data);
    defer allocator.free(hash2);

    // Same input should produce same output
    try std.testing.expectEqualSlices(u8, hash1, hash2);

    // Different input should produce different output
    const data2 = "different";
    const hash3 = try hasher.hashBytes(allocator, data2);
    defer allocator.free(hash3);

    try std.testing.expect(!std.mem.eql(u8, hash1, hash3));
}

test "poseidon2 batch" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    const inputs = [_][]const u8{ "test1", "test2", "test3", "test4" };
    const results = try hasher.hashBatch(allocator, &inputs);
    defer {
        for (results) |result| allocator.free(result);
        allocator.free(results);
    }

    // All results should be 32 bytes
    for (results) |result| {
        try std.testing.expect(result.len == 32);
    }

    // Results should be different
    for (results, 0..) |result, i| {
        for (results[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, result, other));
        }
    }
}

test "poseidon2 chain" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    const start = "initial";
    const chain_length: u32 = 8;

    const result = try hasher.generateChain(allocator, start, chain_length, 0);
    defer allocator.free(result);

    try std.testing.expect(result.len == 32);
}

test "poseidon2 field-native: hash field elements" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    // Create test input (7 field elements)
    var input: [7]FieldElement = undefined;
    for (0..7) |i| {
        input[i] = FieldElement.fromU32(@intCast(i + 1));
    }

    // Hash to 7 output field elements
    const result = try hasher.hashFieldElements(allocator, &input, 7);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 7), result.len);

    // Output should be different from input
    var different = false;
    for (input, result) |inp, res| {
        if (!inp.eql(res)) {
            different = true;
            break;
        }
    }
    try std.testing.expect(different);
}

test "poseidon2 field-native: compress" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    // Create test input
    var input: [10]FieldElement = undefined;
    for (0..10) |i| {
        input[i] = FieldElement.fromU32(@intCast(i * 100));
    }

    // Compress to 7 elements
    const result = try hasher.compress(allocator, &input, 7);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 7), result.len);

    // All output elements should be valid field elements
    for (result) |elem| {
        try std.testing.expect(elem.toU32() < @as(u32, @intCast(FieldElement.PRIME)));
    }
}

test "poseidon2 field-native: permute" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    // Create test input
    var input: [10]FieldElement = undefined;
    for (0..10) |i| {
        input[i] = FieldElement.fromU32(@intCast(i + 42));
    }

    const result = hasher.permute(&input);

    // Should return width (16) field elements
    try std.testing.expectEqual(@as(usize, 16), result.len);

    // Output should be different from input
    var different = false;
    for (0..@min(input.len, result.len)) |i| {
        if (!input[i].eql(result[i])) {
            different = true;
            break;
        }
    }
    try std.testing.expect(different);
}

test "poseidon2 field-native: deterministic" {
    const allocator = std.testing.allocator;
    var hasher = try Poseidon2.init(allocator);
    defer hasher.deinit();

    var input: [7]FieldElement = undefined;
    for (0..7) |i| {
        input[i] = FieldElement.fromU32(@intCast(i * 123));
    }

    const result1 = try hasher.hashFieldElements(allocator, &input, 7);
    defer allocator.free(result1);

    const result2 = try hasher.hashFieldElements(allocator, &input, 7);
    defer allocator.free(result2);

    // Same input should produce same output
    for (result1, result2) |r1, r2| {
        try std.testing.expect(r1.eql(r2));
    }
}
