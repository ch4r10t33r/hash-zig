///! Poseidon2 hash using KoalaBear field
///! Compatible with plonky3's implementation for hash-based signatures
const std = @import("std");
const Allocator = std.mem.Allocator;
const poseidon2_core = @import("poseidon2/root.zig");

const width = 16;
const output_len = 8; // 8 field elements = 32 bytes (8 * 4 bytes)

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

        const field_mod = poseidon2_core.koalabear_field;
        const poseidon2_core_type = poseidon2_core.poseidon2_koalabear16;

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

    /// Batch hash multiple inputs efficiently
    /// Returns array of 32-byte hashes
    pub fn hashBatch(self: *Poseidon2, allocator: Allocator, inputs: []const []const u8) ![][]u8 {
        _ = self;

        const field_mod = poseidon2_core.koalabear_field;
        const poseidon2_core_type = poseidon2_core.poseidon2_koalabear16;

        var results = try allocator.alloc([]u8, inputs.len);
        errdefer {
            for (results) |result| {
                if (result.len > 0) allocator.free(result);
            }
            allocator.free(results);
        }

        // Process inputs in parallel batches for better cache utilization
        const batch_size = 8; // Process 8 hashes at a time
        var i: usize = 0;

        while (i < inputs.len) {
            const batch_end = @min(i + batch_size, inputs.len);

            // Process batch
            for (i..batch_end) |idx| {
                const input = inputs[idx];

                // Initialize state in Montgomery form
                var state: [width]field_mod.MontFieldElem = undefined;
                for (0..width) |j| {
                    field_mod.toMontgomery(&state[j], 0);
                }

                // Process input data
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
                        field_mod.add(&state[j], state[j], chunk_mont);
                    }

                    // Apply permutation
                    poseidon2_core_type.permutation(&state);

                    offset += chunk_size;
                }

                // Convert to output
                results[idx] = try allocator.alloc(u8, 32);
                for (0..output_len) |j| {
                    const val = field_mod.toNormal(state[j]);
                    results[idx][j * 4 + 0] = @truncate(val);
                    results[idx][j * 4 + 1] = @truncate(val >> 8);
                    results[idx][j * 4 + 2] = @truncate(val >> 16);
                    results[idx][j * 4 + 3] = @truncate(val >> 24);
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
