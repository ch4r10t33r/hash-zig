//! Rust-compatible Poseidon2 hash implementation
//! Uses parameters that match Rust hash-sig SIGTopLevelTargetSumLifetime8Dim64Base8

const std = @import("std");
const Allocator = std.mem.Allocator;
const poseidon = @import("poseidon");
const field_types = @import("field.zig");
const FieldElement = field_types.FieldElement;
const poseidon2_plonky3 = @import("poseidon2_plonky3_compat.zig");

// Import Plonky3-compatible Poseidon2 instances (matching Rust hash-sig exactly)
const Poseidon2KoalaBear24 = poseidon2_plonky3.Poseidon2KoalaBear24Plonky3; // Use Plonky3-compatible 24 for message hashing
const Poseidon2KoalaBear16 = poseidon2_plonky3.Poseidon2KoalaBear16Plonky3; // Use Plonky3-compatible 16 for chain compression
const TargetSumEncoding = poseidon.koalabear.TargetSumEncoding;
const TopLevelPoseidonMessageHash = poseidon.koalabear.TopLevelPoseidonMessageHash;

// Rust parameters from actual hash-sig implementation
const WIDTH_24 = 24; // Poseidon2-24 (used in message hashing)
const WIDTH_16 = 16; // Poseidon2-16 (used in chain compression)
const OUTPUT_LEN_RUST = 64; // 64 field elements output
const TARGET_SUM_RUST = 375; // TargetSumEncoding value

pub const Poseidon2RustCompat = struct {
    allocator: Allocator,
    target_sum_encoding: TargetSumEncoding,
    top_level_message_hash: TopLevelPoseidonMessageHash,

    pub fn init(allocator: Allocator) !Poseidon2RustCompat {
        return .{
            .allocator = allocator,
            .target_sum_encoding = TargetSumEncoding{ .target_sum = TARGET_SUM_RUST },
            .top_level_message_hash = TopLevelPoseidonMessageHash{},
        };
    }

    pub fn deinit(self: *Poseidon2RustCompat) void {
        _ = self;
        // No cleanup needed - stateless
    }

    /// Hash field elements using Rust-compatible parameters (width 24)
    pub fn hashFieldElements(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Use Poseidon2-24 for message hashing (matching Rust TopLevelPoseidonMessageHash)
        return self.applyPoseidon2_24(allocator, input);
    }

    /// Hash field elements using Poseidon2-16 (for chain compression)
    pub fn hashFieldElements16(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Use Poseidon2-16 for chain compression (matching Rust PoseidonTweakHash)
        return self.applyPoseidon2_16(allocator, input);
    }

    /// Apply Poseidon2-24 (for message hashing)
    fn applyPoseidon2_24(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Convert input to u32 array for Poseidon2-24
        var input_u32: [WIDTH_24]u32 = undefined;
        for (0..@min(input.len, WIDTH_24)) |i| {
            input_u32[i] = input[i].value;
        }

        // Pad with zeros if input is shorter than WIDTH_24
        if (input.len < WIDTH_24) {
            for (input.len..WIDTH_24) |i| {
                input_u32[i] = 0;
            }
        }

        // Apply Poseidon2-24 permutation
        const output_u32 = self.permute24(input_u32);

        // Convert back to FieldElement array
        const output = try allocator.alloc(FieldElement, WIDTH_24);
        for (0..WIDTH_24) |i| {
            output[i] = FieldElement{ .value = output_u32[i] };
        }

        return output;
    }

    /// Apply Poseidon2-16 (for chain compression)
    fn applyPoseidon2_16(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Convert input to u32 array for Poseidon2-16
        var input_u32: [WIDTH_16]u32 = undefined;
        for (0..@min(input.len, WIDTH_16)) |i| {
            input_u32[i] = input[i].value;
        }

        // Pad with zeros if input is shorter than WIDTH_16
        for (input.len..WIDTH_16) |i| {
            input_u32[i] = 0;
        }

        // Apply Poseidon2-16 permutation
        const output_u32 = self.permute16(input_u32);

        // Convert back to FieldElement array
        const output = try allocator.alloc(FieldElement, WIDTH_16);
        for (0..WIDTH_16) |i| {
            output[i] = FieldElement{ .value = output_u32[i] };
        }

        return output;
    }

    /// Apply Poseidon2-24 permutation
    fn permute24(self: *Poseidon2RustCompat, input: [WIDTH_24]u32) [WIDTH_24]u32 {
        _ = self;

        const F = Poseidon2KoalaBear24.Field;
        var mont_state: [WIDTH_24]F = undefined;

        // Convert to Montgomery form
        for (0..WIDTH_24) |i| {
            F.toMontgomery(&mont_state[i], input[i]);
        }

        // Apply permutation
        Poseidon2KoalaBear24.permutation(&mont_state);

        // Convert back to normal form
        var output: [WIDTH_24]u32 = undefined;
        for (0..WIDTH_24) |i| {
            output[i] = F.toNormal(mont_state[i]);
        }

        return output;
    }

    /// Apply Poseidon2-16 permutation
    fn permute16(self: *Poseidon2RustCompat, input: [WIDTH_16]u32) [WIDTH_16]u32 {
        _ = self;

        const F = Poseidon2KoalaBear16.Field;
        var mont_state: [WIDTH_16]F = undefined;

        // Convert to Montgomery form
        for (0..WIDTH_16) |i| {
            F.toMontgomery(&mont_state[i], input[i]);
        }

        // Apply permutation
        Poseidon2KoalaBear16.permutation(&mont_state);

        // Convert back to normal form
        var output: [WIDTH_16]u32 = undefined;
        for (0..WIDTH_16) |i| {
            output[i] = F.toNormal(mont_state[i]);
        }

        return output;
    }

    /// Hash using TargetSumEncoding (Rust-compatible)
    pub fn hashWithTargetSum(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Apply TargetSumEncoding
        const encoded_input = self.target_sum_encoding.encode(@constCast(input));

        // Hash the encoded input
        return self.hashFieldElements(allocator, encoded_input);
    }

    /// Hash using TopLevelPoseidonMessageHash (Rust-compatible)
    pub fn hashMessage(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Apply TopLevelPoseidonMessageHash
        const hashed_input = self.top_level_message_hash.hash(@constCast(input));

        // Hash the processed input
        return self.hashFieldElements(allocator, hashed_input);
    }

    /// Compress function matching Rust's compress behavior (using Poseidon2-24)
    pub fn compress(self: *Poseidon2RustCompat, input: [WIDTH_24]FieldElement, comptime output_len: usize) ![output_len]FieldElement {
        _ = self;

        // Convert to u32 array
        var input_u32: [WIDTH_24]u32 = undefined;
        for (0..WIDTH_24) |i| {
            input_u32[i] = input[i].value;
        }

        // Apply Poseidon2-24 compress
        const output_u32 = Poseidon2KoalaBear24.compress(output_len, input_u32);

        // Convert back to FieldElement array
        var output: [output_len]FieldElement = undefined;
        for (0..output_len) |i| {
            output[i] = FieldElement{ .value = output_u32[i] };
        }

        return output;
    }

    /// Compress function for Poseidon2-16 (for chain compression)
    pub fn compress16(self: *Poseidon2RustCompat, input: [WIDTH_16]FieldElement, comptime output_len: usize) ![output_len]FieldElement {
        _ = self;

        // Convert to u32 array
        var input_u32: [WIDTH_16]u32 = undefined;
        for (0..WIDTH_16) |i| {
            input_u32[i] = input[i].value;
        }

        // Apply Poseidon2-16 compress
        const output_u32 = Poseidon2KoalaBear16.compress(output_len, input_u32);

        // Convert back to FieldElement array
        var output: [output_len]FieldElement = undefined;
        for (0..output_len) |i| {
            output[i] = FieldElement{ .value = output_u32[i] };
        }

        return output;
    }
};

// Test the Rust-compatible implementation
test "rust_compat_poseidon2 basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var poseidon2_rust = try Poseidon2RustCompat.init(allocator);
    defer poseidon2_rust.deinit();

    // Test with simple input (width 24)
    const input = [_]FieldElement{
        FieldElement{ .value = 1 },
        FieldElement{ .value = 2 },
        FieldElement{ .value = 3 },
        FieldElement{ .value = 4 },
        FieldElement{ .value = 5 },
    };

    const output = try poseidon2_rust.hashFieldElements(allocator, &input);
    defer allocator.free(output);

    // Verify output length (should be width 24)
    try std.testing.expectEqual(WIDTH_24, output.len);

    // Verify non-zero output
    try std.testing.expect(output[0].value != 0);
}

test "rust_compat_poseidon2 compress" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var poseidon2_rust = try Poseidon2RustCompat.init(allocator);
    defer poseidon2_rust.deinit();

    // Test compress function (width 24)
    var input: [WIDTH_24]FieldElement = undefined;
    for (0..WIDTH_24) |i| {
        input[i] = FieldElement{ .value = @as(u32, @intCast(i + 42)) };
    }

    const output = try poseidon2_rust.compress(input, 3);

    // Verify output length
    try std.testing.expectEqual(@as(usize, 3), output.len);

    // Verify non-zero output
    try std.testing.expect(output[0].value != 0);
}
