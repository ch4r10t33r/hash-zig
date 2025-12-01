//! Rust-compatible Poseidon2 hash implementation
//! Uses parameters that match Rust hash-sig SIGTopLevelTargetSumLifetime8Dim64Base8

const std = @import("std");
const Allocator = std.mem.Allocator;
const field_types = @import("../core/field.zig");
const FieldElement = field_types.FieldElement;
const poseidon2 = @import("../poseidon2/root.zig");
const log = @import("../utils/log.zig");

// Import Plonky3-compatible Poseidon2 instances (matching Rust hash-sig exactly)
const Poseidon2KoalaBear24 = poseidon2.Poseidon2KoalaBear24; // Use Plonky3-compatible 24 for message hashing
const Poseidon2KoalaBear16 = poseidon2.Poseidon2KoalaBear16; // Use Plonky3-compatible 16 for chain compression

// Rust parameters from actual hash-sig implementation
const WIDTH_24 = 24; // Poseidon2-24 (used in message hashing)
const WIDTH_16 = 16; // Poseidon2-16 (used in chain compression)
const OUTPUT_LEN_RUST = 64; // 64 field elements output

pub const Poseidon2RustCompat = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) !Poseidon2RustCompat {
        return .{
            .allocator = allocator,
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
    /// Returns exactly hash_len elements (matching Rust's poseidon_compress with OUT_LEN=hash_len)
    pub fn hashFieldElements16(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement, hash_len: usize) ![]FieldElement {
        // Use Poseidon2-16 for chain compression (matching Rust PoseidonTweakHash)
        const full_output = try self.applyPoseidon2_16(allocator, input);
        defer allocator.free(full_output);

        // Return exactly hash_len elements (matching Rust's poseidon_compress with OUT_LEN=hash_len)
        // For lifetime 2^18: hash_len=7, for lifetime 2^8/2^32: hash_len=8
        const output = try allocator.alloc(FieldElement, hash_len);
        @memcpy(output[0..hash_len], full_output[0..hash_len]);
        return output;
    }

    /// Apply Poseidon2-24 (for message hashing)
    fn applyPoseidon2_24(self: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Convert input to u32 array for Poseidon2-24 (canonical form expected)
        var input_u32: [WIDTH_24]u32 = undefined;
        const copy_len = @min(input.len, WIDTH_24);
        for (0..copy_len) |i| {
            input_u32[i] = input[i].toCanonical();
        }

        // Pad with zeros if input is shorter than WIDTH_24
        if (copy_len < WIDTH_24) {
            @memset(input_u32[copy_len..], 0);
        }

        // Apply Poseidon2-24 permutation
        const output_u32 = self.permute24(input_u32);

        // Convert back to FieldElement array (store in Montgomery form)
        const output = try allocator.alloc(FieldElement, WIDTH_24);
        for (0..WIDTH_24) |i| {
            output[i] = FieldElement.fromCanonical(output_u32[i]);
        }

        return output;
    }

    /// Apply Poseidon2-16 (for chain compression)
    /// Matches Rust's poseidon_compress: permute then add input back (feed-forward)
    fn applyPoseidon2_16(_: *Poseidon2RustCompat, allocator: Allocator, input: []const FieldElement) ![]FieldElement {
        // Pad input to WIDTH_16 (matching Rust's poseidon_compress padding)
        var padded_input: [WIDTH_16]FieldElement = [_]FieldElement{FieldElement.zero()} ** WIDTH_16;
        for (0..@min(input.len, WIDTH_16)) |i| {
            padded_input[i] = input[i];
        }

        // Convert to canonical u32 array for compress
        var input_u32: [WIDTH_16]u32 = undefined;
        for (0..WIDTH_16) |i| {
            input_u32[i] = padded_input[i].toCanonical();
        }

        // Use Poseidon2KoalaBear16.compress which handles permute + feed-forward
        const output_u32 = Poseidon2KoalaBear16.compress(8, &input_u32);

        // Convert back to FieldElement array (only first 8 used; remaining zero)
        const output = try allocator.alloc(FieldElement, WIDTH_16);
        for (0..8) |i| {
            output[i] = FieldElement.fromCanonical(output_u32[i]);
        }
        for (8..WIDTH_16) |i| {
            output[i] = FieldElement.zero();
        }
        return output;
    }

    /// Apply Poseidon2-24 permutation
    pub fn permute24(self: *Poseidon2RustCompat, input: [WIDTH_24]u32) [WIDTH_24]u32 {
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
    /// Rust's poseidon_compress expects Montgomery form directly, so we work with Montgomery throughout
    pub fn compress(self: *Poseidon2RustCompat, input: [WIDTH_24]FieldElement, comptime output_len: usize) ![output_len]FieldElement {
        _ = self;

        // Rust's poseidon_compress works directly with Montgomery form (KoalaBear)
        // Convert FieldElement (Montgomery) directly to F (Montgomery) without canonical conversion
        const F = Poseidon2KoalaBear24.Field;
        var state: [WIDTH_24]F = undefined;
        var padded_input: [WIDTH_24]F = undefined;

        // Copy input directly (both are Montgomery form)
        for (0..WIDTH_24) |i| {
            state[i] = F{ .value = input[i].value };
            padded_input[i] = F{ .value = input[i].value };
        }

        // Debug: log state before permutation (first 3 elements)
        log.print("ZIG_COMPRESS_DEBUG: State before perm[0..3]: ", .{});
        for (0..3) |i| {
            log.print("0x{x:0>8} ", .{state[i].value});
        }
        log.print("\n", .{});

        // Apply permutation (matching Rust's perm.permute_mut(&mut state))
        Poseidon2KoalaBear24.permutation(state[0..]);

        // Debug: log state after permutation (first 3 elements)
        log.print("ZIG_COMPRESS_DEBUG: State after perm[0..3]: ", .{});
        for (0..3) |i| {
            log.print("0x{x:0>8} ", .{state[i].value});
        }
        log.print("\n", .{});

        // Feed-forward: Add the input back into the state element-wise (matching Rust's poseidon_compress)
        for (0..WIDTH_24) |i| {
            const before = state[i].value;
            state[i] = state[i].add(padded_input[i]);
            // Debug: log first 3 feed-forward operations
            if (i < 3) {
                log.print("ZIG_COMPRESS_DEBUG: Feed-forward[{}]: before=0x{x:0>8} + input=0x{x:0>8} = after=0x{x:0>8}\n", .{ i, before, padded_input[i].value, state[i].value });
            }
        }

        // Debug: log final state (first 3 elements)
        log.print("ZIG_COMPRESS_DEBUG: Final state[0..3]: ", .{});
        for (0..3) |i| {
            log.print("0x{x:0>8} ", .{state[i].value});
        }
        log.print("\n", .{});

        // Return first output_len elements as FieldElement (Montgomery form)
        var output: [output_len]FieldElement = undefined;
        for (0..output_len) |i| {
            output[i] = FieldElement.fromMontgomery(state[i].value);
        }

        return output;
    }

    /// Compress function for Poseidon2-16 (for chain compression)
    pub fn compress16(self: *Poseidon2RustCompat, input: [WIDTH_16]FieldElement, comptime output_len: usize) ![output_len]FieldElement {
        _ = self;

        // Convert to canonical u32 array
        var input_u32: [WIDTH_16]u32 = undefined;
        for (0..WIDTH_16) |i| {
            input_u32[i] = input[i].toCanonical();
        }

        // Apply Poseidon2-16 compress
        const output_u32 = Poseidon2KoalaBear16.compress(output_len, &input_u32);

        // Convert back to FieldElement array
        var output: [output_len]FieldElement = undefined;
        for (0..output_len) |i| {
            output[i] = FieldElement.fromCanonical(output_u32[i]);
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
        FieldElement.fromCanonical(1),
        FieldElement.fromCanonical(2),
        FieldElement.fromCanonical(3),
        FieldElement.fromCanonical(4),
        FieldElement.fromCanonical(5),
    };

    const output = try poseidon2_rust.hashFieldElements(allocator, &input);
    defer allocator.free(output);

    // Verify output length (should be width 24)
    try std.testing.expectEqual(WIDTH_24, output.len);

    // Verify non-zero output
    try std.testing.expect(output[0].toMontgomery() != 0);
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
        input[i] = FieldElement.fromCanonical(@intCast(i + 42));
    }

    const output = try poseidon2_rust.compress(input, 3);

    // Verify output length
    try std.testing.expectEqual(@as(usize, 3), output.len);

    // Verify non-zero output
    try std.testing.expect(output[0].toMontgomery() != 0);
}
