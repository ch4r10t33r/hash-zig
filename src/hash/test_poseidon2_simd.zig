//! Test to verify SIMD Poseidon2 produces same results as scalar version

const std = @import("std");
const testing = std.testing;
const FieldElement = @import("../core/field.zig").FieldElement;
const poseidon2 = @import("../poseidon2/root.zig");
const poseidon2_simd = @import("poseidon2_hash_simd.zig");
const simd_utils = @import("../signature/native/simd_utils.zig");
const Poseidon2RustCompat = @import("poseidon2_hash.zig").Poseidon2RustCompat;

test "SIMD Poseidon2-16 matches scalar version" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize Poseidon2 instances
    var poseidon2_rust = try Poseidon2RustCompat.init(allocator);
    defer poseidon2_rust.deinit();

    var simd_poseidon2 = poseidon2_simd.Poseidon2SIMD.init(allocator, &poseidon2_rust);

    // Test with multiple inputs
    const test_cases = [_]struct {
        input: []const u32,
        expected_output: []const u32,
    }{
        .{
            .input = &[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .expected_output = &[_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 }, // Will compute
        },
        .{
            .input = &[_]u32{ 100, 200, 300, 400, 500, 600, 700, 800 },
            .expected_output = &[_]u32{ 0, 0, 0, 0, 0, 0, 0, 0 }, // Will compute
        },
    };

    for (test_cases) |test_case| {
        // Convert to FieldElement
        var input_fe = try allocator.alloc(FieldElement, test_case.input.len);
        defer allocator.free(input_fe);
        for (test_case.input, 0..) |val, i| {
            input_fe[i] = FieldElement.fromCanonical(val);
        }

        // Scalar version
        // Test uses hash_len=8 (for lifetime 2^8)
        const scalar_output = try poseidon2_rust.hashFieldElements16(allocator, input_fe, 8);
        defer allocator.free(scalar_output);

        // SIMD version - pack input for all lanes (same input in all lanes)
        var packed_input = try allocator.alloc(simd_utils.PackedF, test_case.input.len);
        defer allocator.free(packed_input);

        for (0..test_case.input.len) |i| {
            const val = input_fe[i].value;
            packed_input[i] = simd_utils.PackedF{
                .values = .{ val, val, val, val }, // Same value in all lanes
            };
        }

        const simd_output = try simd_poseidon2.compress16SIMD(packed_input, 8);
        defer allocator.free(simd_output);

        // Compare results - all lanes should match scalar output
        for (0..8) |i| {
            const scalar_val = scalar_output[i].value;
            // Check all SIMD lanes match
            for (0..simd_utils.SIMD_WIDTH) |lane| {
                const simd_val = simd_output[i].values[lane];
                try testing.expectEqual(scalar_val, simd_val);
            }
        }
    }
}
