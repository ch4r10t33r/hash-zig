//! Verify Poseidon2-24 implementation against plonky3 test vector
//!
//! Test vector from Plonky3:
//! test_poseidon2_width_24_random() in koala-bear/src/poseidon2.rs

const std = @import("std");
const poseidon = @import("poseidon");

pub fn main() !void {
    std.debug.print("\n🔍 Verifying Poseidon2-24 against plonky3 test vector\n", .{});
    std.debug.print("=" ** 80 ++ "\n\n", .{});

    // Test vector from plonky3 test_poseidon2_width_24_random
    const input = [24]u32{
        886409618,  1327899896, 1902407911, 591953491, 648428576,  1844789031,
        1198336108, 355597330,  1799586834, 59617783,  790334801,  1968791836,
        559272107,  31054313,   1042221543, 474748436, 135686258,  263665994,
        1962340735, 1741539604, 2026927696, 449439011, 1131357108, 50869465,
    };

    const expected = [16]u32{
        3825456,   486989921,  613714063,  282152282,  1027154688, 1171655681,
        879344953, 1090688809, 1960721991, 1604199242, 1329947150, 1535171244,
        781646521, 1156559780, 1875690339, 368140677,
    };

    std.debug.print("Input:\n", .{});
    for (input, 0..) |val, i| {
        if (i % 6 == 0) std.debug.print("  ", .{});
        std.debug.print("{d:10}", .{val});
        if ((i + 1) % 6 == 0 or i == input.len - 1) std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});

    // Apply Poseidon2-24 permutation
    const P2_24 = poseidon.koalabear16.Poseidon2KoalaBear;
    const Field = P2_24.Field;

    var state_mont: [16]Field.MontFieldElem = undefined;
    for (0..@min(input.len, 16)) |i| {
        Field.toMontgomery(&state_mont[i], input[i]);
    }
    // Zero out remaining elements if input is shorter than 16
    if (input.len < 16) {
        for (input.len..16) |i| {
            Field.toMontgomery(&state_mont[i], 0);
        }
    }

    P2_24.permutation(&state_mont);

    var output: [16]u32 = undefined;
    for (0..16) |i| {
        output[i] = Field.toNormal(state_mont[i]);
    }

    std.debug.print("Output:\n", .{});
    for (output, 0..) |val, i| {
        if (i % 6 == 0) std.debug.print("  ", .{});
        std.debug.print("{d:10}", .{val});
        if ((i + 1) % 6 == 0 or i == output.len - 1) std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});

    std.debug.print("Expected:\n", .{});
    for (expected, 0..) |val, i| {
        if (i % 6 == 0) std.debug.print("  ", .{});
        std.debug.print("{d:10}", .{val});
        if ((i + 1) % 6 == 0 or i == expected.len - 1) std.debug.print("\n", .{});
    }
    std.debug.print("\n", .{});

    // Compare
    std.debug.print("Verification:\n", .{});
    std.debug.print("-" ** 80 ++ "\n", .{});

    var all_match = true;
    for (output, expected, 0..) |out, exp, i| {
        if (out != exp) {
            std.debug.print("❌ Mismatch at index {d}: got {d}, expected {d}\n", .{ i, out, exp });
            all_match = false;
        }
    }

    if (all_match) {
        std.debug.print("🎉 SUCCESS! Poseidon2-24 matches plonky3 exactly!\n", .{});
        std.debug.print("   All 24 output elements match the test vector.\n", .{});
    } else {
        std.debug.print("❌ FAILED! Poseidon2-24 does not match plonky3.\n", .{});
        std.debug.print("   Round constants or implementation may be incorrect.\n", .{});
    }

    std.debug.print("=" ** 80 ++ "\n\n", .{});
}
