const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Detailed Field Arithmetic Verification ===\n", .{});

    // Test with the exact values from our debugging
    const a = F.fromU32(1862878127);
    const b = F.fromU32(1696502448);
    const c = F.fromU32(192279764);
    const d = F.fromU32(1895619622);

    std.debug.print("Input values:\n", .{});
    std.debug.print("  a = {} (normal: {})\n", .{ a.value, a.toU32() });
    std.debug.print("  b = {} (normal: {})\n", .{ b.value, b.toU32() });
    std.debug.print("  c = {} (normal: {})\n", .{ c.value, c.toU32() });
    std.debug.print("  d = {} (normal: {})\n", .{ d.value, d.toU32() });

    // Test addition
    const sum_bcd = b.add(c).add(d);
    std.debug.print("\nSum of b + c + d: {} (normal: {})\n", .{ sum_bcd.value, sum_bcd.toU32() });

    // Test S-box (x^3)
    const rc = 2102596038;
    const a_plus_rc = a.add(F.fromU32(rc));
    std.debug.print("a + RC: {} (normal: {})\n", .{ a_plus_rc.value, a_plus_rc.toU32() });

    const sbox_result = a_plus_rc.mul(a_plus_rc).mul(a_plus_rc);
    std.debug.print("(a + RC)^3: {} (normal: {})\n", .{ sbox_result.value, sbox_result.toU32() });

    // Test full sum calculation
    const full_sum = sum_bcd.add(sbox_result);
    std.debug.print("Full sum: {} (normal: {})\n", .{ full_sum.value, full_sum.toU32() });

    // Test internal matrix operation
    const internal_result = sum_bcd.sub(sbox_result);
    std.debug.print("Internal matrix result: {} (normal: {})\n", .{ internal_result.value, internal_result.toU32() });

    // Test V-based operations
    std.debug.print("\n=== V-based Operations ===\n", .{});

    // state[1] += full_sum
    const state1_result = b.add(full_sum);
    std.debug.print("state[1] + full_sum: {} (normal: {})\n", .{ state1_result.value, state1_result.toU32() });
    std.debug.print("Expected: 1561259414\n", .{});
    std.debug.print("Match: {}\n", .{state1_result.toU32() == 1561259414});

    // state[2] = state[2].double() + full_sum
    const state2_double = c.double();
    const state2_result = state2_double.add(full_sum);
    std.debug.print("state[2].double() + full_sum: {} (normal: {})\n", .{ state2_result.value, state2_result.toU32() });
    std.debug.print("Expected: 249316494\n", .{});
    std.debug.print("Match: {}\n", .{state2_result.toU32() == 249316494});

    // state[3] = state[3].halve() + full_sum
    const state3_halve = d.halve();
    const state3_result = state3_halve.add(full_sum);
    std.debug.print("state[3].halve() + full_sum: {} (normal: {})\n", .{ state3_result.value, state3_result.toU32() });
    std.debug.print("Expected: 812566777\n", .{});
    std.debug.print("Match: {}\n", .{state3_result.toU32() == 812566777});

    // Let's also test if there's an issue with the field conversion
    std.debug.print("\n=== Field Conversion Test ===\n", .{});

    // Test converting back and forth
    const test_val = 1561259414;
    const test_field = F.fromU32(test_val);
    const test_back = test_field.toU32();
    std.debug.print("Test value: {} -> field: {} -> back: {}\n", .{ test_val, test_field.value, test_back });
    std.debug.print("Round trip match: {}\n", .{test_val == test_back});

    // Test if the issue is with the field arithmetic itself
    const test_add = F.fromU32(1696502448).add(F.fromU32(169548476));
    std.debug.print("1696502448 + 169548476 = {} (normal: {})\n", .{ test_add.value, test_add.toU32() });
    std.debug.print("Expected: 1866050924\n", .{});
    std.debug.print("Match: {}\n", .{test_add.toU32() == 1866050924});
}
