const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Field Arithmetic Reference Implementation ===\n", .{});

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

    // Test if there's an issue with the field arithmetic
    // Let's try to reproduce the expected values step by step

    std.debug.print("\n=== Step-by-step Field Arithmetic ===\n", .{});

    // Test addition
    const sum_bcd = b.add(c).add(d);
    std.debug.print("Sum of b + c + d: {} (normal: {})\n", .{ sum_bcd.value, sum_bcd.toU32() });

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

    // Now let's try to figure out what the expected values should be
    std.debug.print("\n=== Expected Values Analysis ===\n", .{});

    // Expected from Rust: [1311927403, 1561259414, 249316494, 812566777]
    const expected_state0 = 1311927403;
    const expected_state1 = 1561259414;
    const expected_state2 = 249316494;
    const expected_state3 = 812566777;

    std.debug.print("Expected values:\n", .{});
    std.debug.print("  state[0] = {}\n", .{expected_state0});
    std.debug.print("  state[1] = {}\n", .{expected_state1});
    std.debug.print("  state[2] = {}\n", .{expected_state2});
    std.debug.print("  state[3] = {}\n", .{expected_state3});

    // Let's try to work backwards from the expected values
    // to see if we can figure out what the full_sum should be

    // For state[1] = 1561259414, we need: original_state[1] + full_sum = 1561259414
    // So: 1696502448 + full_sum = 1561259414
    // Therefore: full_sum = 1561259414 - 1696502448 = -135248034
    // But this is negative, which suggests there might be an issue with our understanding

    const expected_full_sum = expected_state1 - 1696502448;
    std.debug.print("Expected full_sum (from state[1]): {}\n", .{expected_full_sum});

    // Let's try a different approach
    // Maybe the issue is that we need to apply the V operations differently

    // Let's check if there's an issue with the field arithmetic itself
    std.debug.print("\n=== Field Arithmetic Verification ===\n", .{});

    // Test if the issue is with the field arithmetic
    const test_val1 = 1696502448;
    const test_val2 = 169548476;
    const test_sum = F.fromU32(test_val1).add(F.fromU32(test_val2));
    std.debug.print("{} + {} = {} (normal: {})\n", .{ test_val1, test_val2, test_sum.value, test_sum.toU32() });
    std.debug.print("Expected: {}\n", .{test_val1 + test_val2});
    std.debug.print("Match: {}\n", .{test_sum.toU32() == test_val1 + test_val2});

    // Test if the issue is with the field conversion
    const test_field = F.fromU32(1561259414);
    const test_back = test_field.toU32();
    std.debug.print("1561259414 -> field: {} -> back: {}\n", .{ test_field.value, test_back });
    std.debug.print("Round trip match: {}\n", .{test_back == 1561259414});

    // Maybe the issue is that we need to use a different field implementation
    // or there's a bug in our field arithmetic

    std.debug.print("\n=== Field Implementation Check ===\n", .{});

    // Test basic field operations
    const test_a = F.fromU32(1);
    const test_b = F.fromU32(2);
    const test_c = test_a.add(test_b);
    std.debug.print("1 + 2 = {} (normal: {})\n", .{ test_c.value, test_c.toU32() });

    const test_d = test_a.mul(test_b);
    std.debug.print("1 * 2 = {} (normal: {})\n", .{ test_d.value, test_d.toU32() });

    const test_e = test_a.double();
    std.debug.print("2 * 1 = {} (normal: {})\n", .{ test_e.value, test_e.toU32() });

    const test_f = test_b.halve();
    std.debug.print("2 / 2 = {} (normal: {})\n", .{ test_f.value, test_f.toU32() });
}
