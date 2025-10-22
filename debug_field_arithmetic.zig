const std = @import("std");
const plonky3_field = @import("src/poseidon2/plonky3_field.zig");

const F = plonky3_field.KoalaBearField;

pub fn main() !void {
    std.debug.print("=== Field Arithmetic Verification ===\n", .{});

    // Test basic field operations
    const a = F.fromU32(305419896);
    const b = F.fromU32(2596069104);

    std.debug.print("a = {} (normal: {})\n", .{ a.value, a.toU32() });
    std.debug.print("b = {} (normal: {})\n", .{ b.value, b.toU32() });

    // Test addition
    const sum = a.add(b);
    std.debug.print("a + b = {} (normal: {})\n", .{ sum.value, sum.toU32() });

    // Test multiplication
    const prod = a.mul(b);
    std.debug.print("a * b = {} (normal: {})\n", .{ prod.value, prod.toU32() });

    // Test S-box (x^3)
    const sbox_a = a.mul(a).mul(a);
    std.debug.print("a^3 = {} (normal: {})\n", .{ sbox_a.value, sbox_a.toU32() });

    // Test double
    const double_a = a.double();
    std.debug.print("2*a = {} (normal: {})\n", .{ double_a.value, double_a.toU32() });

    // Test halve
    const halve_a = a.halve();
    std.debug.print("a/2 = {} (normal: {})\n", .{ halve_a.value, halve_a.toU32() });

    // Test div2exp
    const div8_a = a.div2exp(8);
    std.debug.print("a/2^8 = {} (normal: {})\n", .{ div8_a.value, div8_a.toU32() });

    // Test with round constants
    std.debug.print("\n=== Round Constants Test ===\n", .{});
    const rc = 2102596038; // First internal round constant
    const rc_field = F.fromU32(rc);
    std.debug.print("RC = {} (normal: {})\n", .{ rc_field.value, rc_field.toU32() });

    const a_plus_rc = a.add(rc_field);
    std.debug.print("a + RC = {} (normal: {})\n", .{ a_plus_rc.value, a_plus_rc.toU32() });

    // Test S-box on a + RC
    const sbox_result = a_plus_rc.mul(a_plus_rc).mul(a_plus_rc);
    std.debug.print("(a + RC)^3 = {} (normal: {})\n", .{ sbox_result.value, sbox_result.toU32() });

    // Test MDS matrix operations
    std.debug.print("\n=== MDS Matrix Test ===\n", .{});
    var mds_state: [4]F = undefined;
    mds_state[0] = F.fromU32(1);
    mds_state[1] = F.fromU32(2);
    mds_state[2] = F.fromU32(3);
    mds_state[3] = F.fromU32(4);

    std.debug.print("Before MDS:\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, mds_state[i].value, mds_state[i].toU32() });
    }

    // Apply MDS matrix
    const x = mds_state[0..4];
    const t01 = x[0].add(x[1]);
    const t23 = x[2].add(x[3]);
    const t0123 = t01.add(t23);
    const t01123 = t0123.add(x[1]);
    const t01233 = t0123.add(x[3]);

    x[3] = t01233.add(x[0].double());
    x[1] = t01123.add(x[2].double());
    x[0] = t01123.add(t01);
    x[2] = t01233.add(t23);

    std.debug.print("After MDS:\n", .{});
    for (0..4) |i| {
        std.debug.print("  state[{}] = {} (normal: {})\n", .{ i, mds_state[i].value, mds_state[i].toU32() });
    }
}
