const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    std.debug.print("=== Zig Field Operations Test ===\n", .{});

    // Test basic field operations
    const field1 = hash_zig.FieldElement{ .value = 0x1640cb16 };
    const field2 = hash_zig.FieldElement{ .value = 0x54503ce2 };

    std.debug.print("Field1: 0x{x} ({})\n", .{ field1.value, field1.value });
    std.debug.print("Field2: 0x{x} ({})\n", .{ field2.value, field2.value });

    // Test field addition
    const sum = field1.add(field2);
    std.debug.print("Sum: 0x{x} ({})\n", .{ sum.value, sum.value });

    // Test field multiplication
    const product = field1.mul(field2);
    std.debug.print("Product: 0x{x} ({})\n", .{ product.value, product.value });

    // Test if the issue is in the field arithmetic itself
    std.debug.print("\n=== Test Simple Field Operations ===\n", .{});

    // Test with simple values
    const simple1 = hash_zig.FieldElement{ .value = 1 };
    const simple2 = hash_zig.FieldElement{ .value = 2 };

    std.debug.print("Simple1: 0x{x} ({})\n", .{ simple1.value, simple1.value });
    std.debug.print("Simple2: 0x{x} ({})\n", .{ simple2.value, simple2.value });

    const simple_sum = simple1.add(simple2);
    std.debug.print("Simple sum: 0x{x} ({})\n", .{ simple_sum.value, simple_sum.value });

    const simple_product = simple1.mul(simple2);
    std.debug.print("Simple product: 0x{x} ({})\n", .{ simple_product.value, simple_product.value });

    // Test if the issue is in the field arithmetic itself
    std.debug.print("\n=== Test Field Arithmetic Consistency ===\n", .{});

    // Test if the issue is in the field arithmetic itself
    std.debug.print("The issue might be in the field arithmetic operations themselves.\n", .{});
    std.debug.print("Let's check if the field operations are producing the expected results.\n", .{});

    // Test if the issue is in the field arithmetic itself
    std.debug.print("\n=== Analysis ===\n", .{});
    std.debug.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    std.debug.print("Even simple field operations might be producing different results than expected.\n", .{});
    std.debug.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
}
