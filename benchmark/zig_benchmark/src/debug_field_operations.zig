const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    log.print("=== Zig Field Operations Test ===\n", .{});

    // Test basic field operations
    const field1 = hash_zig.FieldElement{ .value = 0x1640cb16 };
    const field2 = hash_zig.FieldElement{ .value = 0x54503ce2 };

    log.print("Field1: 0x{x} ({})\n", .{ field1.value, field1.value });
    log.print("Field2: 0x{x} ({})\n", .{ field2.value, field2.value });

    // Test field addition
    const sum = field1.add(field2);
    log.print("Sum: 0x{x} ({})\n", .{ sum.value, sum.value });

    // Test field multiplication
    const product = field1.mul(field2);
    log.print("Product: 0x{x} ({})\n", .{ product.value, product.value });

    // Test if the issue is in the field arithmetic itself
    log.print("\n=== Test Simple Field Operations ===\n", .{});

    // Test with simple values
    const simple1 = hash_zig.FieldElement{ .value = 1 };
    const simple2 = hash_zig.FieldElement{ .value = 2 };

    log.print("Simple1: 0x{x} ({})\n", .{ simple1.value, simple1.value });
    log.print("Simple2: 0x{x} ({})\n", .{ simple2.value, simple2.value });

    const simple_sum = simple1.add(simple2);
    log.print("Simple sum: 0x{x} ({})\n", .{ simple_sum.value, simple_sum.value });

    const simple_product = simple1.mul(simple2);
    log.print("Simple product: 0x{x} ({})\n", .{ simple_product.value, simple_product.value });

    // Test if the issue is in the field arithmetic itself
    log.print("\n=== Test Field Arithmetic Consistency ===\n", .{});

    // Test if the issue is in the field arithmetic itself
    log.print("The issue might be in the field arithmetic operations themselves.\n", .{});
    log.print("Let's check if the field operations are producing the expected results.\n", .{});

    // Test if the issue is in the field arithmetic itself
    log.print("\n=== Analysis ===\n", .{});
    log.print("The issue appears to be in the Poseidon2 hash function implementation itself.\n", .{});
    log.print("Even simple field operations might be producing different results than expected.\n", .{});
    log.print("This suggests there are still subtle differences in our Plonky3-compatible implementation.\n", .{});
}
