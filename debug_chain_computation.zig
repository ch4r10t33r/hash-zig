const std = @import("std");
const hash_zig = @import("src/root.zig");
const ShakePRFtoF_8_7 = hash_zig.ShakePRFtoF_8_7;
const FieldElement = hash_zig.FieldElement;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Testing Chain Computation ===\n", .{});

    // Use the same PRF key and parameters as the benchmark
    const prf_key = [_]u8{
        0x7e, 0x26, 0xe9, 0xc3, 0x88, 0xd1, 0x2b, 0xe8,
        0x17, 0x90, 0xcc, 0xc9, 0x32, 0x42, 0x4b, 0x20,
        0xdb, 0x4e, 0x16, 0xb9, 0x62, 0x60, 0xac, 0x40,
        0x6e, 0x21, 0x2b, 0x36, 0x25, 0x14, 0x9e, 0xad,
    };

    const parameter = [_]FieldElement{
        FieldElement{ .value = 1128497561 },
        FieldElement{ .value = 1847509114 },
        FieldElement{ .value = 1994249188 },
        FieldElement{ .value = 1874424621 },
        FieldElement{ .value = 1302548296 },
    };

    // Create a scheme to test chain computation
    var scheme = try hash_zig.GeneralizedXMSSSignatureScheme.initWithSeed(allocator, .lifetime_2_8, [_]u8{0x42} ** 32);
    defer scheme.deinit();

    std.debug.print("Testing chain computation for epoch=0, chain=0:\n", .{});

    // Get domain elements
    const domain_elements = ShakePRFtoF_8_7.getDomainElement(prf_key, 0, 0);
    std.debug.print("Domain elements: {any}\n", .{domain_elements});

    // Convert to field elements
    var current: [8]FieldElement = undefined;
    for (0..8) |i| {
        current[i] = FieldElement{ .value = domain_elements[i] };
    }
    std.debug.print("Initial field elements: {any}\n", .{current});

    // Simulate chain computation (BASE-1 steps)
    const base = 8; // From LIFETIME_2_8_PARAMS
    for (0..base - 1) |j| {
        const pos_in_chain = @as(u8, @intCast(j + 1));
        std.debug.print("\nChain step {} (pos_in_chain={}):\n", .{ j, pos_in_chain });
        std.debug.print("  Input: {any}\n", .{current});

        // Apply chain tweak hash
        const next = try scheme.applyPoseidonChainTweakHash(current, 0, 0, pos_in_chain, parameter);
        std.debug.print("  Output: {any}\n", .{next});

        // Update current state
        current = next;
    }

    std.debug.print("\nFinal chain end: {any}\n", .{current});
    std.debug.print("Chain end value: 0x{x}\n", .{current[0].value});
}
