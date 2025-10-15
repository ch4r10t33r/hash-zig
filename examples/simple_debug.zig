const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Simple Debug: First 3 Steps ===\n\n", .{});

    const seed = [_]u8{0x42} ** 32;
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    // Step 1: RNG → Parameter
    std.debug.print("1. Parameter (5 field elements from RNG):\n", .{});
    var rng = hash_zig.chacha12_rng.init(seed);
    var parameter: [5]u32 = undefined;
    for (0..5) |i| {
        var bytes: [4]u8 = undefined;
        rng.fill(&bytes);
        parameter[i] = std.mem.readInt(u32, &bytes, .little);
        std.debug.print("   [{d}] = {d}\n", .{ i, parameter[i] });
    }

    // Step 2: RNG → PRF key
    std.debug.print("\n2. PRF Key (32 bytes from RNG):\n", .{});
    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);
    std.debug.print("   {s}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Step 3: PRF → First OTS private key (epoch 0, chain 0)
    std.debug.print("\n3. First OTS chain (epoch=0, chain=0):\n", .{});
    const chain0 = try hash_zig.prf.ShakePRF.getDomainElementsNative(
        allocator,
        &prf_key,
        0, // epoch
        0, // chain_idx
        params.chain_hash_output_len_fe,
    );
    defer allocator.free(chain0);

    std.debug.print("   Output ({d} field elements):\n", .{chain0.len});
    for (chain0, 0..) |elem, i| {
        std.debug.print("   [{d}] = {d}\n", .{ i, elem.toU32() });
    }

    std.debug.print("\n=== Compare these values with Rust ===\n\n", .{});
}
