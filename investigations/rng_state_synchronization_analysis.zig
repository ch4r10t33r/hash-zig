const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    std.debug.print("=== RNG State Synchronization Analysis ===\n", .{});

    // Initialize RNG with fixed seed
    var seed_bytes = [_]u8{0} ** 32;
    @memset(&seed_bytes, 123);
    var rng = hash_zig.prf.ChaCha12Rng.init(seed_bytes);

    std.debug.print("=== Initial RNG State ===\n", .{});
    var debug_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Generate parameters and PRF key (matching Rust algorithm port)
    var parameter: [5]hash_zig.core.KoalaBearField = undefined;
    var random_bytes: [20]u8 = undefined; // 5 * 4 bytes = 20 bytes for 5 u32 values
    peekRngBytes(&rng, &random_bytes);

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        parameter[i] = hash_zig.core.KoalaBearField{ .value = random_value >> 1 }; // 31-bit field element
    }

    std.debug.print("=== RNG State After Parameter Generation ===\n", .{});
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Generate PRF key (matching Rust algorithm port)
    var prf_key_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &prf_key_bytes);
    std.debug.print("PRF Key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key_bytes)});

    std.debug.print("=== RNG State After PRF Key Generation ===\n", .{});
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Analyze RNG consumption during tree building
    std.debug.print("\n=== RNG Consumption During Tree Building ===\n", .{});

    // Simulate bottom tree building
    std.debug.print("--- Bottom Tree 0 ---\n", .{});
    for (0..4) |layer| {
        const current_level = @as(u8, @intCast(layer));
        const next_level = current_level + 1;

        std.debug.print("Layer {} -> {}: Building layer\n", .{ current_level, next_level });

        // Check RNG state before layer
        peekRngBytes(&rng, &debug_bytes);
        std.debug.print("  RNG State Before Layer: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

        // Simulate padding node generation (if needed)
        if (layer == 0) {
            std.debug.print("  Generating padding node (1 RNG call)\n", .{});
            // Consume 1 RNG call for padding
            var padding_bytes: [4]u8 = undefined;
            peekRngBytes(&rng, &padding_bytes);
            std.debug.print("  Padding Bytes: {x}\n", .{std.fmt.fmtSliceHexLower(&padding_bytes)});
        }

        // Check RNG state after layer
        peekRngBytes(&rng, &debug_bytes);
        std.debug.print("  RNG State After Layer: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});
    }

    // Simulate top tree building
    std.debug.print("\n--- Top Tree ---\n", .{});
    for (0..4) |layer| {
        const current_level = @as(u8, @intCast(layer + 4)); // Top tree starts at level 4
        const next_level = current_level + 1;

        std.debug.print("Layer {} -> {}: Building layer\n", .{ current_level, next_level });

        // Check RNG state before layer
        peekRngBytes(&rng, &debug_bytes);
        std.debug.print("  RNG State Before Layer: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

        // Simulate padding node generation (if needed)
        if (layer == 0) {
            std.debug.print("  Generating padding node (1 RNG call)\n", .{});
            // Consume 1 RNG call for padding
            var padding_bytes: [4]u8 = undefined;
            peekRngBytes(&rng, &padding_bytes);
            std.debug.print("  Padding Bytes: {x}\n", .{std.fmt.fmtSliceHexLower(&padding_bytes)});
        }

        // Check RNG state after layer
        peekRngBytes(&rng, &debug_bytes);
        std.debug.print("  RNG State After Layer: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});
    }

    std.debug.print("\n=== Final RNG State ===\n", .{});
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    std.debug.print("\n=== Analysis Complete ===\n", .{});
}

// Peek RNG bytes without consuming state (matching rust_algorithm_port.zig)
fn peekRngBytes(rng: *hash_zig.prf.ChaCha12Rng, buf: []u8) void {
    // Access the internal state of the RNG to peek without advancing
    const bytes = &rng.state;
    const avail = bytes.len - rng.offset;

    if (avail >= buf.len) {
        // We have enough bytes available in the current state
        @memcpy(buf, bytes[rng.offset..][0..buf.len]);
    } else {
        // Need to peek into the next state block
        const first_part = avail;

        if (first_part > 0) {
            @memcpy(buf[0..first_part], bytes[rng.offset..][0..first_part]);
        }

        // For the second part, we need to peek into the next state
        // This is a simplified version - in practice, we'd need to compute the next state
        @memset(buf[first_part..], 0);
    }
}
