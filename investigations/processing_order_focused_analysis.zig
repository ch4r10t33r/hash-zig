const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    std.debug.print("=== Processing Order Focused Analysis ===\n", .{});

    // Initialize RNG with fixed seed
    var seed_bytes = [_]u8{0} ** 32;
    @memset(&seed_bytes, 123);
    var rng = hash_zig.prf.ChaCha12Rng.init(seed_bytes);

    // Generate parameters and PRF key (matching Rust algorithm port)
    var parameter: [5]hash_zig.core.KoalaBearField = undefined;
    var random_bytes: [20]u8 = undefined; // 5 * 4 bytes = 20 bytes for 5 u32 values
    peekRngBytes(&rng, &random_bytes);

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        parameter[i] = hash_zig.core.KoalaBearField{ .value = random_value >> 1 }; // 31-bit field element
    }

    // Generate PRF key (matching Rust algorithm port)
    var prf_key_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &prf_key_bytes);
    std.debug.print("PRF Key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key_bytes)});

    std.debug.print("=== RNG State After Parameter/PRF Generation ===\n", .{});
    var debug_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes);
    std.debug.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Analyze processing order for bottom trees
    std.debug.print("\n=== Bottom Tree Processing Order Analysis ===\n", .{});

    for (0..16) |bottom_tree_index| {
        std.debug.print("\n--- Bottom Tree {} ---\n", .{bottom_tree_index});

        // Simulate the processing order for this bottom tree
        _ = @as(u32, @intCast(bottom_tree_index)); // Suppress unused variable warning

        // Analyze the processing order for each layer
        for (0..4) |layer| {
            const current_level = @as(u8, @intCast(layer));
            const next_level = current_level + 1;

            // Calculate the number of nodes at current level
            var nodes_at_level: u32 = 0;
            if (current_level == 0) {
                nodes_at_level = 16;
            } else if (current_level == 1) {
                nodes_at_level = 8;
            } else if (current_level == 2) {
                nodes_at_level = 4;
            } else if (current_level == 3) {
                nodes_at_level = 2;
            } else {
                nodes_at_level = 1;
            }
            const parents_len = nodes_at_level / 2;

            std.debug.print("Layer {} -> {}: {} nodes -> {} parents\n", .{ current_level, next_level, nodes_at_level, parents_len });

            // Analyze the processing order for this layer
            for (0..parents_len) |i| {
                const parent_pos = @as(u32, @intCast(i));
                const tweak_level = @as(u8, @intCast(current_level)) + 1;

                std.debug.print("  Parent {}: tweak_level={}, pos={}\n", .{ i, tweak_level, parent_pos });
            }
        }
    }

    // Analyze processing order for top tree
    std.debug.print("\n=== Top Tree Processing Order Analysis ===\n", .{});

    for (0..4) |layer| {
        const current_level = @as(u8, @intCast(layer + 4)); // Top tree starts at level 4
        const next_level = current_level + 1;

        // Calculate the number of nodes at current level
        var nodes_at_level: u32 = 0;
        if (layer == 0) {
            nodes_at_level = 16;
        } else if (layer == 1) {
            nodes_at_level = 8;
        } else if (layer == 2) {
            nodes_at_level = 4;
        } else if (layer == 3) {
            nodes_at_level = 2;
        } else {
            nodes_at_level = 1;
        }
        const parents_len = nodes_at_level / 2;

        std.debug.print("Layer {} -> {}: {} nodes -> {} parents\n", .{ current_level, next_level, nodes_at_level, parents_len });

        // Analyze the processing order for this layer
        for (0..parents_len) |i| {
            const parent_pos = @as(u32, @intCast(i));
            const tweak_level = @as(u8, @intCast(current_level)) + 1;

            std.debug.print("  Parent {}: tweak_level={}, pos={}\n", .{ i, tweak_level, parent_pos });
        }
    }

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
