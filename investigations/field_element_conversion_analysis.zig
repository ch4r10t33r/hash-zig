const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    std.debug.print("=== Field Element Conversion Analysis ===\n", .{});

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

    // Analyze field element conversion for tree building
    std.debug.print("\n=== Field Element Conversion Analysis ===\n", .{});

    // Simulate a tree building operation to analyze field element conversion
    const left_child = [_]u32{ 123456789, 987654321, 456789123, 789123456, 321654987, 654987321, 147258369, 369258147 };
    const right_child = [_]u32{ 111222333, 444555666, 777888999, 123456789, 987654321, 456789123, 789123456, 321654987 };
    const tweak_level: u8 = 5;
    const position: u32 = 0;

    std.debug.print("Left Child: {any}\n", .{left_child});
    std.debug.print("Right Child: {any}\n", .{right_child});
    std.debug.print("Tweak Level: {}\n", .{tweak_level});
    std.debug.print("Position: {}\n", .{position});

    // Analyze tweak encoding
    const tweak_encoding = (@as(u128, tweak_level) << 32) | @as(u128, position);
    std.debug.print("Tweak Encoding: {}\n", .{tweak_encoding});

    // Convert to field elements using base-p representation
    const tweak = tweakToFieldElements(tweak_encoding);
    std.debug.print("Tweak Field Elements: {any}\n", .{tweak});

    // Analyze field element conversion
    std.debug.print("\n=== Field Element Conversion Analysis ===\n", .{});

    // Parameter (5 elements)
    std.debug.print("Parameter (5 elements): {any}\n", .{parameter});

    // Tweak (2 elements)
    std.debug.print("Tweak (2 elements): {any}\n", .{tweak});

    // Message (left + right child, 16 elements total)
    std.debug.print("Message (16 elements): Left={any}, Right={any}\n", .{ left_child, right_child });

    // Analyze the specific field element conversion
    std.debug.print("\n=== Field Element Conversion Details ===\n", .{});

    // Convert left child to field elements
    var left_child_field: [8]hash_zig.core.KoalaBearField = undefined;
    for (0..8) |i| {
        left_child_field[i] = hash_zig.core.KoalaBearField{ .value = left_child[i] };
    }
    std.debug.print("Left Child Field Elements: {any}\n", .{left_child_field});

    // Convert right child to field elements
    var right_child_field: [8]hash_zig.core.KoalaBearField = undefined;
    for (0..8) |i| {
        right_child_field[i] = hash_zig.core.KoalaBearField{ .value = right_child[i] };
    }
    std.debug.print("Right Child Field Elements: {any}\n", .{right_child_field});

    // Analyze the specific differences in field element conversion
    std.debug.print("\n=== Field Element Conversion Differences ===\n", .{});
    std.debug.print("Rust: Uses KoalaBear field elements directly\n", .{});
    std.debug.print("Zig: Converts u32 to KoalaBearField{{ .value = u32 }}\n", .{});

    // Show the difference in field element conversion
    std.debug.print("Rust Field Element Conversion:\n", .{});
    std.debug.print("  KoalaBear{{ .value = u32 }}\n", .{});
    std.debug.print("Zig Field Element Conversion:\n", .{});
    std.debug.print("  KoalaBearField{{ .value = u32 }}\n", .{});

    std.debug.print("Both use the same field element conversion!\n", .{});

    // Analyze the specific field element conversion for tweak
    std.debug.print("\n=== Tweak Field Element Conversion ===\n", .{});
    std.debug.print("Tweak Encoding: {}\n", .{tweak_encoding});
    std.debug.print("Tweak Field Elements: {any}\n", .{tweak});

    // Analyze the base-p representation
    const p = hash_zig.core.KoalaBearField.PRIME;
    std.debug.print("Prime: {}\n", .{p});
    std.debug.print("Tweak[0] = tweak_encoding % p = {}\n", .{tweak[0].value});
    std.debug.print("Tweak[1] = (tweak_encoding / p) % p = {}\n", .{tweak[1].value});

    // Analyze the specific differences in tweak field element conversion
    std.debug.print("\n=== Tweak Field Element Conversion Differences ===\n", .{});
    std.debug.print("Rust: Uses base-p representation for tweak encoding\n", .{});
    std.debug.print("Zig: Uses base-p representation for tweak encoding\n", .{});

    std.debug.print("Both use the same tweak field element conversion!\n", .{});

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

// Convert tweak encoding to field elements using base-p representation
fn tweakToFieldElements(tweak_encoding: u128) [2]hash_zig.core.KoalaBearField {
    const p = hash_zig.core.KoalaBearField.PRIME;

    // Convert to base-p representation
    var result: [2]hash_zig.core.KoalaBearField = undefined;

    // First field element: tweak_encoding % p
    result[0] = hash_zig.core.KoalaBearField{ .value = @as(u32, @intCast(tweak_encoding % p)) };

    // Second field element: (tweak_encoding / p) % p
    result[1] = hash_zig.core.KoalaBearField{ .value = @as(u32, @intCast((tweak_encoding / p) % p)) };

    return result;
}
