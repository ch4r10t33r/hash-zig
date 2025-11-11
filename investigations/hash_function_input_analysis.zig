const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    _ = gpa.allocator(); // Suppress unused variable warning

    log.print("=== Hash Function Input Structure Analysis ===\n", .{});

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
    log.print("PRF Key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key_bytes)});

    log.print("=== RNG State After Parameter/PRF Generation ===\n", .{});
    var debug_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &debug_bytes);
    log.print("RNG State: {x}\n", .{std.fmt.fmtSliceHexLower(&debug_bytes)});

    // Analyze hash function input structure for tree building
    log.print("\n=== Hash Function Input Structure Analysis ===\n", .{});

    // Simulate a tree building operation to analyze input structure
    const left_child = [_]u32{ 123456789, 987654321, 456789123, 789123456, 321654987, 654987321, 147258369, 369258147 };
    const right_child = [_]u32{ 111222333, 444555666, 777888999, 123456789, 987654321, 456789123, 789123456, 321654987 };
    const tweak_level: u8 = 5;
    const position: u32 = 0;

    log.print("Left Child: {any}\n", .{left_child});
    log.print("Right Child: {any}\n", .{right_child});
    log.print("Tweak Level: {}\n", .{tweak_level});
    log.print("Position: {}\n", .{position});

    // Analyze tweak encoding
    const tweak_encoding = (@as(u128, tweak_level) << 32) | @as(u128, position);
    log.print("Tweak Encoding: {}\n", .{tweak_encoding});

    // Convert to field elements using base-p representation
    const tweak = tweakToFieldElements(tweak_encoding);
    log.print("Tweak Field Elements: {any}\n", .{tweak});

    // Analyze hash function input structure
    log.print("\n=== Hash Function Input Structure ===\n", .{});

    // Parameter (5 elements)
    log.print("Parameter (5 elements): {any}\n", .{parameter});

    // Tweak (2 elements)
    log.print("Tweak (2 elements): {any}\n", .{tweak});

    // Message (left + right child, 16 elements total)
    log.print("Message (16 elements): Left={any}, Right={any}\n", .{ left_child, right_child });

    // Total input length
    const total_input_len = 5 + 2 + 16; // parameter + tweak + message
    log.print("Total Input Length: {} elements\n", .{total_input_len});

    // Analyze the specific input structure that would be passed to Poseidon2
    log.print("\n=== Poseidon2 Input Structure ===\n", .{});
    log.print("Input[0-4]: Parameter elements\n", .{});
    log.print("Input[5-6]: Tweak elements\n", .{});
    log.print("Input[7-14]: Left child elements\n", .{});
    log.print("Input[15-22]: Right child elements\n", .{});

    // Analyze how Rust vs Zig might structure this differently
    log.print("\n=== Rust vs Zig Input Structure Comparison ===\n", .{});
    log.print("Rust: Processes left and right as separate iterators\n", .{});
    log.print("Zig: Concatenates left and right into single array\n", .{});

    // Show the difference
    var combined_message: [16]u32 = undefined;
    for (0..8) |i| {
        combined_message[i] = left_child[i];
        combined_message[i + 8] = right_child[i];
    }
    log.print("Zig Combined Message: {any}\n", .{combined_message});

    log.print("Rust Left Iterator: {any}\n", .{left_child});
    log.print("Rust Right Iterator: {any}\n", .{right_child});

    log.print("\n=== Analysis Complete ===\n", .{});
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
