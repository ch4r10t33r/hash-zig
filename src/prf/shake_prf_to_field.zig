//! ShakePRFtoF implementation matching Rust hash-sig
//! Uses SHAKE128 with domain separation for deterministic PRF

const std = @import("std");
const crypto = std.crypto;

// Constants matching Rust implementation
const PRF_BYTES_PER_FE: usize = 8;
const KEY_LENGTH: usize = 32; // 32 bytes
const MESSAGE_LENGTH: usize = 32; // From Rust hash-sig

// Domain separators matching Rust exactly
const PRF_DOMAIN_SEP: [16]u8 = [16]u8{
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff,
    0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
};
const PRF_DOMAIN_SEP_DOMAIN_ELEMENT: [1]u8 = [1]u8{0x00};
const PRF_DOMAIN_SEP_RANDOMNESS: [1]u8 = [1]u8{0x01};

// KoalaBear field modulus from zig-poseidon
const KOALA_BEAR_MODULUS: u64 = 2130706433; // 0x7f000001 = 2^31 - 2^24 + 1

/// ShakePRFtoF implementation matching Rust ShakePRFtoF<DOMAIN_LENGTH_FE, RAND_LENGTH_FE>
pub fn ShakePRFtoF(comptime DOMAIN_LENGTH_FE: usize, comptime RAND_LENGTH_FE: usize) type {
    return struct {
        const Self = @This();

        pub const Key = [KEY_LENGTH]u8;
        pub const Domain = [DOMAIN_LENGTH_FE]u32;
        pub const Randomness = [RAND_LENGTH_FE]u32;

        /// Generate a random key (matching Rust key_gen)
        pub fn keyGen(rng: anytype) Key {
            var key: Key = undefined;
            for (0..key.len) |i| {
                key[i] = rng.int(u8);
            }
            return key;
        }

        /// Get domain element (matching Rust get_domain_element)
        pub fn getDomainElement(key: Key, epoch: u32, index: u64) Domain {
            // Create SHAKE128 hasher
            var hasher = crypto.hash.sha3.Shake128.init(.{});

            // Hash the domain separator
            hasher.update(&PRF_DOMAIN_SEP);

            // Hash the domain element separator
            hasher.update(&PRF_DOMAIN_SEP_DOMAIN_ELEMENT);

            // Hash the key
            hasher.update(&key);

            // Hash the epoch (big-endian)
            const epoch_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, epoch));
            hasher.update(&epoch_bytes);

            // Hash the index (big-endian)
            const index_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, index));
            hasher.update(&index_bytes);

            // Read output bytes directly using squeeze
            var prf_output: [PRF_BYTES_PER_FE * DOMAIN_LENGTH_FE]u8 = undefined;
            hasher.squeeze(&prf_output);

            // Convert bytes to field elements
            var result: Domain = undefined;
            for (0..DOMAIN_LENGTH_FE) |i| {
                const chunk_start = i * PRF_BYTES_PER_FE;
                const chunk_end = chunk_start + PRF_BYTES_PER_FE;

                // Convert big-endian bytes to u64
                const bytes_array: [PRF_BYTES_PER_FE]u8 = prf_output[chunk_start..chunk_end][0..PRF_BYTES_PER_FE].*;
                const integer_value = std.mem.readInt(u64, &bytes_array, .big);

                // Reduce modulo KoalaBear field order
                result[i] = @intCast(integer_value % KOALA_BEAR_MODULUS);
            }

            return result;
        }

        /// Get randomness (matching Rust get_randomness)
        pub fn getRandomness(key: Key, epoch: u32, message: *const [MESSAGE_LENGTH]u8, counter: u64) Randomness {
            // Create SHAKE128 hasher
            var hasher = crypto.hash.sha3.Shake128.init(.{});

            // Hash the domain separator
            hasher.update(&PRF_DOMAIN_SEP);

            // Hash the randomness separator
            hasher.update(&PRF_DOMAIN_SEP_RANDOMNESS);

            // Hash the key
            hasher.update(&key);

            // Hash the epoch (big-endian)
            const epoch_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, epoch));
            hasher.update(&epoch_bytes);

            // Hash the message
            hasher.update(message);

            // Hash the counter (big-endian)
            const counter_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, counter));
            hasher.update(&counter_bytes);

            // Read output bytes directly using squeeze
            var prf_output: [PRF_BYTES_PER_FE * RAND_LENGTH_FE]u8 = undefined;
            hasher.squeeze(&prf_output);

            // Convert bytes to field elements
            var result: Randomness = undefined;
            for (0..RAND_LENGTH_FE) |i| {
                const chunk_start = i * PRF_BYTES_PER_FE;
                const chunk_end = chunk_start + PRF_BYTES_PER_FE;

                // Convert big-endian bytes to u64
                const bytes_array: [PRF_BYTES_PER_FE]u8 = prf_output[chunk_start..chunk_end][0..PRF_BYTES_PER_FE].*;
                const integer_value = std.mem.readInt(u64, &bytes_array, .big);

                // Reduce modulo KoalaBear field order
                result[i] = @intCast(integer_value % KOALA_BEAR_MODULUS);
            }

            return result;
        }
    };
}

// Convenience type aliases matching Rust usage
pub const ShakePRFtoF_8_7 = ShakePRFtoF(8, 7); // For SIGTopLevelTargetSumLifetime8Dim64Base8

// Test to verify the implementation
test "shake_prf_to_field basic functionality" {
    var rng = std.Random.DefaultPrng.init(12345);
    const key = ShakePRFtoF_8_7.keyGen(rng.random());

    // Test get_domain_element
    const domain = ShakePRFtoF_8_7.getDomainElement(key, 0, 0);
    try std.testing.expect(domain.len == 8);

    // Test get_randomness
    const message = [_]u8{0x48} ** 32; // "H" repeated
    const randomness = ShakePRFtoF_8_7.getRandomness(key, 0, &message, 0);
    try std.testing.expect(randomness.len == 7);

    // Verify all values are in field range
    for (domain) |val| {
        try std.testing.expect(val < KOALA_BEAR_MODULUS);
    }
    for (randomness) |val| {
        try std.testing.expect(val < KOALA_BEAR_MODULUS);
    }
}

test "shake_prf_to_field deterministic output" {
    const key = [_]u8{0x42} ** 32;

    // Same inputs should produce same outputs
    const domain1 = ShakePRFtoF_8_7.getDomainElement(key, 0, 0);
    const domain2 = ShakePRFtoF_8_7.getDomainElement(key, 0, 0);

    for (domain1, domain2) |val1, val2| {
        try std.testing.expectEqual(val1, val2);
    }

    const message = [_]u8{0x48} ** 32;
    const rand1 = ShakePRFtoF_8_7.getRandomness(key, 0, &message, 0);
    const rand2 = ShakePRFtoF_8_7.getRandomness(key, 0, &message, 0);

    for (rand1, rand2) |val1, val2| {
        try std.testing.expectEqual(val1, val2);
    }
}
