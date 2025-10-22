//! ChaCha12 CSPRNG matching Rust's StdRng (rand crate 0.9.x)
//! Based on Zig's std.Random.ChaCha but using ChaCha12 instead of ChaCha8

const std = @import("std");
const mem = std.mem;
const Self = @This();

// Use ChaCha12IETF variant (12 rounds, matching Rust's StdRng/rand_chacha 0.9.x)
const Cipher = std.crypto.stream.chacha.ChaCha12IETF;

const State = [8 * Cipher.block_length]u8;

pub const ChaCha12Rng = struct {
    state: State,
    offset: usize,

    const nonce = [_]u8{0} ** Cipher.nonce_length;

    pub const secret_seed_length = Cipher.key_length;

    /// Initialize from a 32-byte seed (matching Rust's StdRng::from_seed)
    pub fn init(secret_seed: [secret_seed_length]u8) Self {
    var self = Self{ .state = undefined, .offset = Cipher.key_length };
    Cipher.stream(&self.state, 0, secret_seed, nonce);
    // Note: Rust's implementation uses the FIRST block (bytes 0-31),
    // but std.Random.ChaCha skips the key (first 32 bytes) for forward security.
    // To match Rust exactly, we set offset to 0 to use bytes from the start.
    self.offset = 0;
    return self;
}

/// Returns a `std.Random` structure backed by the current RNG.
pub fn random(self: *Self) std.Random {
    return std.Random.init(self, fill);
}

// Refills the buffer with random bytes, overwriting the previous key.
fn refill(self: *Self) void {
    Cipher.stream(&self.state, 0, self.state[0..Cipher.key_length].*, nonce);
    self.offset = 0;
}

/// Fills the buffer with random bytes (matching Rust's RngCore::fill_bytes).
pub fn fill(self: *Self, buf_: []u8) void {
    // Use entire state for compatibility with Rust (not skipping key like std.Random.ChaCha)
    const bytes = &self.state;
    var buf = buf_;

    const avail = bytes.len - self.offset;
    if (avail > 0) {
        // Bytes from the current block
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], bytes[self.offset..][0..n]);
        buf = buf[n..];
        self.offset += n;
    }
    if (buf.len == 0) return;

    self.refill();

    // Full blocks
    while (buf.len >= bytes.len) {
        @memcpy(buf[0..bytes.len], bytes);
        buf = buf[bytes.len..];
        self.refill();
    }

    // Remaining bytes
    if (buf.len > 0) {
        @memcpy(buf, bytes[0..buf.len]);
        self.offset = buf.len;
    }
}

test "chacha12 rng basic" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var rng = init(seed);
    var buf: [64]u8 = undefined;
    rng.fill(&buf);

    // Should produce different bytes (not all zeros or all same)
    const all_same = blk: {
        for (buf[1..]) |b| {
            if (b != buf[0]) break :blk false;
        }
        break :blk true;
    };
    try std.testing.expect(!all_same);
}

test "chacha12 rng deterministic" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var rng1 = init(seed);
    var buf1: [64]u8 = undefined;
    rng1.fill(&buf1);

    var rng2 = init(seed);
    var buf2: [64]u8 = undefined;
    rng2.fill(&buf2);

    // Same seed should produce same output
    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "chacha12 matches rust stdrng" {
    // Test that we match Rust's StdRng output for the same seed
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var rng = init(seed);
    var prf_key: [32]u8 = undefined;
    rng.fill(&prf_key);

    // Expected output from Rust's StdRng::from_seed([0x42; 32]).random()
    const expected_rust_prf_key = [_]u8{
        0x32, 0x03, 0x87, 0x86, 0xf4, 0x80, 0x3d, 0xdc,
        0xc9, 0xa7, 0xbb, 0xed, 0x5a, 0xe6, 0x72, 0xdf,
        0x91, 0x9e, 0x46, 0x9b, 0x7e, 0x26, 0xe9, 0xc3,
        0x88, 0xd1, 0x2b, 0xe8, 0x17, 0x90, 0xcc, 0xc9,
    };

    // Compare with Rust output
    try std.testing.expectEqualSlices(u8, &expected_rust_prf_key, &prf_key);
}
