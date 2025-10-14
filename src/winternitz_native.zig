//! Winternitz One-Time Signature scheme (Field-Native Implementation)
//!
//! This implementation operates directly on field elements (KoalaBear)
//! for compatibility with the Rust hash-sig implementation.
//!
//! Key differences from byte-based implementation (winternitz.zig):
//! - Private keys are arrays of field elements, not bytes
//! - Hash chains operate on field elements, not byte arrays
//! - PRF generates field elements directly via SHAKE-128
//! - Public keys are field element arrays

const std = @import("std");
const params = @import("params.zig");
const tweakable_hash = @import("tweakable_hash.zig");
const encoding = @import("encoding.zig");
const field_types = @import("field.zig");
const tweak_types = @import("tweak.zig");
const Parameters = params.Parameters;
const TweakableHash = tweakable_hash.TweakableHash;
const IncomparableEncoding = encoding.IncomparableEncoding;
const FieldElement = field_types.FieldElement;
const PoseidonTweak = tweak_types.PoseidonTweak;
const Allocator = std.mem.Allocator;

pub const WinternitzOTSNative = struct {
    params: Parameters,
    hash: TweakableHash,

    pub fn init(allocator: Allocator, parameters: Parameters) !WinternitzOTSNative {
        return .{
            .params = parameters,
            .hash = try TweakableHash.init(allocator, parameters),
        };
    }

    pub fn deinit(self: *WinternitzOTSNative) void {
        self.hash.deinit();
    }

    pub inline fn getChainLength(self: WinternitzOTSNative) u32 {
        return @as(u32, 1) << @intCast(self.params.winternitz_w);
    }

    /// Generate private key as field elements
    /// This matches Rust's PRF::get_domain_element() which returns field elements
    pub fn generatePrivateKey(
        self: *WinternitzOTSNative,
        allocator: Allocator,
        prf_key: []const u8,
        epoch: u32,
    ) ![][]FieldElement {
        const num_chains = self.params.num_chains;
        const chain_hash_output_len_fe = self.params.chain_hash_output_len_fe;

        var private_key = try allocator.alloc([]FieldElement, num_chains);
        errdefer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        for (0..num_chains) |chain_index| {
            // Generate field elements directly from SHAKE-128 PRF
            private_key[chain_index] = try self.hash.prfHashFieldElements(
                allocator,
                prf_key,
                epoch,
                chain_index,
                chain_hash_output_len_fe,
            );
        }

        return private_key;
    }

    const ChainGenContext = struct {
        wots: *WinternitzOTSNative,
        private_key: [][]FieldElement,
        public_parts: [][]FieldElement,
        chain_len: u32,
        epoch: u32,
        parent_allocator: Allocator,
        errors: []?anyerror,
        mutex: std.Thread.Mutex,
    };

    fn generateChainRange(context: *ChainGenContext, start: usize, end: usize) void {
        // Create thread-local arena for this worker
        var thread_arena = std.heap.ArenaAllocator.init(context.parent_allocator);
        defer thread_arena.deinit();
        const allocator = thread_arena.allocator();

        for (start..end) |i| {
            var current = allocator.dupe(FieldElement, context.private_key[i]) catch |err| {
                context.mutex.lock();
                defer context.mutex.unlock();
                context.errors[i] = err;
                return;
            };

            // Iterate hash chain
            for (0..context.chain_len) |pos_in_chain| {
                // Create chain tweak for this iteration
                const tweak = PoseidonTweak{ .chain_tweak = .{
                    .epoch = context.epoch,
                    .chain_index = @intCast(i),
                    .pos_in_chain = @intCast(pos_in_chain),
                } };

                // Use hardcoded 7 for KoalaBear chain hash output (matches Rust)
                const next = context.wots.hash.hashFieldElements(
                    allocator,
                    current,
                    tweak,
                    7, // chain_hash_output_len_fe for KoalaBear
                ) catch |err| {
                    context.mutex.lock();
                    defer context.mutex.unlock();
                    context.errors[i] = err;
                    return;
                };
                current = next;
            }

            // Duplicate to parent allocator since thread arena will be freed
            context.mutex.lock();
            const result = context.parent_allocator.dupe(FieldElement, current) catch |err| {
                context.errors[i] = err;
                context.mutex.unlock();
                return;
            };
            context.public_parts[i] = result;
            context.mutex.unlock();
        }
    }

    /// Generate public key from private key (field-native)
    pub fn generatePublicKey(
        self: *WinternitzOTSNative,
        allocator: Allocator,
        private_key: [][]FieldElement,
        epoch: u32,
    ) ![]FieldElement {
        const chain_len = self.getChainLength();

        const public_parts = try allocator.alloc([]FieldElement, private_key.len);
        defer {
            for (public_parts) |part| {
                if (part.len > 0) allocator.free(part);
            }
            allocator.free(public_parts);
        }

        // Initialize public_parts to empty slices
        for (public_parts) |*part| {
            part.* = &[_]FieldElement{};
        }

        const errors = try allocator.alloc(?anyerror, private_key.len);
        defer allocator.free(errors);
        @memset(errors, null);

        const num_threads = 4;
        const chains_per_thread = (private_key.len + num_threads - 1) / num_threads;

        var context = ChainGenContext{
            .wots = self,
            .private_key = private_key,
            .public_parts = public_parts,
            .chain_len = chain_len,
            .epoch = epoch,
            .parent_allocator = allocator,
            .errors = errors,
            .mutex = std.Thread.Mutex{},
        };

        var threads = try allocator.alloc(std.Thread, num_threads);
        defer allocator.free(threads);

        // Spawn worker threads
        for (0..num_threads) |i| {
            const start = i * chains_per_thread;
            const end = @min(start + chains_per_thread, private_key.len);
            if (start >= end) continue;

            threads[i] = try std.Thread.spawn(.{}, generateChainRange, .{ &context, start, end });
        }

        // Wait for all threads
        for (0..num_threads) |i| {
            const start = i * chains_per_thread;
            if (start >= private_key.len) continue;
            threads[i].join();
        }

        // Check for errors
        for (errors, 0..) |err, i| {
            if (err) |e| {
                std.debug.print("Chain generation error at index {d}: {}\n", .{ i, e });
                return e;
            }
        }

        // Concatenate all public parts into a single array
        var total_len: usize = 0;
        for (public_parts) |part| {
            total_len += part.len;
        }

        var result = try allocator.alloc(FieldElement, total_len);
        var offset: usize = 0;
        for (public_parts) |part| {
            @memcpy(result[offset..][0..part.len], part);
            offset += part.len;
        }

        return result;
    }

    /// Sign a message (field-native)
    pub fn sign(
        self: *WinternitzOTSNative,
        allocator: Allocator,
        private_key: [][]FieldElement,
        message: []const u8,
        epoch: u32,
    ) ![][]FieldElement {
        // Encode message to chain positions
        var encoder = IncomparableEncoding.init(self.params);
        const encoded = try encoder.encode(allocator, message);
        defer allocator.free(encoded);

        // Compute signature for each chain
        var signature = try allocator.alloc([]FieldElement, encoded.len);
        errdefer {
            for (signature) |sig| allocator.free(sig);
            allocator.free(signature);
        }

        for (encoded, 0..) |target_pos, chain_idx| {
            var current = try allocator.dupe(FieldElement, private_key[chain_idx]);
            errdefer allocator.free(current);

            // Hash chain from 0 to target_pos
            for (0..target_pos) |pos_in_chain| {
                const tweak = PoseidonTweak{ .chain_tweak = .{
                    .epoch = epoch,
                    .chain_index = @intCast(chain_idx),
                    .pos_in_chain = @intCast(pos_in_chain),
                } };

                // Use hardcoded 7 for KoalaBear chain hash output (matches Rust)
                const next = try self.hash.hashFieldElements(
                    allocator,
                    current,
                    tweak,
                    7, // chain_hash_output_len_fe for KoalaBear
                );
                allocator.free(current);
                current = next;
            }

            signature[chain_idx] = current;
        }

        return signature;
    }

    /// Verify a signature (field-native)
    pub fn verify(
        self: *WinternitzOTSNative,
        allocator: Allocator,
        public_key: []FieldElement,
        message: []const u8,
        signature: [][]FieldElement,
        epoch: u32,
    ) !bool {
        // Encode message
        var encoder = IncomparableEncoding.init(self.params);
        const encoded = try encoder.encode(allocator, message);
        defer allocator.free(encoded);

        if (signature.len != encoded.len) return false;

        const chain_len = self.getChainLength();

        // Compute public key from signature
        var computed_parts = try allocator.alloc([]FieldElement, signature.len);
        defer {
            for (computed_parts) |part| allocator.free(part);
            allocator.free(computed_parts);
        }

        for (signature, 0..) |sig_part, chain_idx| {
            const target_pos = encoded[chain_idx];
            var current = try allocator.dupe(FieldElement, sig_part);

            // Hash from target_pos to chain_len
            for (target_pos..chain_len) |pos_in_chain| {
                const tweak = PoseidonTweak{ .chain_tweak = .{
                    .epoch = epoch,
                    .chain_index = @intCast(chain_idx),
                    .pos_in_chain = @intCast(pos_in_chain),
                } };

                // Use hardcoded 7 for KoalaBear chain hash output (matches Rust)
                const next = try self.hash.hashFieldElements(
                    allocator,
                    current,
                    tweak,
                    7, // chain_hash_output_len_fe for KoalaBear
                );
                allocator.free(current);
                current = next;
            }

            computed_parts[chain_idx] = current;
        }

        // Concatenate computed parts
        var total_len: usize = 0;
        for (computed_parts) |part| {
            total_len += part.len;
        }

        var computed_pk = try allocator.alloc(FieldElement, total_len);
        defer allocator.free(computed_pk);

        var offset: usize = 0;
        for (computed_parts) |part| {
            @memcpy(computed_pk[offset..][0..part.len], part);
            offset += part.len;
        }

        // Compare field elements
        if (computed_pk.len != public_key.len) return false;
        for (computed_pk, public_key) |c, p| {
            if (c.value != p.value) return false;
        }

        return true;
    }
};

test "winternitz native: key generation" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);

    var wots = try WinternitzOTSNative.init(allocator, parameters);
    defer wots.deinit();

    const prf_key = "test_key_32_bytes_long_padded";
    const epoch: u32 = 0;

    const private_key = try wots.generatePrivateKey(allocator, prf_key, epoch);
    defer {
        for (private_key) |pk| allocator.free(pk);
        allocator.free(private_key);
    }

    // Should have correct number of chains
    try std.testing.expectEqual(@as(usize, 22), private_key.len);

    // Each chain should have correct number of field elements
    const expected_len = parameters.chain_hash_output_len_fe;
    for (private_key) |pk| {
        try std.testing.expectEqual(expected_len, pk.len);
    }
}

test "winternitz native: sign and verify" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);

    var wots = try WinternitzOTSNative.init(allocator, parameters);
    defer wots.deinit();

    const prf_key = "test_key_32_bytes_long_padded";
    const epoch: u32 = 0;

    // Create message hash (20 bytes / 160 bits for encoding)
    var message_hash: [20]u8 = undefined;
    for (0..20) |i| {
        message_hash[i] = @intCast((i * 13 + 7) % 256); // Simple deterministic hash
    }

    // Generate keys
    const private_key = try wots.generatePrivateKey(allocator, prf_key, epoch);
    defer {
        for (private_key) |pk| allocator.free(pk);
        allocator.free(private_key);
    }

    const public_key = try wots.generatePublicKey(allocator, private_key, epoch);
    defer allocator.free(public_key);

    // Sign
    const signature = try wots.sign(allocator, private_key, &message_hash, epoch);
    defer {
        for (signature) |sig| allocator.free(sig);
        allocator.free(signature);
    }

    // Verify
    const is_valid = try wots.verify(allocator, public_key, &message_hash, signature, epoch);
    try std.testing.expect(is_valid);

    // Verify with wrong message should fail
    var wrong_hash: [20]u8 = undefined;
    for (0..20) |i| {
        wrong_hash[i] = @intCast((i * 17 + 3) % 256); // Different deterministic hash
    }
    const is_invalid = try wots.verify(allocator, public_key, &wrong_hash, signature, epoch);
    try std.testing.expect(!is_invalid);
}

test "winternitz native: deterministic" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_16);

    var wots = try WinternitzOTSNative.init(allocator, parameters);
    defer wots.deinit();

    const prf_key = "test_key_32_bytes_long_padded";
    const epoch: u32 = 0;

    // Generate twice with same inputs
    const pk1 = try wots.generatePrivateKey(allocator, prf_key, epoch);
    defer {
        for (pk1) |pk| allocator.free(pk);
        allocator.free(pk1);
    }

    const pk2 = try wots.generatePrivateKey(allocator, prf_key, epoch);
    defer {
        for (pk2) |pk| allocator.free(pk);
        allocator.free(pk2);
    }

    // Should be identical
    try std.testing.expectEqual(pk1.len, pk2.len);
    for (pk1, pk2) |p1, p2| {
        try std.testing.expectEqual(p1.len, p2.len);
        for (p1, p2) |elem1, elem2| {
            try std.testing.expectEqual(elem1.value, elem2.value);
        }
    }
}
