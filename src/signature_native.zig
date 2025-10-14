//! Hash-based signature scheme (Field-Native Implementation)
//!
//! This implementation operates directly on field elements (KoalaBear)
//! for compatibility with the Rust hash-sig implementation.
//!
//! Key differences from byte-based implementation (signature.zig):
//! - Merkle root is a single FieldElement, not bytes
//! - Tree nodes are field elements
//! - OTS signatures are field element arrays
//! - Authentication paths are field elements

const std = @import("std");
const params = @import("params.zig");
const winternitz_native = @import("winternitz_native.zig");
const merkle_native = @import("merkle_native.zig");
const field_types = @import("field.zig");
const chacha12_rng = @import("chacha12_rng.zig");
const Parameters = params.Parameters;
const WinternitzOTSNative = winternitz_native.WinternitzOTSNative;
const MerkleTreeNative = merkle_native.MerkleTreeNative;
const FieldElement = field_types.FieldElement;
const Allocator = std.mem.Allocator;

pub const HashSignatureNative = struct {
    params: Parameters,
    wots: WinternitzOTSNative,
    tree: MerkleTreeNative,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !HashSignatureNative {
        return .{
            .params = parameters,
            .wots = try WinternitzOTSNative.init(allocator, parameters),
            .tree = try MerkleTreeNative.init(allocator, parameters),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HashSignatureNative) void {
        self.wots.deinit();
        self.tree.deinit();
    }

    /// Public key - field-native version
    pub const PublicKey = struct {
        root: FieldElement, // Merkle root (single field element)
        parameter: Parameters,

        pub fn serialize(self: *const PublicKey, allocator: Allocator) ![]u8 {
            // Serialize as: root (4 bytes for KoalaBear) + parameters (20 bytes)
            var buffer = std.ArrayList(u8).init(allocator);
            errdefer buffer.deinit();

            // Root as field element (4 bytes, little-endian)
            const root_bytes = self.root.toBytes();
            try buffer.appendSlice(&root_bytes);

            // Parameters (same as byte-based version)
            try buffer.append(@intFromEnum(self.parameter.security_level));
            try buffer.append(@intFromEnum(self.parameter.hash_function));
            try buffer.append(@intFromEnum(self.parameter.encoding_type));

            var temp: [4]u8 = undefined;
            std.mem.writeInt(u32, &temp, self.parameter.tree_height, .little);
            try buffer.appendSlice(&temp);

            std.mem.writeInt(u32, &temp, self.parameter.winternitz_w, .little);
            try buffer.appendSlice(&temp);

            std.mem.writeInt(u32, &temp, self.parameter.num_chains, .little);
            try buffer.appendSlice(&temp);

            std.mem.writeInt(u32, &temp, self.parameter.hash_output_len, .little);
            try buffer.appendSlice(&temp);

            try buffer.append(@intFromEnum(self.parameter.key_lifetime));

            return buffer.toOwnedSlice();
        }
    };

    /// Secret key - field-native version
    pub const SecretKey = struct {
        prf_key: [32]u8,
        tree: [][]FieldElement, // Full tree: tree[level][index]
        tree_height: u32,
        parameter: Parameters,
        activation_epoch: u64,
        num_active_epochs: u64,

        pub fn deinit(self: *SecretKey, allocator: Allocator) void {
            for (self.tree) |level| allocator.free(level);
            allocator.free(self.tree);
        }
    };

    pub const KeyPair = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn deinit(self: *KeyPair, allocator: Allocator) void {
            self.secret_key.deinit(allocator);
        }
    };

    /// Signature - field-native version
    pub const Signature = struct {
        epoch: u64,
        auth_path: []FieldElement, // Authentication path
        rho: [32]u8, // Encoding randomness (not yet used)
        hashes: [][]FieldElement, // OTS signature

        pub fn deinit(self: *Signature, allocator: Allocator) void {
            for (self.hashes) |hash| allocator.free(hash);
            allocator.free(self.hashes);
            allocator.free(self.auth_path);
        }
    };

    /// Generate key pair
    pub fn generateKeyPair(
        self: *HashSignatureNative,
        allocator: Allocator,
        seed: []const u8,
        activation_epoch: u64,
        num_active_epochs: u64,
    ) !KeyPair {
        if (seed.len < 32) return error.SeedTooShort;

        // CRITICAL: Generate PRF key from RNG FIRST (before generating leaves)
        // In Rust: let prf_key = PRF::key_gen(rng); which calls rng.random()
        // Use ChaCha12 to match Rust's StdRng (rand crate 0.9.x uses ChaCha12)
        var prf_key: [32]u8 = undefined;
        var rng = chacha12_rng.init(seed[0..32].*);
        rng.fill(&prf_key);

        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);

        // Validate epoch range
        if (activation_epoch + num_active_epochs > num_leaves) {
            return error.InvalidEpochRange;
        }

        // Generate all OTS public keys (leaves)
        var leaves = try allocator.alloc(FieldElement, num_leaves);
        defer allocator.free(leaves);

        for (0..num_leaves) |i| {
            const epoch = @as(u32, @intCast(i));

            // Generate private key (field elements)
            const sk = try self.wots.generatePrivateKey(allocator, &prf_key, epoch);
            defer {
                for (sk) |k| allocator.free(k);
                allocator.free(sk);
            }

            // Generate public key (concatenated field elements)
            const pk = try self.wots.generatePublicKey(allocator, sk, epoch);
            defer allocator.free(pk);

            // Hash public key to single field element for tree leaf
            // For simplicity, use the first element as the leaf
            // In production, this should hash all elements together
            leaves[i] = pk[0];
        }

        // Build full Merkle tree
        const tree_levels = try self.tree.buildFullTree(allocator, leaves);

        const root = tree_levels[tree_levels.len - 1][0];

        return KeyPair{
            .public_key = PublicKey{
                .root = root,
                .parameter = self.params,
            },
            .secret_key = SecretKey{
                .prf_key = prf_key,
                .tree = tree_levels,
                .tree_height = self.params.tree_height,
                .parameter = self.params,
                .activation_epoch = activation_epoch,
                .num_active_epochs = num_active_epochs,
            },
        };
    }

    /// Sign a message
    pub fn sign(
        self: *HashSignatureNative,
        allocator: Allocator,
        secret_key: *const SecretKey,
        message: []const u8,
        epoch: u64,
    ) !Signature {
        // Validate epoch
        if (epoch < secret_key.activation_epoch or
            epoch >= secret_key.activation_epoch + secret_key.num_active_epochs)
        {
            return error.InvalidEpoch;
        }

        const epoch_u32 = @as(u32, @intCast(epoch));

        // Generate OTS private key for this epoch
        const ots_sk = try self.wots.generatePrivateKey(allocator, &secret_key.prf_key, epoch_u32);
        defer {
            for (ots_sk) |k| allocator.free(k);
            allocator.free(ots_sk);
        }

        // Sign message with OTS
        const ots_signature = try self.wots.sign(allocator, ots_sk, message, epoch_u32);

        // Get authentication path from tree
        const auth_path = try self.tree.getAuthPath(
            allocator,
            @ptrCast(secret_key.tree),
            @intCast(epoch),
        );

        return Signature{
            .epoch = epoch,
            .auth_path = auth_path,
            .rho = std.mem.zeroes([32]u8), // Not used yet
            .hashes = ots_signature,
        };
    }

    /// Verify a signature
    pub fn verify(
        self: *HashSignatureNative,
        allocator: Allocator,
        public_key: *const PublicKey,
        message: []const u8,
        signature: *const Signature,
    ) !bool {
        const epoch_u32 = @as(u32, @intCast(signature.epoch));

        // Recover OTS public key from signature
        const ots_pk = try self.recoverOTSPublicKey(
            allocator,
            message,
            signature.hashes,
            epoch_u32,
        );
        defer allocator.free(ots_pk);

        // Convert to tree leaf (use first element for simplicity)
        const leaf = ots_pk[0];

        // Verify Merkle path
        return self.tree.verifyAuthPath(
            allocator,
            leaf,
            @intCast(signature.epoch),
            signature.auth_path,
            public_key.root,
        );
    }

    /// Helper: Recover OTS public key from signature
    fn recoverOTSPublicKey(
        self: *HashSignatureNative,
        allocator: Allocator,
        message: []const u8,
        signature_hashes: []const []FieldElement,
        epoch: u32,
    ) ![]FieldElement {
        // Encode message
        var encoder = @import("encoding.zig").IncomparableEncoding.init(self.params);
        const encoded = try encoder.encode(allocator, message);
        defer allocator.free(encoded);

        if (signature_hashes.len != encoded.len) return error.SignatureLengthMismatch;

        const chain_len = self.wots.getChainLength();
        var recovered_parts = try allocator.alloc([]FieldElement, signature_hashes.len);
        defer {
            for (recovered_parts) |part| allocator.free(part);
            allocator.free(recovered_parts);
        }

        // For each signature part, hash from encoded position to chain end
        for (signature_hashes, 0..) |sig_part, chain_idx| {
            const target_pos = encoded[chain_idx];
            var current = try allocator.dupe(FieldElement, sig_part);

            // Hash from target_pos to chain_len
            for (target_pos..chain_len) |pos_in_chain| {
                const tweak = @import("tweak.zig").PoseidonTweak{ .chain_tweak = .{
                    .epoch = epoch,
                    .chain_index = @intCast(chain_idx),
                    .pos_in_chain = @intCast(pos_in_chain),
                } };

                const next = try self.wots.hash.hashFieldElements(
                    allocator,
                    current,
                    tweak,
                    7, // chain_hash_output_len_fe
                );
                allocator.free(current);
                current = next;
            }

            recovered_parts[chain_idx] = current;
        }

        // Concatenate all parts
        var total_len: usize = 0;
        for (recovered_parts) |part| {
            total_len += part.len;
        }

        var result = try allocator.alloc(FieldElement, total_len);
        var offset: usize = 0;
        for (recovered_parts) |part| {
            @memcpy(result[offset..][0..part.len], part);
            offset += part.len;
        }

        return result;
    }
};

test "signature native: key generation" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_10); // 2^10 = 1024 signatures

    var hash_sig = try HashSignatureNative.init(allocator, parameters);
    defer hash_sig.deinit();

    const seed = "test_seed_32_bytes_long_padded!!";
    const activation_epoch: u64 = 0;
    const num_active_epochs: u64 = 1024;

    var keypair = try hash_sig.generateKeyPair(
        allocator,
        seed,
        activation_epoch,
        num_active_epochs,
    );
    defer keypair.deinit(allocator);

    // Root should be non-zero
    try std.testing.expect(keypair.public_key.root.value != 0);

    // Tree should have correct height + 1 levels
    const expected_levels = parameters.tree_height + 1;
    try std.testing.expectEqual(@as(usize, expected_levels), keypair.secret_key.tree.len);
}

test "signature native: sign and verify" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_10);

    var hash_sig = try HashSignatureNative.init(allocator, parameters);
    defer hash_sig.deinit();

    const seed = "test_seed_32_bytes_long_padded!!";
    const activation_epoch: u64 = 0;
    const num_active_epochs: u64 = 10; // Small for testing

    var keypair = try hash_sig.generateKeyPair(
        allocator,
        seed,
        activation_epoch,
        num_active_epochs,
    );
    defer keypair.deinit(allocator);

    // Create message hash (20 bytes)
    var message_hash: [20]u8 = undefined;
    for (0..20) |i| {
        message_hash[i] = @intCast((i * 13 + 7) % 256);
    }

    // Sign
    const epoch: u64 = 5;
    var signature = try hash_sig.sign(allocator, &keypair.secret_key, &message_hash, epoch);
    defer signature.deinit(allocator);

    // Verify
    const is_valid = try hash_sig.verify(allocator, &keypair.public_key, &message_hash, &signature);
    try std.testing.expect(is_valid);

    // Wrong message should fail
    var wrong_message: [20]u8 = undefined;
    for (0..20) |i| {
        wrong_message[i] = @intCast((i * 17 + 3) % 256);
    }
    const is_invalid = try hash_sig.verify(allocator, &keypair.public_key, &wrong_message, &signature);
    try std.testing.expect(!is_invalid);
}

test "signature native: epoch validation" {
    const allocator = std.testing.allocator;
    const parameters = Parameters.init(.lifetime_2_10);

    var hash_sig = try HashSignatureNative.init(allocator, parameters);
    defer hash_sig.deinit();

    const seed = "test_seed_32_bytes_long_padded!!";
    const activation_epoch: u64 = 100;
    const num_active_epochs: u64 = 10; // Valid: 100-109

    var keypair = try hash_sig.generateKeyPair(
        allocator,
        seed,
        activation_epoch,
        num_active_epochs,
    );
    defer keypair.deinit(allocator);

    var message_hash: [20]u8 = undefined;
    for (0..20) |i| {
        message_hash[i] = @intCast((i * 13 + 7) % 256);
    }

    // Valid epoch should succeed
    const epoch_valid: u64 = 105;
    var sig_valid = try hash_sig.sign(allocator, &keypair.secret_key, &message_hash, epoch_valid);
    defer sig_valid.deinit(allocator);

    // Invalid epoch (too high) should fail
    const epoch_invalid: u64 = 110;
    const result = hash_sig.sign(allocator, &keypair.secret_key, &message_hash, epoch_invalid);
    try std.testing.expectError(error.InvalidEpoch, result);
}
