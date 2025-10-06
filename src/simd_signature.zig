const std = @import("std");
const simd_winternitz = @import("simd_winternitz");
const hz = @import("hash-zig");
const params = hz.params;

// SIMD-optimized hash-based signature scheme
// Integrates SIMD Winternitz OTS and Poseidon2 for maximum performance

pub const SimdHashSignature = struct {
    const Winternitz = simd_winternitz.simd_winternitz_ots;
    const Hash = hz.tweakable_hash.TweakableHash;

    // Configuration
    params: params.Parameters,

    // Merkle tree state
    tree_height: u32,
    num_leaves: u32,

    // SIMD batch processing
    batch_size: u32,

    // Hash function for Merkle tree
    hash: Hash,

    pub fn init(allocator: std.mem.Allocator, signature_params: params.Parameters) !SimdHashSignature {
        const tree_height = signature_params.tree_height;
        const num_leaves = @as(u32, 1) << @intCast(tree_height);

        return SimdHashSignature{
            .params = signature_params,
            .tree_height = tree_height,
            .num_leaves = num_leaves,
            .batch_size = 4, // Process 4 operations in parallel
            .hash = try Hash.init(allocator, signature_params),
        };
    }

    pub fn deinit(self: *SimdHashSignature) void {
        self.hash.deinit();
    }

    /// Public key matching Rust GeneralizedXMSSPublicKey
    pub const PublicKey = struct {
        root: []u8, // Merkle root hash
        parameter: params.Parameters, // Hash function parameters

        pub fn deinit(self: *PublicKey, allocator: std.mem.Allocator) void {
            allocator.free(self.root);
        }
    };

    /// Secret key matching Rust GeneralizedXMSSSecretKey
    pub const SecretKey = struct {
        prf_key: [32]u8, // PRF key for key derivation
        tree: [][]u8, // Full Merkle tree structure
        tree_height: u32,
        parameter: params.Parameters, // Hash function parameters
        activation_epoch: u64, // First valid epoch
        num_active_epochs: u64, // Number of valid epochs

        pub fn deinit(self: *SecretKey, allocator: std.mem.Allocator) void {
            for (self.tree) |node| allocator.free(node);
            allocator.free(self.tree);
        }
    };

    pub const KeyPair = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn deinit(self: *KeyPair, allocator: std.mem.Allocator) void {
            self.public_key.deinit(allocator);
            self.secret_key.deinit(allocator);
        }
    };

    /// Signature matching Rust GeneralizedXMSSSignature
    pub const Signature = struct {
        epoch: u64, // Signature epoch/index
        auth_path: [][]u8, // Merkle authentication path
        rho: [32]u8, // Encoding randomness
        hashes: [][]u8, // OTS signature values (SIMD-derived)

        pub fn deinit(self: *Signature, allocator: std.mem.Allocator) void {
            for (self.hashes) |hash| allocator.free(hash);
            allocator.free(self.hashes);
            for (self.auth_path) |path| allocator.free(path);
            allocator.free(self.auth_path);
        }
    };

    /// Generate key pair matching Rust implementation (with SIMD optimizations)
    /// - activation_epoch: first valid epoch for this key (default 0)
    /// - num_active_epochs: number of epochs this key covers (default: all, 0 means use full lifetime)
    pub fn generateKeyPair(
        self: *SimdHashSignature,
        allocator: std.mem.Allocator,
        seed: []const u8,
        activation_epoch: u64,
        num_active_epochs: u64,
    ) !KeyPair {
        if (seed.len != 32) return error.InvalidSeedLength;

        const lifetime = @as(u64, 1) << @intCast(self.params.tree_height);
        const actual_num_active = if (num_active_epochs == 0) lifetime else num_active_epochs;

        // Validate epoch range
        if (activation_epoch + actual_num_active > lifetime) {
            return error.InvalidEpochRange;
        }

        const tree_height = self.params.tree_height;
        const num_leaves = @as(u32, 1) << @intCast(tree_height);

        var leaf_public_keys = try allocator.alloc([]u8, num_leaves);
        defer {
            for (leaf_public_keys) |pk| allocator.free(pk);
            allocator.free(leaf_public_keys);
        }

        // Generate leaf public keys using SIMD winternitz (with epoch addressing)
        for (0..num_leaves) |i| {
            const epoch = @as(u32, @intCast(i)); // Use epoch directly (matches Rust)
            var sk = try Winternitz.generatePrivateKey(allocator, self.params, seed, epoch);
            var pk = try Winternitz.generatePublicKey(allocator, sk);

            // Convert SIMD public key to bytes
            const pk_bytes = try convertPublicKeyToBytes(allocator, pk);

            // Clean up SIMD keys (we don't store them)
            sk.deinit(allocator);
            pk.deinit(allocator);

            leaf_public_keys[i] = pk_bytes;
        }

        // Build full Merkle tree structure (all nodes, level by level)
        const tree_nodes = try self.buildFullMerkleTree(allocator, leaf_public_keys);
        const merkle_root = try allocator.dupe(u8, tree_nodes[tree_nodes.len - 1]); // Root is last node

        // Use the provided seed as the PRF key (in Rust this would be PRF::key_gen(rng))
        var prf_key: [32]u8 = undefined;
        @memcpy(&prf_key, seed);

        return KeyPair{
            .public_key = .{
                .root = merkle_root,
                .parameter = self.params,
            },
            .secret_key = .{
                .prf_key = prf_key,
                .tree = tree_nodes,
                .tree_height = self.params.tree_height,
                .parameter = self.params,
                .activation_epoch = activation_epoch,
                .num_active_epochs = actual_num_active,
            },
        };
    }

    /// Build full Merkle tree structure (all nodes, level by level)
    /// Returns array of all tree nodes from leaves to root
    fn buildFullMerkleTree(self: *SimdHashSignature, allocator: std.mem.Allocator, leaves: []const []u8) ![][]u8 {
        const num_leaves = leaves.len;
        const tree_height = self.params.tree_height;

        // Calculate total number of nodes in the tree
        var total_nodes: usize = num_leaves;
        var level_size = num_leaves;
        var h: u32 = 0;
        while (h < tree_height) : (h += 1) {
            level_size = (level_size + 1) / 2;
            total_nodes += level_size;
        }

        var all_nodes = try allocator.alloc([]u8, total_nodes);
        errdefer {
            for (all_nodes) |node| allocator.free(node);
            allocator.free(all_nodes);
        }

        // Copy leaves to first level
        for (leaves, 0..) |leaf, i| {
            all_nodes[i] = try allocator.dupe(u8, leaf);
        }

        var current_level_start: usize = 0;
        var current_level_size = num_leaves;
        var next_level_start = num_leaves;

        // Build tree level by level
        h = 0;
        while (h < tree_height) : (h += 1) {
            const next_level_size = (current_level_size + 1) / 2;

            for (0..next_level_size) |i| {
                const left_idx = current_level_start + (i * 2);
                const right_idx = left_idx + 1;

                if (right_idx < current_level_start + current_level_size) {
                    // Both children exist
                    const combined = try allocator.alloc(u8, all_nodes[left_idx].len + all_nodes[right_idx].len);
                    defer allocator.free(combined);
                    @memcpy(combined[0..all_nodes[left_idx].len], all_nodes[left_idx]);
                    @memcpy(combined[all_nodes[left_idx].len..], all_nodes[right_idx]);
                    all_nodes[next_level_start + i] = try self.hash.hash(allocator, combined, i);
                } else {
                    // Only left child exists (odd number of nodes)
                    all_nodes[next_level_start + i] = try allocator.dupe(u8, all_nodes[left_idx]);
                }
            }

            current_level_start = next_level_start;
            current_level_size = next_level_size;
            next_level_start += next_level_size;
        }

        return all_nodes;
    }

    // Convert SIMD private key to byte array
    fn convertPrivateKeyToBytes(allocator: std.mem.Allocator, sk: Winternitz.PrivateKey) ![][]u8 {
        const num_chains = sk.chains.len;
        var chains = try allocator.alloc([]u8, num_chains);
        errdefer {
            for (chains) |c| allocator.free(c);
            allocator.free(chains);
        }

        for (sk.chains, 0..) |chain, i| {
            const chain_bytes = std.mem.asBytes(&chain);
            chains[i] = try allocator.dupe(u8, chain_bytes);
        }

        return chains;
    }

    // Convert SIMD public key to byte array
    fn convertPublicKeyToBytes(allocator: std.mem.Allocator, pk: Winternitz.PublicKey) ![]u8 {
        const num_chains = pk.chains.len;
        const chain_size = @sizeOf(@TypeOf(pk.chains[0]));
        const total_size = num_chains * chain_size;

        var bytes = try allocator.alloc(u8, total_size);
        var offset: usize = 0;

        for (pk.chains) |chain| {
            const chain_bytes = std.mem.asBytes(&chain);
            @memcpy(bytes[offset .. offset + chain_size], chain_bytes);
            offset += chain_size;
        }

        return bytes;
    }

    // Convert SIMD signature to byte array
    fn convertSignatureToBytes(allocator: std.mem.Allocator, sig: Winternitz.Signature) ![][]u8 {
        const num_chains = sig.chains.len;
        var hashes = try allocator.alloc([]u8, num_chains);
        errdefer {
            for (hashes) |hash| allocator.free(hash);
            allocator.free(hashes);
        }

        for (sig.chains, 0..) |chain, i| {
            const chain_bytes = std.mem.asBytes(&chain);
            hashes[i] = try allocator.dupe(u8, chain_bytes);
        }

        return hashes;
    }

    /// Sign a message matching Rust implementation (with SIMD key derivation)
    /// Derives OTS keys on-demand from PRF key using SIMD operations
    pub fn sign(
        self: *SimdHashSignature,
        allocator: std.mem.Allocator,
        message: []const u8,
        secret_key: *const SecretKey,
        epoch: u64,
        rng_seed: []const u8, // For generating encoding randomness
    ) !Signature {
        // Check that epoch is within the activation range
        if (epoch < secret_key.activation_epoch or
            epoch >= secret_key.activation_epoch + secret_key.num_active_epochs)
        {
            return error.EpochOutOfRange;
        }

        // Generate encoding randomness (rho) - in Rust this is IE::rand(rng)
        var rho: [32]u8 = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(rng_seed, &rho, .{});

        // Derive OTS private key for this epoch from PRF key using SIMD
        const epoch_u32 = @as(u32, @intCast(epoch));
        var simd_sk = try Winternitz.generatePrivateKey(allocator, self.params, &secret_key.prf_key, epoch_u32);
        defer simd_sk.deinit(allocator);

        // Sign with SIMD Winternitz
        var simd_sig = try Winternitz.sign(allocator, message, simd_sk);
        defer simd_sig.deinit(allocator);

        // Convert SIMD signature to byte array
        const ots_hashes = try convertSignatureToBytes(allocator, simd_sig);

        // Generate authentication path from stored tree
        const auth_path = try self.generateAuthPath(allocator, secret_key.tree, epoch);

        return Signature{
            .epoch = epoch,
            .auth_path = auth_path,
            .rho = rho,
            .hashes = ots_hashes,
        };
    }

    /// Verify a signature matching Rust implementation
    pub fn verify(
        self: *SimdHashSignature,
        allocator: std.mem.Allocator,
        message: []const u8,
        signature: Signature,
        public_key: *const PublicKey,
    ) !bool {
        _ = self;

        // For SIMD, we'd need to convert to SIMD types and verify
        // For now, use standard verification logic
        const enc = hz.encoding.IncomparableEncoding.init(public_key.parameter.encoding_type);

        // Hash message
        var hash_fn = try hz.tweakable_hash.TweakableHash.init(allocator, public_key.parameter);
        defer hash_fn.deinit();

        const msg_hash = try hash_fn.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        const chain_len = @as(u32, 1) << @intCast(public_key.parameter.winternitz_w);
        const hash_output_len = public_key.parameter.hash_output_len;

        // Derive public key parts from signature by completing hash chains
        var public_parts = try allocator.alloc([]u8, signature.hashes.len);
        defer {
            for (public_parts) |part| allocator.free(part);
            allocator.free(public_parts);
        }

        for (signature.hashes, 0..) |sig, i| {
            var current = try allocator.dupe(u8, sig);

            const start_val = if (i < encoded.len) encoded[i] else 0;
            const remaining = chain_len - start_val;

            for (0..remaining) |_| {
                const next = try hash_fn.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            public_parts[i] = current;
        }

        // Combine public key parts into the leaf
        var combined = try allocator.alloc(u8, public_parts.len * hash_output_len);
        defer allocator.free(combined);

        for (public_parts, 0..) |part, i| {
            @memcpy(combined[i * hash_output_len ..][0..hash_output_len], part);
        }

        var current_hash = try hash_fn.hash(allocator, combined, 0);
        defer allocator.free(current_hash);

        // Use authentication path to compute the Merkle root
        var leaf_idx = signature.epoch;

        for (signature.auth_path, 0..) |sibling, level| {
            _ = level;
            const is_left = (leaf_idx % 2 == 0);

            const combined_len = current_hash.len + sibling.len;
            const combined_nodes = try allocator.alloc(u8, combined_len);
            defer allocator.free(combined_nodes);

            if (is_left) {
                @memcpy(combined_nodes[0..current_hash.len], current_hash);
                @memcpy(combined_nodes[current_hash.len..], sibling);
            } else {
                @memcpy(combined_nodes[0..sibling.len], sibling);
                @memcpy(combined_nodes[sibling.len..], current_hash);
            }

            const parent_index = leaf_idx / 2;
            const parent = try hash_fn.hash(allocator, combined_nodes, parent_index);

            allocator.free(current_hash);
            current_hash = parent;
            leaf_idx = parent_index;
        }

        // Compare computed root with provided public_key root
        return std.mem.eql(u8, current_hash, public_key.root);
    }

    /// Generate authentication path from stored tree
    fn generateAuthPath(self: *SimdHashSignature, allocator: std.mem.Allocator, tree: []const []u8, leaf_idx: u64) ![][]u8 {
        _ = self;
        const tree_height = @ctz(@as(u64, tree.len + 1));
        var auth_path = try allocator.alloc([]u8, tree_height);
        errdefer {
            for (auth_path) |path| allocator.free(path);
            allocator.free(auth_path);
        }

        var idx = leaf_idx;
        var level_start: usize = 0;
        var level_size = (tree.len + 1) / 2;

        for (0..tree_height) |level| {
            const sibling_idx = if (idx % 2 == 0) idx + 1 else idx - 1;
            const abs_sibling = level_start + sibling_idx;

            if (abs_sibling < level_start + level_size and abs_sibling < tree.len) {
                auth_path[level] = try allocator.dupe(u8, tree[abs_sibling]);
            } else {
                // No sibling (odd node at end)
                auth_path[level] = try allocator.dupe(u8, tree[level_start + idx]);
            }

            idx = idx / 2;
            level_start += level_size;
            level_size = (level_size + 1) / 2;
        }

        return auth_path;
    }

    // TODO: Implement batch signature generation with new Rust-compatible API
    // Batch signature generation (deprecated - needs update for new API)
    pub fn batchSign(self: *SimdHashSignature, allocator: std.mem.Allocator, messages: []const []const u8, secret_key: *const SecretKey, epochs: []const u64, rng_seeds: []const []const u8) ![]Signature {
        _ = self;
        _ = allocator;
        _ = messages;
        _ = secret_key;
        _ = epochs;
        _ = rng_seeds;
        return error.NotImplemented;
    }

    // Batch signature verification (deprecated - needs update for new API)
    pub fn batchVerify(self: *SimdHashSignature, allocator: std.mem.Allocator, messages: []const []const u8, signatures: []const Signature, public_key: *const PublicKey) ![]bool {
        _ = self;
        _ = allocator;
        _ = messages;
        _ = signatures;
        _ = public_key;
        return error.NotImplemented;
    }
};
