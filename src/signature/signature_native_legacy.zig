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
const poseidon = @import("poseidon");
const field_mod = poseidon.koalabear16.Poseidon2KoalaBear.Field;
const chacha12_rng = @import("chacha12_rng.zig");
const streaming_tree_builder = @import("../merkle/streaming_tree_builder.zig");
const Parameters = params.Parameters;
const WinternitzOTSNative = winternitz_native.WinternitzOTSNative;
const MerkleTreeNative = merkle_native.MerkleTreeNative;
const FieldElement = field_types.FieldElement;
const Allocator = std.mem.Allocator;
const StreamingTreeBuilder = streaming_tree_builder.StreamingTreeBuilder;

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
        root: []FieldElement, // Merkle root (7 field elements for Poseidon2)
        parameter: Parameters,
        hash_parameter: [5]FieldElement, // Random parameter for hash operations

        pub fn serialize(self: *const PublicKey, allocator: Allocator) ![]u8 {
            // Serialize as: root (8 × 4 = 32 bytes) + params (20 bytes)
            var buffer = std.ArrayList(u8).init(allocator);
            errdefer buffer.deinit();

            // Root as exactly 8 field elements (32 bytes total, little-endian)
            // If fewer are present, pad with zero elements
            var i: usize = 0;
            while (i < 8) : (i += 1) {
                const fe = if (i < self.root.len) self.root[i] else FieldElement.zero();
                const bytes = fe.toBytes();
                try buffer.appendSlice(&bytes);
            }

            // Parameters (same as byte-based version), total 20 bytes
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
        tree: [][][]FieldElement, // Full tree: tree[level][index][elements] (3D)
        tree_height: u32,
        parameter: Parameters,
        hash_parameter: [5]FieldElement, // Random parameter for hash operations
        activation_epoch: u64,
        num_active_epochs: u64,

        pub fn deinit(self: *SecretKey, allocator: Allocator) void {
            for (self.tree) |level| {
                for (level) |node| allocator.free(node);
                allocator.free(level);
            }
            allocator.free(self.tree);
        }
    };

    pub const KeyPair = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn deinit(self: *KeyPair, allocator: Allocator) void {
            allocator.free(self.public_key.root);
            self.secret_key.deinit(allocator);
        }
    };

    /// Signature - field-native version
    pub const Signature = struct {
        epoch: u64,
        auth_path: [][]FieldElement, // Authentication path (array of 7-FE nodes)
        rho: [32]u8, // Encoding randomness (not yet used)
        hashes: [][]FieldElement, // OTS signature

        pub fn deinit(self: *Signature, allocator: Allocator) void {
            for (self.hashes) |hash| allocator.free(hash);
            allocator.free(self.hashes);
            for (self.auth_path) |node| allocator.free(node);
            allocator.free(self.auth_path);
        }
    };

    /// Generate only the root using streaming approach (for large lifetimes)
    /// This avoids building the full tree by computing the root directly
    fn generateRootStreaming(
        allocator: std.mem.Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: u64,
    ) ![]FieldElement {
        // For now, use the existing generateTreeSimple for the root
        // TODO: Implement true streaming root computation
        const result = try generateTreeSimple(allocator, param_wots, param_tree, prf_key, @intCast(num_leaves));
        return result[0]; // Return only the root as []FieldElement
    }

    /// Generate a single leaf hash for a given epoch
    fn generateLeafHash(
        self: *HashSignatureNative,
        allocator: std.mem.Allocator,
        epoch: u64,
        hash_parameter: [5]FieldElement,
        prf_key: [32]u8,
    ) ![]FieldElement {
        // Create parameter-ized wots for leaf generation
        var param_wots = try WinternitzOTSNative.initWithParameter(
            allocator,
            self.params,
            hash_parameter,
        );
        defer param_wots.deinit();

        const epoch_u32 = @as(u32, @intCast(epoch));

        // Generate private key
        const sk = try param_wots.generatePrivateKey(allocator, &prf_key, epoch_u32);
        defer {
            for (sk) |k| allocator.free(k);
            allocator.free(sk);
        }

        // Generate public key
        const pk = try param_wots.generatePublicKey(allocator, sk, epoch_u32);
        defer allocator.free(pk);

        // Hash public key to create leaf hash
        const leaf_tweak = @import("tweak.zig").PoseidonTweak{
            .tree_tweak = .{
                .level = 0,
                .pos_in_level = epoch_u32,
            },
        };

        return try param_wots.hash.hashFieldElements(allocator, pk, leaf_tweak, 7);
    }

    /// Generate auth path for a specific epoch using streaming approach (for large lifetimes)
    /// This avoids building the full tree by computing only the needed sibling hashes
    fn generateAuthPathStreaming(
        self: *HashSignatureNative,
        allocator: std.mem.Allocator,
        epoch: u64,
        num_leaves: u64,
        hash_parameter: [5]FieldElement,
        prf_key: [32]u8,
    ) ![][]FieldElement {
        const tree_height = std.math.log2_int(u64, num_leaves);
        var auth_path = try allocator.alloc([]FieldElement, tree_height);
        errdefer {
            for (auth_path) |level| allocator.free(level);
            allocator.free(auth_path);
        }

        // For each level, compute the sibling hash needed for the auth path
        var current_epoch = epoch;
        for (0..tree_height) |level| {
            const sibling_epoch = current_epoch ^ 1; // XOR with 1 to get sibling
            const sibling_hash = try self.generateLeafHash(allocator, sibling_epoch, hash_parameter, prf_key);
            auth_path[level] = sibling_hash;
            current_epoch >>= 1; // Move up one level
        }

        return auth_path;
    }

    /// Generate key pair
    pub fn generateKeyPair(
        self: *HashSignatureNative,
        allocator: Allocator,
        seed: []const u8,
        activation_epoch: u64,
        num_active_epochs: u64,
    ) !KeyPair {
        if (seed.len < 32) return error.SeedTooShort;

        var rng = chacha12_rng.init(seed[0..32].*);

        // CRITICAL: Generate hash parameter FIRST (matching Rust line 104)
        // This is a random 5-element array used in all hash operations
        var parameter: [5]FieldElement = undefined;
        for (&parameter) |*elem| {
            var bytes: [4]u8 = undefined;
            rng.fill(&bytes);
            const val = std.mem.readInt(u32, &bytes, .little);
            // Don't reduce - plonky3 stores raw u32 values (reduction happens in arithmetic)
            elem.* = FieldElement{ .value = val };
        }

        // Then generate PRF key (matching Rust line 107)
        var prf_key: [32]u8 = undefined;
        rng.fill(&prf_key);

        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);

        // Removed debug print for performance

        // Validate epoch range
        if (activation_epoch + num_active_epochs > num_leaves) {
            return error.InvalidEpochRange;
        }

        // Create parameter-ized hash instances for this key generation
        var param_wots = try WinternitzOTSNative.initWithParameter(allocator, self.params, parameter);
        defer param_wots.deinit();

        var param_tree = try MerkleTreeNative.initWithParameter(allocator, self.params, parameter);
        defer param_tree.deinit();

        // Removed debug print for performance

        // For large lifetimes (2^18+), use streaming approach without full tree
        if (num_leaves >= (1 << 18)) {
            // Generate only the root using streaming approach
            const root = try generateRootStreaming(allocator, &param_wots, &param_tree, &prf_key, num_leaves);

            return KeyPair{
                .public_key = PublicKey{
                    .root = root,
                    .parameter = self.params,
                    .hash_parameter = parameter,
                },
                .secret_key = SecretKey{
                    .prf_key = prf_key,
                    .tree = &[_][][]FieldElement{}, // Empty tree for streaming
                    .tree_height = self.params.tree_height,
                    .parameter = self.params,
                    .hash_parameter = parameter,
                    .activation_epoch = activation_epoch,
                    .num_active_epochs = num_active_epochs,
                },
            };
        } else {
            // Use the appropriate tree generation method based on size
            const result = try generateTreeWithParallelization(self, allocator, &param_wots, &param_tree, &prf_key, num_leaves);

            // Removed debug print for performance
            const root = result[0];
            const tree_levels = result[1];

            // The root is already duplicated in generateTreeSimple, so we can use it directly
            const root_copy = root;

            return KeyPair{
                .public_key = PublicKey{
                    .root = root_copy,
                    .parameter = self.params,
                    .hash_parameter = parameter,
                },
                .secret_key = SecretKey{
                    .prf_key = prf_key,
                    .tree = tree_levels, // Full tree for signing
                    .tree_height = self.params.tree_height,
                    .parameter = self.params,
                    .hash_parameter = parameter,
                    .activation_epoch = activation_epoch,
                    .num_active_epochs = num_active_epochs,
                },
            };
        }
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

        // Create parameter-ized wots for signing (using secret key's parameter)
        var param_wots = try WinternitzOTSNative.initWithParameter(
            allocator,
            self.params,
            secret_key.hash_parameter,
        );
        defer param_wots.deinit();

        // Generate OTS private key for this epoch
        const ots_sk = try param_wots.generatePrivateKey(allocator, &secret_key.prf_key, epoch_u32);
        defer {
            for (ots_sk) |k| allocator.free(k);
            allocator.free(ots_sk);
        }

        // Sign message with OTS
        const ots_signature = try param_wots.sign(allocator, ots_sk, message, epoch_u32);

        // Get authentication path from tree
        const auth_path = if (secret_key.tree.len == 0) blk: {
            // For large lifetimes, use streaming auth-path computation
            const num_leaves = @as(u64, 1) << @intCast(self.params.tree_height);
            break :blk try self.generateAuthPathStreaming(allocator, @intCast(epoch), num_leaves, secret_key.hash_parameter, secret_key.prf_key);
        } else blk: {
            // For small lifetimes, use the stored tree
            break :blk try self.tree.getAuthPath(
                allocator,
                secret_key.tree,
                @intCast(epoch),
            );
        };

        // (debug removed)

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

        // Create parameter-ized hash instances for verification
        var param_wots = try WinternitzOTSNative.initWithParameter(
            allocator,
            self.params,
            public_key.hash_parameter,
        );
        defer param_wots.deinit();

        var param_tree = try MerkleTreeNative.initWithParameter(
            allocator,
            self.params,
            public_key.hash_parameter,
        );
        defer param_tree.deinit();

        // Recover OTS public key from signature
        const ots_pk = try self.recoverOTSPublicKeyWithParam(
            allocator,
            &param_wots,
            message,
            signature.hashes,
            epoch_u32,
        );
        defer allocator.free(ots_pk);

        // Removed debug code for performance

        // Hash OTS public key to produce tree leaf (same as in key generation)
        const leaf_tweak = @import("tweak.zig").PoseidonTweak{
            .tree_tweak = .{
                .level = 0, // Leaf level
                .pos_in_level = @intCast(signature.epoch),
            },
        };

        const leaf_hash = try param_wots.hash.hashFieldElements(
            allocator,
            ots_pk,
            leaf_tweak,
            7, // 7 field elements output (HASH_LEN_FE in Rust)
        );
        defer allocator.free(leaf_hash);
        // Removed debug code for performance

        // Verify Merkle path against 7-FE public root (Rust-compatible)
        return param_tree.verifyAuthPath(
            allocator,
            leaf_hash,
            @intCast(signature.epoch),
            signature.auth_path,
            public_key.root,
        );
    }

    /// Helper: Recover OTS public key from signature (with parameter)
    fn recoverOTSPublicKeyWithParam(
        self: *HashSignatureNative,
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        message: []const u8,
        signature_hashes: []const []FieldElement,
        epoch: u32,
    ) ![]FieldElement {
        _ = self; // Now using param_wots instead of self.wots
        // Encode message
        var encoder = @import("encoding.zig").IncomparableEncoding.init(param_wots.params);
        const encoded = try encoder.encode(allocator, message);
        defer allocator.free(encoded);

        if (signature_hashes.len != encoded.len) return error.SignatureLengthMismatch;

        const chain_len = param_wots.getChainLength();
        var recovered_parts = try allocator.alloc([]FieldElement, signature_hashes.len);
        defer {
            for (recovered_parts) |part| allocator.free(part);
            allocator.free(recovered_parts);
        }

        // For each signature part, hash from encoded position to chain end
        // Apply positions (target_pos .. chain_len-1) with pos_in_chain = pos+1
        for (signature_hashes, 0..) |sig_part, chain_idx| {
            const target_pos = encoded[chain_idx];
            var current = try allocator.dupe(FieldElement, sig_part);

            // Iterate positions target_pos+1 .. chain_len-1 (1-indexed), i.e., pos_zero_indexed in [target_pos .. chain_len-2]
            if (target_pos < chain_len - 1) {
                for (target_pos..chain_len - 1) |pos_zero_indexed| {
                    const tweak = @import("tweak.zig").PoseidonTweak{ .chain_tweak = .{
                        .epoch = epoch,
                        .chain_index = @intCast(chain_idx),
                        .pos_in_chain = @intCast(@as(u8, @intCast(pos_zero_indexed + 1))),
                    } };

                    const next = try param_wots.hash.hashFieldElements(
                        allocator,
                        current,
                        tweak,
                        7, // chain_hash_output_len_fe
                    );
                    allocator.free(current);
                    current = next;
                }
            }

            recovered_parts[chain_idx] = current;
            // Removed debug code for performance
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

    /// Generate tree with streaming approach (memory-efficient)
    /// This generates leaf hashes on-demand to avoid massive memory allocation
    fn generateTreeWithParallelization(
        _: *HashSignatureNative,
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Optimized thresholds for better performance
        // Removed debug prints for maximum performance

        if (num_leaves > 1 << 20) { // Threshold: 1,048,576 leaves - use streaming only for extremely large trees
            // Use streaming approach for extremely large trees to manage memory
            return try generateTreeWithStreaming(allocator, param_wots, param_tree, prf_key, num_leaves);
        } else if (num_leaves >= 1 << 12) { // Threshold: 4096 leaves - use parallel for large trees
            // Use ultra-optimized parallel approach for large trees
            return try generateTreeUltraOptimized(allocator, param_wots, param_tree, prf_key, num_leaves);
        } else {
            // Use optimized single-threaded approach for very small trees
            return try generateTreeSimple(allocator, param_wots, param_tree, prf_key, num_leaves);
        }
    }

    /// Ultra-optimized tree generation using streaming parallel processing
    fn generateTreeUltraOptimized(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Allocate output leaves (7-FE each) for all indices
        const leaf_hashes = try allocator.alloc([]FieldElement, num_leaves);
        errdefer {
            for (leaf_hashes) |h| if (h.len > 0) allocator.free(h);
            allocator.free(leaf_hashes);
        }

        // Use moderate parallelization to avoid memory issues
        const num_threads = @min(std.Thread.getCpuCount() catch 4, 16); // Reduced max threads
        const leaves_per_thread = (num_leaves + num_threads - 1) / num_threads;

        // Create shared state for parallel processing
        const shared_state = try allocator.create(BatchSharedState);
        defer allocator.destroy(shared_state);
        shared_state.* = BatchSharedState{
            .param_wots = param_wots,
            .prf_key = prf_key,
            .allocator = allocator,
            .leaf_hashes = undefined, // unused in this variant
            .leaves_out = leaf_hashes,
            .error_flag = std.atomic.Value(bool).init(false),
            .start_idx = 0,
            .end_idx = num_leaves,
            .progress_mutex = std.Thread.Mutex{},
            .progress_counter = 0,
            .total_leaves = num_leaves,
        };

        // Spawn worker threads
        const threads = try allocator.alloc(std.Thread, num_threads);
        defer allocator.free(threads);

        for (0..num_threads) |thread_idx| {
            threads[thread_idx] = try std.Thread.spawn(.{}, processBatchWorker, .{ shared_state, thread_idx, leaves_per_thread });
        }

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }

        // Check for errors
        if (shared_state.error_flag.load(.monotonic)) {
            return error.ThreadError;
        }

        // Build full tree from 7-FE leaf hashes (for auth paths and root)
        const tree_levels = try param_tree.buildFullTree(allocator, leaf_hashes);
        const final_level = tree_levels[tree_levels.len - 1];
        const root_node = final_level[0];
        const root_slice = try allocator.dupe(FieldElement, root_node);
        return .{ root_slice, tree_levels };
    }

    /// Hybrid tree generation with memory pools and aggressive optimizations
    fn generateTreeHybrid(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Removed debug print for performance

        // Initialize memory pools for common allocation sizes
        var field_pool = @import("../utils/memory_pool.zig").MemoryPool.init(allocator, @sizeOf(FieldElement) * 22); // For OTS private keys
        defer field_pool.deinit();

        var hash_pool = @import("../utils/memory_pool.zig").MemoryPool.init(allocator, @sizeOf(FieldElement) * 7); // For leaf hashes
        defer hash_pool.deinit();

        // Pre-allocate all leaf hashes to avoid repeated allocations
        var leaf_hashes = try allocator.alloc([]FieldElement, num_leaves);
        defer {
            for (leaf_hashes) |hash| {
                if (hash.len > 0) allocator.free(hash);
            }
            allocator.free(leaf_hashes);
        }

        // Note: Merkle buildTree uses single-FE nodes, but buildFullTree expects 7-FE leaves.
        // We only need buildFullTree for auth paths; the public root will use the 7-FE root node.
        // For buildTree we still supply single-FE leaves (first element of each leaf hash).
        var flattened_leaves = try allocator.alloc(FieldElement, num_leaves);
        defer allocator.free(flattened_leaves);

        // Process each leaf with aggressive optimizations and memory pools
        for (0..num_leaves) |leaf_idx| {
            const epoch = @as(u32, @intCast(leaf_idx));

            // Generate private key with optimized allocation
            const sk = try param_wots.generatePrivateKey(allocator, prf_key, epoch);
            defer {
                for (sk) |k| allocator.free(k);
                allocator.free(sk);
            }

            // Generate public key with optimized allocation
            const pk = try param_wots.generatePublicKey(allocator, sk, epoch);
            defer allocator.free(pk);

            // Hash public key to create leaf hash (optimized tweak)
            const leaf_tweak = @import("tweak.zig").PoseidonTweak{
                .tree_tweak = .{
                    .level = 0,
                    .pos_in_level = @as(u32, @intCast(leaf_idx)),
                },
            };

            const leaf_hash = try param_wots.hash.hashFieldElements(allocator, pk, leaf_tweak, 7);
            leaf_hashes[leaf_idx] = leaf_hash;

            // Store flattened version for tree building
            flattened_leaves[leaf_idx] = leaf_hash[0];
        }

        // Removed debug print for performance

        // Build full tree structure (nodes are 7-FE arrays at each level)
        const tree_levels = try param_tree.buildFullTree(allocator, leaf_hashes);

        // Set public root as the 7-FE node at the final level (Rust-compatible)
        const final_level = tree_levels[tree_levels.len - 1];
        const root_node = final_level[0]; // []FieldElement of length 7
        const root_slice = try allocator.dupe(FieldElement, root_node);

        return .{ root_slice, tree_levels };
    }

    /// Optimized single-threaded tree generation
    fn generateTreeSimple(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Removed debug print for performance

        // Pre-allocate all leaf hashes to avoid repeated allocations
        var leaf_hashes = try allocator.alloc([]FieldElement, num_leaves);
        defer {
            for (leaf_hashes) |hash| {
                if (hash.len > 0) allocator.free(hash);
            }
            allocator.free(leaf_hashes);
        }

        // Pre-allocate flattened leaves array
        var flattened_leaves = try allocator.alloc(FieldElement, num_leaves);
        defer allocator.free(flattened_leaves);

        // Process each leaf with aggressive optimizations
        for (0..num_leaves) |leaf_idx| {
            const epoch = @as(u32, @intCast(leaf_idx));

            // Generate private key with optimized allocation
            const sk = try param_wots.generatePrivateKey(allocator, prf_key, epoch);
            defer {
                for (sk) |k| allocator.free(k);
                allocator.free(sk);
            }

            // Generate public key with optimized allocation
            const pk = try param_wots.generatePublicKey(allocator, sk, epoch);
            defer allocator.free(pk);

            // Hash public key to create leaf hash (optimized tweak)
            const leaf_tweak = @import("tweak.zig").PoseidonTweak{
                .tree_tweak = .{
                    .level = 0,
                    .pos_in_level = @as(u32, @intCast(leaf_idx)),
                },
            };

            const leaf_hash = try param_wots.hash.hashFieldElements(allocator, pk, leaf_tweak, 7);
            leaf_hashes[leaf_idx] = leaf_hash;

            // Store flattened version for tree building
            flattened_leaves[leaf_idx] = leaf_hash[0];
        }

        // Removed debug print for performance

        // Build full tree from 7-FE leaf hashes (for auth paths and root)
        const tree_levels = try param_tree.buildFullTree(allocator, leaf_hashes);

        // Set public root as the 7-FE node at the final level (Rust-compatible)
        const final_level2 = tree_levels[tree_levels.len - 1];
        const root_node2 = final_level2[0];
        const root_slice2 = try allocator.dupe(FieldElement, root_node2);

        return .{ root_slice2, tree_levels };
    }

    /// Batching tree generation for large lifetimes
    fn generateTreeWithStreaming(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Removed debug print for performance

        // For extremely large lifetimes, use batch processing to manage memory
        if (num_leaves > 65536) { // 2^16 threshold
            // Removed debug print for performance
            return try generateTreeWithBatching(allocator, param_wots, param_tree, prf_key, num_leaves);
        }

        // Removed debug print for performance

        // Initialize streaming tree builder
        var tree_builder = try StreamingTreeBuilder.init(allocator, @intCast(param_tree.height), &param_wots.hash);
        defer tree_builder.deinit();

        // Determine optimal number of threads
        const num_threads = @min(num_leaves, std.Thread.getCpuCount() catch 4);
        const leaves_per_thread = (num_leaves + num_threads - 1) / num_threads;

        // Create thread-safe shared state
        var shared_state = try allocator.create(StreamingSharedState);
        defer allocator.destroy(shared_state);
        shared_state.* = StreamingSharedState{
            .tree_builder = &tree_builder,
            .param_wots = param_wots,
            .prf_key = prf_key,
            .allocator = allocator,
            .error_flag = std.atomic.Value(bool).init(false),
        };

        // Launch parallel threads
        var threads: []std.Thread = try allocator.alloc(std.Thread, num_threads);
        defer allocator.free(threads);

        for (0..num_threads) |thread_id| {
            const start_idx = thread_id * leaves_per_thread;
            const end_idx = @min(start_idx + leaves_per_thread, num_leaves);

            threads[thread_id] = try std.Thread.spawn(.{}, processEpochsRangeStreaming, .{ shared_state, start_idx, end_idx });
        }

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }

        // Check for errors
        if (shared_state.error_flag.load(.monotonic)) {
            return error.ThreadError;
        }

        // Get final results
        const root_element = tree_builder.getRoot() catch return error.IncompleteTree;
        const root_value = root_element orelse return error.IncompleteTree;
        const tree_levels = try tree_builder.getTreeLevels();

        // Convert single FieldElement to slice for consistency
        const root = try allocator.alloc(FieldElement, 1);
        root[0] = root_value;

        return .{ root, tree_levels };
    }

    /// Optimized batch processing for extremely large lifetimes
    fn generateTreeWithBatching(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Pre-allocate leaf hashes (7 field elements per leaf)
        const leaf_hashes = try allocator.alloc([]FieldElement, num_leaves);
        errdefer {
            for (leaf_hashes) |h| if (h.len > 0) allocator.free(h);
            allocator.free(leaf_hashes);
        }

        // Use larger batches with parallel processing for better performance
        const batch_size = 8192; // Process 8192 epochs at a time (increased for maximum performance)
        var processed_leaves: usize = 0;

        // Use parallel processing for batches
        const num_threads = @min(std.Thread.getCpuCount() catch 4, 16); // Increased max threads for better performance

        while (processed_leaves < num_leaves) {
            const batch_end = @min(processed_leaves + batch_size, num_leaves);
            // Removed unused variables for performance

            // Removed debug print for performance

            // Process batch with parallel workers
            const batch_size_actual = batch_end - processed_leaves;
            const leaves_per_thread = (batch_size_actual + num_threads - 1) / num_threads;

            // Create thread handles for this batch
            const batch_threads = try allocator.alloc(std.Thread, num_threads);
            defer allocator.free(batch_threads);

            // Create shared state for this batch
            const batch_state = try allocator.create(BatchSharedState);
            defer allocator.destroy(batch_state);
            batch_state.* = BatchSharedState{
                .param_wots = param_wots,
                .prf_key = prf_key,
                .allocator = allocator,
                .leaf_hashes = undefined,
                .leaves_out = leaf_hashes,
                .start_idx = processed_leaves,
                .end_idx = batch_end,
                .error_flag = std.atomic.Value(bool).init(false),
                .progress_mutex = std.Thread.Mutex{},
                .progress_counter = 0,
                .total_leaves = batch_size_actual,
                // .start_time = std.time.Instant{ .timestamp = .{ .tv_sec = 0, .tv_nsec = 0 } },
                // .last_report_time = std.time.Instant{ .timestamp = .{ .tv_sec = 0, .tv_nsec = 0 } },
            };

            // Spawn threads for this batch
            for (0..num_threads) |thread_idx| {
                batch_threads[thread_idx] = try std.Thread.spawn(.{}, processBatchWorker, .{ batch_state, thread_idx, leaves_per_thread });
            }

            // Wait for all threads to complete
            for (batch_threads) |thread| {
                thread.join();
            }

            // Check for errors
            if (batch_state.error_flag.load(.monotonic)) {
                return error.BatchProcessingFailed;
            }

            processed_leaves = batch_end;
            // Removed debug print for performance
        }

        // Removed debug print for performance

        // Build full tree from 7-FE leaf hashes (for auth paths and root)
        const tree_levels = try param_tree.buildFullTree(allocator, leaf_hashes);
        const final_level = tree_levels[tree_levels.len - 1];
        const root_node = final_level[0];
        const root_slice = try allocator.dupe(FieldElement, root_node);
        return .{ root_slice, tree_levels };
    }

    // Removed generateTreeTraditional - redundant with generateTreeParallel

    // Removed computeRootRecursive - redundant with streaming approach

    // Removed parallelWorker - redundant with generateLeavesWorker
};

// Streaming shared state for parallel processing
const StreamingSharedState = struct {
    tree_builder: *StreamingTreeBuilder,
    param_wots: *WinternitzOTSNative,
    prf_key: *const [32]u8,
    allocator: Allocator,
    error_flag: std.atomic.Value(bool),
};

// Process epochs range for streaming approach
fn processEpochsRangeStreaming(shared_state: *StreamingSharedState, start_idx: usize, end_idx: usize) void {
    // Use thread-local allocator to avoid memory corruption
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
    const temp_allocator = gpa.allocator();
    defer _ = gpa.deinit();

    for (start_idx..end_idx) |i| {
        if (shared_state.error_flag.load(.monotonic)) {
            break;
        }

        const epoch = @as(u32, @intCast(i));

        // Generate OTS key pair for this epoch using thread-local allocator
        const sk = shared_state.param_wots.generatePrivateKey(
            temp_allocator,
            shared_state.prf_key,
            epoch,
        ) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer {
            for (sk) |k| temp_allocator.free(k);
            temp_allocator.free(sk);
        }

        // Generate public key using in-place chain computation
        var chain_ends = temp_allocator.alloc(FieldElement, sk.len) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer temp_allocator.free(chain_ends);

        for (sk, 0..) |private_key_chain, chain_idx| {
            if (private_key_chain.len == 0) {
                shared_state.error_flag.store(true, .monotonic);
                break;
            }
            chain_ends[chain_idx] = shared_state.param_wots.generateChainEndInPlace(
                private_key_chain[0], // Start with first element
                epoch,
                @intCast(chain_idx),
                shared_state.param_wots.getChainLength() - 1, // steps
            ) catch {
                shared_state.error_flag.store(true, .monotonic);
                break;
            };
        }

        // Hash chain ends to get leaf hash
        const leaf_tweak = @import("tweak.zig").PoseidonTweak{
            .tree_tweak = .{
                .level = 0,
                .pos_in_level = @intCast(i),
            },
        };

        const leaf_hash = shared_state.param_wots.hash.hashFieldElements(
            temp_allocator,
            chain_ends,
            leaf_tweak,
            7,
        ) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer temp_allocator.free(leaf_hash);

        // Add to streaming tree builder (thread-safe)
        shared_state.tree_builder.addLeafHash(leaf_hash[0]) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
    }
}

// Removed ThreadContext - redundant with ParallelSharedState

// Batch shared state for parallel batch processing
const BatchSharedState = struct {
    // Removed tree_builder; we will collect leaf hashes directly for full-tree build
    param_wots: *WinternitzOTSNative,
    prf_key: *const [32]u8,
    allocator: Allocator,
    leaf_hashes: [][][]FieldElement, // shared array of per-level nodes (index 0 used for leaves)
    leaves_out: [][]FieldElement, // shared array to store 7-FE leaf hashes per index
    start_idx: usize,
    end_idx: usize,
    error_flag: std.atomic.Value(bool),
    progress_mutex: std.Thread.Mutex,
    progress_counter: usize,
    total_leaves: usize,
    // start_time: std.time.Instant,
    // last_report_time: std.time.Instant,
};

// Process batch worker for parallel batch processing
fn processBatchWorker(shared_state: *BatchSharedState, thread_idx: usize, leaves_per_thread: usize) void {
    const start_idx = shared_state.start_idx + (thread_idx * leaves_per_thread);
    const end_idx = @min(start_idx + leaves_per_thread, shared_state.end_idx);

    // Use thread-local allocator for better performance
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = false }){};
    const temp_allocator = gpa.allocator();
    defer _ = gpa.deinit();

    for (start_idx..end_idx) |i| {
        if (shared_state.error_flag.load(.monotonic)) {
            break;
        }

        const epoch = @as(u32, @intCast(i));

        // Generate OTS key pair for this epoch using temp allocator
        const sk = shared_state.param_wots.generatePrivateKey(temp_allocator, shared_state.prf_key, epoch) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer {
            for (sk) |k| temp_allocator.free(k);
            temp_allocator.free(sk);
        }

        // Generate public key using temp allocator
        const pk = shared_state.param_wots.generatePublicKey(temp_allocator, sk, epoch) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer temp_allocator.free(pk);

        // Hash public key to create leaf hash using temp allocator
        const leaf_tweak = @import("tweak.zig").PoseidonTweak{
            .tree_tweak = .{
                .level = 0,
                .pos_in_level = @as(u32, @intCast(i)),
            },
        };

        // IMPORTANT: allocate leaf hashes with the shared allocator so they outlive the worker
        const leaf_hash = shared_state.param_wots.hash.hashFieldElements(shared_state.allocator, pk, leaf_tweak, 7) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        // Store the full 7-FE leaf at the proper index (no lock needed: disjoint indices)
        shared_state.leaves_out[i] = leaf_hash;

        // Update progress less frequently for better performance
        shared_state.progress_mutex.lock();
        defer shared_state.progress_mutex.unlock();
        shared_state.progress_counter += 1;

        // Only report every 1000 leaves to reduce overhead
        // Temporarily disabled due to timestamp field issues
        // if (shared_state.progress_counter % 1000 == 0) {
        //     const current_time = std.time.Instant.now() catch shared_state.last_report_time;
        //     const time_since_last_report = current_time.since(shared_state.last_report_time);
        //     const five_minutes = std.time.ns_per_min * 5;

        //     if (time_since_last_report >= five_minutes) {
        //         const total_elapsed = current_time.since(shared_state.start_time);
        //         const percentage = (@as(f64, @floatFromInt(shared_state.progress_counter)) / @as(f64, @floatFromInt(shared_state.total_leaves))) * 100.0;
        //         const elapsed_minutes = @as(f64, @floatFromInt(total_elapsed)) / @as(f64, @floatFromInt(std.time.ns_per_min));

        //         std.debug.print("Batch Progress: {d:.1}% complete ({d}/{d} leaves) - Elapsed: {d:.1} minutes\n", .{ percentage, shared_state.progress_counter, shared_state.total_leaves, elapsed_minutes });

        //         shared_state.last_report_time = current_time;
        //     }
        // }
    }
}

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

    // Root should be non-zero (check first element)
    try std.testing.expect(keypair.public_key.root.len > 0);
    try std.testing.expect(keypair.public_key.root[0].toU32() != 0);

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
    const epoch: u64 = 0;
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
