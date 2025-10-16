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
            // Serialize as: root (7 × 4 = 28 bytes) + hash_parameter (5 × 4 = 20 bytes) + params
            var buffer = std.ArrayList(u8).init(allocator);
            errdefer buffer.deinit();

            // Root as 7 field elements (28 bytes total, little-endian)
            for (self.root) |elem| {
                const bytes = elem.toBytes();
                try buffer.appendSlice(&bytes);
            }

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
        
        std.debug.print("generateKeyPair: Starting with {} leaves (tree_height={})\n", .{num_leaves, self.params.tree_height});

        // Validate epoch range
        if (activation_epoch + num_active_epochs > num_leaves) {
            return error.InvalidEpochRange;
        }

        // Create parameter-ized hash instances for this key generation
        var param_wots = try WinternitzOTSNative.initWithParameter(allocator, self.params, parameter);
        defer param_wots.deinit();

        var param_tree = try MerkleTreeNative.initWithParameter(allocator, self.params, parameter);
        defer param_tree.deinit();

        std.debug.print("generateKeyPair: About to call generateTreeWithParallelization with {} leaves\n", .{num_leaves});
        
        // Generate all leaf hashes and build tree (matching Rust implementation)
        const result = try self.generateTreeWithParallelization(allocator, &param_wots, &param_tree, &prf_key, num_leaves);
        
        std.debug.print("generateKeyPair: Successfully completed tree generation\n", .{});
        const root = result[0];
        const tree_levels = result[1];

        // Duplicate root for the public key
        const root_copy = try allocator.dupe(FieldElement, root);

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
        const auth_path = try self.tree.getAuthPath(
            allocator,
            secret_key.tree,
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

        // Verify Merkle path
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
        for (signature_hashes, 0..) |sig_part, chain_idx| {
            const target_pos = encoded[chain_idx];
            var current = try allocator.dupe(FieldElement, sig_part);

            // Hash from target_pos to chain_len - 1 (positions are 1..255)
            for (target_pos..chain_len - 1) |pos_in_chain| {
                const tweak = @import("tweak.zig").PoseidonTweak{ .chain_tweak = .{
                    .epoch = epoch,
                    .chain_index = @intCast(chain_idx),
                    .pos_in_chain = @intCast(@as(u8, @intCast(pos_in_chain + 1))),
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
        // For very large lifetimes (2^18), use streaming approach
        // This generates leaves on-demand instead of storing them all in memory
        std.debug.print("generateTreeWithParallelization: num_leaves = {}, threshold = {}\n", .{ num_leaves, 1 << 12 });
        std.debug.print("generateTreeWithParallelization: About to select approach...\n", .{});

        if (num_leaves > 1 << 12) { // Threshold: 4,096 leaves
            // Use streaming approach for large trees to manage memory
            return try generateTreeWithStreaming(allocator, param_wots, param_tree, prf_key, num_leaves);
        } else {
            // Use traditional approach for smaller trees
            return try generateTreeTraditional(allocator, param_wots, param_tree, prf_key, num_leaves);
        }
    }

    /// Batching tree generation for large lifetimes
    fn generateTreeWithStreaming(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        std.debug.print("generateTreeWithStreaming: num_leaves = {}, threshold = {}\n", .{num_leaves, 65536});
        
        // For extremely large lifetimes, use batch processing to manage memory
        if (num_leaves > 65536) { // 2^16 threshold
            std.debug.print("Using batch processing for {} leaves\n", .{num_leaves});
            return try generateTreeWithBatching(allocator, param_wots, param_tree, prf_key, num_leaves);
        }
        
        std.debug.print("Using streaming approach for {} leaves\n", .{num_leaves});

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

    /// Batch processing for extremely large lifetimes (memory-constrained)
    fn generateTreeWithBatching(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Process in small batches to minimize memory usage
        const batch_size = 64; // Process 64 epochs at a time (further reduced for debugging)
        var processed_leaves: usize = 0;
        
        std.debug.print("BATCH PROCESSING: Starting with {} epochs, batch size: {}\n", .{num_leaves, batch_size});
        std.debug.print("BATCH PROCESSING: Estimated memory usage: ~{}MB\n", .{(batch_size * 180) / 1024});

        // Initialize streaming tree builder
        var tree_builder = try StreamingTreeBuilder.init(allocator, @intCast(param_tree.height), &param_wots.hash);
        defer tree_builder.deinit();

        while (processed_leaves < num_leaves) {
            const batch_end = @min(processed_leaves + batch_size, num_leaves);
            const batch_num = (processed_leaves / batch_size) + 1;
            const total_batches = (num_leaves + batch_size - 1) / batch_size;
            
            std.debug.print("BATCH {}/{}: Processing epochs {} to {} of {} ({}% complete)\n", .{
                batch_num, total_batches, processed_leaves, batch_end - 1, num_leaves,
                (processed_leaves * 100) / num_leaves
            });

            // Process batch sequentially to minimize memory usage
            for (processed_leaves..batch_end) |i| {
                const epoch = @as(u32, @intCast(i));
                
                // Progress indicator every 10 epochs
                if ((i - processed_leaves) % 10 == 0) {
                    std.debug.print("  Processing epoch {}/{} in batch\n", .{i - processed_leaves + 1, batch_end - processed_leaves});
                }

                // Generate OTS key pair for this epoch using in-place computation
                const sk = param_wots.generatePrivateKey(allocator, prf_key, epoch) catch return error.KeyGenerationFailed;
                defer {
                    for (sk) |k| allocator.free(k);
                    allocator.free(sk);
                }

                // Generate public key using in-place chain computation
                var chain_ends = try allocator.alloc(FieldElement, sk.len);
                defer allocator.free(chain_ends);

                for (sk, 0..) |private_key_chain, chain_idx| {
                    chain_ends[chain_idx] = param_wots.generateChainEndInPlace(
                        private_key_chain[0], // Start with first element
                        epoch,
                        @intCast(chain_idx),
                        param_wots.getChainLength() - 1, // steps
                    ) catch return error.ChainGenerationFailed;
                }

                // Hash chain ends to get leaf hash
                const leaf_tweak = @import("tweak.zig").PoseidonTweak{
                    .tree_tweak = .{
                        .level = 0,
                        .pos_in_level = @intCast(i),
                    },
                };

                const leaf_hash = param_wots.hash.hashFieldElements(
                    allocator,
                    chain_ends,
                    leaf_tweak,
                    7,
                ) catch return error.HashGenerationFailed;
                defer allocator.free(leaf_hash);

                // Add to streaming tree builder
                tree_builder.addLeafHash(leaf_hash[0]) catch return error.TreeBuildingFailed;
            }
            
            processed_leaves = batch_end;
            std.debug.print("BATCH {}/{}: Completed successfully\n", .{batch_num, total_batches});
        }

        std.debug.print("BATCH PROCESSING: All batches completed, computing final tree...\n", .{});
        
        // Get final results
        const root_element = tree_builder.getRoot() catch return error.IncompleteTree;
        const root_value = root_element orelse return error.IncompleteTree;
        const tree_levels = try tree_builder.getTreeLevels();

        // Convert single FieldElement to slice for consistency
        const root = try allocator.alloc(FieldElement, 1);
        root[0] = root_value;

        std.debug.print("BATCH PROCESSING: Successfully completed {} epochs with batch processing!\n", .{num_leaves});
        return .{ root, tree_levels };
    }

    /// Traditional tree generation for smaller lifetimes
    fn generateTreeTraditional(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        param_tree: *MerkleTreeNative,
        prf_key: *const [32]u8,
        num_leaves: usize,
    ) !struct { []FieldElement, [][][]FieldElement } {
        // Generate all leaf hashes (matching Rust's chain_ends_hashes)
        const leaf_hashes = try allocator.alloc([]FieldElement, num_leaves);
        defer {
            for (leaf_hashes) |hash| {
                allocator.free(hash);
            }
            allocator.free(leaf_hashes);
        }

        // Generate leaf hashes in parallel (matching Rust implementation)
        // Use a simple parallelization approach with a fixed number of threads
        const num_threads = @min(std.Thread.getCpuCount() catch 4, num_leaves);

        // Use atomic counter for thread coordination
        var next_leaf = std.atomic.Value(usize).init(0);

        // Use the global ThreadContext definition

        var threads = try allocator.alloc(std.Thread, num_threads);
        defer allocator.free(threads);

        // Create contexts for all threads
        var contexts: []ThreadContext = try allocator.alloc(ThreadContext, num_threads);
        defer allocator.free(contexts);

        // Spawn worker threads
        for (0..num_threads) |i| {
            contexts[i] = ThreadContext{
                .param_wots = param_wots,
                .prf_key = prf_key,
                .leaf_hashes = leaf_hashes,
                .next_leaf = &next_leaf,
                .total_leaves = num_leaves,
                .allocator = allocator,
                .error_flag = std.atomic.Value(bool).init(false),
            };

            threads[i] = try std.Thread.spawn(.{}, parallelWorker, .{&contexts[i]});
        }

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }

        // Check for errors
        if (next_leaf.load(.monotonic) < num_leaves) {
            return error.ParallelGenerationFailed;
        }

        // Flatten leaf hashes for buildTree (it expects individual field elements)
        var flattened_leaves = try allocator.alloc(FieldElement, num_leaves);
        defer allocator.free(flattened_leaves);

        for (leaf_hashes, 0..) |leaf_hash, i| {
            // Take the first element of each leaf hash as the tree leaf
            flattened_leaves[i] = leaf_hash[0];
        }

        // Build tree and get root (matching Rust's HashTree::new)
        const root_element = try param_tree.buildTree(allocator, flattened_leaves);
        const tree_levels = try param_tree.buildFullTree(allocator, leaf_hashes);

        // Convert single FieldElement to slice for consistency
        const root = try allocator.alloc(FieldElement, 1);
        root[0] = root_element;

        return .{ root, tree_levels };
    }

    /// Recursive root computation for streaming approach
    fn computeRootRecursive(
        allocator: Allocator,
        param_wots: *WinternitzOTSNative,
        prf_key: *const [32]u8,
        start_idx: usize,
        end_idx: usize,
        level: u8,
    ) !FieldElement {
        if (start_idx == end_idx) {
            // Base case: single leaf - generate the leaf hash
            const epoch = @as(u32, @intCast(start_idx));

            // Generate private key (field elements)
            const sk = try param_wots.generatePrivateKey(allocator, prf_key, epoch);
            defer {
                for (sk) |k| allocator.free(k);
                allocator.free(sk);
            }

            // Generate public key (concatenated field elements)
            const pk = try param_wots.generatePublicKey(allocator, sk, epoch);
            defer allocator.free(pk);

            // Hash full OTS public key to produce tree leaf
            const leaf_tweak = @import("tweak.zig").PoseidonTweak{
                .tree_tweak = .{
                    .level = level,
                    .pos_in_level = @intCast(start_idx),
                },
            };

            const leaf_hash = try param_wots.hash.hashFieldElements(
                allocator,
                pk,
                leaf_tweak,
                7, // 7 field elements output (HASH_LEN_FE in Rust)
            );
            defer allocator.free(leaf_hash);

            // Return the first element of the leaf hash
            return leaf_hash[0];
        }

        // Recursive case: combine two subtrees
        const mid_idx = (start_idx + end_idx) / 2;

        // Compute left and right subtrees recursively
        const left_child = try computeRootRecursive(allocator, param_wots, prf_key, start_idx, mid_idx, level + 1);
        const right_child = try computeRootRecursive(allocator, param_wots, prf_key, mid_idx + 1, end_idx, level + 1);

        // Combine children
        const combined = try allocator.alloc(FieldElement, 2);
        defer allocator.free(combined);
        combined[0] = left_child;
        combined[1] = right_child;

        // Hash the combined node
        const node_tweak = @import("tweak.zig").PoseidonTweak{
            .tree_tweak = .{
                .level = level,
                .pos_in_level = @intCast(start_idx / 2), // Approximate position
            },
        };

        const result = try param_wots.hash.hashFieldElements(
            allocator,
            combined,
            node_tweak,
            1, // Single field element output for tree nodes
        );
        defer allocator.free(result);

        return result[0];
    }

    /// Parallel worker thread for generating leaf hashes
    fn parallelWorker(context: *ThreadContext) void {
        while (!context.error_flag.load(.monotonic)) {
            // Atomically get next leaf index to process
            const leaf_idx = context.next_leaf.fetchAdd(1, .monotonic);
            if (leaf_idx >= context.total_leaves) {
                break; // All leaves processed
            }

            const epoch = @as(u32, @intCast(leaf_idx));

            // Generate private key for this epoch (this is memory-efficient)
            const sk = context.param_wots.generatePrivateKey(context.allocator, context.prf_key, epoch) catch {
                context.error_flag.store(true, .monotonic);
                return;
            };
            defer {
                for (sk) |k| context.allocator.free(k);
                context.allocator.free(sk);
            }

            // Generate public key (chain ends) - this is the memory-intensive part
            const pk = context.param_wots.generatePublicKey(context.allocator, sk, epoch) catch {
                context.error_flag.store(true, .monotonic);
                return;
            };
            defer context.allocator.free(pk);

            // Hash the public key to create leaf hash (matching Rust)
            const leaf_tweak = @import("tweak.zig").PoseidonTweak{
                .tree_tweak = .{
                    .level = 0, // Leaf level
                    .pos_in_level = @intCast(leaf_idx),
                },
            };

            const leaf_hash = context.param_wots.hash.hashFieldElements(
                context.allocator,
                pk,
                leaf_tweak,
                7, // 7 field elements output
            ) catch {
                context.error_flag.store(true, .monotonic);
                return;
            };

            // Store the leaf hash
            context.leaf_hashes[leaf_idx] = leaf_hash;
        }
    }
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
    for (start_idx..end_idx) |i| {
        if (shared_state.error_flag.load(.monotonic)) {
            break;
        }

        const epoch = @as(u32, @intCast(i));

        // Generate OTS key pair for this epoch using in-place computation
        const sk = shared_state.param_wots.generatePrivateKey(
            shared_state.allocator,
            shared_state.prf_key,
            epoch,
        ) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer {
            for (sk) |k| shared_state.allocator.free(k);
            shared_state.allocator.free(sk);
        }

        // Generate public key using in-place chain computation
        var chain_ends = shared_state.allocator.alloc(FieldElement, sk.len) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer shared_state.allocator.free(chain_ends);

        for (sk, 0..) |private_key_chain, chain_idx| {
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
            shared_state.allocator,
            chain_ends,
            leaf_tweak,
            7,
        ) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
        defer shared_state.allocator.free(leaf_hash);

        // Add to streaming tree builder (thread-safe)
        shared_state.tree_builder.addLeafHash(leaf_hash[0]) catch {
            shared_state.error_flag.store(true, .monotonic);
            break;
        };
    }
}

// Thread context type definition
const ThreadContext = struct {
    param_wots: *WinternitzOTSNative,
    prf_key: *const [32]u8,
    leaf_hashes: [][]FieldElement,
    next_leaf: *std.atomic.Value(usize),
    total_leaves: usize,
    allocator: Allocator,
    error_flag: std.atomic.Value(bool),
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
