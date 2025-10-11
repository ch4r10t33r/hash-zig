//! Main hash-based signature scheme

const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const winternitz = @import("winternitz.zig");
const merkle = @import("merkle.zig");
const encoding = @import("encoding.zig");
const Parameters = params.Parameters;
const WinternitzOTS = winternitz.WinternitzOTS;
const MerkleTree = merkle.MerkleTree;
const IncomparableEncoding = encoding.IncomparableEncoding;
const Allocator = std.mem.Allocator;

pub const HashSignature = struct {
    params: Parameters,
    wots: WinternitzOTS,
    tree: MerkleTree,
    allocator: Allocator,
    cached_leaves: ?[][]u8,

    pub fn init(allocator: Allocator, parameters: Parameters) !HashSignature {
        return .{
            .params = parameters,
            .wots = try WinternitzOTS.init(allocator, parameters),
            .tree = try MerkleTree.init(allocator, parameters),
            .allocator = allocator,
            .cached_leaves = null,
        };
    }

    pub fn deinit(self: *HashSignature) void {
        self.wots.deinit();
        self.tree.deinit();

        // Free cached leaves if they exist
        // NOTE: cached_leaves contains direct references to leaf memory (not duplicates)
        // So we need to free both the leaf contents AND the array container
        if (self.cached_leaves) |cached| {
            for (cached) |leaf| self.allocator.free(leaf);
            self.allocator.free(cached);
        }
    }

    /// Public key matching Rust GeneralizedXMSSPublicKey
    pub const PublicKey = struct {
        root: []u8, // Merkle root (TH::Domain)
        parameter: Parameters, // Hash function parameters (TH::Parameter)

        pub fn deinit(self: *PublicKey, allocator: Allocator) void {
            allocator.free(self.root);
        }
    };

    /// Secret key matching Rust GeneralizedXMSSSecretKey
    pub const SecretKey = struct {
        prf_key: [32]u8, // PRF key for key derivation (PRF::Key)
        tree: [][]u8, // Full Merkle tree structure (HashTree<TH>)
        tree_height: u32, // Height of the Merkle tree
        parameter: Parameters, // Hash function parameters (TH::Parameter)
        activation_epoch: u64, // First valid epoch
        num_active_epochs: u64, // Number of valid epochs

        pub fn deinit(self: *SecretKey, allocator: Allocator) void {
            for (self.tree) |node| allocator.free(node);
            allocator.free(self.tree);
        }
    };

    pub const KeyPair = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn deinit(self: *KeyPair, allocator: Allocator) void {
            self.public_key.deinit(allocator);
            self.secret_key.deinit(allocator);
        }
    };

    /// Signature matching Rust GeneralizedXMSSSignature
    pub const Signature = struct {
        epoch: u64, // Epoch index (implicit in Rust via function parameter)
        auth_path: [][]u8, // Merkle authentication path (HashTreeOpening<TH>)
        rho: [32]u8, // Encoding randomness (IE::Randomness)
        hashes: [][]u8, // OTS signature (Vec<TH::Domain>)

        pub fn deinit(self: *Signature, allocator: Allocator) void {
            for (self.hashes) |hash| allocator.free(hash);
            allocator.free(self.hashes);
            for (self.auth_path) |path| allocator.free(path);
            allocator.free(self.auth_path);
        }
    };

    const LeafJob = struct { start: usize, end: usize };

    const LeafQueue = struct {
        jobs: []LeafJob,
        next: std.atomic.Value(usize),

        fn init(jobs: []LeafJob) LeafQueue {
            return .{ .jobs = jobs, .next = std.atomic.Value(usize).init(0) };
        }

        fn pop(self: *LeafQueue) ?LeafJob {
            const idx = self.next.fetchAdd(1, .monotonic);
            if (idx >= self.jobs.len) return null;
            return self.jobs[idx];
        }
    };

    const WorkerCtx = struct {
        hash_sig: *HashSignature,
        allocator: Allocator,
        seed: []const u8,
        leaves: [][]u8,
        leaf_secret_keys: [][][]u8,
        queue: *LeafQueue,
        error_flag: *std.atomic.Value(bool),
    };

    fn worker(ctx: *WorkerCtx) void {
        // Create arena allocator for this worker thread to reduce allocation overhead
        // All intermediate hash computations use the arena; final results copied to parent
        var arena = std.heap.ArenaAllocator.init(ctx.allocator);
        defer arena.deinit();
        const arena_allocator = arena.allocator();

        while (!ctx.error_flag.load(.monotonic)) {
            const maybe_job = ctx.queue.pop();
            if (maybe_job == null) break;
            const job = maybe_job.?;
            
            for (job.start..job.end) |i| {
                const epoch = @as(u32, @intCast(i)); // Use epoch directly
                
                // Generate keys using arena allocator for intermediate allocations
                const sk_temp = ctx.hash_sig.wots.generatePrivateKey(arena_allocator, ctx.seed, epoch) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                const pk_temp = ctx.hash_sig.wots.generatePublicKey(arena_allocator, sk_temp) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                // Copy final results to parent allocator (these persist after arena cleanup)
                const sk = ctx.allocator.alloc([]u8, sk_temp.len) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };
                for (sk_temp, 0..) |k, idx| {
                    sk[idx] = ctx.allocator.dupe(u8, k) catch {
                        // Clean up on error
                        for (sk[0..idx]) |s| ctx.allocator.free(s);
                        ctx.allocator.free(sk);
                        ctx.error_flag.store(true, .monotonic);
                        return;
                    };
                }

                const pk = ctx.allocator.dupe(u8, pk_temp) catch {
                    for (sk) |k| ctx.allocator.free(k);
                    ctx.allocator.free(sk);
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                ctx.leaf_secret_keys[i] = sk;
                ctx.leaves[i] = pk;
            }
            
            // Reset arena after each job to keep memory usage bounded
            _ = arena.reset(.retain_capacity);
        }
    }

    /// Generate key pair matching Rust implementation
    /// - activation_epoch: first valid epoch for this key (default 0)
    /// - num_active_epochs: number of epochs this key covers (default: all, 0 means use full lifetime)
    pub fn generateKeyPair(
        self: *HashSignature,
        allocator: Allocator,
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

        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);

        // Allocate arrays for leaves and secret keys
        var leaves = try allocator.alloc([]u8, num_leaves);
        var leaf_secret_keys = try allocator.alloc([][]u8, num_leaves);

        errdefer {
            // Clean up on error
            for (leaves) |leaf| {
                if (leaf.len > 0) allocator.free(leaf);
            }
            allocator.free(leaves);
            for (leaf_secret_keys) |sk| {
                if (sk.len > 0) {
                    for (sk) |s| allocator.free(s);
                    allocator.free(sk);
                }
            }
            allocator.free(leaf_secret_keys);
        }

        // Determine optimal number of threads (use CPU count or default to 8)
        const num_cpus = std.Thread.getCpuCount() catch 8;
        const num_threads = @min(num_cpus, num_leaves);

        // Use adaptive threshold: parallelize aggressively for large trees
        const parallel_threshold: usize = if (num_leaves >= 1 << 16) 512 else if (num_leaves >= 8192) 256 else 2048;
        if (num_threads <= 1 or num_leaves < parallel_threshold) {
            // Fall back to sequential for small workloads
            // Use arena allocator for intermediate allocations (same optimization as parallel path)
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const arena_allocator = arena.allocator();

            for (0..num_leaves) |i| {
                const epoch = @as(u32, @intCast(i)); // Use epoch directly, not i * 1000

                // Generate using arena allocator for intermediate allocations
                const sk_temp = try self.wots.generatePrivateKey(arena_allocator, seed, epoch);
                const pk_temp = try self.wots.generatePublicKey(arena_allocator, sk_temp);

                // Copy final results to parent allocator
                const sk = try allocator.alloc([]u8, sk_temp.len);
                errdefer allocator.free(sk);
                for (sk_temp, 0..) |k, idx| {
                    sk[idx] = try allocator.dupe(u8, k);
                }

                const pk = try allocator.dupe(u8, pk_temp);

                leaf_secret_keys[i] = sk;
                leaves[i] = pk;

                // Periodically reset arena to keep memory usage bounded
                if (i % 64 == 63) {
                    _ = arena.reset(.retain_capacity);
                }
            }
        } else {
            // Parallel leaf generation using a global queue and workers
            var error_flag = std.atomic.Value(bool).init(false);

            // Determine job size adaptively for max throughput on large trees
            const base_job: usize = if (num_leaves >= (1 << 20)) 2048 else if (num_leaves >= (1 << 16)) 1024 else 256;
            const job_size = if (num_leaves / num_threads < base_job)
                @max(64, num_leaves / (num_threads * 2))
            else
                base_job;
            const num_jobs = (num_leaves + job_size - 1) / job_size;

            var jobs = try allocator.alloc(LeafJob, num_jobs);
            defer allocator.free(jobs);
            var job_idx: usize = 0;
            var i: usize = 0;
            while (i < num_leaves) : (i += job_size) {
                const end = @min(i + job_size, num_leaves);
                jobs[job_idx] = .{ .start = i, .end = end };
                job_idx += 1;
            }

            var queue = LeafQueue.init(jobs);

            var threads = try allocator.alloc(std.Thread, num_threads);
            defer allocator.free(threads);

            var ctxs = try allocator.alloc(WorkerCtx, num_threads);
            defer allocator.free(ctxs);

            for (0..num_threads) |t| {
                ctxs[t] = .{
                    .hash_sig = self,
                    .allocator = allocator,
                    .seed = seed,
                    .leaves = leaves,
                    .leaf_secret_keys = leaf_secret_keys,
                    .queue = &queue,
                    .error_flag = &error_flag,
                };
                threads[t] = try std.Thread.spawn(.{}, worker, .{&ctxs[t]});
            }

            for (threads) |th| th.join();

            if (error_flag.load(.monotonic)) return error.InternalError;
        }

        // Build full Merkle tree structure (bottom-up, level by level)
        const tree_nodes = try self.buildFullMerkleTree(allocator, leaves);
        const merkle_root = try allocator.dupe(u8, tree_nodes[tree_nodes.len - 1]); // Root is last node

        // Use the provided seed as the PRF key (in Rust this would be PRF::key_gen(rng))
        var prf_key: [32]u8 = undefined;
        @memcpy(&prf_key, seed);

        // Cache the leaves for future signing operations (needed for auth path generation)
        // We MUST duplicate to ensure memory safety with Arena allocators
        const cached = try allocator.alloc([]u8, num_leaves);
        for (leaves, 0..) |leaf, i| {
            cached[i] = try allocator.dupe(u8, leaf);
        }
        self.cached_leaves = cached;

        // Now free the temporary leaves array
        for (leaves) |leaf| allocator.free(leaf);
        allocator.free(leaves);

        // Free leaf secret keys (we don't need them after key generation)
        for (leaf_secret_keys) |sk| {
            for (sk) |s| allocator.free(s);
            allocator.free(sk);
        }
        allocator.free(leaf_secret_keys);

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
    fn buildFullMerkleTree(self: *HashSignature, allocator: Allocator, leaves: []const []u8) ![][]u8 {
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
                    all_nodes[next_level_start + i] = try self.tree.hash.hash(allocator, combined, i);
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

    /// Sign a message matching Rust implementation
    /// Derives OTS keys on-demand from PRF key
    pub fn sign(
        self: *HashSignature,
        allocator: Allocator,
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
        crypto.hash.sha3.Sha3_256.hash(rng_seed, &rho, .{});

        // Derive OTS private key for this epoch from PRF key
        // In Rust: PRF::apply(&prf_key, epoch as u32, chain_index as u64)
        const num_chains = self.params.num_chains;
        var private_key = try allocator.alloc([]u8, num_chains);
        defer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        for (0..num_chains) |chain_idx| {
            // PRF: hash(prf_key, epoch + chain_idx)
            private_key[chain_idx] = try self.wots.hash.prfHash(
                allocator,
                &secret_key.prf_key,
                epoch + chain_idx,
            );
        }

        // Sign the message with the one-time signature scheme
        const ots_signature = try self.wots.sign(allocator, message, private_key);

        // Generate authentication path using cached leaves
        const auth_path = if (self.cached_leaves) |leaves|
            try self.tree.generateAuthPath(allocator, leaves, @intCast(epoch))
        else
            return error.LeavesNotCached;

        return Signature{
            .epoch = epoch,
            .auth_path = auth_path,
            .rho = rho,
            .hashes = ots_signature,
        };
    }

    /// Verify a signature matching Rust implementation
    pub fn verify(
        self: *HashSignature,
        allocator: Allocator,
        message: []const u8,
        signature: Signature,
        public_key: *const PublicKey,
    ) !bool {
        // Step 1: Compute the OTS leaf public key from the signature
        const msg_hash = try self.wots.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        const chain_len = self.wots.getChainLength();
        const hash_output_len = self.params.hash_output_len;

        var public_parts = try allocator.alloc([]u8, signature.hashes.len);
        defer {
            for (public_parts) |part| allocator.free(part);
            allocator.free(public_parts);
        }

        // Derive public key parts from signature by completing hash chains
        for (signature.hashes, 0..) |sig, i| {
            var current = try allocator.dupe(u8, sig);

            const start_val = if (i < encoded.len) encoded[i] else 0;
            const remaining = chain_len - start_val;

            for (0..remaining) |_| {
                const next = try self.wots.hash.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            public_parts[i] = current;
        }

        // Combine public key parts into the leaf
        // CRITICAL: Zero the buffer to ensure deterministic results with Arena allocators
        var combined = try allocator.alloc(u8, public_parts.len * hash_output_len);
        @memset(combined, 0);
        defer allocator.free(combined);

        for (public_parts, 0..) |part, i| {
            @memcpy(combined[i * hash_output_len ..][0..hash_output_len], part);
        }

        var current_hash = try self.wots.hash.hash(allocator, combined, 0);
        defer allocator.free(current_hash);

        // Step 2: Use authentication path to compute the Merkle root
        var leaf_idx = signature.epoch;

        for (signature.auth_path, 0..) |sibling, level| {
            _ = level;
            // Determine if current node is left or right child
            const is_left = (leaf_idx % 2 == 0);

            // Combine current hash with sibling
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

            // Hash to get parent node
            // IMPORTANT: Use index within level (not absolute index) to match tree building
            // During tree building, tweak is `i` (index within level), so use same here
            const parent_index_in_level = leaf_idx / 2;
            const parent = try self.tree.hash.hash(allocator, combined_nodes, parent_index_in_level);

            allocator.free(current_hash);
            current_hash = parent;

            // Move to parent index within next level
            leaf_idx = parent_index_in_level;
        }

        // Step 3: Compare computed root with provided public_key root
        return std.mem.eql(u8, current_hash, public_key.root);
    }
};
