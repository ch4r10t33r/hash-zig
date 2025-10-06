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
    cached_leaves: ?[][]const u8,

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
        if (self.cached_leaves) |leaves| {
            for (leaves) |leaf| self.allocator.free(leaf);
            self.allocator.free(leaves);
        }
    }

    pub const KeyPair = struct {
        public_key: []u8,
        secret_key: []u8,

        pub fn deinit(self: *KeyPair, allocator: Allocator) void {
            allocator.free(self.public_key);
            allocator.free(self.secret_key);
        }
    };

    pub const Signature = struct {
        index: u64,
        ots_signature: [][]u8,
        auth_path: [][]u8,

        pub fn deinit(self: *Signature, allocator: Allocator) void {
            for (self.ots_signature) |sig| allocator.free(sig);
            allocator.free(self.ots_signature);
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
        leaves: [][]const u8,
        leaf_secret_keys: [][][]u8,
        queue: *LeafQueue,
        error_flag: *std.atomic.Value(bool),
    };

    fn worker(ctx: *WorkerCtx) void {
        while (!ctx.error_flag.load(.monotonic)) {
            const maybe_job = ctx.queue.pop();
            if (maybe_job == null) break;
            const job = maybe_job.?;
            for (job.start..job.end) |i| {
                const epoch = @as(u32, @intCast(i)); // Use epoch directly
                const sk = ctx.hash_sig.wots.generatePrivateKey(ctx.allocator, ctx.seed, epoch) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                const pk = ctx.hash_sig.wots.generatePublicKey(ctx.allocator, sk) catch {
                    for (sk) |k| ctx.allocator.free(k);
                    ctx.allocator.free(sk);
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                ctx.leaf_secret_keys[i] = sk;
                ctx.leaves[i] = pk;
            }
        }
    }

    pub fn generateKeyPair(self: *HashSignature, allocator: Allocator, seed: []const u8) !KeyPair {
        if (seed.len != 32) return error.InvalidSeedLength;

        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);

        var leaf_public_keys = try allocator.alloc([]u8, num_leaves);
        defer {
            for (leaf_public_keys) |pk| allocator.free(pk);
            allocator.free(leaf_public_keys);
        }

        var leaf_secret_keys = try allocator.alloc([][]u8, num_leaves);
        defer {
            for (leaf_secret_keys) |sk| {
                for (sk) |s| allocator.free(s);
                allocator.free(sk);
            }
            allocator.free(leaf_secret_keys);
        }

        var leaves = try allocator.alloc([]const u8, num_leaves);
        defer {
            for (leaves) |leaf| {
                if (leaf.len > 0) allocator.free(leaf);
            }
            allocator.free(leaves);
        }

        // Initialize leaves to empty slices
        for (leaves) |*leaf| {
            leaf.* = &[_]u8{};
        }

        // Determine optimal number of threads (use CPU count or default to 8)
        const num_cpus = std.Thread.getCpuCount() catch 8;
        const num_threads = @min(num_cpus, num_leaves);

        // Use adaptive threshold: parallelize aggressively for large trees
        const parallel_threshold: usize = if (num_leaves >= 1 << 16) 512 else if (num_leaves >= 8192) 256 else 2048;
        if (num_threads <= 1 or num_leaves < parallel_threshold) {
            // Fall back to sequential for small workloads
            for (0..num_leaves) |i| {
                const epoch = @as(u32, @intCast(i)); // Use epoch directly, not i * 1000
                const sk = try self.wots.generatePrivateKey(allocator, seed, epoch);
                const pk = try self.wots.generatePublicKey(allocator, sk);

                leaf_secret_keys[i] = sk;
                leaf_public_keys[i] = pk;
                leaves[i] = pk;
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

        // Build Merkle tree and get root
        const merkle_root = try self.tree.buildTree(allocator, leaves);

        // Combine all secret keys into one large secret key
        const total_secret_len = num_leaves * self.params.num_chains * self.params.hash_output_len;
        var combined_secret = try allocator.alloc(u8, total_secret_len);
        var offset: usize = 0;

        for (leaf_secret_keys) |sk| {
            for (sk) |s| {
                @memcpy(combined_secret[offset .. offset + s.len], s);
                offset += s.len;
            }
        }

        // Cache the leaves for future signing operations
        const cached = try allocator.alloc([]const u8, num_leaves);
        for (leaves, 0..) |leaf, i| {
            cached[i] = try allocator.dupe(u8, leaf);
        }
        self.cached_leaves = cached;

        return KeyPair{
            .public_key = merkle_root,
            .secret_key = combined_secret,
        };
    }

    pub fn sign(self: *HashSignature, allocator: Allocator, message: []const u8, secret_key: []const u8, epoch: u64) !Signature {
        // epoch is the index/epoch of the signature (0 to lifetime-1)
        // Extract the OTS private key for this epoch from the combined secret key
        const num_chains = self.params.num_chains;
        const hash_output_len = self.params.hash_output_len;
        const leaf_sk_size = num_chains * hash_output_len;
        const leaf_offset = epoch * leaf_sk_size;

        if (leaf_offset + leaf_sk_size > secret_key.len) {
            return error.InvalidIndex;
        }

        // Reconstruct the leaf secret key structure
        var private_key = try allocator.alloc([]u8, num_chains);
        defer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        for (0..num_chains) |i| {
            const chain_offset = leaf_offset + (i * hash_output_len);
            private_key[i] = try allocator.dupe(u8, secret_key[chain_offset .. chain_offset + hash_output_len]);
        }

        // Sign the message with the one-time signature scheme
        const ots_signature = try self.wots.sign(allocator, message, private_key);

        // Generate authentication path using cached leaves
        // This is the key optimization: leaves were already generated during key generation
        const auth_path = if (self.cached_leaves) |leaves|
            try self.tree.generateAuthPath(allocator, leaves, @intCast(epoch))
        else
            return error.LeavesNotCached; // Signing requires cached leaves

        return Signature{
            .index = epoch,
            .ots_signature = ots_signature,
            .auth_path = auth_path,
        };
    }

    pub fn verify(self: *HashSignature, allocator: Allocator, message: []const u8, signature: Signature, public_key: []const u8) !bool {
        // Step 1: Compute the OTS leaf public key from the signature
        const msg_hash = try self.wots.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        const chain_len = self.wots.getChainLength();
        const hash_output_len = self.params.hash_output_len;

        var public_parts = try allocator.alloc([]u8, signature.ots_signature.len);
        defer {
            for (public_parts) |part| allocator.free(part);
            allocator.free(public_parts);
        }

        // Derive public key parts from signature by completing hash chains
        for (signature.ots_signature, 0..) |sig, i| {
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
        var combined = try allocator.alloc(u8, public_parts.len * hash_output_len);
        defer allocator.free(combined);

        for (public_parts, 0..) |part, i| {
            @memcpy(combined[i * hash_output_len ..][0..hash_output_len], part);
        }

        var current_hash = try self.wots.hash.hash(allocator, combined, 0);
        defer allocator.free(current_hash);

        // Step 2: Use authentication path to compute the Merkle root
        var leaf_idx = signature.index;

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

            // Hash to get parent node (use parent position as tweak to match tree build)
            const parent_index = leaf_idx / 2;
            const parent = try self.tree.hash.hash(allocator, combined_nodes, parent_index);

            allocator.free(current_hash);
            current_hash = parent;

            // Move to parent index
            leaf_idx = parent_index;
        }

        // Step 3: Compare computed root with provided public_key
        return std.mem.eql(u8, current_hash, public_key);
    }
};
