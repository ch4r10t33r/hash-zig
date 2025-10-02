//! Optimized hash-based signature scheme with improved performance

const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const optimized_winternitz = @import("optimized_winternitz.zig");
const merkle = @import("merkle.zig");
const encoding = @import("encoding.zig");
const arena_allocator = @import("arena_allocator.zig");
const Parameters = params.Parameters;
const OptimizedWinternitzOTS = optimized_winternitz.OptimizedWinternitzOTS;
const MerkleTree = merkle.MerkleTree;
const IncomparableEncoding = encoding.IncomparableEncoding;
const ArenaAllocator = arena_allocator.ArenaAllocator;
const Allocator = std.mem.Allocator;

pub const OptimizedHashSignature = struct {
    params: Parameters,
    wots: OptimizedWinternitzOTS,
    tree: MerkleTree,
    arena: ArenaAllocator,
    cached_leaves: ?[][]const u8,

    pub fn init(allocator: Allocator, parameters: Parameters) !OptimizedHashSignature {
        return .{
            .params = parameters,
            .wots = try OptimizedWinternitzOTS.init(allocator, parameters),
            .tree = try MerkleTree.init(allocator, parameters),
            .arena = ArenaAllocator.init(4 * 1024 * 1024), // 4MB arena
            .cached_leaves = null,
        };
    }

    pub fn deinit(self: *OptimizedHashSignature) void {
        self.wots.deinit();
        self.tree.deinit();
        self.arena.deinit();

        // Free cached leaves if they exist
        if (self.cached_leaves) |leaves| {
            for (leaves) |leaf| self.arena.allocator().free(leaf);
            self.arena.allocator().free(leaves);
        }
    }

    pub const KeyPair = struct {
        public_key: []u8,
        secret_key: []u8,

        pub fn deinit(self: *KeyPair, arena: *ArenaAllocator) void {
            arena.allocator().free(self.public_key);
            arena.allocator().free(self.secret_key);
        }
    };

    pub const Signature = struct {
        index: u64,
        ots_signature: [][]u8,
        auth_path: [][]u8,

        pub fn deinit(self: *Signature, arena: *ArenaAllocator) void {
            for (self.ots_signature) |sig| arena.allocator().free(sig);
            arena.allocator().free(self.ots_signature);
            for (self.auth_path) |path| arena.allocator().free(path);
            arena.allocator().free(self.auth_path);
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
        hash_sig: *OptimizedHashSignature,
        secret_key: []const u8,
        leaves: [][]const u8,
        queue: *LeafQueue,
        error_flag: *std.atomic.Value(bool),
        thread_arena: ArenaAllocator,
    };

    fn worker(ctx: *WorkerCtx) void {
        const arena = ctx.thread_arena.allocator();

        while (!ctx.error_flag.load(.monotonic)) {
            const maybe_job = ctx.queue.pop();
            if (maybe_job == null) break;
            const job = maybe_job.?;

            for (job.start..job.end) |i| {
                const sk_part = ctx.hash_sig.wots.generatePrivateKey(arena, ctx.secret_key, i * 1000) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };

                ctx.leaves[i] = ctx.hash_sig.wots.generatePublicKey(arena, sk_part) catch {
                    ctx.error_flag.store(true, .monotonic);
                    return;
                };
            }
        }
    }

    /// Optimized key generation with improved parallelization and memory management
    pub fn generateKeyPair(self: *OptimizedHashSignature, seed: []const u8) !KeyPair {
        if (seed.len != 32) return error.InvalidSeedLength;

        // Reset arena for fresh allocation
        self.arena.reset();
        const arena = self.arena.allocator();

        const secret_key = try arena.dupe(u8, seed);
        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);
        var leaves = try arena.alloc([]const u8, num_leaves);

        // Initialize leaves to empty slices
        for (leaves) |*leaf| {
            leaf.* = &[_]u8{};
        }

        // Determine optimal parallelization strategy
        const num_cpus = std.Thread.getCpuCount() catch 8;
        const num_threads = @min(num_cpus, num_leaves);

        // Use more aggressive parallelization thresholds
        const parallel_threshold: usize = if (num_leaves >= 1 << 20) 1024 else if (num_leaves >= 1 << 16) 512 else 128;

        if (num_threads <= 1 or num_leaves < parallel_threshold) {
            // Sequential for small workloads
            for (0..num_leaves) |i| {
                const secret_key_part = try self.wots.generatePrivateKey(arena, secret_key, i * 1000);
                leaves[i] = try self.wots.generatePublicKey(arena, secret_key_part);
            }
        } else {
            // Optimized parallel leaf generation
            try self.generateLeavesParallel(leaves, secret_key, num_threads);
        }

        const public_key = try self.tree.buildTree(arena, leaves);

        // Cache the leaves for future signing operations
        const cached = try arena.alloc([]const u8, num_leaves);
        for (leaves, 0..) |leaf, i| {
            cached[i] = try arena.dupe(u8, leaf);
        }
        self.cached_leaves = cached;

        return KeyPair{
            .public_key = public_key,
            .secret_key = secret_key,
        };
    }

    /// Parallel leaf generation with work-stealing and per-thread arenas
    fn generateLeavesParallel(self: *OptimizedHashSignature, leaves: [][]const u8, secret_key: []const u8, num_threads: usize) !void {
        var error_flag = std.atomic.Value(bool).init(false);

        // Adaptive job sizing based on workload size
        const base_job: usize = if (leaves.len >= (1 << 20)) 4096 else if (leaves.len >= (1 << 16)) 2048 else 512;
        const job_size = if (leaves.len / num_threads < base_job)
            @max(64, leaves.len / (num_threads * 2))
        else
            base_job;
        const num_jobs = (leaves.len + job_size - 1) / job_size;

        var jobs = try std.heap.page_allocator.alloc(LeafJob, num_jobs);
        defer std.heap.page_allocator.free(jobs);

        var job_idx: usize = 0;
        var i: usize = 0;
        while (i < leaves.len) : (i += job_size) {
            const end = @min(i + job_size, leaves.len);
            jobs[job_idx] = .{ .start = i, .end = end };
            job_idx += 1;
        }

        var queue = LeafQueue.init(jobs);
        var threads = try std.heap.page_allocator.alloc(std.Thread, num_threads);
        defer std.heap.page_allocator.free(threads);

        var ctxs = try std.heap.page_allocator.alloc(WorkerCtx, num_threads);
        defer std.heap.page_allocator.free(ctxs);

        for (0..num_threads) |t| {
            ctxs[t] = .{
                .hash_sig = self,
                .secret_key = secret_key,
                .leaves = leaves,
                .queue = &queue,
                .error_flag = &error_flag,
                .thread_arena = ArenaAllocator.init(512 * 1024), // 512KB per thread
            };
            threads[t] = try std.Thread.spawn(.{}, worker, .{&ctxs[t]});
        }

        for (threads) |th| th.join();

        // Clean up thread arenas
        for (ctxs) |*ctx| ctx.thread_arena.deinit();

        if (error_flag.load(.monotonic)) return error.InternalError;
    }

    /// Optimized signing with cached leaves
    pub fn sign(self: *OptimizedHashSignature, message: []const u8, secret_key: []const u8, index: u64) !Signature {
        const arena = self.arena.allocator();

        // Generate the OTS private key deterministically for this index
        const private_key = try self.wots.generatePrivateKey(arena, secret_key, index * 1000);

        // Sign the message with the one-time signature scheme
        const ots_signature = try self.wots.sign(message, private_key);

        // Generate authentication path using cached leaves
        const auth_path = if (self.cached_leaves) |leaves|
            try self.tree.generateAuthPath(arena, leaves, @intCast(index))
        else
            return error.LeavesNotCached;

        return Signature{
            .index = index,
            .ots_signature = ots_signature,
            .auth_path = auth_path,
        };
    }

    /// Optimized verification
    pub fn verify(self: *OptimizedHashSignature, message: []const u8, signature: Signature, public_key: []const u8) !bool {
        const arena = self.arena.allocator();

        // Step 1: Compute the OTS leaf public key from the signature
        const msg_hash = try self.wots.hash.hash(arena, message, 0);
        defer arena.free(msg_hash);

        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(arena, msg_hash);
        defer arena.free(encoded);

        // Step 2: Reconstruct the OTS public key from the signature
        const ots_public_key = try self.reconstructOTSPublicKey(arena, signature.ots_signature, encoded);

        // Step 3: Verify the Merkle authentication path
        return self.tree.verifyAuthPath(arena, ots_public_key, signature.auth_path, signature.index, public_key);
    }

    /// Reconstruct OTS public key from signature
    fn reconstructOTSPublicKey(self: *OptimizedHashSignature, arena: Allocator, ots_signature: [][]u8, encoded: []u32) ![]u8 {
        const winternitz_w = self.params.winternitz_w;
        const hash_output_len = self.params.hash_output_len;
        const len = (8 * hash_output_len + @ctz(winternitz_w) - 1) / @ctz(winternitz_w);

        var public_parts = try arena.alloc([]u8, len);
        defer {
            for (public_parts) |part| arena.free(part);
            arena.free(public_parts);
        }

        // Reconstruct each chain
        for (0..len) |i| {
            const steps = if (i < encoded.len) encoded[i] else 0;
            const remaining_steps = self.wots.getChainLength() - steps;

            var current = try arena.dupe(u8, ots_signature[i]);
            for (0..remaining_steps) |_| {
                const next = try self.wots.hash.hash(arena, current, i);
                arena.free(current);
                current = next;
            }
            public_parts[i] = current;
        }

        // Concatenate all parts
        const total_len = len * hash_output_len;
        const result = try arena.alloc(u8, total_len);

        var offset: usize = 0;
        for (public_parts) |part| {
            @memcpy(result[offset .. offset + part.len], part);
            offset += part.len;
        }

        return result;
    }
};

test "optimized hash signature basic functionality" {
    const allocator = std.testing.allocator;
    const test_params = Parameters.init(.lifetime_2_10);

    var sig_scheme = try OptimizedHashSignature.init(allocator, test_params);
    defer sig_scheme.deinit();

    const seed: [32]u8 = .{42} ** 32;
    const keypair = try sig_scheme.generateKeyPair(&seed);
    defer keypair.deinit(&sig_scheme.arena);

    const message = "test message";
    const signature = try sig_scheme.sign(message, keypair.secret_key, 0);
    defer signature.deinit(&sig_scheme.arena);

    const is_valid = try sig_scheme.verify(message, signature, keypair.public_key);
    try std.testing.expect(is_valid);
}
