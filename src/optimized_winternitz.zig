//! Optimized Winternitz OTS with reduced allocations and better memory layout

const std = @import("std");
const params = @import("params.zig");
const tweakable_hash = @import("tweakable_hash.zig");
const encoding = @import("encoding.zig");
const arena_allocator = @import("arena_allocator.zig");
const Parameters = params.Parameters;
const TweakableHash = tweakable_hash.TweakableHash;
const IncomparableEncoding = encoding.IncomparableEncoding;
const ArenaAllocator = arena_allocator.ArenaAllocator;
const Allocator = std.mem.Allocator;

pub const OptimizedWinternitzOTS = struct {
    params: Parameters,
    hash: TweakableHash,
    arena: ArenaAllocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !OptimizedWinternitzOTS {
        return .{
            .params = parameters,
            .hash = try TweakableHash.init(allocator, parameters),
            .arena = ArenaAllocator.init(1024 * 1024), // 1MB arena
        };
    }

    pub fn deinit(self: *OptimizedWinternitzOTS) void {
        self.hash.deinit();
        self.arena.deinit();
    }

    pub inline fn getChainLength(self: OptimizedWinternitzOTS) u32 {
        return @as(u32, 1) << @intCast(@ctz(self.params.winternitz_w));
    }

    /// Generate private key with reduced allocations
    pub fn generatePrivateKey(self: *OptimizedWinternitzOTS, seed: []const u8, addr: u64) ![][]u8 {
        const winternitz_w = self.params.winternitz_w;
        const hash_output_len = self.params.hash_output_len;
        const len = (8 * hash_output_len + @ctz(winternitz_w) - 1) / @ctz(winternitz_w);

        const arena = self.arena.allocator();
        var private_key = try arena.alloc([]u8, len);

        for (0..len) |i| {
            private_key[i] = try self.hash.prfHash(arena, seed, addr + i);
        }

        return private_key;
    }

    /// Optimized chain generation with minimal allocations
    pub fn generatePublicKey(self: *OptimizedWinternitzOTS, private_key: [][]u8) ![]u8 {
        const chain_len = self.getChainLength();
        const hash_output_len = self.params.hash_output_len;
        const arena = self.arena.allocator();

        // Pre-allocate all public parts in a single allocation
        var public_parts = try arena.alloc([]u8, private_key.len);
        
        // Initialize to empty slices
        for (public_parts) |*part| {
            part.* = &[_]u8{};
        }

        // Generate chains in parallel with work-stealing
        const num_threads = std.Thread.getCpuCount() catch 4;
        const num_chains = private_key.len;
        
        if (num_chains < 64 or num_threads <= 1) {
            // Sequential for small workloads
            for (0..num_chains) |i| {
                public_parts[i] = try self.generateChain(arena, private_key[i], chain_len, i);
            }
        } else {
            // Parallel chain generation
            try self.generateChainsParallel(public_parts, private_key, chain_len, num_threads);
        }

        // Concatenate all public parts
        const total_len = num_chains * hash_output_len;
        const result = try arena.alloc(u8, total_len);
        
        var offset: usize = 0;
        for (public_parts) |part| {
            @memcpy(result[offset..offset + part.len], part);
            offset += part.len;
        }

        return result;
    }

    /// Generate a single hash chain with minimal allocations
    fn generateChain(self: *OptimizedWinternitzOTS, arena: Allocator, start_value: []u8, chain_len: u32, chain_index: usize) ![]u8 {
        var current = try arena.dupe(u8, start_value);
        
        for (0..chain_len) |_| {
            const next = try self.hash.hash(arena, current, chain_index);
            arena.free(current);
            current = next;
        }

        return current;
    }

    /// Parallel chain generation with work-stealing
    fn generateChainsParallel(self: *OptimizedWinternitzOTS, public_parts: [][]u8, private_key: [][]u8, chain_len: u32, num_threads: usize) !void {
        const num_chains = private_key.len;
        const work_queue = std.atomic.Value(usize).init(0);
        const error_flag = std.atomic.Value(bool).init(false);
        
        var threads = try std.heap.page_allocator.alloc(std.Thread, num_threads);
        defer std.heap.page_allocator.free(threads);

        const WorkerCtx = struct {
            wots: *OptimizedWinternitzOTS,
            public_parts: [][]u8,
            private_key: [][]u8,
            chain_len: u32,
            work_queue: *std.atomic.Value(usize),
            error_flag: *std.atomic.Value(bool),
            arena: ArenaAllocator,
        };

        var ctxs = try std.heap.page_allocator.alloc(WorkerCtx, num_threads);
        defer std.heap.page_allocator.free(ctxs);

        for (0..num_threads) |t| {
            ctxs[t] = .{
                .wots = self,
                .public_parts = public_parts,
                .private_key = private_key,
                .chain_len = chain_len,
                .work_queue = &work_queue,
                .error_flag = &error_flag,
                .arena = ArenaAllocator.init(256 * 1024), // 256KB per thread
            };
            
            threads[t] = try std.Thread.spawn(.{}, worker, .{&ctxs[t]});
        }

        for (threads) |th| th.join();
        
        // Clean up thread arenas
        for (ctxs) |*ctx| ctx.arena.deinit();

        if (error_flag.load(.monotonic)) return error.InternalError;
    }

    fn worker(ctx: *WorkerCtx) void {
        const arena = ctx.arena.allocator();
        
        while (!ctx.error_flag.load(.monotonic)) {
            const work_index = ctx.work_queue.fetchAdd(1, .monotonic);
            if (work_index >= ctx.public_parts.len) break;
            
            ctx.public_parts[work_index] = ctx.wots.generateChain(arena, ctx.private_key[work_index], ctx.chain_len, work_index) catch {
                ctx.error_flag.store(true, .monotonic);
                return;
            };
        }
    }

    /// Sign a message with optimized memory usage
    pub fn sign(self: *OptimizedWinternitzOTS, message: []const u8, private_key: [][]u8) ![][]u8 {
        const arena = self.arena.allocator();
        
        // Hash the message
        const msg_hash = try self.hash.hash(arena, message, 0);
        defer arena.free(msg_hash);

        // Encode the message
        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(arena, msg_hash);
        defer arena.free(encoded);

        const winternitz_w = self.params.winternitz_w;
        const hash_output_len = self.params.hash_output_len;
        const len = (8 * hash_output_len + @ctz(winternitz_w) - 1) / @ctz(winternitz_w);

        var signature = try arena.alloc([]u8, len);
        
        // Generate signature chains in parallel
        const num_threads = std.Thread.getCpuCount() catch 4;
        if (len < 32 or num_threads <= 1) {
            // Sequential for small signatures
            for (0..len) |i| {
                const steps = if (i < encoded.len) encoded[i] else 0;
                signature[i] = try self.generateChainSteps(arena, private_key[i], steps, i);
            }
        } else {
            // Parallel signature generation
            try self.generateSignatureParallel(signature, private_key, encoded, num_threads);
        }

        return signature;
    }

    fn generateChainSteps(self: *OptimizedWinternitzOTS, arena: Allocator, start_value: []u8, steps: u32, chain_index: usize) ![]u8 {
        var current = try arena.dupe(u8, start_value);
        
        for (0..steps) |_| {
            const next = try self.hash.hash(arena, current, chain_index);
            arena.free(current);
            current = next;
        }

        return current;
    }

    fn generateSignatureParallel(self: *OptimizedWinternitzOTS, signature: [][]u8, private_key: [][]u8, encoded: []u32, num_threads: usize) !void {
        const work_queue = std.atomic.Value(usize).init(0);
        const error_flag = std.atomic.Value(bool).init(false);
        
        var threads = try std.heap.page_allocator.alloc(std.Thread, num_threads);
        defer std.heap.page_allocator.free(threads);

        const WorkerCtx = struct {
            wots: *OptimizedWinternitzOTS,
            signature: [][]u8,
            private_key: [][]u8,
            encoded: []u32,
            work_queue: *std.atomic.Value(usize),
            error_flag: *std.atomic.Value(bool),
            arena: ArenaAllocator,
        };

        var ctxs = try std.heap.page_allocator.alloc(WorkerCtx, num_threads);
        defer std.heap.page_allocator.free(ctxs);

        for (0..num_threads) |t| {
            ctxs[t] = .{
                .wots = self,
                .signature = signature,
                .private_key = private_key,
                .encoded = encoded,
                .work_queue = &work_queue,
                .error_flag = &error_flag,
                .arena = ArenaAllocator.init(128 * 1024), // 128KB per thread
            };
            
            threads[t] = try std.Thread.spawn(.{}, signatureWorker, .{&ctxs[t]});
        }

        for (threads) |th| th.join();
        
        // Clean up thread arenas
        for (ctxs) |*ctx| ctx.arena.deinit();

        if (error_flag.load(.monotonic)) return error.InternalError;
    }

    fn signatureWorker(ctx: *WorkerCtx) void {
        const arena = ctx.arena.allocator();
        
        while (!ctx.error_flag.load(.monotonic)) {
            const work_index = ctx.work_queue.fetchAdd(1, .monotonic);
            if (work_index >= ctx.signature.len) break;
            
            const steps = if (work_index < ctx.encoded.len) ctx.encoded[work_index] else 0;
            ctx.signature[work_index] = ctx.wots.generateChainSteps(arena, ctx.private_key[work_index], steps, work_index) catch {
                ctx.error_flag.store(true, .monotonic);
                return;
            };
        }
    }
};

test "optimized winternitz basic functionality" {
    const allocator = std.testing.allocator;
    const params = Parameters.init(.lifetime_2_10);
    
    var wots = try OptimizedWinternitzOTS.init(allocator, params);
    defer wots.deinit();
    
    const seed = "test seed for winternitz";
    const private_key = try wots.generatePrivateKey(seed, 0);
    
    const public_key = try wots.generatePublicKey(private_key);
    try std.testing.expect(public_key.len > 0);
    
    const message = "test message";
    const signature = try wots.sign(message, private_key);
    try std.testing.expect(signature.len == private_key.len);
}
