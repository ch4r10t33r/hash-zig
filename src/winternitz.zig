//! Winternitz One-Time Signature scheme

const std = @import("std");
const params = @import("params.zig");
const tweakable_hash = @import("tweakable_hash.zig");
const encoding = @import("encoding.zig");
const Parameters = params.Parameters;
const TweakableHash = tweakable_hash.TweakableHash;
const IncomparableEncoding = encoding.IncomparableEncoding;
const Allocator = std.mem.Allocator;

pub const WinternitzOTS = struct {
    params: Parameters,
    hash: TweakableHash,

    pub fn init(allocator: Allocator, parameters: Parameters) !WinternitzOTS {
        return .{
            .params = parameters,
            .hash = try TweakableHash.init(allocator, parameters),
        };
    }

    pub fn deinit(self: *WinternitzOTS) void {
        self.hash.deinit();
    }

    pub inline fn getChainLength(self: WinternitzOTS) u32 {
        return @as(u32, 1) << @intCast(@ctz(self.params.winternitz_w));
    }

    pub fn generatePrivateKey(self: *WinternitzOTS, allocator: Allocator, seed: []const u8, addr: u64) ![][]u8 {
        const winternitz_w = self.params.winternitz_w;
        const hash_output_len = self.params.hash_output_len;
        const len = (8 * hash_output_len + @ctz(winternitz_w) - 1) / @ctz(winternitz_w);

        var private_key = try allocator.alloc([]u8, len);
        errdefer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        for (0..len) |i| {
            private_key[i] = try self.hash.prfHash(allocator, seed, addr + i);
        }

        return private_key;
    }

    const ChainGenContext = struct {
        wots: *WinternitzOTS,
        private_key: [][]u8,
        public_parts: [][]u8,
        chain_len: u32,
        allocator: Allocator,
        errors: []?anyerror,
        mutex: std.Thread.Mutex,
    };

    fn generateChainRange(context: *ChainGenContext, start: usize, end: usize) void {
        for (start..end) |i| {
            var current = context.allocator.dupe(u8, context.private_key[i]) catch |err| {
                context.mutex.lock();
                defer context.mutex.unlock();
                context.errors[i] = err;
                return;
            };

            for (0..context.chain_len) |_| {
                const next = context.wots.hash.hash(context.allocator, current, i) catch |err| {
                    context.allocator.free(current);
                    context.mutex.lock();
                    defer context.mutex.unlock();
                    context.errors[i] = err;
                    return;
                };
                context.allocator.free(current);
                current = next;
            }

            context.public_parts[i] = current;
        }
    }

    pub fn generatePublicKey(self: *WinternitzOTS, allocator: Allocator, private_key: [][]u8) ![]u8 {
        const chain_len = self.getChainLength();
        const hash_output_len = self.params.hash_output_len;

        var public_parts = try allocator.alloc([]u8, private_key.len);
        defer {
            for (public_parts) |part| {
                if (part.len > 0) allocator.free(part);
            }
            allocator.free(public_parts);
        }

        // Initialize to empty slices
        for (public_parts) |*part| {
            part.* = &[_]u8{};
        }

        const num_chains = private_key.len;
        const num_cpus = std.Thread.getCpuCount() catch 8;
        const num_threads = @min(num_cpus, num_chains);

        if (num_threads <= 1 or num_chains < 16) {
            // Sequential fallback for small workloads
            for (private_key, 0..) |pk, i| {
                var current = try allocator.dupe(u8, pk);

                for (0..chain_len) |_| {
                    const next = try self.hash.hash(allocator, current, i);
                    allocator.free(current);
                    current = next;
                }

                public_parts[i] = current;
            }
        } else {
            // Parallel chain generation
            const errors = try allocator.alloc(?anyerror, num_chains);
            defer allocator.free(errors);
            for (errors) |*err| err.* = null;

            var context = ChainGenContext{
                .wots = self,
                .private_key = private_key,
                .public_parts = public_parts,
                .chain_len = chain_len,
                .allocator = allocator,
                .errors = errors,
                .mutex = std.Thread.Mutex{},
            };

            var threads = try allocator.alloc(std.Thread, num_threads);
            defer allocator.free(threads);

            const chains_per_thread = num_chains / num_threads;
            const remainder = num_chains % num_threads;

            // Spawn worker threads
            for (0..num_threads) |t| {
                const start = t * chains_per_thread + @min(t, remainder);
                const end = start + chains_per_thread + (if (t < remainder) @as(usize, 1) else 0);
                threads[t] = try std.Thread.spawn(.{}, generateChainRange, .{ &context, start, end });
            }

            // Wait for all threads
            for (threads) |thread| {
                thread.join();
            }

            // Check for errors
            for (errors, 0..) |err, i| {
                if (err) |e| {
                    std.debug.print("Error generating chain {d}: {}\n", .{ i, e });
                    return e;
                }
            }
        }

        var combined = try allocator.alloc(u8, public_parts.len * hash_output_len);
        defer allocator.free(combined);
        for (public_parts, 0..) |part, i| {
            @memcpy(combined[i * hash_output_len ..][0..hash_output_len], part);
        }

        return self.hash.hash(allocator, combined, 0);
    }

    pub fn sign(self: *WinternitzOTS, allocator: Allocator, message: []const u8, private_key: [][]u8) ![][]u8 {
        const msg_hash = try self.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        var signature = try allocator.alloc([]u8, private_key.len);
        errdefer {
            for (signature) |sig| allocator.free(sig);
            allocator.free(signature);
        }

        for (private_key, 0..) |pk, i| {
            var current = try allocator.dupe(u8, pk);

            const iterations = if (i < encoded.len) encoded[i] else 0;
            for (0..iterations) |_| {
                const next = try self.hash.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            signature[i] = current;
        }

        return signature;
    }

    pub fn verify(self: *WinternitzOTS, allocator: Allocator, message: []const u8, signature: [][]u8, public_key: []const u8) !bool {
        const msg_hash = try self.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        const chain_len = self.getChainLength();
        const hash_output_len = self.params.hash_output_len;

        var public_parts = try allocator.alloc([]u8, signature.len);
        defer {
            for (public_parts) |part| allocator.free(part);
            allocator.free(public_parts);
        }

        for (signature, 0..) |sig, i| {
            var current = try allocator.dupe(u8, sig);

            const start_val = if (i < encoded.len) encoded[i] else 0;
            const remaining = chain_len - start_val;

            for (0..remaining) |_| {
                const next = try self.hash.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            public_parts[i] = current;
        }

        var combined = try allocator.alloc(u8, public_parts.len * hash_output_len);
        defer allocator.free(combined);

        for (public_parts, 0..) |part, i| {
            @memcpy(combined[i * hash_output_len ..][0..hash_output_len], part);
        }

        const derived_pk = try self.hash.hash(allocator, combined, 0);
        defer allocator.free(derived_pk);

        return std.mem.eql(u8, derived_pk, public_key);
    }
};
