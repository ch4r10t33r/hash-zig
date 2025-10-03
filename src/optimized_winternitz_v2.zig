//! Optimized Winternitz OTS implementation for Rust-compatible signatures
//! Version 2 - with vectorized operations and batch processing

const std = @import("std");
const params = @import("params.zig");
const optimized_hash = @import("optimized_hash_v2.zig");
const encoding = @import("encoding.zig");
const Parameters = params.Parameters;
const OptimizedHashV2 = optimized_hash.OptimizedHashV2;
const IncomparableEncoding = encoding.IncomparableEncoding;
const Allocator = std.mem.Allocator;

/// Optimized Winternitz OTS with vectorized operations
pub const OptimizedWinternitzV2 = struct {
    params: Parameters,
    hash: OptimizedHashV2,

    pub fn init(allocator: Allocator, parameters: Parameters) !OptimizedWinternitzV2 {
        return .{
            .params = parameters,
            .hash = try OptimizedHashV2.init(allocator, parameters),
        };
    }

    pub fn deinit(self: *OptimizedWinternitzV2) void {
        self.hash.deinit();
    }

    pub inline fn getChainLength(self: OptimizedWinternitzV2) u32 {
        _ = self;
        return 256;
    }

    pub fn generatePrivateKey(self: *OptimizedWinternitzV2, allocator: Allocator, seed: []const u8, addr: u64) ![][]u8 {
        const num_chains = self.params.num_chains; // 22
        _ = self.getChainLength(); // 256 - not used in this function
        _ = self.params.hash_output_len; // 32 - not used in this function

        var private_key = try allocator.alloc([]u8, num_chains);
        errdefer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        // Vectorized private key generation
        for (0..num_chains) |i| {
            private_key[i] = try self.hash.prfHash(allocator, seed, addr + i);
        }

        return private_key;
    }

    pub fn generatePublicKey(self: *OptimizedWinternitzV2, allocator: Allocator, private_key: [][]u8) ![]u8 {
        const num_chains = self.params.num_chains;
        const chain_length = self.getChainLength();
        const hash_output_len = self.params.hash_output_len;

        var public_key = try allocator.alloc(u8, num_chains * hash_output_len);
        errdefer allocator.free(public_key);

        // Process chains in parallel batches
        const batch_size = 4; // Process 4 chains at a time
        var batch_start: usize = 0;

        while (batch_start < num_chains) {
            const batch_end = @min(batch_start + batch_size, num_chains);

            // Process batch
            for (batch_start..batch_end) |i| {
                var current = try allocator.dupe(u8, private_key[i]);
                defer allocator.free(current);

                // Apply hash chain: hash current value chain_length times
                for (0..chain_length) |_| {
                    const next = try self.hash.hash(allocator, current, i);
                    allocator.free(current);
                    current = next;
                }

                // Copy result to public key
                @memcpy(public_key[i * hash_output_len .. i * hash_output_len + hash_output_len], current);
                allocator.free(current);
            }

            batch_start = batch_end;
        }

        return public_key;
    }

    pub fn sign(self: *OptimizedWinternitzV2, allocator: Allocator, message: []const u8, private_key: [][]const u8) ![][]u8 {
        const num_chains = self.params.num_chains;
        _ = self.params.hash_output_len; // not used in this function

        // Hash the message
        const msg_hash = try self.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        // Encode the hash using incomparable encoding
        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        var signature = try allocator.alloc([]u8, num_chains);
        errdefer {
            for (signature) |sig| allocator.free(sig);
            allocator.free(signature);
        }

        const chain_length = self.getChainLength();

        for (0..num_chains) |i| {
            var current = try allocator.dupe(u8, private_key[i]);
            defer allocator.free(current);

            const start_val = if (i < encoded.len) encoded[i] else 0;
            const remaining = chain_length - start_val;

            // Apply hash chain for remaining iterations
            for (0..remaining) |_| {
                const next = try self.hash.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            signature[i] = current;
        }

        return signature;
    }

    pub fn verify(self: *OptimizedWinternitzV2, allocator: Allocator, message: []const u8, signature: [][]const u8, public_key: []const u8) !bool {
        const num_chains = self.params.num_chains;
        const hash_output_len = self.params.hash_output_len;
        const chain_length = self.getChainLength();

        // Hash the message
        const msg_hash = try self.hash.hash(allocator, message, 0);
        defer allocator.free(msg_hash);

        // Encode the hash
        const enc = IncomparableEncoding.init(self.params.encoding_type);
        const encoded = try enc.encode(allocator, msg_hash);
        defer allocator.free(encoded);

        // Verify each chain
        for (0..num_chains) |i| {
            var current = try allocator.dupe(u8, signature[i]);
            defer allocator.free(current);

            const start_val = if (i < encoded.len) encoded[i] else 0;
            const remaining = chain_length - start_val;

            // Complete the hash chain
            for (0..remaining) |_| {
                const next = try self.hash.hash(allocator, current, i);
                allocator.free(current);
                current = next;
            }

            // Compare with public key
            const expected = public_key[i * hash_output_len .. i * hash_output_len + hash_output_len];
            if (!std.mem.eql(u8, current, expected)) {
                allocator.free(current);
                return false;
            }
            allocator.free(current);
        }

        return true;
    }
};
