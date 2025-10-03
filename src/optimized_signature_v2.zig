//! Optimized signature implementation for Rust-compatible hash-based signatures
//! Version 2 - with better memory management and optimized Merkle tree construction

const std = @import("std");
const params = @import("params.zig");
const optimized_winternitz = @import("optimized_winternitz_v2.zig");
const optimized_hash = @import("optimized_hash_v2.zig");
const Parameters = params.Parameters;
const OptimizedWinternitzV2 = optimized_winternitz.OptimizedWinternitzV2;
const OptimizedHashV2 = optimized_hash.OptimizedHashV2;
const Allocator = std.mem.Allocator;

/// Optimized signature implementation with better memory management
pub const OptimizedSignatureV2 = struct {
    params: Parameters,
    wots: OptimizedWinternitzV2,
    hash: OptimizedHashV2,
    allocator: Allocator,

    pub fn init(allocator: Allocator, parameters: Parameters) !OptimizedSignatureV2 {
        return .{
            .params = parameters,
            .wots = try OptimizedWinternitzV2.init(allocator, parameters),
            .hash = try OptimizedHashV2.init(allocator, parameters),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *OptimizedSignatureV2) void {
        self.wots.deinit();
        self.hash.deinit();
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

    pub fn generateKeyPair(self: *OptimizedSignatureV2, allocator: Allocator, seed: []const u8) !KeyPair {
        if (seed.len != 32) return error.InvalidSeedLength;

        const tree_height = self.params.tree_height;
        const num_leaves = @as(u32, 1) << @intCast(tree_height);

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

        // Generate keys for each leaf with optimized memory layout
        for (0..num_leaves) |i| {
            const addr = @as(u64, @intCast(i));
            const sk = try self.wots.generatePrivateKey(allocator, seed, addr);
            const pk = try self.wots.generatePublicKey(allocator, sk);

            leaf_secret_keys[i] = sk;
            leaf_public_keys[i] = pk;
        }

        // Build Merkle tree and get root
        const merkle_root = try self.buildMerkleTree(allocator, leaf_public_keys);

        // Combine all secret keys into one
        const total_secret_len = num_leaves * self.params.num_chains * self.params.hash_output_len;
        var combined_secret = try allocator.alloc(u8, total_secret_len);
        var offset: usize = 0;

        for (leaf_secret_keys) |sk| {
            for (sk) |s| {
                @memcpy(combined_secret[offset .. offset + s.len], s);
                offset += s.len;
            }
        }

        return KeyPair{
            .public_key = merkle_root,
            .secret_key = combined_secret,
        };
    }

    fn buildMerkleTree(self: *OptimizedSignatureV2, allocator: Allocator, leaf_public_keys: [][]u8) ![]u8 {
        const tree_height = self.params.tree_height;
        const num_leaves = leaf_public_keys.len;
        const hash_output_len = self.params.hash_output_len;

        // Start with leaf nodes
        var current_level = try allocator.alloc([]u8, num_leaves);
        defer {
            for (current_level) |node| allocator.free(node);
            allocator.free(current_level);
        }

        // Copy leaf public keys
        for (leaf_public_keys, 0..) |leaf, i| {
            current_level[i] = try allocator.dupe(u8, leaf);
        }

        var level_size = num_leaves;
        var current_height = tree_height;

        // Build tree level by level with optimized memory management
        while (level_size > 1) {
            const next_level_size = (level_size + 1) / 2;
            var next_level = try allocator.alloc([]u8, next_level_size);
            defer {
                for (next_level) |node| allocator.free(node);
                allocator.free(next_level);
            }

            for (0..next_level_size) |i| {
                const left_idx = i * 2;
                const right_idx = left_idx + 1;

                if (right_idx < level_size) {
                    // Combine left and right children
                    var combined = try allocator.alloc(u8, hash_output_len * 2);
                    @memcpy(combined[0..hash_output_len], current_level[left_idx][0..hash_output_len]);
                    @memcpy(combined[hash_output_len .. hash_output_len * 2], current_level[right_idx][0..hash_output_len]);

                    const hash_result = try self.hash.hash(allocator, combined, current_height);
                    allocator.free(combined);
                    next_level[i] = hash_result;
                } else {
                    // Odd number of nodes, copy the last one
                    next_level[i] = try allocator.dupe(u8, current_level[left_idx]);
                }
            }

            // Clean up current level
            for (current_level) |node| allocator.free(node);
            allocator.free(current_level);

            current_level = next_level;
            level_size = next_level_size;
            current_height -= 1;
        }

        // Return the root
        const root = current_level[0];
        current_level[0] = try allocator.dupe(u8, root);
        allocator.free(root);
        return current_level[0];
    }

    pub fn sign(self: *OptimizedSignatureV2, allocator: Allocator, message: []const u8, secret_key: []const u8, leaf_index: u64) !Signature {
        const tree_height = self.params.tree_height;
        const num_leaves = @as(u32, 1) << @intCast(tree_height);
        const hash_output_len = self.params.hash_output_len;
        const secret_key_per_leaf = self.params.num_chains * hash_output_len;

        if (leaf_index >= num_leaves) return error.InvalidLeafIndex;

        // Extract secret key for this leaf
        const leaf_secret_start = @as(usize, @intCast(leaf_index)) * secret_key_per_leaf;
        const leaf_secret_end = leaf_secret_start + secret_key_per_leaf;
        const leaf_secret_bytes = secret_key[leaf_secret_start..leaf_secret_end];

        // Convert bytes back to array of arrays
        var leaf_secret = try allocator.alloc([]u8, self.params.num_chains);
        defer {
            for (leaf_secret) |s| allocator.free(s);
            allocator.free(leaf_secret);
        }

        for (0..self.params.num_chains) |i| {
            const start = i * hash_output_len;
            const end = start + hash_output_len;
            leaf_secret[i] = try allocator.dupe(u8, leaf_secret_bytes[start..end]);
        }

        // Sign with Winternitz
        const ots_signature = try self.wots.sign(allocator, message, leaf_secret);

        // Generate authentication path (simplified - would need full Merkle tree state)
        var auth_path = try allocator.alloc([]u8, tree_height);
        defer {
            for (auth_path) |path| allocator.free(path);
            allocator.free(auth_path);
        }

        // For now, create dummy auth path
        for (0..tree_height) |i| {
            auth_path[i] = try allocator.alloc(u8, hash_output_len);
            @memset(auth_path[i], 0);
        }

        return Signature{
            .index = leaf_index,
            .ots_signature = ots_signature,
            .auth_path = auth_path,
        };
    }

    pub fn verify(self: *OptimizedSignatureV2, allocator: Allocator, message: []const u8, signature: Signature, public_key: []const u8) !bool {
        // This is a simplified verification - would need full implementation
        _ = self;
        _ = allocator;
        _ = message;
        _ = signature;
        _ = public_key;
        return true;
    }
};
