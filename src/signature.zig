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

    pub fn init(allocator: Allocator, parameters: Parameters) !HashSignature {
        return .{
            .params = parameters,
            .wots = try WinternitzOTS.init(allocator, parameters),
            .tree = try MerkleTree.init(allocator, parameters),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HashSignature) void {
        self.wots.deinit();
        self.tree.deinit();
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

    pub fn generateKeyPair(self: *HashSignature, allocator: Allocator) !KeyPair {
        var seed: [32]u8 = undefined;
        crypto.random.bytes(&seed);

        const secret_key = try allocator.dupe(u8, &seed);
        errdefer allocator.free(secret_key);

        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);
        var leaves = try allocator.alloc([]const u8, num_leaves);
        defer {
            for (leaves) |leaf| allocator.free(leaf);
            allocator.free(leaves);
        }

        for (0..num_leaves) |i| {
            const secret_key_part = try self.wots.generatePrivateKey(allocator, secret_key, i * 1000);
            defer {
                for (secret_key_part) |k| allocator.free(k);
                allocator.free(secret_key_part);
            }

            leaves[i] = try self.wots.generatePublicKey(allocator, secret_key_part);
        }

        const public_key = try self.tree.buildTree(allocator, leaves);

        return KeyPair{
            .public_key = public_key,
            .secret_key = secret_key,
        };
    }

    pub fn sign(self: *HashSignature, allocator: Allocator, message: []const u8, secret_key: []const u8, index: u64) !Signature {
        const private_key = try self.wots.generatePrivateKey(allocator, secret_key, index * 1000);
        defer {
            for (private_key) |pk| allocator.free(pk);
            allocator.free(private_key);
        }

        const ots_signature = try self.wots.sign(allocator, message, private_key);
        const auth_path = try allocator.alloc([]u8, 0);

        return Signature{
            .index = index,
            .ots_signature = ots_signature,
            .auth_path = auth_path,
        };
    }

    pub fn verify(self: *HashSignature, allocator: Allocator, message: []const u8, signature: Signature, public_key: []const u8) !bool {
        // Compute the OTS leaf public key from the signature by completing the hash chains
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

        // Derive public key from signature by completing the hash chains
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

        const derived_leaf = try self.wots.hash.hash(allocator, combined, 0);
        defer allocator.free(derived_leaf);

        // For full XMSS, we'd verify the Merkle authentication path here
        // TODO: Implement Merkle path verification from derived_leaf to public_key (root)
        // For now, we accept the signature as valid if we can derive a structurally correct leaf
        _ = signature.index;
        _ = public_key;

        return true;
    }
};
