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

        // Generate all leaves to create the authentication path
        const num_leaves = @as(usize, 1) << @intCast(self.params.tree_height);
        var leaves = try allocator.alloc([]const u8, num_leaves);
        defer {
            for (leaves) |leaf| allocator.free(leaf);
            allocator.free(leaves);
        }

        for (0..num_leaves) |i| {
            const sk_part = try self.wots.generatePrivateKey(allocator, secret_key, i * 1000);
            defer {
                for (sk_part) |k| allocator.free(k);
                allocator.free(sk_part);
            }
            leaves[i] = try self.wots.generatePublicKey(allocator, sk_part);
        }

        // Generate authentication path for this leaf index
        const auth_path = try self.tree.generateAuthPath(allocator, leaves, @intCast(index));

        return Signature{
            .index = index,
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
            const parent = try self.wots.hash.hash(allocator, combined_nodes, level);
            allocator.free(current_hash);
            current_hash = parent;

            // Move to parent index
            leaf_idx = leaf_idx / 2;
        }

        // Step 3: Compare computed root with provided public_key
        const roots_match = std.mem.eql(u8, current_hash, public_key);

        return roots_match;
    }
};
