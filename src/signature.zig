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
        // XMSS verification requires:
        // 1. Compute the OTS leaf public key from the signature
        // 2. Use the authentication path to compute the Merkle root
        // 3. Compare computed root with the provided public_key (expected root)
        //
        // This is a SIMPLIFIED implementation for demonstration
        // Authentication paths are not yet implemented
        // TODO: Implement full Merkle authentication path verification

        // Verify the OTS signature by deriving the leaf public key
        // and checking it's valid (without full Merkle path verification)
        return self.wots.verify(allocator, message, signature.ots_signature, public_key);
    }
};
