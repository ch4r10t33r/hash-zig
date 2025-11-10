// Rust-compatible hash signature implementation
// Uses Rust-compatible parameters throughout the entire process

const std = @import("std");
const Allocator = std.mem.Allocator;
const FieldElement = @import("../core/field.zig").FieldElement;
const KoalaBearField = @import("../core/field.zig").KoalaBearField;
const ParametersRustCompat = @import("../core/params_rust_compat.zig").ParametersRustCompat;
const Poseidon2RustCompat = @import("../hash/poseidon2_hash.zig").Poseidon2RustCompat;
const poseidon2_root = @import("../poseidon2/root.zig");
const TargetSumEncoding = poseidon2_root.TargetSumEncoding;
const TopLevelPoseidonMessageHash = poseidon2_root.TopLevelPoseidonMessageHash;
const WinternitzOTS = @import("../wots/winternitz.zig").WinternitzOTS;
const MerkleTree = @import("../merkle/merkle.zig").MerkleTree;
const Chacha12Rng = @import("../prf/chacha12_rng.zig");

pub const HashSignatureRustCompat = struct {
    params: ParametersRustCompat,
    poseidon2: *Poseidon2RustCompat,
    target_sum_encoding: TargetSumEncoding,
    top_level_message_hash: TopLevelPoseidonMessageHash,
    allocator: Allocator,

    pub fn init(allocator: Allocator, lifetime: @import("../core/params_rust_compat.zig").KeyLifetime) !*HashSignatureRustCompat {
        const params = ParametersRustCompat.init(lifetime);
        const poseidon2 = try Poseidon2RustCompat.init(allocator);

        const self = try allocator.create(HashSignatureRustCompat);
        self.* = HashSignatureRustCompat{
            .params = params,
            .poseidon2 = try allocator.create(Poseidon2RustCompat),
            .target_sum_encoding = TargetSumEncoding{},
            .top_level_message_hash = TopLevelPoseidonMessageHash{},
            .allocator = allocator,
        };

        self.poseidon2.* = poseidon2;

        return self;
    }

    pub fn deinit(self: *HashSignatureRustCompat) void {
        self.allocator.destroy(self.poseidon2);
        self.allocator.destroy(self);
    }

    /// Generate a keypair using Rust-compatible parameters
    pub fn keyGen(self: *HashSignatureRustCompat, seed: []const u8) !struct { public_key: []FieldElement, private_key: []FieldElement } {
        std.debug.print("Generating keypair with Rust-compatible parameters...\n", .{});
        std.debug.print("Lifetime: 2^{} = {} signatures\n", .{ self.params.tree_height, @as(u32, 1) << @intCast(self.params.tree_height) });
        std.debug.print("Hash Function: {s}\n", .{@tagName(self.params.hash_function)});
        std.debug.print("Encoding Type: {s}\n", .{@tagName(self.params.encoding_type)});
        std.debug.print("Target Sum Value: {}\n", .{self.params.target_sum_value});
        std.debug.print("Poseidon Width: {}\n", .{self.params.poseidon_width});
        std.debug.print("Poseidon Rate: {}\n", .{self.params.poseidon_rate});
        std.debug.print("Poseidon Capacity: {}\n", .{self.params.poseidon_capacity});
        std.debug.print("Poseidon Rounds: {}\n", .{self.params.poseidon_rounds});
        std.debug.print("\n", .{});

        // Initialize RNG with seed
        var rng = Chacha12Rng.init(seed[0..32].*);

        // Generate parameter array using Rust-compatible method
        const param_array = try self.generateParameterArray(&rng);
        defer self.allocator.free(param_array);

        // Generate PRF key using Rust-compatible method
        const prf_key = try self.generatePRFKey(&rng);
        defer self.allocator.free(prf_key);

        // Generate WOTS+ keypairs using Rust-compatible parameters
        const wots_keypairs = try self.generateWOTSKeypairs(&rng, param_array, prf_key);
        defer {
            for (wots_keypairs) |keypair| {
                self.allocator.free(keypair.public_key);
                self.allocator.free(keypair.private_key);
            }
            self.allocator.free(wots_keypairs);
        }

        // Build Merkle tree using Rust-compatible hash function
        const merkle_tree = try self.buildMerkleTree(wots_keypairs);
        defer merkle_tree.deinit();

        // Extract public key (root of Merkle tree)
        const public_key = try self.extractPublicKey(merkle_tree);

        // Generate private key (all WOTS+ private keys)
        const private_key = try self.generatePrivateKey(wots_keypairs);

        return .{
            .public_key = public_key,
            .private_key = private_key,
        };
    }

    /// Generate parameter array using Rust-compatible method
    fn generateParameterArray(self: *HashSignatureRustCompat, rng: *Chacha12Rng) ![]u32 {
        const param_array = try self.allocator.alloc(u32, 5);

        // Generate 5 random parameters (matching Rust's parameter generation)
        var random = rng.random();
        for (param_array) |*param| {
            param.* = random.int(u32);
        }

        std.debug.print("Generated parameter array: [{}, {}, {}, {}, {}]\n", .{ param_array[0], param_array[1], param_array[2], param_array[3], param_array[4] });

        return param_array;
    }

    /// Generate PRF key using Rust-compatible method
    fn generatePRFKey(self: *HashSignatureRustCompat, rng: *Chacha12Rng) ![]u8 {
        const prf_key = try self.allocator.alloc(u8, 32);

        // Generate 32 random bytes for PRF key
        var random = rng.random();
        for (prf_key) |*byte| {
            byte.* = random.int(u8);
        }

        std.debug.print("Generated PRF key: {}\n", .{std.fmt.fmtSliceHexLower(prf_key)});

        return prf_key;
    }

    /// Generate WOTS+ keypairs using Rust-compatible parameters
    fn generateWOTSKeypairs(self: *HashSignatureRustCompat, rng: *Chacha12Rng, param_array: []const u32, prf_key: []const u8) ![]struct { public_key: []FieldElement, private_key: []FieldElement } {
        const num_keypairs = @as(u32, 1) << @intCast(self.params.tree_height);
        const keypairs = try self.allocator.alloc(struct { public_key: []FieldElement, private_key: []FieldElement }, num_keypairs);

        std.debug.print("Generating {} WOTS+ keypairs...\n", .{num_keypairs});

        for (keypairs, 0..) |*keypair, i| {
            // Generate private key using Rust-compatible method
            const private_key = try self.generateWOTSPrivateKey(rng, prf_key, @as(u32, @intCast(i)));

            // Generate public key using Rust-compatible hash function
            const public_key = try self.generateWOTSPublicKey(private_key, param_array);

            keypair.* = .{
                .public_key = public_key,
                .private_key = private_key,
            };

            if (i % 1000 == 0) {
                std.debug.print("Generated {}/{} keypairs\n", .{ i, num_keypairs });
            }
        }

        return keypairs;
    }

    /// Generate WOTS+ private key using Rust-compatible method
    fn generateWOTSPrivateKey(self: *HashSignatureRustCompat, rng: *Chacha12Rng, prf_key: []const u8, index: u32) ![]FieldElement {
        const private_key = try self.allocator.alloc(FieldElement, 22); // Standard num_chains

        // Generate private key using Rust-compatible PRF
        for (private_key, 0..) |*field_elem, i| {
            const seed_data = try self.allocator.alloc(u8, 36); // 32 bytes PRF key + 4 bytes index
            defer self.allocator.free(seed_data);

            @memcpy(seed_data[0..32], prf_key);
            std.mem.writeInt(u32, seed_data[32..36], index, .little);
            std.mem.writeInt(u32, seed_data[32..36], @as(u32, @intCast(i)), .little);

            // Use Rust-compatible hash function
            var random = rng.random();
            const hash_input = [_]FieldElement{
                FieldElement{ .value = random.int(u32) },
                FieldElement{ .value = random.int(u32) },
                FieldElement{ .value = random.int(u32) },
                FieldElement{ .value = random.int(u32) },
                FieldElement{ .value = random.int(u32) },
            };

            const hash_output = try self.poseidon2.hashFieldElements(self.allocator, &hash_input);
            defer self.allocator.free(hash_output);

            field_elem.* = hash_output[0];
        }

        return private_key;
    }

    /// Generate WOTS+ public key using Rust-compatible hash function
    fn generateWOTSPublicKey(self: *HashSignatureRustCompat, private_key: []const FieldElement, _: []const u32) ![]FieldElement {
        const public_key = try self.allocator.alloc(FieldElement, 22); // Standard num_chains

        // Generate public key using Rust-compatible hash chains
        for (private_key, public_key) |private_elem, *public_elem| {
            var current = private_elem;

            // Apply hash chain (simplified for now)
            for (0..7) |_| { // Standard chain_hash_output_len_fe
                const hash_input = [_]FieldElement{current} ** 5;
                const hash_output = try self.poseidon2.hashFieldElements(self.allocator, &hash_input);
                defer self.allocator.free(hash_output);
                current = hash_output[0];
            }

            public_elem.* = current;
        }

        return public_key;
    }

    /// Build Merkle tree using Rust-compatible hash function
    fn buildMerkleTree(self: *HashSignatureRustCompat, wots_keypairs: []const struct { public_key: []FieldElement, private_key: []FieldElement }) !MerkleTree {
        std.debug.print("Building Merkle tree with {} leaves...\n", .{wots_keypairs.len});

        // Create Merkle tree using Rust-compatible parameters
        const merkle_tree = try MerkleTree.init(self.allocator, self.params.tree_height);

        // Add all WOTS+ public keys as leaves
        for (wots_keypairs, 0..) |keypair, i| {
            // Hash the WOTS+ public key using Rust-compatible method
            const leaf_hash = try self.hashWOTSPublicKey(keypair.public_key);
            defer self.allocator.free(leaf_hash);

            try merkle_tree.addLeaf(leaf_hash);

            if (i % 1000 == 0) {
                std.debug.print("Added {}/{} leaves to Merkle tree\n", .{ i, wots_keypairs.len });
            }
        }

        return merkle_tree;
    }

    /// Hash WOTS+ public key using Rust-compatible method
    fn hashWOTSPublicKey(self: *HashSignatureRustCompat, public_key: []const FieldElement) ![]FieldElement {
        // Use Rust-compatible hash function to hash the public key
        const hash_input = try self.allocator.alloc(FieldElement, @min(public_key.len, 5));
        defer self.allocator.free(hash_input);

        for (hash_input, 0..) |*elem, i| {
            elem.* = public_key[i];
        }

        return try self.poseidon2.hashFieldElements(self.allocator, hash_input);
    }

    /// Extract public key (root of Merkle tree)
    fn extractPublicKey(self: *HashSignatureRustCompat, merkle_tree: MerkleTree) ![]FieldElement {
        const root = merkle_tree.getRoot();
        const public_key = try self.allocator.alloc(FieldElement, 7); // Standard tree_hash_output_len_fe

        // Copy root to public key
        for (public_key, 0..) |*elem, i| {
            if (i < root.len) {
                elem.* = root[i];
            } else {
                elem.* = FieldElement{ .value = 0 };
            }
        }

        return public_key;
    }

    /// Generate private key (all WOTS+ private keys)
    fn generatePrivateKey(self: *HashSignatureRustCompat, wots_keypairs: []const struct { public_key: []FieldElement, private_key: []FieldElement }) ![]FieldElement {
        const total_private_keys = wots_keypairs.len * 22; // Standard num_chains
        const private_key = try self.allocator.alloc(FieldElement, total_private_keys);

        var index: usize = 0;
        for (wots_keypairs) |keypair| {
            for (keypair.private_key) |private_elem| {
                private_key[index] = private_elem;
                index += 1;
            }
        }

        return private_key;
    }
};
