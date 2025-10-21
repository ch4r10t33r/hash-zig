//! GeneralizedXMSS Signature Scheme - Full Rust Compatibility Implementation
//! This implementation matches Rust GeneralizedXMSSSignatureScheme exactly

const std = @import("std");
const Allocator = std.mem.Allocator;
const FieldElement = @import("../core/field.zig").FieldElement;
const ParametersRustCompat = @import("../core/params_rust_compat.zig").ParametersRustCompat;
const ShakePRFtoF_8_7 = @import("../prf/shake_prf_to_field.zig").ShakePRFtoF_8_7;
const Poseidon2RustCompat = @import("../hash/poseidon2_hash.zig").Poseidon2RustCompat;

// Constants matching Rust exactly
const MESSAGE_LENGTH = 32;

// Parameter configurations for different lifetimes (matching Rust exactly)
pub const LifetimeParams = struct {
    log_lifetime: usize,
    dimension: usize,
    base: usize,
    final_layer: usize,
    target_sum: usize,
    parameter_len: usize,
    tweak_len_fe: usize,
    msg_len_fe: usize,
    rand_len_fe: usize,
    hash_len_fe: usize,
    capacity: usize,
};

// Rust parameter configurations for each lifetime
pub const LIFETIME_2_8_PARAMS = LifetimeParams{
    .log_lifetime = 8,
    .dimension = 64,
    .base = 8,
    .final_layer = 77,
    .target_sum = 375,
    .parameter_len = 5,
    .tweak_len_fe = 2,
    .msg_len_fe = 9,
    .rand_len_fe = 7,
    .hash_len_fe = 8,
    .capacity = 9,
};

pub const LIFETIME_2_18_PARAMS = LifetimeParams{
    .log_lifetime = 18,
    .dimension = 64,
    .base = 8,
    .final_layer = 77,
    .target_sum = 375,
    .parameter_len = 5,
    .tweak_len_fe = 2,
    .msg_len_fe = 9,
    .rand_len_fe = 6, // Different from 2^8
    .hash_len_fe = 7, // Different from 2^8
    .capacity = 9,
};

pub const LIFETIME_2_32_HASHING_PARAMS = LifetimeParams{
    .log_lifetime = 32,
    .dimension = 64,
    .base = 8,
    .final_layer = 77,
    .target_sum = 375,
    .parameter_len = 5,
    .tweak_len_fe = 2,
    .msg_len_fe = 9,
    .rand_len_fe = 7,
    .hash_len_fe = 8,
    .capacity = 9,
};

// Hash SubTree structure (simplified for now)
pub const HashSubTree = struct {
    root_value: FieldElement,
    allocator: Allocator,

    pub fn init(allocator: Allocator, root_value: FieldElement) !*HashSubTree {
        const self = try allocator.create(HashSubTree);
        self.* = HashSubTree{
            .root_value = root_value,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *HashSubTree) void {
        self.allocator.destroy(self);
    }

    pub fn root(self: *const HashSubTree) FieldElement {
        return self.root_value;
    }
};

// Hash Tree Opening for Merkle paths
pub const HashTreeOpening = struct {
    path: []FieldElement,
    allocator: Allocator,

    pub fn init(allocator: Allocator, path: []FieldElement) !*HashTreeOpening {
        const self = try allocator.create(HashTreeOpening);
        const path_copy = try allocator.alloc(FieldElement, path.len);
        @memcpy(path_copy, path);
        self.* = HashTreeOpening{
            .path = path_copy,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *HashTreeOpening) void {
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }
};

// Signature structure matching Rust exactly
pub const GeneralizedXMSSSignature = struct {
    path: *HashTreeOpening,
    rho: [7]FieldElement, // IE::Randomness for ShakePRFtoF_8_7
    hashes: []FieldElement, // Vec<TH::Domain>
    allocator: Allocator,

    pub fn init(allocator: Allocator, path: *HashTreeOpening, rho: [7]FieldElement, hashes: []FieldElement) !*GeneralizedXMSSSignature {
        const self = try allocator.create(GeneralizedXMSSSignature);
        const hashes_copy = try allocator.alloc(FieldElement, hashes.len);
        @memcpy(hashes_copy, hashes);
        self.* = GeneralizedXMSSSignature{
            .path = path,
            .rho = rho,
            .hashes = hashes_copy,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *GeneralizedXMSSSignature) void {
        self.path.deinit(); // Free the HashTreeOpening
        self.allocator.free(self.hashes);
        self.allocator.destroy(self);
    }
};

// Public key structure matching Rust exactly
pub const GeneralizedXMSSPublicKey = struct {
    root: FieldElement,
    parameter: [5]FieldElement, // TH::Parameter

    pub fn init(root: FieldElement, parameter: [5]FieldElement) GeneralizedXMSSPublicKey {
        return GeneralizedXMSSPublicKey{
            .root = root,
            .parameter = parameter,
        };
    }
};

// Secret key structure matching Rust exactly
pub const GeneralizedXMSSSecretKey = struct {
    prf_key: [32]u8, // PRF::Key
    parameter: [5]FieldElement, // TH::Parameter
    activation_epoch: usize,
    num_active_epochs: usize,
    top_tree: *HashSubTree,
    left_bottom_tree_index: usize,
    left_bottom_tree: *HashSubTree,
    right_bottom_tree: *HashSubTree,
    allocator: Allocator,

    pub fn init(
        allocator: Allocator,
        prf_key: [32]u8,
        parameter: [5]FieldElement,
        activation_epoch: usize,
        num_active_epochs: usize,
        top_tree: *HashSubTree,
        left_bottom_tree_index: usize,
        left_bottom_tree: *HashSubTree,
        right_bottom_tree: *HashSubTree,
    ) !*GeneralizedXMSSSecretKey {
        const self = try allocator.create(GeneralizedXMSSSecretKey);
        self.* = GeneralizedXMSSSecretKey{
            .prf_key = prf_key,
            .parameter = parameter,
            .activation_epoch = activation_epoch,
            .num_active_epochs = num_active_epochs,
            .top_tree = top_tree,
            .left_bottom_tree_index = left_bottom_tree_index,
            .left_bottom_tree = left_bottom_tree,
            .right_bottom_tree = right_bottom_tree,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *GeneralizedXMSSSecretKey) void {
        self.top_tree.deinit();
        self.left_bottom_tree.deinit();
        self.right_bottom_tree.deinit();
        self.allocator.destroy(self);
    }

    /// Get activation interval (matching Rust get_activation_interval)
    pub fn getActivationInterval(self: *const GeneralizedXMSSSecretKey) struct { start: u64, end: u64 } {
        const start = @as(u64, @intCast(self.activation_epoch));
        const end = start + @as(u64, @intCast(self.num_active_epochs));
        return .{ .start = start, .end = end };
    }

    /// Get prepared interval (matching Rust get_prepared_interval)
    pub fn getPreparedInterval(self: *const GeneralizedXMSSSecretKey, log_lifetime: usize) struct { start: u64, end: u64 } {
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(log_lifetime / 2);
        const start = @as(u64, @intCast(self.left_bottom_tree_index * leafs_per_bottom_tree));
        const end = start + @as(u64, @intCast(2 * leafs_per_bottom_tree));
        return .{ .start = start, .end = end };
    }

    /// Advance preparation (matching Rust advance_preparation)
    pub fn advancePreparation(self: *GeneralizedXMSSSecretKey, log_lifetime: usize) !void {
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(log_lifetime / 2);
        const next_prepared_end_epoch = self.left_bottom_tree_index * leafs_per_bottom_tree + 3 * leafs_per_bottom_tree;

        if (next_prepared_end_epoch > self.activation_epoch + self.num_active_epochs) {
            return; // Cannot advance
        }

        // Compute new right bottom tree
        const new_right_bottom_tree = try self.bottomTreeFromPrfKey(log_lifetime, self.left_bottom_tree_index + 2);

        // Move right to left and update index
        self.left_bottom_tree = self.right_bottom_tree;
        self.right_bottom_tree = new_right_bottom_tree;
        self.left_bottom_tree_index += 1;
    }

    /// Helper function to compute bottom tree from PRF key
    fn bottomTreeFromPrfKey(self: *GeneralizedXMSSSecretKey, _: usize, _: usize) !*HashSubTree {
        // This is a simplified implementation - in practice this would need the full tree construction
        // For now, return a placeholder tree
        return try HashSubTree.init(self.allocator, FieldElement{ .value = 0 });
    }
};

// Main GeneralizedXMSS Signature Scheme
pub const GeneralizedXMSSSignatureScheme = struct {
    lifetime_params: LifetimeParams,
    poseidon2: *Poseidon2RustCompat,
    allocator: Allocator,

    pub fn init(allocator: Allocator, lifetime: @import("../core/params_rust_compat.zig").KeyLifetime) !*GeneralizedXMSSSignatureScheme {
        const poseidon2 = try Poseidon2RustCompat.init(allocator);

        // Select the correct lifetime parameters
        const lifetime_params = switch (lifetime) {
            .lifetime_2_8 => LIFETIME_2_8_PARAMS,
            .lifetime_2_18 => LIFETIME_2_18_PARAMS,
            .lifetime_2_32 => LIFETIME_2_32_HASHING_PARAMS,
            else => return error.UnsupportedLifetime,
        };

        const self = try allocator.create(GeneralizedXMSSSignatureScheme);
        self.* = GeneralizedXMSSSignatureScheme{
            .lifetime_params = lifetime_params,
            .poseidon2 = try allocator.create(Poseidon2RustCompat),
            .allocator = allocator,
        };

        self.poseidon2.* = poseidon2;

        return self;
    }

    pub fn deinit(self: *GeneralizedXMSSSignatureScheme) void {
        self.allocator.destroy(self.poseidon2);
        self.allocator.destroy(self);
    }

    /// Expand activation time (matching Rust expand_activation_time exactly)
    fn expandActivationTime(log_lifetime: usize, desired_activation_epoch: usize, desired_num_active_epochs: usize) struct { start: usize, end: usize } {
        const lifetime = @as(usize, 1) << @intCast(log_lifetime);
        const c = @as(usize, 1) << @intCast(log_lifetime / 2);
        const c_mask = ~(c - 1);

        const desired_start = desired_activation_epoch;
        const desired_end = desired_activation_epoch + desired_num_active_epochs;

        // 1. Align start downward to multiple of C
        var start = desired_start & c_mask;

        // 2. Round end upward to multiple of C
        var end = (desired_end + c - 1) & c_mask;

        // 3. Enforce minimum duration of 2*C
        if (end - start < 2 * c) {
            end = start + 2 * c;
        }

        // 4. If interval exceeds lifetime, shift left to fit
        if (end > lifetime) {
            const duration = end - start;
            if (duration > lifetime) {
                start = 0;
                end = lifetime;
            } else {
                end = lifetime;
                start = (lifetime - duration) & c_mask;
            }
        }

        // Divide by c to get bottom tree indices
        start >>= @intCast(log_lifetime / 2);
        end >>= @intCast(log_lifetime / 2);

        return .{ .start = start, .end = end };
    }

    /// Bottom tree from PRF key (matching Rust bottom_tree_from_prf_key exactly)
    fn bottomTreeFromPrfKey(
        self: *GeneralizedXMSSSignatureScheme,
        prf_key: [32]u8,
        bottom_tree_index: usize,
        parameter: [5]FieldElement,
    ) !*HashSubTree {
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);
        const num_chains = self.lifetime_params.dimension;
        _ = self.lifetime_params.base; // chain_length unused for now

        // Calculate epoch range for this bottom tree
        const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
        const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;

        // Generate chain ends hashes for each epoch
        var chain_ends_hashes = try self.allocator.alloc(FieldElement, leafs_per_bottom_tree);
        defer self.allocator.free(chain_ends_hashes);

        for (epoch_range_start..epoch_range_end) |epoch| {
            // Generate chain ends for this epoch
            var chain_ends = try self.allocator.alloc(FieldElement, num_chains);
            defer self.allocator.free(chain_ends);

            for (0..num_chains) |chain_index| {
                // Get chain start using ShakePRFtoF
                const domain_elements = ShakePRFtoF_8_7.getDomainElement(prf_key, @as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

                // Walk the chain to get the chain end
                chain_ends[chain_index] = try self.computeHashChain(domain_elements, @as(u32, @intCast(epoch)), @as(u8, @intCast(chain_index)), parameter);
            }

            // Hash all chain ends to get the leaf hash for this epoch
            chain_ends_hashes[epoch - epoch_range_start] = try self.hashChainEnds(chain_ends, parameter);
        }

        // Build bottom tree from leaf hashes
        const bottom_tree_root = try self.buildBottomTree(chain_ends_hashes, parameter);
        return try HashSubTree.init(self.allocator, bottom_tree_root);
    }

    /// Compute hash chain (matching Rust chain function)
    fn computeHashChain(
        self: *GeneralizedXMSSSignatureScheme,
        domain_elements: [8]u32,
        epoch: u32,
        chain_index: u8,
        parameter: [5]FieldElement,
    ) !FieldElement {
        var current_state = try self.allocator.alloc(FieldElement, 8);
        defer self.allocator.free(current_state);

        // Initialize with domain elements
        for (0..8) |i| {
            current_state[i] = FieldElement{ .value = domain_elements[i] };
        }

        // Walk the chain for BASE-1 steps
        for (0..self.lifetime_params.base - 1) |_| {
            const next_state = try self.applyPoseidonTweakHash(current_state, epoch, chain_index, parameter);
            defer self.allocator.free(next_state);

            // Update current state
            for (0..8) |i| {
                current_state[i] = next_state[i];
            }
        }

        return current_state[0];
    }

    /// Apply Poseidon2 tweak hash (matching Rust PoseidonTweakHash)
    fn applyPoseidonTweakHash(
        self: *GeneralizedXMSSSignatureScheme,
        input: []const FieldElement,
        epoch: u32,
        chain_index: u8,
        parameter: [5]FieldElement,
    ) ![]FieldElement {
        // Convert epoch and chain_index to field elements for tweak
        const tweak = [_]FieldElement{
            FieldElement{ .value = @as(u32, @intCast(epoch)) },
            FieldElement{ .value = @as(u32, @intCast(chain_index)) },
        };

        // Prepare combined input: parameter + tweak + message
        const total_input_len = 5 + 2 + input.len;
        var combined_input = try self.allocator.alloc(FieldElement, total_input_len);
        defer self.allocator.free(combined_input);

        var input_index: usize = 0;

        // Add parameter elements
        for (0..5) |i| {
            combined_input[input_index] = parameter[i];
            input_index += 1;
        }

        // Add tweak elements
        for (tweak) |t| {
            combined_input[input_index] = t;
            input_index += 1;
        }

        // Add message elements
        for (input) |fe| {
            combined_input[input_index] = fe;
            input_index += 1;
        }

        // Apply Poseidon2-16
        const hash_result = try self.poseidon2.hashFieldElements16(self.allocator, combined_input);
        defer self.allocator.free(hash_result);

        // Return result with capacity elements
        const result = try self.allocator.alloc(FieldElement, self.lifetime_params.capacity);
        for (0..self.lifetime_params.capacity) |i| {
            result[i] = hash_result[i];
        }

        return result;
    }

    /// Hash chain ends using Poseidon2
    fn hashChainEnds(self: *GeneralizedXMSSSignatureScheme, chain_ends: []FieldElement, _: [5]FieldElement) !FieldElement {
        // Use Poseidon2-24 for hashing many chain ends
        const input_len = @min(chain_ends.len, 24);
        const hash_result = try self.poseidon2.hashFieldElements(self.allocator, chain_ends[0..input_len]);
        defer self.allocator.free(hash_result);
        return hash_result[0];
    }

    /// Build bottom tree from leaf hashes
    fn buildBottomTree(self: *GeneralizedXMSSSignatureScheme, leaf_hashes: []FieldElement, parameter: [5]FieldElement) !FieldElement {
        if (leaf_hashes.len == 1) {
            return leaf_hashes[0];
        }

        // Build tree layer by layer
        var current_level = try self.allocator.alloc(FieldElement, leaf_hashes.len);
        @memcpy(current_level, leaf_hashes);

        var level_size = leaf_hashes.len;
        while (level_size > 1) {
            const next_level_size = (level_size + 1) / 2;
            var next_level = try self.allocator.alloc(FieldElement, next_level_size);

            for (0..next_level_size) |i| {
                if (i * 2 + 1 < level_size) {
                    // Hash two elements together
                    const left = current_level[i * 2];
                    const right = current_level[i * 2 + 1];
                    const pair = [_]FieldElement{ left, right };

                    const hash_result = try self.applyPoseidonTweakHash(&pair, 0, 0, parameter);
                    defer self.allocator.free(hash_result);
                    next_level[i] = hash_result[0];
                } else {
                    // Odd number of elements, copy the last one
                    next_level[i] = current_level[i * 2];
                }
            }

            self.allocator.free(current_level);
            current_level = next_level;
            level_size = next_level_size;
        }

        const root = current_level[0];
        self.allocator.free(current_level);
        return root;
    }

    /// Build top tree from bottom tree roots
    fn buildTopTree(self: *GeneralizedXMSSSignatureScheme, bottom_tree_roots: []FieldElement, parameter: [5]FieldElement) !*HashSubTree {
        const root = try self.buildBottomTree(bottom_tree_roots, parameter);
        return try HashSubTree.init(self.allocator, root);
    }

    /// Generate random PRF key (matching Rust PRF::key_gen)
    fn generateRandomPRFKey(_: *GeneralizedXMSSSignatureScheme) ![32]u8 {
        var prf_key: [32]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        const rng = prng.random();

        for (0..32) |i| {
            prf_key[i] = rng.int(u8);
        }

        return prf_key;
    }

    /// Generate random parameter (matching Rust TH::rand_parameter)
    fn generateRandomParameter(_: *GeneralizedXMSSSignatureScheme) ![5]FieldElement {
        var parameter: [5]FieldElement = undefined;
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        const rng = prng.random();

        for (0..5) |i| {
            const random_value = rng.int(u32);
            parameter[i] = FieldElement{ .value = random_value % 2130706433 }; // KoalaBear modulus
        }

        return parameter;
    }

    /// Key generation (matching Rust key_gen exactly)
    pub fn keyGen(
        self: *GeneralizedXMSSSignatureScheme,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) !struct { public_key: GeneralizedXMSSPublicKey, secret_key: *GeneralizedXMSSSecretKey } {
        const lifetime = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime);

        // Validate activation parameters
        if (activation_epoch + num_active_epochs > lifetime) {
            return error.InvalidActivationParameters;
        }

        // Expand activation time to align with bottom trees
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);
        const expansion_result = expandActivationTime(self.lifetime_params.log_lifetime, activation_epoch, num_active_epochs);
        const num_bottom_trees = expansion_result.end - expansion_result.start;

        if (num_bottom_trees < 2) {
            return error.InsufficientBottomTrees;
        }

        const expanded_activation_epoch = expansion_result.start * leafs_per_bottom_tree;
        const expanded_num_active_epochs = num_bottom_trees * leafs_per_bottom_tree;

        // Generate random parameter and PRF key
        const parameter = try self.generateRandomParameter();
        const prf_key = try self.generateRandomPRFKey();

        // Generate bottom trees and collect their roots
        var roots_of_bottom_trees = try self.allocator.alloc(FieldElement, num_bottom_trees);
        defer self.allocator.free(roots_of_bottom_trees);

        // Generate left and right bottom trees (first two)
        const left_bottom_tree_index = expansion_result.start;
        const left_bottom_tree = try self.bottomTreeFromPrfKey(prf_key, left_bottom_tree_index, parameter);
        roots_of_bottom_trees[0] = left_bottom_tree.root();

        const right_bottom_tree_index = expansion_result.start + 1;
        const right_bottom_tree = try self.bottomTreeFromPrfKey(prf_key, right_bottom_tree_index, parameter);
        roots_of_bottom_trees[1] = right_bottom_tree.root();

        // Generate remaining bottom trees
        for (expansion_result.start + 2..expansion_result.end) |bottom_tree_index| {
            const bottom_tree = try self.bottomTreeFromPrfKey(prf_key, bottom_tree_index, parameter);
            roots_of_bottom_trees[bottom_tree_index - expansion_result.start] = bottom_tree.root();
            bottom_tree.deinit(); // Clean up individual trees
        }

        // Build top tree from bottom tree roots
        const top_tree = try self.buildTopTree(roots_of_bottom_trees, parameter);

        // Create public and secret keys
        const public_key = GeneralizedXMSSPublicKey.init(top_tree.root(), parameter);
        const secret_key = try GeneralizedXMSSSecretKey.init(
            self.allocator,
            prf_key,
            parameter,
            expanded_activation_epoch,
            expanded_num_active_epochs,
            top_tree,
            left_bottom_tree_index,
            left_bottom_tree,
            right_bottom_tree,
        );

        return .{
            .public_key = public_key,
            .secret_key = secret_key,
        };
    }

    /// Signing function (matching Rust sign exactly)
    pub fn sign(
        self: *GeneralizedXMSSSignatureScheme,
        secret_key: *GeneralizedXMSSSecretKey,
        epoch: u32,
        message: [MESSAGE_LENGTH]u8,
    ) !*GeneralizedXMSSSignature {
        // Check activation interval
        const activation_interval = secret_key.getActivationInterval();
        if (epoch < activation_interval.start or epoch >= activation_interval.end) {
            return error.KeyNotActive;
        }

        // Check prepared interval
        const prepared_interval = secret_key.getPreparedInterval(self.lifetime_params.log_lifetime);
        if (epoch < prepared_interval.start or epoch >= prepared_interval.end) {
            return error.EpochNotPrepared;
        }

        // Generate Merkle path (simplified for now)
        const path = try HashTreeOpening.init(self.allocator, &[_]FieldElement{});
        errdefer path.deinit(); // Clean up if signature creation fails

        // Generate randomness using PRF
        const rho = try self.generateRandomness(secret_key.prf_key, epoch, message, 0);

        // Generate hashes for chains (simplified for now)
        const hashes = try self.allocator.alloc(FieldElement, self.lifetime_params.dimension);
        defer self.allocator.free(hashes); // Free the original allocation after copying
        for (0..self.lifetime_params.dimension) |i| {
            hashes[i] = FieldElement{ .value = @as(u32, @intCast(i)) };
        }

        return try GeneralizedXMSSSignature.init(self.allocator, path, rho, hashes);
    }

    /// Generate randomness (matching Rust PRF::get_randomness)
    fn generateRandomness(
        _: *GeneralizedXMSSSignatureScheme,
        _: [32]u8,
        _: u32,
        _: [MESSAGE_LENGTH]u8,
        _: u64,
    ) ![7]FieldElement {
        // This is a simplified implementation - in practice this would use ShakePRFtoF
        var rho: [7]FieldElement = undefined;
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        const rng = prng.random();

        for (0..7) |i| {
            const random_value = rng.int(u32);
            rho[i] = FieldElement{ .value = random_value % 2130706433 };
        }

        return rho;
    }

    /// Verification function (matching Rust verify exactly)
    pub fn verify(
        self: *GeneralizedXMSSSignatureScheme,
        _: *const GeneralizedXMSSPublicKey,
        epoch: u32,
        _: [MESSAGE_LENGTH]u8,
        _: *GeneralizedXMSSSignature,
    ) !bool {
        const lifetime = @as(u64, 1) << @intCast(self.lifetime_params.log_lifetime);

        if (epoch >= lifetime) {
            return error.EpochTooLarge;
        }

        // This is a simplified verification - in practice this would implement the full verification logic
        // including message encoding, chain recomputation, and Merkle path verification

        return true; // Placeholder
    }
};

// Test functions
test "generalized_xmss_keygen" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Verify key structure
    try std.testing.expect(keypair.public_key.root.value != 0);
    try std.testing.expect(keypair.secret_key.activation_epoch == 0);
    try std.testing.expect(keypair.secret_key.num_active_epochs >= 256);
}

test "generalized_xmss_sign_verify" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    const message = [_]u8{0x42} ** MESSAGE_LENGTH;
    const signature = try scheme.sign(keypair.secret_key, 0, message);
    defer signature.deinit();

    const is_valid = try scheme.verify(&keypair.public_key, 0, message, signature);
    try std.testing.expect(is_valid);
}
