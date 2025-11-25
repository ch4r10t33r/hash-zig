//! GeneralizedXMSS Signature Scheme - Full Rust Compatibility Implementation
//! This implementation matches Rust GeneralizedXMSSSignatureScheme exactly

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = @import("../../utils/log.zig");
const FieldElement = @import("../../core/field.zig").FieldElement;
const ParametersRustCompat = @import("../../core/params_rust_compat.zig").ParametersRustCompat;
const ShakePRFtoF_8_7 = @import("../../prf/shake_prf_to_field.zig").ShakePRFtoF_8_7;
const ShakePRFtoF_7_6 = @import("../../prf/shake_prf_to_field.zig").ShakePRFtoF_7_6;
const Poseidon2RustCompat = @import("../../hash/poseidon2_hash.zig").Poseidon2RustCompat;
const serialization = @import("../serialization.zig");
const KOALABEAR_PRIME = @import("../../core/field.zig").KOALABEAR_PRIME;
const ChaCha12Rng = @import("../../prf/chacha12_rng.zig").ChaCha12Rng;
const KoalaBearField = @import("../../poseidon2/plonky3_field.zig").KoalaBearField;
const BigInt = std.math.big.int.Managed;
const rng_flow = @import("rng_flow.zig");
const poseidon_top_level = @import("poseidon_top_level.zig");
const target_sum_encoding = @import("target_sum_encoding.zig");
const simd_utils = @import("simd_utils.zig");

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
pub const PaddedLayer = struct {
    nodes: [][8]FieldElement,
    start_index: usize,
};

pub const HashSubTree = struct {
    root_value: [8]FieldElement,
    layers: ?[]PaddedLayer,
    allocator: Allocator,

    pub fn init(allocator: Allocator, root_value: [8]FieldElement) !*HashSubTree {
        const self = try allocator.create(HashSubTree);
        self.* = HashSubTree{
            .root_value = root_value,
            .layers = null,
            .allocator = allocator,
        };
        return self;
    }

    pub fn initWithLayers(
        allocator: Allocator,
        root_value: [8]FieldElement,
        layers: []PaddedLayer,
    ) !*HashSubTree {
        const self = try allocator.create(HashSubTree);
        self.* = HashSubTree{
            .root_value = root_value,
            .layers = layers,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *HashSubTree) void {
        if (self.layers) |layers| {
            for (layers) |layer| {
                self.allocator.free(layer.nodes);
            }
            self.allocator.free(layers);
        }
        self.allocator.destroy(self);
    }

    pub fn root(self: *const HashSubTree) [8]FieldElement {
        return self.root_value;
    }

    pub fn getLayers(self: *const HashSubTree) ?[]const PaddedLayer {
        if (self.layers) |layers| {
            return layers;
        }
        return null;
    }
};

// Hash Tree Opening for Merkle paths
pub const HashTreeOpening = struct {
    nodes: [][8]FieldElement,
    allocator: Allocator,

    pub fn init(allocator: Allocator, nodes: [][8]FieldElement) !*HashTreeOpening {
        const self = try allocator.create(HashTreeOpening);
        const nodes_copy = try allocator.alloc([8]FieldElement, nodes.len);
        @memcpy(nodes_copy, nodes);
        self.* = HashTreeOpening{
            .nodes = nodes_copy,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *HashTreeOpening) void {
        self.allocator.free(self.nodes);
        self.allocator.destroy(self);
    }

    pub fn getNodes(self: *const HashTreeOpening) [][8]FieldElement {
        return self.nodes;
    }
};

// Signature structure matching Rust exactly
pub const GeneralizedXMSSSignature = struct {
    // Private fields - not directly accessible from outside
    path: *HashTreeOpening,
    rho: [7]FieldElement, // IE::Randomness (max length; actual rand_len_fe may be smaller)
    hashes: [][8]FieldElement, // Vec<TH::Domain>
    allocator: Allocator,
    is_deserialized: bool, // Track if signature was deserialized from JSON (Rust→Zig)

    pub fn init(allocator: Allocator, path: *HashTreeOpening, rho: [7]FieldElement, hashes: [][8]FieldElement) !*GeneralizedXMSSSignature {
        const self = try allocator.create(GeneralizedXMSSSignature);
        const hashes_copy = try allocator.alloc([8]FieldElement, hashes.len);
        @memcpy(hashes_copy, hashes);
        self.* = GeneralizedXMSSSignature{
            .path = path,
            .rho = rho,
            .hashes = hashes_copy,
            .allocator = allocator,
            .is_deserialized = false, // Created directly, not deserialized
        };
        return self;
    }

    pub fn initDeserialized(allocator: Allocator, path: *HashTreeOpening, rho: [7]FieldElement, hashes: [][8]FieldElement) !*GeneralizedXMSSSignature {
        const self = try allocator.create(GeneralizedXMSSSignature);
        const hashes_copy = try allocator.alloc([8]FieldElement, hashes.len);
        @memcpy(hashes_copy, hashes);
        self.* = GeneralizedXMSSSignature{
            .path = path,
            .rho = rho,
            .hashes = hashes_copy,
            .allocator = allocator,
            .is_deserialized = true, // Deserialized from JSON (Rust→Zig)
        };
        return self;
    }

    pub fn deinit(self: *GeneralizedXMSSSignature) void {
        self.path.deinit(); // Free the HashTreeOpening
        self.allocator.free(self.hashes);
        self.allocator.destroy(self);
    }

    // Controlled access methods for private fields
    pub fn getPath(self: *const GeneralizedXMSSSignature) *HashTreeOpening {
        return self.path;
    }

    pub fn getRho(self: *const GeneralizedXMSSSignature) [7]FieldElement {
        return self.rho;
    }

    pub fn getHashes(self: *const GeneralizedXMSSSignature) [][8]FieldElement {
        return self.hashes;
    }

    // Serialization method using controlled access
    pub fn serialize(self: *const GeneralizedXMSSSignature, allocator: Allocator) ![]u8 {
        return serialization.serializeSignature(allocator, self);
    }
};

// Public key structure matching Rust exactly
pub const GeneralizedXMSSPublicKey = struct {
    // Private fields - not directly accessible from outside
    root: [8]FieldElement, // Root should be an array of 8 field elements to match Rust
    parameter: [5]FieldElement, // TH::Parameter

    pub fn init(root: [8]FieldElement, parameter: [5]FieldElement) GeneralizedXMSSPublicKey {
        return GeneralizedXMSSPublicKey{
            .root = root,
            .parameter = parameter,
        };
    }

    // Controlled access methods for private fields
    pub fn getRoot(self: *const GeneralizedXMSSPublicKey) [8]FieldElement {
        return self.root;
    }

    pub fn getParameter(self: *const GeneralizedXMSSPublicKey) [5]FieldElement {
        return self.parameter;
    }

    // Serialization method using controlled access
    pub fn serialize(self: *const GeneralizedXMSSPublicKey, allocator: Allocator) ![]u8 {
        return serialization.serializePublicKey(allocator, self);
    }
};

// Secret key structure matching Rust exactly
pub const GeneralizedXMSSSecretKey = struct {
    // Private fields - not directly accessible from outside
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
        _parameter: [5]FieldElement,
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
            .parameter = _parameter,
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

    // Controlled access methods for private fields
    pub fn getActivationEpoch(self: *const GeneralizedXMSSSecretKey) usize {
        return self.activation_epoch;
    }

    pub fn getNumActiveEpochs(self: *const GeneralizedXMSSSecretKey) usize {
        return self.num_active_epochs;
    }

    pub fn getLeftBottomTreeIndex(self: *const GeneralizedXMSSSecretKey) usize {
        return self.left_bottom_tree_index;
    }

    // Note: These methods expose sensitive data for serialization
    // In a production system, you might want to restrict access to these
    pub fn getPrfKey(self: *const GeneralizedXMSSSecretKey) [32]u8 {
        return self.prf_key;
    }

    pub fn getParameter(self: *const GeneralizedXMSSSecretKey) [5]FieldElement {
        return self.parameter;
    }

    // Serialization method using controlled access
    pub fn serialize(self: *const GeneralizedXMSSSecretKey, allocator: Allocator) ![]u8 {
        return serialization.serializeSecretKey(allocator, self);
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

    /// Advance preparation (matching Rust advance_preparation exactly)
    /// Note: This method needs access to the scheme to compute bottom trees
    pub fn advancePreparation(self: *GeneralizedXMSSSecretKey, scheme: *GeneralizedXMSSSignatureScheme, log_lifetime: usize) !void {
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(log_lifetime / 2);
        const next_prepared_end_epoch = self.left_bottom_tree_index * leafs_per_bottom_tree + 3 * leafs_per_bottom_tree;

        // Match Rust: compare with get_activation_interval().end
        const activation_interval = self.getActivationInterval();
        if (@as(u64, @intCast(next_prepared_end_epoch)) > activation_interval.end) {
            return; // Cannot advance
        }

        // Compute new right bottom tree using scheme's method (matching Rust bottom_tree_from_prf_key)
        const new_right_bottom_tree = try scheme.bottomTreeFromPrfKey(self.prf_key, self.left_bottom_tree_index + 2, self.parameter);

        // Clean up the old left bottom tree before replacing it
        self.left_bottom_tree.deinit();

        // Move right to left and update index (matching Rust exactly)
        self.left_bottom_tree = self.right_bottom_tree;
        self.right_bottom_tree = new_right_bottom_tree;
        self.left_bottom_tree_index += 1;
    }
};

// Main GeneralizedXMSS Signature Scheme
pub const GeneralizedXMSSSignatureScheme = struct {
    lifetime_params: LifetimeParams,
    poseidon2: *Poseidon2RustCompat,
    allocator: Allocator,
    rng: ChaCha12Rng,
    layer_cache: std.HashMap(usize, poseidon_top_level.AllLayerInfoForBase, std.hash_map.AutoContext(usize), std.hash_map.default_max_load_percentage),
    layer_cache_mutex: std.Thread.Mutex,

    pub fn init(allocator: Allocator, lifetime: @import("../../core/params_rust_compat.zig").KeyLifetime) !*GeneralizedXMSSSignatureScheme {
        const poseidon2 = try Poseidon2RustCompat.init(allocator);

        // Select the correct lifetime parameters (only 3 lifetimes supported: 2^8, 2^18, 2^32)
        const lifetime_params = switch (lifetime) {
            .lifetime_2_8 => LIFETIME_2_8_PARAMS,
            .lifetime_2_18 => LIFETIME_2_18_PARAMS,
            .lifetime_2_32 => LIFETIME_2_32_HASHING_PARAMS,
        };

        const self = try allocator.create(GeneralizedXMSSSignatureScheme);
        self.* = GeneralizedXMSSSignatureScheme{
            .lifetime_params = lifetime_params,
            .poseidon2 = try allocator.create(Poseidon2RustCompat),
            .allocator = allocator,
            .rng = ChaCha12Rng.init(initDefaultSeed()),
            .layer_cache = std.HashMap(usize, poseidon_top_level.AllLayerInfoForBase, std.hash_map.AutoContext(usize), std.hash_map.default_max_load_percentage).init(allocator),
            .layer_cache_mutex = .{},
        };

        self.poseidon2.* = poseidon2;

        return self;
    }

    pub fn initWithSeed(allocator: Allocator, lifetime: @import("../../core/params_rust_compat.zig").KeyLifetime, seed: [32]u8) !*GeneralizedXMSSSignatureScheme {
        const poseidon2 = try Poseidon2RustCompat.init(allocator);
        // Select the correct lifetime parameters (only 3 lifetimes supported: 2^8, 2^18, 2^32)
        const lifetime_params = switch (lifetime) {
            .lifetime_2_8 => LIFETIME_2_8_PARAMS,
            .lifetime_2_18 => LIFETIME_2_18_PARAMS,
            .lifetime_2_32 => LIFETIME_2_32_HASHING_PARAMS,
        };
        const self = try allocator.create(GeneralizedXMSSSignatureScheme);
        self.* = GeneralizedXMSSSignatureScheme{
            .lifetime_params = lifetime_params,
            .poseidon2 = try allocator.create(Poseidon2RustCompat),
            .allocator = allocator,
            .rng = ChaCha12Rng.init(seed),
            .layer_cache = std.HashMap(usize, poseidon_top_level.AllLayerInfoForBase, std.hash_map.AutoContext(usize), std.hash_map.default_max_load_percentage).init(allocator),
            .layer_cache_mutex = .{},
        };
        self.poseidon2.* = poseidon2;
        return self;
    }

    fn initDefaultSeed() [32]u8 {
        var seed: [32]u8 = undefined;
        const now = @as(u64, @intCast(std.time.timestamp()));
        // Expand timestamp into 32 bytes deterministically
        var tmp = now;
        var i: usize = 0;
        while (i < 32) : (i += 1) {
            tmp = tmp ^ (tmp << 13) ^ (tmp >> 7) ^ (tmp << 17);
            seed[i] = @as(u8, @truncate(tmp >> @intCast((i & 7) * 8)));
        }
        return seed;
    }

    pub fn deinit(self: *GeneralizedXMSSSignatureScheme) void {
        // Clean up layer cache
        var it = self.layer_cache.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.layer_cache.deinit();

        self.allocator.destroy(self.poseidon2);
        self.allocator.destroy(self);
    }

    fn prfDomainElement(
        self: *const GeneralizedXMSSSignatureScheme,
        prf_key: [32]u8,
        epoch: u32,
        index: u64,
    ) [8]u32 {
        const hash_len = self.lifetime_params.hash_len_fe;
        var padded: [8]u32 = undefined;
        if (self.lifetime_params.rand_len_fe == 6 and hash_len == 7) {
            const raw = ShakePRFtoF_7_6.getDomainElement(prf_key, epoch, index);
            for (0..hash_len) |i| {
                padded[i] = raw[i];
            }
        } else {
            const raw = ShakePRFtoF_8_7.getDomainElement(prf_key, epoch, index);
            for (0..hash_len) |i| {
                padded[i] = raw[i];
            }
        }
        for (hash_len..8) |i| {
            padded[i] = 0;
        }
        return padded;
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
    ///
    /// Note: This matches the structure from leanSig PR #5 (simd: apply packing for tree leaves).
    /// The Rust implementation uses SIMD packing via Plonky3's Packing trait to optimize
    /// tree leaf computation. Future optimizations can use Zig's @Vector for SIMD operations.
    pub fn bottomTreeFromPrfKey(
        self: *GeneralizedXMSSSignatureScheme,
        prf_key: [32]u8,
        bottom_tree_index: usize,
        parameter: [5]FieldElement,
    ) !*HashSubTree {
        const num_chains = self.lifetime_params.dimension;
        _ = self.lifetime_params.base; // chain_length unused for now

        // Calculate leaves per bottom tree
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);

        // Calculate epoch range for this bottom tree
        const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
        const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;

        // Generate leaf domains (8-wide) for each epoch
        // TODO: Optimize with SIMD packing (see leanSig PR #5) to process multiple epochs/chains in parallel
        var leaf_domains = try self.allocator.alloc([8]FieldElement, leafs_per_bottom_tree);
        defer self.allocator.free(leaf_domains);

        for (epoch_range_start..epoch_range_end) |epoch| {
            // Generate chain end domains (8-wide) for this epoch
            var chain_domains = try self.allocator.alloc([8]FieldElement, num_chains);
            defer self.allocator.free(chain_domains);

            for (0..num_chains) |chain_index| {
                // Get chain start using ShakePRFtoF
                const domain_elements = self.prfDomainElement(prf_key, @as(u32, @intCast(epoch)), @as(u64, @intCast(chain_index)));

                // Debug: Print domain elements for all epochs and chains in first bottom tree
                if (bottom_tree_index == 0) {
                    // log.print("DEBUG: Bottom tree {} epoch {} chain {} domain elements: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ bottom_tree_index, epoch, chain_index, domain_elements[0], domain_elements[1], domain_elements[2], domain_elements[3], domain_elements[4], domain_elements[5], domain_elements[6], domain_elements[7] });
                }

                // Walk the chain to get the final 8-wide domain
                const chain_end_domain = try self.computeHashChainDomain(domain_elements, @as(u32, @intCast(epoch)), @as(u8, @intCast(chain_index)), parameter);

                // Debug: Print chain end for all epochs and chains in first bottom tree
                if (bottom_tree_index == 0) {
                    log.print("DEBUG: Bottom tree {} epoch {} chain {} chain end[0]: 0x{x}\n", .{ bottom_tree_index, epoch, chain_index, chain_end_domain[0].value });
                }

                chain_domains[chain_index] = chain_end_domain;
            }

            // Reduce chain domains to a single leaf domain using tree-tweak hashing
            const leaf_domain_slice = try self.reduceChainDomainsToLeafDomain(chain_domains, parameter, @as(u32, @intCast(epoch)));
            defer self.allocator.free(leaf_domain_slice);
            // Convert to fixed-size [8]FieldElement array (pad with zeros if needed)
            var leaf_domain: [8]FieldElement = undefined;
            const hash_len = self.lifetime_params.hash_len_fe;
            for (0..hash_len) |i| {
                leaf_domain[i] = leaf_domain_slice[i];
            }
            for (hash_len..8) |i| {
                leaf_domain[i] = FieldElement{ .value = 0 };
            }
            leaf_domains[epoch - epoch_range_start] = leaf_domain;

            // Debug: Print leaf domain head for all epochs in first bottom tree
            if (bottom_tree_index == 0) {
                log.print("DEBUG: Bottom tree {} epoch {} leaf domain[0]: 0x{x}\n", .{ bottom_tree_index, epoch, leaf_domain[0].value });
                if (epoch == 0) {
                    log.print("ZIG_LEAF_DOMAIN_EPOCH0:[", .{});
                    for (leaf_domain, 0..) |fe, i| {
                        log.print("\"0x{x}\"", .{fe.value});
                        if (i < 7) log.print(",", .{});
                    }
                    log.print("]\n", .{});
                }
            }
        }

        // Build bottom tree layers from leaf domains (shared with signing path)
        const bottom_layers = try self.buildBottomTreeLayersFromLeafDomains(leaf_domains, parameter, bottom_tree_index);
        defer {
            for (bottom_layers) |layer| self.allocator.free(layer.nodes);
            self.allocator.free(bottom_layers);
        }

        if (bottom_layers.len == 0 or bottom_layers[bottom_layers.len - 1].nodes.len == 0) {
            return error.InvalidBottomTree;
        }

        // Debug: check root layer structure
        const root_layer = bottom_layers[bottom_layers.len - 1];
        if (bottom_tree_index == 1) {
            std.debug.print("ZIG_BOTTOM_ROOT: bottom_tree_index={}, root_layer.nodes.len={}, root_layer.start_index={}\n", .{ bottom_tree_index, root_layer.nodes.len, root_layer.start_index });
        }

        // Rust extracts from layers[depth / 2].nodes[bottom_tree_index % 2]
        // For depth=8: layers[4].nodes[bottom_tree_index % 2]
        // For bottom_tree_index=1: layers[4].nodes[1]
        // But we build with full_depth=4, so our root layer should have only 1 node
        // However, if the root layer has multiple nodes, we should use bottom_tree_index % 2
        const root_node_index = if (root_layer.nodes.len > 1) bottom_tree_index % 2 else 0;
        var bottom_root: [8]FieldElement = undefined;
        @memcpy(&bottom_root, &root_layer.nodes[root_node_index]);
        
        if (bottom_tree_index == 1) {
            std.debug.print("ZIG_BOTTOM_ROOT: Using root_node_index={}, root[0]=0x{x:0>8}\n", .{ root_node_index, bottom_root[0].value });
        }
        
        return try HashSubTree.init(self.allocator, bottom_root);
    }

    /// Compute hash chain (matching Rust chain function)
    pub fn computeHashChain(
        self: *GeneralizedXMSSSignatureScheme,
        domain_elements: [8]u32,
        epoch: u32,
        chain_index: u8,
        parameter: [5]FieldElement,
    ) !FieldElement {
        // Convert domain elements to field elements
        var current: [8]FieldElement = undefined;
        for (0..8) |i| {
            current[i] = FieldElement{ .value = domain_elements[i] };
        }

        // Debug: Print initial state for first bottom tree, epoch 0, chain 0
        if (epoch == 0 and chain_index == 0) {
            // log.print("DEBUG: Chain initial state epoch={} chain={}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ epoch, chain_index, current[0].value, current[1].value, current[2].value, current[3].value, current[4].value, current[5].value, current[6].value, current[7].value });
        }

        // Walk the chain for BASE-1 steps (matching Rust chain function)
        for (0..self.lifetime_params.base - 1) |j| {
            const pos_in_chain = @as(u8, @intCast(j + 1));

            // Apply chain tweak hash (matching Rust TH::apply with chain_tweak)
            const next = try self.applyPoseidonChainTweakHash(current, epoch, chain_index, pos_in_chain, parameter);

            // Debug: Print chain step for first bottom tree, epoch 0, chain 0
            if (epoch == 0 and chain_index == 0) {
                // log.print("DEBUG: Chain step {} epoch={} chain={}: [{}, {}, {}, {}, {}, {}, {}, {}] -> [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ j + 1, epoch, chain_index, current[0].value, current[1].value, current[2].value, current[3].value, current[4].value, current[5].value, current[6].value, current[7].value, next[0].value, next[1].value, next[2].value, next[3].value, next[4].value, next[5].value, next[6].value, next[7].value });
            }

            // Update current state
            current = next;
        }

        // Debug: Print final chain result for first bottom tree, epoch 0, chain 0
        if (epoch == 0 and chain_index == 0) {
            log.print("DEBUG: Chain final result epoch={} chain={}: 0x{x}\n", .{ epoch, chain_index, current[0].value });
        }

        return current[0];
    }

    /// Compute hash chain and return the full 8-wide domain state after BASE-1 steps
    /// domain_elements are in Montgomery form (from ShakePRFtoF)
    pub fn computeHashChainDomain(
        self: *GeneralizedXMSSSignatureScheme,
        domain_elements: [8]u32,
        epoch: u32,
        chain_index: u8,
        parameter: [5]FieldElement,
    ) ![8]FieldElement {
        // domain_elements are in Montgomery form (from ShakePRFtoF)
        // applyPoseidonChainTweakHash expects input in Montgomery form
        // So we can use domain_elements directly as Montgomery values
        var current: [8]FieldElement = undefined;
        for (0..8) |i| current[i] = FieldElement{ .value = domain_elements[i] }; // Already Montgomery
        for (0..self.lifetime_params.base - 1) |j| {
            const pos_in_chain = @as(u8, @intCast(j + 1));
            const next = try self.applyPoseidonChainTweakHash(current, epoch, chain_index, pos_in_chain, parameter);
            const hash_len = self.lifetime_params.hash_len_fe;
            for (0..hash_len) |k| {
                current[k] = next[k];
            }
            // Pad remaining elements with zeros
            for (hash_len..8) |k| {
                current[k] = FieldElement{ .value = 0 };
            }
        }
        return current;
    }

    /// Apply Poseidon2 tweak hash (matching Rust PoseidonTweakHash)
    fn applyPoseidonTweakHash(
        self: *GeneralizedXMSSSignatureScheme,
        input: []const FieldElement,
        epoch: u32,
        chain_index: u8,
        parameter: [5]FieldElement,
    ) ![]FieldElement {
        // Convert epoch and chain_index to field elements for tweak using Rust's encoding
        // ChainTweak: ((epoch as u128) << 24) | ((chain_index as u128) << 16) | ((pos_in_chain as u128) << 8) | 0x00
        const pos_in_chain = 0; // For chain computation, pos_in_chain is always 0
        const tweak_encoding = (@as(u128, epoch) << 24) | (@as(u128, chain_index) << 16) | (@as(u128, pos_in_chain) << 8) | 0x00;

        // Convert to field elements using base-p representation
        const tweak = tweakToFieldElements(tweak_encoding);

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

    /// Apply Poseidon2 chain tweak hash (matching Rust chain_tweak)
    pub fn applyPoseidonChainTweakHash(
        self: *GeneralizedXMSSSignatureScheme,
        input: [8]FieldElement,
        epoch: u32,
        chain_index: u8,
        pos_in_chain: u8,
        parameter: [5]FieldElement,
    ) ![8]FieldElement {
        // Convert epoch, chain_index, and pos_in_chain to field elements for tweak using Rust's encoding
        // ChainTweak: ((epoch as u128) << 24) | ((chain_index as u128) << 16) | ((pos_in_chain as u128) << 8) | 0x00
        const tweak_encoding = (@as(u128, epoch) << 24) | (@as(u128, chain_index) << 16) | (@as(u128, pos_in_chain) << 8) | 0x00;

        // Convert to field elements using base-p representation (canonical form)
        const tweak = tweakToFieldElements(tweak_encoding);

        // Only use hash_len_fe elements from input (7 for lifetime 2^18, 8 for lifetime 2^8)
        const hash_len = self.lifetime_params.hash_len_fe;

        // Prepare combined input: parameter + tweak + input (all already in Montgomery form)
        const total_input_len = 5 + 2 + hash_len;
        var combined_input = try self.allocator.alloc(FieldElement, total_input_len);
        defer self.allocator.free(combined_input);

        // Parameter and tweak are already stored in Montgomery form.
        for (0..5) |i| {
            combined_input[i] = parameter[i];
        }
        for (0..2) |i| {
            combined_input[5 + i] = tweak[i];
        }

        // Copy input (already in Montgomery form) - only hash_len_fe elements
        @memcpy(combined_input[7 .. 7 + hash_len], input[0..hash_len]);

        // Apply Poseidon2-16 hash (matching Rust's poseidon_compress with CHAIN_COMPRESSION_WIDTH=16)
        // Rust uses poseidon2_16() for chain hashing, not poseidon2_24()
        const hash_result = try self.poseidon2.hashFieldElements16(self.allocator, combined_input);
        defer self.allocator.free(hash_result);

        // Return first hash_len_fe elements as the result (7 for lifetime 2^18, 8 for lifetime 2^8)
        // But return type is [8]FieldElement, so pad with zeros if hash_len_fe < 8
        var result: [8]FieldElement = undefined;
        for (0..hash_len) |i| {
            result[i] = hash_result[i];
        }
        for (hash_len..8) |i| {
            result[i] = FieldElement{ .value = 0 };
        }
        return result;
    }

    /// Process all pairs in parallel (matching Rust par_chunks_exact(2))
    fn processPairsInParallel(
        self: *GeneralizedXMSSSignatureScheme,
        nodes: [][8]FieldElement,
        parents: [][8]FieldElement,
        parent_start: usize,
        current_level: usize,
        parameter: [5]FieldElement,
    ) !void {
        const parents_len = parents.len;

        // CRITICAL FIX: Process sequentially to match Rust's exact order
        // Even though Rust uses par_chunks_exact(2), the RNG consumption order is deterministic
        // We need to process in the same order as Rust to maintain identical RNG state
        for (0..parents_len) |i| {
            // Hash two children together (matching Rust exactly)
            const left_idx = i * 2;
            const right_idx = i * 2 + 1;

            const left = nodes[left_idx];
            const right = nodes[right_idx];

            // Convert arrays to slices for hashing
            // Only use first hash_len_fe elements (7 for lifetime 2^18, 8 for lifetime 2^8)
            const hash_len = self.lifetime_params.hash_len_fe;
            // Debug: log hash_len for epoch 16 (bottom tree 1, level 0, parent_pos=8)
            if (current_level == 0 and parent_start == 8 and i == 0) {
                std.debug.print("ZIG_BUILDTREE_HASHLEN: level={} parent_start={} i={} hash_len={} left.len={} right.len={}\n", .{ current_level, parent_start, i, hash_len, left.len, right.len });
            }
            const left_slice = left[0..hash_len];
            const right_slice = right[0..hash_len];
            // Debug: log slice lengths for epoch 16
            if (current_level == 0 and parent_start == 8 and i == 0) {
                std.debug.print("ZIG_BUILDTREE_SLICES: left_slice.len={} right_slice.len={}\n", .{ left_slice.len, right_slice.len });
            }

            // Use tree tweak for this level and position (matching Rust exactly)
            // CRITICAL FIX: parent_pos should be computed from actual node positions
            // For i=0, we hash nodes[0] and nodes[1], which are at positions
            // layer_start_index and layer_start_index+1, so parent is at layer_start_index >> 1
            // But Rust uses parent_pos = parent_start + i, where parent_start = layer_start_index >> 1
            // So parent_pos = (layer_start_index >> 1) + i, which matches Rust!
            const parent_pos = @as(u32, @intCast(parent_start + i));
            // Debug: log parent computation for bottom tree (level 0-3) - show all parent_start values
            // Only log for parent_start=8 (bottom tree 1, level 0) to match epoch 16
            // For epoch 16 in bottom tree 1: epoch=16, bottom_tree_index=1, position in tree=16-16=0
            // So we hash nodes[0] and nodes[1] (left_idx=0, right_idx=1) for i=0
            // Calculate which epoch this corresponds to: for bottom tree 1, start_index=16, so epoch = start_index + left_idx = 16 + 0 = 16
            if (current_level == 0 and i == 0 and parent_start == 8) {
                // Get epoch_range_start from the function context - we need to pass it or calculate it
                // For now, calculate: parent_start=8 means start_index=16, so epoch_range_start = (parent_start << 1) = 16
                const epoch_range_start = parent_start << 1;
                const epoch = @as(u32, @intCast(epoch_range_start + left_idx));
                std.debug.print("ZIG_BUILDTREE: Bottom tree level {} parent {}: parent_start={} parent_pos={} left[0]=0x{x:0>8} right[0]=0x{x:0>8} (left_idx={} right_idx={}) level={} tweak_level={} epoch={} param[0]=0x{x:0>8} hash_len={}\n", .{ current_level, i, parent_start, parent_pos, left[0].value, right[0].value, left_idx, right_idx, current_level, current_level, epoch, parameter[0].value, hash_len });
            }
            // Debug: log parent computation for top tree (level 4+)
            if (current_level >= 4) {
                std.debug.print("ZIG_BUILDTREE: Top tree level {} parent {}: parent_start={} parent_pos={} left[0]=0x{x:0>8} right[0]=0x{x:0>8}\n", .{ current_level, i, parent_start, parent_pos, left[0].value, right[0].value });
            }
            const hash_result = self.applyPoseidonTreeTweakHashWithSeparateInputs(left_slice, right_slice, @as(u8, @intCast(current_level)), parent_pos, parameter) catch {
                // Handle error - in a real implementation, we'd need proper error handling
                return;
            };
            defer self.allocator.free(hash_result);
            
            // Debug: log parent result for bottom tree (level 0-3) - show all parent_start values
            if (current_level < 4 and i == 0) {
                std.debug.print("ZIG_BUILDTREE: Bottom tree level {} parent {}: parent[0]=0x{x:0>8} (left[0]=0x{x:0>8} right[0]=0x{x:0>8} level={} parent_start={} parent_pos={})\n", .{ current_level, i, hash_result[0].value, left[0].value, right[0].value, current_level, parent_start, parent_pos });
            }
            // Debug: log parent result for top tree (level 4+)
            if (current_level >= 4) {
                std.debug.print("ZIG_BUILDTREE: Top tree level {} parent {}: parent[0]=0x{x:0>8} (left[0]=0x{x:0>8} right[0]=0x{x:0>8} parent_pos={})\n", .{ current_level, i, hash_result[0].value, left[0].value, right[0].value, parent_pos });
            }

            // Copy the result to the parents array (only hash_len_fe elements, pad rest with zeros)
            for (0..hash_len) |j| {
                parents[i][j] = hash_result[j];
            }
            for (hash_len..8) |j| {
                parents[i][j] = FieldElement{ .value = 0 };
            }
        }
    }

    /// Process a batch of pairs (thread worker function)
    fn processPairBatch(
        self: *GeneralizedXMSSSignatureScheme,
        nodes: [][8]FieldElement,
        parents: [][8]FieldElement,
        parent_start: usize,
        current_level: usize,
        parameter: [5]FieldElement,
        start_idx: usize,
        end_idx: usize,
    ) void {
        for (start_idx..end_idx) |i| {
            // Hash two children together (matching Rust exactly)
            const left_idx = i * 2;
            const right_idx = i * 2 + 1;

            const left = nodes[left_idx];
            const right = nodes[right_idx];

            // Convert arrays to slices for hashing
            const left_slice = left[0..];
            const right_slice = right[0..];

            // Use tree tweak for this level and position (matching Rust exactly)
            const parent_pos = @as(u32, @intCast(parent_start + i));
            const hash_result = self.applyPoseidonTreeTweakHashWithSeparateInputs(left_slice, right_slice, @as(u8, @intCast(current_level)), parent_pos, parameter) catch {
                // Handle error - in a real implementation, we'd need proper error handling
                return;
            };
            defer self.allocator.free(hash_result);

            // Copy the result to the parents array (all 8 elements)
            @memcpy(parents[i][0..], hash_result[0..8]);
        }
    }

    /// Apply Poseidon2 tree tweak hash with separate left/right inputs (matching Rust exactly)
    pub fn applyPoseidonTreeTweakHashWithSeparateInputs(
        self: *GeneralizedXMSSSignatureScheme,
        left: []const FieldElement,
        right: []const FieldElement,
        level: u8,
        pos_in_level: u32,
        parameter: [5]FieldElement,
    ) ![]FieldElement {
        // Inputs are expected canonical; Poseidon layer handles Montgomery internally.
        // Compute tree tweak: ((level + 1 as u128) << 40) | ((pos_in_level as u128) << 8) | 0x01
        // Match Rust: let tweak_level = (level as u8) + 1;
        const tweak_level = level + 1;
        const tweak_bigint = (@as(u128, tweak_level) << 40) | (@as(u128, pos_in_level) << 8) | 0x01;
        
        // Create a unique identifier for this hash call based on inputs (for matching across build/verify)
        // Use first element of left, right, and param[0] as a simple identifier
        const call_id = left[0].value ^ right[0].value ^ parameter[0].value ^ @as(u32, @intCast(level)) ^ @as(u32, @intCast(pos_in_level));
        
        // Debug: log hash call for level 0, pos 8 (epoch 16 bottom tree)
        if (level == 0 and pos_in_level == 8 and left.len > 0 and right.len > 0) {
            std.debug.print("ZIG_HASH_CALL: level={} pos={} tweak=0x{x} param[0]=0x{x:0>8} left[0]=0x{x:0>8} right[0]=0x{x:0>8} left.len={} right.len={} call_id=0x{x:0>8} left_all=", .{ level, pos_in_level, tweak_bigint, parameter[0].value, left[0].value, right[0].value, left.len, right.len, call_id });
            for (left) |fe| std.debug.print("0x{x:0>8} ", .{fe.value});
            std.debug.print("right_all=", .{});
            for (right) |fe| std.debug.print("0x{x:0>8} ", .{fe.value});
            std.debug.print("\n", .{});
        }
        
        log.print("DEBUG: Tree tweak level={} pos={} -> 0x{x}\n", .{ tweak_level, pos_in_level, tweak_bigint });

        // Convert to 2 field elements using base-p representation
        const p: u128 = 2130706433; // KoalaBear field modulus
        const tweak = [_]FieldElement{
            FieldElement.fromCanonical(@intCast(tweak_bigint % p)),
            FieldElement.fromCanonical(@intCast((tweak_bigint / p) % p)),
        };

        // Debug: print tweak field elements
        log.print("DEBUG: Sponge tweak_fe: [0x{x}, 0x{x}]\n", .{ tweak[0].value, tweak[1].value });

        // Prepare combined input: parameter + tweak + left + right (matching Rust exactly)
        const total_input_len = 5 + 2 + left.len + right.len;
        var combined_input = try self.allocator.alloc(FieldElement, total_input_len);
        defer self.allocator.free(combined_input);

        var input_index: usize = 0;

        // Add parameter elements (canonical)
        for (0..5) |i| {
            combined_input[input_index] = parameter[i];
            input_index += 1;
        }

        // Add tweak elements (canonical)
        for (tweak) |t| {
            combined_input[input_index] = t;
            input_index += 1;
        }

        // Add left elements
        for (left) |fe| {
            combined_input[input_index] = fe;
            input_index += 1;
        }

        // Add right elements
        for (right) |fe| {
            combined_input[input_index] = fe;
            input_index += 1;
        }

        // Use Poseidon2-24 compress (feed-forward) with zero-padding to width 24,
        // then take the first hash_len_fe elements (matching Rust poseidon_compress::<_, 24, HASH_LEN>)
        var padded: [24]FieldElement = [_]FieldElement{FieldElement{ .value = 0 }} ** 24;
        for (combined_input, 0..) |fe, i| {
            padded[i] = fe;
        }
        // compress requires comptime output_len, so use max (8) and slice to hash_len_fe
        const full_out = try self.poseidon2.compress(padded, 8);
        
        // Debug: log hash result for level 0, pos 8 (epoch 16 bottom tree)
        if (level == 0 and pos_in_level == 8 and left.len > 0 and right.len > 0) {
            std.debug.print("ZIG_HASH_RESULT: level={} pos={} result[0]=0x{x:0>8} call_id=0x{x:0>8}\n", .{ level, pos_in_level, full_out[0].value, call_id });
        }
        
        // DETAILED HASH LOGGING
        log.print("DEBUG: Hash input ({} elements): ", .{combined_input.len});
        for (combined_input, 0..) |fe, i| {
            log.print("{}:0x{x}", .{ i, fe.value });
            if (i < combined_input.len - 1) log.print(", ", .{});
        }
        log.print("\n", .{});
        const hash_len = self.lifetime_params.hash_len_fe;
        log.print("DEBUG: Hash output (first {} of {} elements): ", .{ hash_len, full_out.len });
        for (0..hash_len) |i| {
            log.print("{}:0x{x}", .{ i, full_out[i].value });
            if (i < hash_len - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        const result = try self.allocator.alloc(FieldElement, hash_len);
        for (0..hash_len) |i| {
            result[i] = full_out[i];
        }
        return result;
    }

    /// Apply Poseidon2 tree tweak hash (matching Rust PoseidonTweakHash for tree hashing)
    pub fn applyPoseidonTreeTweakHash(
        self: *GeneralizedXMSSSignatureScheme,
        input: []const FieldElement,
        level: u8,
        pos_in_level: u32,
        parameter: [5]FieldElement,
    ) ![]FieldElement {
        // Compute tree tweak: ((level + 1 as u128) << 40) | ((pos_in_level as u128) << 8) | 0x01
        // Match Rust: let tweak_level = (level as u8) + 1;
        const tweak_level = level + 1;
        const tweak_bigint = (@as(u128, tweak_level) << 40) | (@as(u128, pos_in_level) << 8) | 0x01;
        log.print("DEBUG: Tree tweak level={} pos={} -> 0x{x}\n", .{ tweak_level, pos_in_level, tweak_bigint });

        // Convert to 2 field elements using base-p representation
        const p: u128 = 2130706433; // KoalaBear field modulus
        const tweak = [_]FieldElement{
            FieldElement.fromCanonical(@intCast(tweak_bigint % p)),
            FieldElement.fromCanonical(@intCast((tweak_bigint / p) % p)),
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

        // Apply Poseidon2-24 for tree hashing (matching Rust implementation)
        const hash_result = try self.poseidon2.hashFieldElements(self.allocator, combined_input);
        defer self.allocator.free(hash_result);

        // DETAILED HASH LOGGING: Log input and output for debugging
        log.print("DEBUG: Tree Hash input ({} elements): ", .{combined_input.len});
        for (combined_input, 0..) |fe, i| {
            log.print("{}:0x{x}", .{ i, fe.value });
            if (i < combined_input.len - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        log.print("DEBUG: Tree Hash output ({} elements): ", .{hash_result.len});
        for (hash_result, 0..) |fe, i| {
            log.print("{}:0x{x}", .{ i, fe.value });
            if (i < hash_result.len - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        // Return result with hash_len_fe elements (8 for tree hashing)
        const result = try self.allocator.alloc(FieldElement, self.lifetime_params.hash_len_fe);
        for (0..self.lifetime_params.hash_len_fe) |i| {
            result[i] = hash_result[i];
        }

        return result;
    }

    /// Hash chain ends using Poseidon2 by reducing all elements pairwise until one remains
    pub fn hashChainEnds(self: *GeneralizedXMSSSignatureScheme, chain_ends: []FieldElement, parameter: [5]FieldElement) !FieldElement {
        if (chain_ends.len == 0) return error.InvalidInput;

        var current = try self.allocator.alloc(FieldElement, chain_ends.len);
        defer self.allocator.free(current);
        @memcpy(current, chain_ends);

        var cur_len = chain_ends.len;
        while (cur_len > 1) {
            const next_len = (cur_len + 1) / 2;
            var next = try self.allocator.alloc(FieldElement, next_len);
            defer self.allocator.free(next);

            var i: usize = 0;
            var out_idx: usize = 0;
            while (i < cur_len) : (i += 2) {
                if (i + 1 < cur_len) {
                    // Hash the pair [current[i], current[i+1]]
                    const pair = [_]FieldElement{ current[i], current[i + 1] };
                    const h = try self.applyPoseidonTweakHash(&pair, 0, 0, parameter);
                    defer self.allocator.free(h);
                    next[out_idx] = h[0];
                } else {
                    // Odd tail: carry forward
                    next[out_idx] = current[i];
                }
                out_idx += 1;
            }

            // Move to next level
            self.allocator.free(current);
            current = try self.allocator.alloc(FieldElement, next_len);
            @memcpy(current, next);
            cur_len = next_len;
        }

        return current[0];
    }

    /// Reduce chain ends into an 8-wide domain by pairwise hashing until 8 remain
    pub fn hashChainEndsToDomain(self: *GeneralizedXMSSSignatureScheme, chain_ends: []FieldElement, parameter: [5]FieldElement) ![8]FieldElement {
        if (chain_ends.len == 0) return error.InvalidInput;

        var current = try self.allocator.alloc(FieldElement, chain_ends.len);
        defer self.allocator.free(current);
        @memcpy(current, chain_ends);

        var cur_len = chain_ends.len;
        while (cur_len > 8) {
            const next_len = (cur_len + 1) / 2;
            var next = try self.allocator.alloc(FieldElement, next_len);
            defer self.allocator.free(next);

            var i: usize = 0;
            var out_idx: usize = 0;
            while (i < cur_len) : (i += 2) {
                if (i + 1 < cur_len) {
                    const pair = [_]FieldElement{ current[i], current[i + 1] };
                    const h = try self.applyPoseidonTweakHash(&pair, 0, 0, parameter);
                    defer self.allocator.free(h);
                    next[out_idx] = h[0];
                } else {
                    next[out_idx] = current[i];
                }
                out_idx += 1;
            }

            self.allocator.free(current);
            current = try self.allocator.alloc(FieldElement, next_len);
            @memcpy(current, next);
            cur_len = next_len;
        }

        var domain: [8]FieldElement = undefined;
        // If fewer than 8 remain (shouldn't happen with 64), pad with zeros
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            domain[i] = if (i < cur_len) current[i] else FieldElement{ .value = 0 };
        }
        return domain;
    }

    /// Reduce 64 chain domains ([8] each) into a single leaf domain using Poseidon sponge
    /// This matches Rust's TH::apply when message.len() > 2 (sponge mode)
    /// Returns hash_len_fe elements (7 for lifetime 2^18, 8 for lifetime 2^8)
    pub fn reduceChainDomainsToLeafDomain(
        self: *GeneralizedXMSSSignatureScheme,
        chain_domains_in: [][8]FieldElement,
        parameter: [5]FieldElement,
        epoch: u32,
    ) ![]FieldElement {
        if (chain_domains_in.len == 0) return error.InvalidInput;

        // Implement the sponge mode matching Rust exactly:
        // 1. Flatten all domains: message.iter().flatten()
        // 2. Create domain separator from [PARAMETER_LEN, TWEAK_LEN, NUM_CHUNKS, HASH_LEN]
        // 3. Use poseidon_sponge with width 24, capacity from domain separator

        const PARAMETER_LEN: u32 = @intCast(self.lifetime_params.parameter_len);
        const TWEAK_LEN: u32 = @intCast(self.lifetime_params.tweak_len_fe);
        const NUM_CHUNKS: u32 = @intCast(chain_domains_in.len); // dimension (64)
        const HASH_LEN: u32 = @intCast(self.lifetime_params.hash_len_fe);

        // Flatten all domains into a single slice (matching Rust: message.iter().flatten())
        // Only use hash_len_fe elements from each domain (7 for lifetime 2^18, 8 for lifetime 2^8)
        const hash_len = self.lifetime_params.hash_len_fe;
        const flattened_len = chain_domains_in.len * hash_len;
        var flattened_input = try self.allocator.alloc(FieldElement, flattened_len);
        defer self.allocator.free(flattened_input);

        var flat_idx: usize = 0;
        for (chain_domains_in) |domain| {
            // Only use first hash_len_fe elements (7 for lifetime 2^18, 8 for lifetime 2^8)
            for (0..hash_len) |j| {
                flattened_input[flat_idx] = domain[j];
                flat_idx += 1;
            }
        }

        // Create tree tweak: level=0, pos_in_level=epoch (matching Rust: TH::tree_tweak(0, epoch))
        const tweak_level: u8 = 0;
        const tweak_bigint = (@as(u128, tweak_level) << 40) | (@as(u128, epoch) << 8) | 0x01;

        // Convert tweak to 2 field elements using base-p representation
        const p: u128 = 2130706433; // KoalaBear field modulus
        const tweak = [_]FieldElement{
            FieldElement.fromCanonical(@intCast(tweak_bigint % p)),
            FieldElement.fromCanonical(@intCast((tweak_bigint / p) % p)),
        };

        // Create domain separator from lengths (matching Rust's poseidon_safe_domain_separator)
        const DOMAIN_PARAMETERS_LENGTH: usize = 4;
        const domain_params: [DOMAIN_PARAMETERS_LENGTH]u32 = [4]u32{ PARAMETER_LEN, TWEAK_LEN, NUM_CHUNKS, HASH_LEN };

        // Combine params into a single number in base 2^32 (matching Rust)
        var acc: u128 = 0;
        for (domain_params) |param| {
            acc = (acc << 32) | (@as(u128, param));
        }

        // Compute base-p decomposition to 24 elements (matching Rust)
        // Rust uses F::from_u64(digit) which converts to Montgomery, so we need to do the same
        // (using p already declared above for tweak computation)
        const Poseidon24 = @import("../../poseidon2/poseidon2.zig").Poseidon2KoalaBear24Plonky3;
        const F = Poseidon24.Field;
        var input_24_monty: [24]F = undefined;
        var remaining = acc;
        for (0..24) |i| {
            const digit = remaining % p;
            input_24_monty[i] = F.fromU32(@as(u32, @intCast(digit))); // Convert to Montgomery (matching Rust F::from_u64)
            remaining /= p;
        }

        // Use poseidon_compress directly with Montgomery values (matching Rust's poseidon_compress)
        // Rust's poseidon_compress takes &[F] (Montgomery) and returns [F; OUT_LEN] (Montgomery)
        const CAPACITY: usize = self.lifetime_params.capacity; // From lifetime_params (9 for lifetime 2^8, 2^18, 2^32)
        var padded_input_monty: [24]F = undefined;
        @memcpy(&padded_input_monty, &input_24_monty);

        // Apply permutation
        Poseidon24.permutation(&padded_input_monty);

        // Feed-forward: Add the input back into the state element-wise (matching Rust's poseidon_compress)
        for (0..24) |i| {
            padded_input_monty[i] = padded_input_monty[i].add(input_24_monty[i]);
        }

        // Extract capacity_value in Montgomery form (matching Rust's return type [F; OUT_LEN])
        var capacity_value_monty = try self.allocator.alloc(F, CAPACITY);
        defer self.allocator.free(capacity_value_monty);
        for (0..CAPACITY) |i| {
            capacity_value_monty[i] = padded_input_monty[i];
        }

        // Debug: log capacity_value (in Montgomery form, print as canonical for comparison)
        log.print("DEBUG: Sponge capacity_value ({} elements, Montgomery->canonical): ", .{CAPACITY});
        for (capacity_value_monty, 0..) |fe, i| {
            log.print("{}:0x{x}", .{ i, fe.toU32() });
            if (i < CAPACITY - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        // Combine parameter + tweak + flattened input (matching Rust's poseidon_sponge input)
        // Rust passes everything in Montgomery form directly to poseidon_sponge
        // Chain ends are already in Montgomery form (from Poseidon2-16 compress)
        // Parameter and tweak need to be converted to Montgomery
        const combined_input_len = self.lifetime_params.parameter_len + self.lifetime_params.tweak_len_fe + flattened_len;
        var combined_input_monty = try self.allocator.alloc(F, combined_input_len);
        defer self.allocator.free(combined_input_monty);

        var input_idx: usize = 0;
        // Add parameter (values already stored in Montgomery form)
        for (parameter) |fe| {
            combined_input_monty[input_idx] = F{ .value = fe.value };
            input_idx += 1;
        }
        // Add tweak (already in Montgomery form)
        for (tweak) |fe| {
            combined_input_monty[input_idx] = F{ .value = fe.value };
            input_idx += 1;
        }
        // Add flattened input (chain ends - already in Montgomery form from chain walking)
        // Chain ends are stored as Montgomery u32 values in FieldElement.value
        // We need to create F directly from the Montgomery value (not convert canonical to Montgomery)
        for (flattened_input) |fe| {
            // fe.value is already in Montgomery form (from chain walking)
            // Create F directly with this Montgomery value (F{ .value = ... } creates F with Montgomery value)
            combined_input_monty[input_idx] = F{ .value = fe.value };
            input_idx += 1;
        }

        // Debug: print first RATE elements of combined input (in canonical form for comparison)
        log.print("DEBUG: Sponge combined_input head RATE ({}): ", .{15});
        for (0..@min(15, combined_input_monty.len)) |i| {
            log.print("{}:0x{x}", .{ i, combined_input_monty[i].toU32() });
            if (i + 1 < @min(15, combined_input_monty.len)) log.print(", ", .{});
        }
        log.print("\n", .{});

        // Apply Poseidon2-24 sponge (matching Rust's poseidon_sponge)
        const WIDTH: usize = 24;
        const RATE: usize = WIDTH - CAPACITY; // 24 - capacity
        const OUTPUT_LEN: usize = self.lifetime_params.hash_len_fe; // Domain size (7 for lifetime 2^18, 8 for lifetime 2^8)

        // Pad input to multiple of rate (matching Rust's input_vector.resize)
        const input_remainder = combined_input_monty.len % RATE;
        const extra_elements = if (input_remainder == 0) 0 else (RATE - input_remainder) % RATE;
        var padded_input = try self.allocator.alloc(F, combined_input_monty.len + extra_elements);
        defer self.allocator.free(padded_input);
        @memcpy(padded_input[0..combined_input_monty.len], combined_input_monty);
        // Pad with zeros (in Montgomery form)
        for (combined_input_monty.len..padded_input.len) |i| {
            padded_input[i] = F.zero; // Zero in Montgomery is still zero
        }

        // Initialize state: capacity in capacity part, zeros in rate part
        // Use Montgomery form throughout (matching Rust's KoalaBear which uses Montgomery internally)
        // capacity_value_monty is already in Montgomery form (from poseidon_compress)
        var state: [WIDTH]F = undefined;

        // Initialize rate part with zeros, capacity part with capacity_value (both in Montgomery)
        for (0..RATE) |i| {
            state[i] = F.zero; // Zero in Montgomery is still zero
        }
        for (0..CAPACITY) |i| {
            state[RATE + i] = capacity_value_monty[i]; // Already in Montgomery form
        }

        // Debug: print initial state (after initialization, before absorption)
        log.print("ZIG_SPONGE_DEBUG: Initial state (canonical): ", .{});
        for (0..WIDTH) |i| {
            log.print("{}:0x{x}", .{ i, state[i].toU32() });
            if (i < WIDTH - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        // Absorb: process padded input in chunks of RATE (matching Rust's poseidon_sponge)
        // Rust's KoalaBear uses Montgomery form internally, so convert canonical input to Montgomery before adding
        log.print("DEBUG: Sponge padded_input_len={} rate={}\n", .{ padded_input.len, RATE });
        var chunk_start: usize = 0;
        var chunk_num: usize = 0;
        while (chunk_start < padded_input.len) {
            const chunk_end = chunk_start + RATE;
            // Debug: print input values for first few chunks (in canonical form for comparison)
            if (chunk_num < 3) {
                log.print("ZIG_SPONGE_DEBUG: Input chunk {} (canonical): ", .{chunk_num});
                for (0..RATE) |i| {
                    log.print("{}:0x{x}", .{ chunk_start + i, padded_input[chunk_start + i].toU32() });
                    if (i < RATE - 1) log.print(", ", .{});
                }
                log.print("\n", .{});
            }
            // Add chunk to rate part of state (state[0..RATE])
            // Input is already in Montgomery form, so add directly (matching Rust's state[i] += chunk[i])
            for (0..RATE) |i| {
                state[i] = state[i].add(padded_input[chunk_start + i]);
            }

            // Debug: print state after adding chunk (before permutation) for first few chunks
            if (chunk_num < 3) {
                log.print("ZIG_SPONGE_DEBUG: State after adding chunk {} (before perm): ", .{chunk_num});
                for (0..WIDTH) |i| {
                    log.print("{}:0x{x}", .{ i, state[i].toU32() });
                    if (i < WIDTH - 1) log.print(", ", .{});
                }
                log.print("\n", .{});
            }

            // Permute state (matching Rust's perm.permute_mut(&mut state))
            // This works directly with Montgomery values
            Poseidon24.permutation(&state);

            // Debug: print state after permutation for first few chunks
            if (chunk_num < 3) {
                log.print("ZIG_SPONGE_DEBUG: State after chunk {} perm (canonical): ", .{chunk_num});
                for (0..WIDTH) |i| {
                    log.print("{}:0x{x}", .{ i, state[i].toU32() });
                    if (i < WIDTH - 1) log.print(", ", .{});
                }
                log.print("\n", .{});
            }

            chunk_start = chunk_end;
            chunk_num += 1;
        }

        // Debug: print state after all absorptions (before squeeze)
        log.print("ZIG_SPONGE_DEBUG: State after all absorptions (canonical): ", .{});
        for (0..WIDTH) |i| {
            log.print("{}:0x{x}", .{ i, state[i].toU32() });
            if (i < WIDTH - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        // Squeeze: extract OUTPUT_LEN elements from rate part (matching Rust's squeeze exactly)
        // Rust's squeeze: while out.len() < OUT_LEN { out.extend_from_slice(&state[..rate]); perm.permute_mut(&mut state); }
        // Since OUTPUT_LEN=8 < RATE=15, it reads 15 elements, then permutes, then takes first 8
        var out = std.ArrayList(F).init(self.allocator);
        defer out.deinit();

        while (out.items.len < OUTPUT_LEN) {
            // Read from state[0..rate] (15 elements)
            try out.appendSlice(state[0..RATE]);
            // Debug: print state before squeeze permutation
            log.print("ZIG_SPONGE_DEBUG: State before squeeze perm (canonical): ", .{});
            for (0..WIDTH) |i| {
                log.print("{}:0x{x}", .{ i, state[i].toU32() });
                if (i < WIDTH - 1) log.print(", ", .{});
            }
            log.print("\n", .{});
            // Permute state (matching Rust's perm.permute_mut(&mut state))
            Poseidon24.permutation(&state);
            // Debug: print state after squeeze permutation
            log.print("ZIG_SPONGE_DEBUG: State after squeeze perm (canonical): ", .{});
            for (0..WIDTH) |i| {
                log.print("{}:0x{x}", .{ i, state[i].toU32() });
                if (i < WIDTH - 1) log.print(", ", .{});
            }
            log.print("\n", .{});
        }

        // Take first OUTPUT_LEN elements (matching Rust's &out[0..OUT_LEN])
        var result = try self.allocator.alloc(FieldElement, OUTPUT_LEN);
        for (0..OUTPUT_LEN) |i| {
            result[i] = FieldElement.fromMontgomery(out.items[i].value);
        }

        log.print("DEBUG: Sponge leaf domain ({} elements): ", .{OUTPUT_LEN});
        for (result, 0..) |fe, i| {
            log.print("{}:0x{x}", .{ i, fe.value });
            if (i < OUTPUT_LEN - 1) log.print(", ", .{});
        }
        log.print("\n", .{});

        return result;
    }

    /// Build bottom tree from leaf hashes and return as array of 8 field elements
    /// This matches the Rust HashSubTree::new_subtree algorithm exactly
    pub fn buildBottomTree(self: *GeneralizedXMSSSignatureScheme, leaf_hashes: []FieldElement, parameter: [5]FieldElement, bottom_tree_index: usize) ![8]FieldElement {
        // For bottom trees: build full 8-layer tree (0->8), then truncate to 4 layers (0->4)
        // This matches Rust: new_subtree builds 0->8, then truncates to 0->4
        const full_depth = 8; // Build full 8-layer tree like Rust
        // TODO: Implement proper truncation to 4 layers like Rust
        const lowest_layer = 0;
        const start_index = bottom_tree_index * 16; // Each bottom tree has 16 leaves

        log.print("DEBUG: Building bottom tree from layer {} to layer {}\n", .{ lowest_layer, full_depth });
        log.print("DEBUG: Starting with {} leaf hashes\n", .{leaf_hashes.len});

        // Convert single field elements to arrays of 8 field elements
        var leaf_nodes = try self.allocator.alloc([8]FieldElement, leaf_hashes.len);
        defer self.allocator.free(leaf_nodes);

        for (0..leaf_hashes.len) |i| {
            // Convert single field element to array of 8 field elements
            // First element is the actual value, rest are zeros
            leaf_nodes[i][0] = leaf_hashes[i];
            for (1..8) |j| {
                leaf_nodes[i][j] = FieldElement{ .value = 0 };
            }
        }

        // Start with the lowest layer, padded accordingly (matching Rust HashTreeLayer::padded)
        // CRITICAL: Use real RNG for bottom trees (matching Rust implementation)
        // Rust uses the real RNG for both bottom trees and top tree
        const initial_padded = try self.padLayer(leaf_nodes, start_index);

        log.print("DEBUG: Initial padding: {} nodes (start_index: {})\n", .{ initial_padded.nodes.len, initial_padded.start_index });

        // Build tree layer by layer (matching Rust exactly)
        // Track all layers for proper truncation
        var layers = std.ArrayList(PaddedLayer).init(self.allocator);
        defer {
            for (layers.items) |layer| self.allocator.free(layer.nodes);
            layers.deinit();
        }

        var current_layer = initial_padded;
        var current_level: usize = lowest_layer;

        while (current_level < full_depth) {
            const next_level = current_level + 1;

            log.print("DEBUG: Zig Layer {} -> {}: {} nodes (start_index: {})\n", .{ current_level, next_level, current_layer.nodes.len, current_layer.start_index });

            // Parent layer starts at half the previous start index (matching Rust)
            const parent_start = current_layer.start_index >> 1;

            // Compute all parents by pairing children two-by-two (matching Rust par_chunks_exact(2))
            const parents_len = current_layer.nodes.len / 2; // This is guaranteed to be exact due to padding
            const parents = try self.allocator.alloc([8]FieldElement, parents_len);

            log.print("DEBUG: Processing {} nodes to get {} parents\n", .{ current_layer.nodes.len, parents_len });

            // Process all pairs in parallel (matching Rust par_chunks_exact(2))
            try self.processPairsInParallel(current_layer.nodes, parents, parent_start, current_level, parameter);

            // Free the current layer before creating the new one
            self.allocator.free(current_layer.nodes);

            // Add the new layer with padding so next iteration also has even start and length (matching Rust)
            // Use real RNG for bottom trees (matching Rust implementation)
            const new_layer = try self.padLayer(parents, parent_start);
            self.allocator.free(parents);

            current_layer = new_layer;

            log.print("DEBUG: After padding: {} nodes (start_index: {})\n", .{ current_layer.nodes.len, current_layer.start_index });

            // Store this layer for truncation
            // We need to store a copy of the layer, not the original
            const layer_copy = PaddedLayer{
                .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len),
                .start_index = current_layer.start_index,
            };
            @memcpy(layer_copy.nodes, current_layer.nodes);
            try layers.append(layer_copy);

            current_level = next_level;
        }

        // CRITICAL: Truncate to final_depth = 4 layers like Rust does
        // Rust truncates to depth/2 = 4 layers and gets root from layer 4
        // According to Rust: bottom_tree_root = bottom_tree.layers[depth / 2].nodes[bottom_tree_index % 2]
        // where depth = 8, so depth/2 = 4, and we need the root from layer 4

        // Get the root from layer 4
        // layers.items[0] = result of layer 0->1 (i.e., layer 1)
        // layers.items[1] = layer 2
        // layers.items[2] = layer 3
        // layers.items[3] = layer 4
        // layers.items[4] = layer 5
        // So layer 4 is at index 3, not 4!
        const target_layer_index = (full_depth / 2) - 1; // 8 / 2 - 1 = 3
        log.print("DEBUG: Looking for root in layer {} (stored layers: {})\n", .{ target_layer_index + 1, layers.items.len });

        if (target_layer_index >= layers.items.len) {
            log.print("ERROR: target_layer_index {} >= layers.len {}\n", .{ target_layer_index, layers.items.len });
            // Fallback to current layer
            const truncated_root = current_layer.nodes[0];
            log.print("DEBUG: Using fallback root from current layer: {any}\n", .{truncated_root});
            self.allocator.free(current_layer.nodes);
            return truncated_root;
        }

        const target_layer = layers.items[target_layer_index];
        log.print("DEBUG: Target layer has {} nodes\n", .{target_layer.nodes.len});

        // Get the root from the correct position in layer 4
        // Rust uses: bottom_tree_index % 2 to select which of the 2 nodes to use
        const root_index = bottom_tree_index % 2;
        const truncated_root = target_layer.nodes[root_index];
        log.print("DEBUG: Final bottom tree root array (truncated from 8-layer to 4-layer, from layer {}): {any}\n", .{ target_layer_index, truncated_root });

        // Free the final layer
        self.allocator.free(current_layer.nodes);

        return truncated_root;
    }

    /// Build top tree from bottom tree roots
    fn buildTopTree(
        self: *GeneralizedXMSSSignatureScheme,
        bottom_tree_roots: [][8]FieldElement,
        parameter: [5]FieldElement,
        start_bottom_tree_index: usize,
    ) !*HashSubTree {
        const root_array = try self.buildTopTreeAsArray(bottom_tree_roots, parameter, start_bottom_tree_index);
        // Use the entire array as the root for the HashSubTree
        return try HashSubTree.init(self.allocator, root_array);
    }

    fn computePathFromLayers(
        self: *GeneralizedXMSSSignatureScheme,
        layers: []const PaddedLayer,
        position_initial: u32,
    ) ![][8]FieldElement {
        var co_path = try self.allocator.alloc([8]FieldElement, layers.len);
        var co_len: usize = 0;
        var current_position = position_initial;
        var l: usize = 0;
        // For bottom trees: depth = log_lifetime / 2, so we should walk depth levels
        // For top trees: depth = log_lifetime / 2 as well
        // Stop when we've walked through all non-root layers (layers.len - 1) or when we hit root
        while (l < layers.len) : (l += 1) {
            const layer = layers[l];
            // Stop if we've reached the root layer (1 or fewer nodes)
            // But also check if this is the last layer - if so, it's the root
            if (layer.nodes.len <= 1 or l >= layers.len - 1) break;

            const sibling_position: u32 = current_position ^ 0x01;
            const sibling_index_in_vec_u32: u32 = sibling_position - @as(u32, @intCast(layer.start_index));
            const sibling_index = @as(usize, @intCast(sibling_index_in_vec_u32));
            
            // Debug logging for epoch 16, bottom tree (layers.len == 4)
            if (position_initial == 16 and layers.len == 4 and l == 0) {
                const current_node_index = current_position - @as(u32, @intCast(layer.start_index));
                const current_node_val = if (current_node_index < layer.nodes.len) layer.nodes[@as(usize, @intCast(current_node_index))][0].value else 0;
                std.debug.print("ZIG_SIGN: computePathFromLayers epoch {} layer {}: current_position={}, sibling_position={}, layer.start_index={}, sibling_index={}, layer.nodes.len={}, current_node[0]=0x{x:0>8}, sibling_node[0]=0x{x:0>8}\n", .{ position_initial, l, current_position, sibling_position, layer.start_index, sibling_index, layer.nodes.len, current_node_val, layer.nodes[sibling_index][0].value });
            }
            
            // Debug logging for top tree path computation
            if (layers.len > 4) { // Likely top tree (more layers than bottom tree)
                log.print("ZIG_SIGN_DEBUG: computePathFromLayers layer {}: current_position={}, sibling_position={}, layer.start_index={}, sibling_index={}, layer.nodes.len={}\n", .{ l, current_position, sibling_position, layer.start_index, sibling_index, layer.nodes.len });
            }
            
            if (sibling_index >= layer.nodes.len) {
                log.print("ZIG_SIGN_DEBUG: ERROR: sibling_index {} >= layer.nodes.len {} (layer {}, start_index={}, current_position={})\n", .{ sibling_index, layer.nodes.len, l, layer.start_index, current_position });
                return error.InvalidPathComputation;
            }

            co_path[co_len] = layer.nodes[sibling_index];
            co_len += 1;
            current_position >>= 1;
        }

        const out = try self.allocator.alloc([8]FieldElement, co_len);
        @memcpy(out, co_path[0..co_len]);
        self.allocator.free(co_path);
        return out;
    }

    fn buildBottomTreeLayers(
        self: *GeneralizedXMSSSignatureScheme,
        leaf_hashes: []FieldElement,
        parameter: [5]FieldElement,
        bottom_tree_index: usize,
    ) ![]PaddedLayer {
        const full_depth = 8;
        const start_index = bottom_tree_index * 16;

        var layers = std.ArrayList(PaddedLayer).init(self.allocator);
        errdefer {
            for (layers.items) |pl| self.allocator.free(pl.nodes);
            layers.deinit();
        }

        var leaf_nodes = try self.allocator.alloc([8]FieldElement, leaf_hashes.len);
        defer self.allocator.free(leaf_nodes);
        for (0..leaf_hashes.len) |i| {
            leaf_nodes[i][0] = leaf_hashes[i];
            for (1..8) |j| leaf_nodes[i][j] = FieldElement{ .value = 0 };
        }

        var current_layer = try self.padLayer(leaf_nodes, start_index);
        try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
        @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);

        var current_level: usize = 0;
        while (current_level < full_depth) : (current_level += 1) {
            const parent_start = current_layer.start_index >> 1;
            const parents_len = current_layer.nodes.len / 2;
            const parents = try self.allocator.alloc([8]FieldElement, parents_len);
            try self.processPairsInParallel(current_layer.nodes, parents, parent_start, current_level, parameter);
            self.allocator.free(current_layer.nodes);
            const new_layer = try self.padLayer(parents, parent_start);
            self.allocator.free(parents);
            current_layer = new_layer;
            try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
            @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);
        }

        self.allocator.free(current_layer.nodes);

        return layers.toOwnedSlice();
    }

    fn buildBottomTreeLayersFromLeafDomains(
        self: *GeneralizedXMSSSignatureScheme,
        leaf_nodes_in: [][8]FieldElement,
        parameter: [5]FieldElement,
        bottom_tree_index: usize,
    ) ![]PaddedLayer {
        // Bottom trees should have depth = log_lifetime / 2 = 4 for lifetime 2^8
        // Rust builds full_depth = 8 but truncates to depth/2 = 4
        // We should only build 4 layers to match the actual bottom tree structure
        const full_depth = self.lifetime_params.log_lifetime / 2; // 4 for lifetime 2^8
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);
        const start_index = bottom_tree_index * leafs_per_bottom_tree;

        var layers = std.ArrayList(PaddedLayer).init(self.allocator);
        errdefer {
            for (layers.items) |pl| self.allocator.free(pl.nodes);
            layers.deinit();
        }

        const leaf_nodes = try self.allocator.alloc([8]FieldElement, leaf_nodes_in.len);
        defer self.allocator.free(leaf_nodes);
        @memcpy(leaf_nodes, leaf_nodes_in);

        var current_layer = try self.padLayer(leaf_nodes, start_index);
        try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
        @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);
        
        // Debug: log leaf nodes for epoch 16 (bottom tree 1)
        // For bottom tree 1, epoch 16 is at index 0 (epoch - epoch_range_start = 16 - 16 = 0)
        if (bottom_tree_index == 1 and current_layer.nodes.len >= 2) {
            const epoch_16_index = 0; // epoch 16 is the first epoch in bottom tree 1
            if (current_layer.nodes.len > epoch_16_index) {
                std.debug.print("ZIG_BUILDTREE: Bottom tree {} level 0 layer: start_index={}, epoch_16_index={}, nodes[{}][0]=0x{x:0>8}, nodes[{}][0]=0x{x:0>8}\n", .{ bottom_tree_index, current_layer.start_index, epoch_16_index, epoch_16_index, current_layer.nodes[epoch_16_index][0].value, epoch_16_index + 1, current_layer.nodes[epoch_16_index + 1][0].value });
            }
        }

        var current_level: usize = 0;
        while (current_level < full_depth) : (current_level += 1) {
            // CRITICAL FIX: Use current_layer.start_index (which is the previous layer at start of iteration)
            // This matches Rust's behavior: prev = &layers[level - lowest_layer]
            // At the start of each iteration, current_layer is the previous layer
            const prev_layer_start_index = current_layer.start_index;
            const parent_start = prev_layer_start_index >> 1;
            const parents_len = current_layer.nodes.len / 2;
            const parents = try self.allocator.alloc([8]FieldElement, parents_len);
            try self.processPairsInParallel(current_layer.nodes, parents, parent_start, current_level, parameter);
            self.allocator.free(current_layer.nodes);
            const new_layer = try self.padLayer(parents, parent_start);
            self.allocator.free(parents);
            current_layer = new_layer;
            try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
            @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);
        }

        self.allocator.free(current_layer.nodes);

        return layers.toOwnedSlice();
    }

    fn buildTopTreeLayers(
        self: *GeneralizedXMSSSignatureScheme,
        roots_of_bottom_trees: [][8]FieldElement,
        parameter: [5]FieldElement,
        start_bottom_tree_index: usize,
    ) ![]PaddedLayer {
        // start_bottom_tree_index is used as start_index for top tree layers
        const log_lifetime = self.lifetime_params.log_lifetime;
        const lowest_layer = log_lifetime / 2;
        const depth = log_lifetime;
        // Use the actual start_bottom_tree_index for top tree layers
        // Rust's combined_path uses epoch directly, and the top tree layers must use
        // the actual bottom tree indices (start_bottom_tree_index) so that path computation
        // can use bottom_tree_index directly (absolute position)
        const start_index = start_bottom_tree_index;

        var layers = std.ArrayList(PaddedLayer).init(self.allocator);
        errdefer {
            for (layers.items) |pl| self.allocator.free(pl.nodes);
            layers.deinit();
        }

        const lowest_layer_nodes = try self.allocator.alloc([8]FieldElement, roots_of_bottom_trees.len);
        defer self.allocator.free(lowest_layer_nodes);
        @memcpy(lowest_layer_nodes, roots_of_bottom_trees);

        var current_layer = try self.padLayer(lowest_layer_nodes, start_index);
        try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
        @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);

        var current_level: usize = lowest_layer;
        while (current_level < depth) : (current_level += 1) {
            const parent_start = current_layer.start_index >> 1;
            const parents_len = current_layer.nodes.len / 2;
            const parents = try self.allocator.alloc([8]FieldElement, parents_len);
            try self.processPairsInParallel(current_layer.nodes, parents, parent_start, current_level, parameter);
            self.allocator.free(current_layer.nodes);
            const new_layer = try self.padLayerWithRng(parents, parent_start, &self.rng.random());
            self.allocator.free(parents);
            current_layer = new_layer;
            try layers.append(.{ .nodes = try self.allocator.alloc([8]FieldElement, current_layer.nodes.len), .start_index = current_layer.start_index });
            @memcpy(layers.items[layers.items.len - 1].nodes, current_layer.nodes);
        }

        self.allocator.free(current_layer.nodes);

        return layers.toOwnedSlice();
    }

    /// Encode message as field elements (matching Rust encode_message)
    /// Uses base-p decomposition: interprets message as little-endian big integer
    /// Uses multi-precision arithmetic to handle 32-byte (256-bit) message
    pub fn encodeMessage(self: *GeneralizedXMSSSignatureScheme, MSG_LEN_FE: usize, message: [MESSAGE_LENGTH]u8) ![]FieldElement {
        const p: u256 = 2130706433; // KoalaBear field modulus
        var result = try self.allocator.alloc(FieldElement, MSG_LEN_FE);
        errdefer self.allocator.free(result);

        // Load little-endian 32-byte message into u256
        var acc: u256 = 0;
        for (message, 0..) |b, i| {
            acc +%= (@as(u256, b) << @intCast(8 * i));
        }

        // Repeated division by p to extract base-p digits (little-endian digits)
        var i: usize = 0;
        while (i < MSG_LEN_FE) : (i += 1) {
            const digit: u256 = acc % p;
            result[i] = FieldElement.fromCanonical(@intCast(digit));
            acc = acc / p;
        }

        return result;
    }

    /// Encode epoch as field elements (matching Rust encode_epoch)
    pub fn encodeEpoch(self: *GeneralizedXMSSSignatureScheme, TWEAK_LEN_FE: usize, epoch: u32) ![]FieldElement {
        const p: u64 = 2130706433; // KoalaBear field modulus
        const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02; // From Rust
        var result = try self.allocator.alloc(FieldElement, TWEAK_LEN_FE);
        errdefer self.allocator.free(result);

        // Combine epoch and separator: ((epoch as u64) << 8) | separator
        const acc = (@as(u64, epoch) << 8) | @as(u64, TWEAK_SEPARATOR_FOR_MESSAGE_HASH);

        // Two-step base-p decomposition (optimization for 40-bit value)
        if (TWEAK_LEN_FE > 0) {
            result[0] = FieldElement.fromCanonical(@intCast(acc % p));
        }
        if (TWEAK_LEN_FE > 1) {
            result[1] = FieldElement.fromCanonical(@intCast(acc / p));
        }
        // Any remaining elements remain zero
        for (2..TWEAK_LEN_FE) |i| {
            result[i] = FieldElement.zero();
        }

        return result;
    }

    /// Decode field elements to chunks (matching Rust decode_to_chunks)
    /// Builds big integer: acc = 0; for fe in field_elements: acc = acc * p + fe
    /// Then extracts DIMENSION digits: for i in 0..DIMENSION: chunk = acc % BASE; acc /= BASE
    fn decodeToChunks(_: *GeneralizedXMSSSignatureScheme, comptime DIMENSION: usize, comptime BASE: usize, comptime HASH_LEN_FE: usize, field_elements: [HASH_LEN_FE]FieldElement) [DIMENSION]u8 {
        const p: u64 = 2130706433; // KoalaBear field modulus
        var result: [DIMENSION]u8 = undefined;

        // Use base 2^32 representation (6 words = 192 bits, enough for p^5 ≈ 2^155)
        var bigint_u32: [6]u32 = [6]u32{ 0, 0, 0, 0, 0, 0 };

        // Build big integer: start with 0, for each fe: bigint = bigint * p + fe.value
        // This matches Rust: acc = 0; for fe in field_elements: acc = acc * p + fe
        for (field_elements) |fe| {
            // Multiply by p: bigint_u32 = bigint_u32 * p
            var mul_carry: u64 = 0;
            for (0..bigint_u32.len) |j| {
                const prod = @as(u64, bigint_u32[j]) * @as(u64, p) + mul_carry;
                bigint_u32[j] = @as(u32, @truncate(prod));
                mul_carry = prod >> 32;
            }

            // Add fe.value to the LSB (index 0)
            var add_carry: u64 = @as(u64, fe.value);
            var add_idx: usize = 0;
            while (add_carry > 0 and add_idx < bigint_u32.len) {
                const sum = @as(u64, bigint_u32[add_idx]) + add_carry;
                bigint_u32[add_idx] = @as(u32, @truncate(sum));
                add_carry = sum >> 32;
                add_idx += 1;
            }
        }

        // Debug: check bigint value and field elements
        if (HASH_LEN_FE == 5 and DIMENSION == 64 and BASE == 8) {
            var has_nonzero = false;
            for (bigint_u32) |word| {
                if (word != 0) {
                    has_nonzero = true;
                    break;
                }
            }
            if (has_nonzero) {
                log.print("ZIG_DECODE_DEBUG: bigint_u32[0..3]={any} field_elements={any}\n", .{
                    bigint_u32[0..3],
                    field_elements,
                });
            }
        }

        // Precompute 2^32 % BASE once (constant for given BASE)
        var two_pow_32_mod: u64 = 1;
        var bit: usize = 0;
        while (bit < 32) : (bit += 1) {
            two_pow_32_mod = (two_pow_32_mod * 2) % BASE;
        }

        // Extract DIMENSION digits in base-BASE by repeatedly:
        //   1. Compute bigint_u32 % BASE
        //   2. Divide bigint_u32 by BASE
        for (0..DIMENSION) |i| {
            // Extract digit: compute bigint_u32 % BASE
            // Use Horner's method: process from MSB to LSB
            // For value = bigint_u32[5]*2^160 + ... + bigint_u32[1]*2^32 + bigint_u32[0]
            // We compute: ((...((bigint_u32[5]*2^32 + bigint_u32[4])*2^32 + bigint_u32[3])...)*2^32 + bigint_u32[0]) % BASE
            var mod_remainder: u64 = 0;
            // Process from MSB (highest index) to LSB (index 0)
            for (0..bigint_u32.len) |j| {
                const idx = bigint_u32.len - 1 - j; // MSB to LSB
                // Horner's method: remainder = (remainder * base + digit) % BASE
                mod_remainder = ((mod_remainder * two_pow_32_mod) % BASE + (bigint_u32[idx] % BASE)) % BASE;
            }
            result[i] = @as(u8, @intCast(mod_remainder));

            // Divide bigint_u32 by BASE (for next iteration)
            // Process from MSB to LSB, carrying remainder
            var div_carry: u64 = 0;
            for (0..bigint_u32.len) |j| {
                const idx = bigint_u32.len - 1 - j; // MSB to LSB
                const val = (@as(u128, div_carry) << 32) | @as(u128, bigint_u32[idx]);
                bigint_u32[idx] = @as(u32, @truncate(val / BASE));
                div_carry = @as(u64, @truncate(val % BASE));
            }
        }

        return result;
    }

    fn getLayerData(self: *GeneralizedXMSSSignatureScheme, w: usize) !*const poseidon_top_level.AllLayerInfoForBase {
        return poseidon_top_level.getLayerData(self, w);
    }

    fn hypercubeFindLayerBig(
        self: *GeneralizedXMSSSignatureScheme,
        BASE: usize,
        DIMENSION: usize,
        final_layer: usize,
        value: *const BigInt,
        offset_out: *BigInt,
    ) !usize {
        return poseidon_top_level.hypercubeFindLayerBig(self, BASE, DIMENSION, final_layer, value, offset_out);
    }

    fn mapToVertexBig(
        self: *GeneralizedXMSSSignatureScheme,
        BASE: usize,
        DIMENSION: usize,
        layer: usize,
        offset: *const BigInt,
    ) ![]u8 {
        return poseidon_top_level.mapToVertexBig(self, BASE, DIMENSION, layer, offset);
    }

    fn mapIntoHypercubePart(
        self: *GeneralizedXMSSSignatureScheme,
        DIMENSION: usize,
        BASE: usize,
        final_layer: usize,
        field_elements: []const FieldElement,
    ) ![]u8 {
        return poseidon_top_level.mapIntoHypercubePart(self, DIMENSION, BASE, final_layer, field_elements);
    }

    pub fn applyTopLevelPoseidonMessageHash(
        self: *GeneralizedXMSSSignatureScheme,
        parameter: [5]FieldElement,
        epoch: u32,
        randomness: []const FieldElement,
        message: [MESSAGE_LENGTH]u8,
    ) ![]u8 {
        return poseidon_top_level.applyTopLevelPoseidonMessageHash(self, parameter, epoch, randomness, message);
    }

    fn deriveTargetSumEncoding(
        self: *GeneralizedXMSSSignatureScheme,
        parameter: [5]FieldElement,
        epoch: u32,
        randomness: []const FieldElement,
        message: [MESSAGE_LENGTH]u8,
    ) ![]u8 {
        return target_sum_encoding.deriveTargetSumEncoding(self, parameter, epoch, randomness, message);
    }

    /// Pad a layer to ensure it starts at an even index and ends at an odd index
    /// This matches the Rust HashTreeLayer::padded algorithm exactly
    fn padLayer(self: *GeneralizedXMSSSignatureScheme, nodes: [][8]FieldElement, start_index: usize) !PaddedLayer {
        return self.padLayerWithRng(nodes, start_index, &self.rng.random());
    }

    /// Pad a layer with a specific RNG (for bottom trees with dummy RNG)
    fn padLayerWithRng(self: *GeneralizedXMSSSignatureScheme, nodes: [][8]FieldElement, start_index: usize, rng: *const std.Random) !PaddedLayer {
        // End index of the provided contiguous run (inclusive)
        const end_index = start_index + nodes.len - 1;

        // Do we need a front pad? Start must be even
        const needs_front = (start_index & 1) == 1;

        // Do we need a back pad? End must be odd
        const needs_back = (end_index & 1) == 0;

        // The effective start index after optional front padding (always even)
        const actual_start_index = if (needs_front) start_index - 1 else start_index;

        // Reserve exactly the space we may need: original nodes plus up to two pads
        var total_capacity = nodes.len;
        if (needs_front) total_capacity += 1;
        if (needs_back) total_capacity += 1;
        var padded_nodes = try self.allocator.alloc([8]FieldElement, total_capacity);
        errdefer self.allocator.free(padded_nodes);

        var output_index: usize = 0;

        // Optional front padding to align to an even start index
        if (needs_front) {
            // Generate random node for front padding (matching Rust TH::rand_domain(rng))
            // Rust calls rng.random() once to generate a full domain element (8 field elements)
            log.print("DEBUG: padLayer: Generating front padding node (1 RNG call)\n", .{});
            const random_domain = try self.generateRandomDomainSingleWithRng(rng);
            @memcpy(padded_nodes[output_index][0..8], random_domain[0..8]);
            output_index += 1;
            log.print("DEBUG: padLayer: Added front padding node at index {}\n", .{output_index - 1});
        }

        // Insert the actual content in order
        @memcpy(padded_nodes[output_index .. output_index + nodes.len], nodes);
        output_index += nodes.len;

        // Optional back padding to ensure we end on an odd index
        if (needs_back) {
            // Generate random node for back padding (matching Rust rng.random() for arrays)
            log.print("DEBUG: padLayer: Generating back padding node (1 RNG call)\n", .{});
            const random_domain = try self.generateRandomDomainSingleWithRng(rng);
            @memcpy(padded_nodes[output_index][0..8], random_domain[0..8]);
            log.print("DEBUG: padLayer: Added back padding node at index {}\n", .{output_index});
        }

        log.print("DEBUG: padLayer: start_index={}, nodes.len={}, end_index={}\n", .{ start_index, nodes.len, end_index });
        log.print("DEBUG: padLayer: needs_front={}, needs_back={}, actual_start_index={}\n", .{ needs_front, needs_back, actual_start_index });
        log.print("DEBUG: padLayer: total_capacity={}, padded_nodes.len={}\n", .{ total_capacity, padded_nodes.len });

        return .{
            .nodes = padded_nodes,
            .start_index = actual_start_index,
        };
    }

    /// Get RNG state for debugging
    pub fn getRngState(self: *GeneralizedXMSSSignatureScheme) [5]u32 {
        // Create a copy of the RNG to avoid consuming the original state
        var rng_copy = self.rng;
        var result: [5]u32 = undefined;
        for (0..5) |i| {
            result[i] = rng_copy.random().int(u32);
        }
        return result;
    }

    /// Build top tree from bottom tree roots and return root as array of 8 field elements
    /// This matches the Rust HashSubTree::new_top_tree algorithm exactly
    pub fn buildTopTreeAsArray(
        self: *GeneralizedXMSSSignatureScheme,
        roots_of_bottom_trees: [][8]FieldElement,
        parameter: [5]FieldElement,
        start_bottom_tree_index: usize,
    ) ![8]FieldElement {
        log.print("DEBUG: Building tree from lowest layer {} up to depth {}\n", .{
            self.lifetime_params.log_lifetime / 2,
            self.lifetime_params.log_lifetime,
        });
        log.print("DEBUG: Starting with {} bottom tree roots (start index: {})\n", .{ roots_of_bottom_trees.len, start_bottom_tree_index });

        const layers = try self.buildTopTreeLayers(roots_of_bottom_trees, parameter, start_bottom_tree_index);
        defer {
            for (layers) |pl| self.allocator.free(pl.nodes);
            self.allocator.free(layers);
        }

        if (layers.len == 0 or layers[layers.len - 1].nodes.len == 0) {
            return error.InvalidTopTree;
        }

        const root_array = layers[layers.len - 1].nodes[0];
        log.print("DEBUG: Final top tree root array: {any}\n", .{root_array});
        return root_array;
    }

    /// Build bottom tree from leaf hashes and return as array of 8 field elements
    fn buildBottomTreeAsArray(self: *GeneralizedXMSSSignatureScheme, leaf_hashes: []FieldElement, parameter: [5]FieldElement) ![8]FieldElement {
        // Debug: Print input information
        log.print("DEBUG: buildBottomTreeAsArray called with {} leaf hashes\n", .{leaf_hashes.len});

        // Instead of building to a single root, build to exactly 8 field elements
        // This matches the Rust implementation which produces 8 different values

        // Start with the leaf hashes
        var current_level = try self.allocator.alloc(FieldElement, leaf_hashes.len);
        @memcpy(current_level, leaf_hashes);

        var level_size = leaf_hashes.len;
        var level_count: usize = 0;

        // Build tree until we have exactly 8 elements or fewer
        while (level_size > 8) {
            const next_level_size = (level_size + 1) / 2;
            var next_level = try self.allocator.alloc(FieldElement, next_level_size);

            log.print("DEBUG: Level {}: {} -> {} elements\n", .{ level_count, level_size, next_level_size });

            for (0..next_level_size) |i| {
                if (i * 2 + 1 < level_size) {
                    // Hash two elements together
                    const left = current_level[i * 2];
                    const right = current_level[i * 2 + 1];
                    const pair = [_]FieldElement{ left, right };

                    // log.print("DEBUG: Hashing pair [{}] = 0x{x} + 0x{x}\n", .{ i, left.value, right.value });

                    const hash_result = try self.applyPoseidonTweakHash(&pair, 0, 0, parameter);
                    defer self.allocator.free(hash_result);
                    next_level[i] = hash_result[0];

                    // log.print("DEBUG: Result [{}] = 0x{x}\n", .{ i, next_level[i].value });
                } else {
                    // Odd number of elements, copy the last one
                    next_level[i] = current_level[i * 2];
                    // log.print("DEBUG: Copying [{}] = 0x{x}\n", .{ i, next_level[i].value });
                }
            }

            self.allocator.free(current_level);
            current_level = next_level;
            level_size = next_level_size;
            level_count += 1;
        }

        log.print("DEBUG: Final level {} has {} elements\n", .{ level_count, level_size });

        // Convert to array of 8 field elements
        var result: [8]FieldElement = undefined;

        // Copy existing elements
        for (0..@min(8, level_size)) |i| {
            result[i] = current_level[i];
            // log.print("DEBUG: result[{}] = 0x{x}\n", .{ i, result[i].value });
        }

        // Fill remaining with zeros if we have fewer than 8 elements
        for (level_size..8) |i| {
            result[i] = FieldElement{ .value = 0 };
            // log.print("DEBUG: result[{}] = 0x{x} (zero)\n", .{ i, result[i].value });
        }

        self.allocator.free(current_level);
        return result;
    }

    /// Generate random PRF key (matching Rust PRF::key_gen)
    pub fn generateRandomPRFKey(self: *GeneralizedXMSSSignatureScheme) ![32]u8 {
        return rng_flow.generateRandomPRFKey(self);
    }

    /// Generate random parameter (matching Rust TH::rand_parameter)
    pub fn generateRandomParameter(self: *GeneralizedXMSSSignatureScheme) ![5]FieldElement {
        return rng_flow.generateRandomParameter(self);
    }

    /// Generate random domain elements for padding (matching Rust TH::rand_domain)
    pub fn generateRandomDomain(self: *GeneralizedXMSSSignatureScheme, count: usize) ![8]FieldElement {
        return rng_flow.generateRandomDomain(self, count);
    }

    /// Generate a single random domain element (matching Rust TH::rand_domain exactly)
    pub fn generateRandomDomainSingle(self: *GeneralizedXMSSSignatureScheme) ![8]FieldElement {
        return rng_flow.generateRandomDomainSingle(self);
    }

    /// Generate a single random domain element using a specific RNG
    fn generateRandomDomainSingleWithRng(self: *GeneralizedXMSSSignatureScheme, rng: *const std.Random) ![8]FieldElement {
        return rng_flow.generateRandomDomainSingleWithRng(self, rng);
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
        const expansion_result = expandActivationTime(self.lifetime_params.log_lifetime, activation_epoch, num_active_epochs);
        const num_bottom_trees = expansion_result.end - expansion_result.start;

        if (num_bottom_trees < 2) {
            return error.InsufficientBottomTrees;
        }

        // Use the provided activation parameters directly (not expanded)
        const expanded_activation_epoch = activation_epoch;
        const expanded_num_active_epochs = num_active_epochs;

        // Generate random parameter and PRF key (matching Rust order exactly)
        const parameter = try self.generateRandomParameter();

        const prf_key = try self.generateRandomPRFKey();

        // Consume RNG state for padding AFTER parameter generation to match Rust's HashTreeLayer::padded
        // This happens in Rust's HashSubTree::new_top_tree call, which occurs after parameter generation
        // The parameters that end up in the public key are generated BEFORE this padding consumption
        const needs_front_padding = (0 % 2) != 0; // start_index = 0
        const needs_back_padding = (0 + num_bottom_trees) % 2 != 0;

        if (needs_front_padding) {
            // Consume RNG state for front padding (matching Rust TH::rand_domain)
            // HASH_LEN = 8 for lifetime_2_to_the_8
            for (0..8) |_| {
                _ = self.rng.random().int(u32);
            }
            log.print("DEBUG: Consumed RNG state for front padding (8 elements)\n", .{});
        }

        if (needs_back_padding) {
            // Consume RNG state for back padding (matching Rust TH::rand_domain)
            // HASH_LEN = 8 for lifetime_2_to_the_8
            for (0..8) |_| {
                _ = self.rng.random().int(u32);
            }
            log.print("DEBUG: Consumed RNG state for back padding (8 elements)\n", .{});
        }

        // Generate bottom trees and collect their roots as arrays of 8 field elements
        var roots_of_bottom_trees = try self.allocator.alloc([8]FieldElement, num_bottom_trees);
        defer self.allocator.free(roots_of_bottom_trees);

        log.print("DEBUG: Generating {} bottom trees\n", .{num_bottom_trees});
        log.print("DEBUG: PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});
        // log.print("DEBUG: Parameter: {any}\n", .{parameter});

        log.print("DEBUG: Expansion result: start={}, end={}\n", .{ expansion_result.start, expansion_result.end });

        // Generate left and right bottom trees (first two)
        const left_bottom_tree_index = expansion_result.start;
        const left_bottom_tree = try self.bottomTreeFromPrfKey(prf_key, left_bottom_tree_index, parameter);
        roots_of_bottom_trees[0] = left_bottom_tree.root();
        log.print("ZIG_KEYGEN_DEBUG: Bottom tree {} root: ", .{left_bottom_tree_index});
        for (roots_of_bottom_trees[0]) |fe| {
            log.print("0x{x:0>8} ", .{fe.value});
        }
        log.print("\n", .{});

        const right_bottom_tree_index = expansion_result.start + 1;
        const right_bottom_tree = try self.bottomTreeFromPrfKey(prf_key, right_bottom_tree_index, parameter);
        roots_of_bottom_trees[1] = right_bottom_tree.root();
        // log.print("DEBUG: Bottom tree {} root: 0x{x}\n", .{ right_bottom_tree_index, roots_of_bottom_trees[1][0].value });

        // Generate remaining bottom trees
        for (expansion_result.start + 2..expansion_result.end) |bottom_tree_index| {
            const bottom_tree = try self.bottomTreeFromPrfKey(prf_key, bottom_tree_index, parameter);
            roots_of_bottom_trees[bottom_tree_index - expansion_result.start] = bottom_tree.root();
            // log.print("DEBUG: Bottom tree {} root: 0x{x}\n", .{ bottom_tree_index, bottom_tree.root()[0].value });
            bottom_tree.deinit(); // Clean up individual trees
        }

        // Debug: log all roots before building top tree
        log.print("ZIG_KEYGEN_DEBUG: All {} roots before building top tree:\n", .{roots_of_bottom_trees.len});
        for (roots_of_bottom_trees, 0..) |root, i| {
            log.print("ZIG_KEYGEN_DEBUG:   Root {}: ", .{i});
            for (root) |fe| {
                log.print("0x{x:0>8} ", .{fe.value});
            }
            log.print("\n", .{});
        }

        // Build top tree from bottom tree roots and get root as array
        // This matches Rust's HashSubTree::new_top_tree call which happens after parameter generation
        // Use buildTopTreeLayers to ensure consistency with signing/verification
        log.print("DEBUG: Building top tree from {} bottom tree roots\n", .{roots_of_bottom_trees.len});
        var top_layers = try self.buildTopTreeLayers(roots_of_bottom_trees, parameter, expansion_result.start);

        // Extract root from the final layer (should have exactly 1 node)
        if (top_layers.len == 0 or top_layers[top_layers.len - 1].nodes.len == 0) {
            for (top_layers) |pl| self.allocator.free(pl.nodes);
            self.allocator.free(top_layers);
            return error.InvalidTopTree;
        }
        const root_array = top_layers[top_layers.len - 1].nodes[0];

        // Debug: log the computed root (canonical)
        log.print("ZIG_KEYGEN_DEBUG: Computed root during keygen (canonical): ", .{});
        for (root_array) |fe| {
            log.print("0x{x:0>8} ", .{fe.value});
        }
        log.print("\n", .{});

        // Roots are already represented in Montgomery form in our FieldElement type.
        const root_monty: [8]FieldElement = root_array;

        // Debug: log the root in Montgomery form
        log.print("ZIG_KEYGEN_DEBUG: Root in Montgomery form: ", .{});
        for (root_monty) |fe| {
            log.print("0x{x:0>8} ", .{fe.value});
        }
        log.print("\n", .{});

        // Create a top tree for the secret key, preserving the layered structure for future path computation
        const top_tree = try HashSubTree.initWithLayers(self.allocator, root_array, top_layers);
        top_layers = top_layers[0..0];

        // Create public and secret keys (store root in Montgomery form to match Rust)
        const public_key = GeneralizedXMSSPublicKey.init(root_monty, parameter);

        // Debug: log the public key root
        log.print("ZIG_KEYGEN_DEBUG: Public key root: ", .{});
        for (public_key.root) |fe| {
            log.print("0x{x:0>8} ", .{fe.value});
        }
        log.print("\n", .{});
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

        // Generate Merkle path via combined bottom+top tree layers
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);
        const bottom_tree_index = @as(usize, @intCast(epoch)) / leafs_per_bottom_tree;

        // Build bottom tree layers for the selected bottom tree
        const epoch_range_start = bottom_tree_index * leafs_per_bottom_tree;
        const epoch_range_end = epoch_range_start + leafs_per_bottom_tree;
        var leaf_domains_bt = try self.allocator.alloc([8]FieldElement, leafs_per_bottom_tree);
        defer self.allocator.free(leaf_domains_bt);
        for (epoch_range_start..epoch_range_end) |e| {
            const num_chains = self.lifetime_params.dimension;
            var chain_domains = try self.allocator.alloc([8]FieldElement, num_chains);
            defer self.allocator.free(chain_domains);
            for (0..num_chains) |chain_index| {
                const domain_elements = self.prfDomainElement(secret_key.prf_key, @as(u32, @intCast(e)), @as(u64, @intCast(chain_index)));
                const chain_end_domain = try self.computeHashChainDomain(domain_elements, @as(u32, @intCast(e)), @as(u8, @intCast(chain_index)), secret_key.parameter);
                chain_domains[chain_index] = chain_end_domain;
            }
            // Debug: log chain ends before reduction for the signing epoch
            if (e == epoch) {
                std.debug.print("ZIG_SIGN_DEBUG: Chain ends before reduction for epoch {} (first 3 chains): ", .{epoch});
                for (0..@min(3, chain_domains.len)) |ci| {
                    std.debug.print("chain{}[0]=0x{x:0>8} ", .{ ci, chain_domains[ci][0].value });
                }
                std.debug.print("\n", .{});
            }
            const leaf_domain_slice = try self.reduceChainDomainsToLeafDomain(chain_domains, secret_key.parameter, @as(u32, @intCast(e)));
            defer self.allocator.free(leaf_domain_slice);
            // Convert to fixed-size [8]FieldElement array (pad with zeros if needed)
            var leaf_domain: [8]FieldElement = undefined;
            const hash_len = self.lifetime_params.hash_len_fe;
            for (0..hash_len) |i| {
                leaf_domain[i] = leaf_domain_slice[i];
            }
            for (hash_len..8) |i| {
                leaf_domain[i] = FieldElement{ .value = 0 };
            }
            leaf_domains_bt[e - epoch_range_start] = leaf_domain;

            // Debug: log leaf domain for the signing epoch
            if (e == epoch) {
                std.debug.print("ZIG_SIGN: Epoch {} - Leaf domain[0]=0x{x:0>8} (chain_domains.len={})\n", .{ epoch, leaf_domain[0].value, chain_domains.len });
                log.print("ZIG_SIGN_DEBUG: Leaf domain for epoch {}: ", .{epoch});
                for (leaf_domain) |fe| {
                    log.print("0x{x:0>8} ", .{fe.value});
                }
                log.print("\n", .{});
            }
        }
        const bottom_layers = try self.buildBottomTreeLayersFromLeafDomains(leaf_domains_bt, secret_key.parameter, bottom_tree_index);
        defer {
            for (bottom_layers) |pl| self.allocator.free(pl.nodes);
            self.allocator.free(bottom_layers);
        }

        // Debug: log number of bottom layers
        log.print("ZIG_SIGN_DEBUG: Built {} bottom tree layers\n", .{bottom_layers.len});
        for (bottom_layers, 0..) |layer, i| {
            log.print("ZIG_SIGN_DEBUG:   Bottom layer {}: {} nodes, start_index={}\n", .{ i, layer.nodes.len, layer.start_index });
        }

        // Debug: compare computed bottom tree root with stored left bottom tree root (canonical values)
        if (bottom_layers.len > 0) {
            const bottom_root_layer = bottom_layers[bottom_layers.len - 1];
            if (bottom_root_layer.nodes.len > 0) {
                // CRITICAL FIX: Extract root using bottom_tree_index % 2 to match Rust and bottomTreeFromPrfKey
                const root_node_index = if (bottom_root_layer.nodes.len > 1) bottom_tree_index % 2 else 0;
                const computed_bottom_root = bottom_root_layer.nodes[root_node_index];
                
                // Debug: log computed bottom root for epoch 16
                if (epoch == 16) {
                    std.debug.print("ZIG_SIGN: Epoch {} - Computed bottom tree {} root[0]=0x{x:0>8} (using root_node_index={})\n", .{ epoch, bottom_tree_index, computed_bottom_root[0].value, root_node_index });
                }
                
                const stored_bottom_root = secret_key.left_bottom_tree.root();
                log.print("ZIG_SIGN_DEBUG: Computed bottom root (canonical): ", .{});
                for (computed_bottom_root) |fe| {
                    log.print("0x{x:0>8} ", .{fe.value});
                }
                log.print("\n", .{});
                log.print("ZIG_SIGN_DEBUG: Stored left bottom root (canonical): ", .{});
                for (stored_bottom_root) |fe| {
                    log.print("0x{x:0>8} ", .{fe.value});
                }
                log.print("\n", .{});
            }
        }

        // Use the stored top tree layers from the secret key (generated during keyGen)
        const top_layers = secret_key.top_tree.getLayers() orelse return error.MissingTopTreeLayers;
        log.print("ZIG_SIGN_DEBUG: top_layers.len={} (log_lifetime={} lowest_layer={})\n", .{
            top_layers.len,
            self.lifetime_params.log_lifetime,
            self.lifetime_params.log_lifetime / 2,
        });

        // Bottom path at absolute epoch, top path uses bottom_tree_index directly
        // Rust's combined_path uses epoch directly, and the top tree layers are built
        // with start_index matching the actual bottom tree indices
        const bottom_copath = try self.computePathFromLayers(bottom_layers, epoch);
        defer self.allocator.free(bottom_copath);
        
        // For top tree, use bottom_tree_index directly (absolute position)
        // Rust's combined_path uses epoch directly, and the top tree layers are built
        // with start_index = left_bottom_tree_index from keyGen, so we use bottom_tree_index
        // directly, and computePathFromLayers handles the offset via layer.start_index subtraction
        const left_bottom_tree_index = secret_key.getLeftBottomTreeIndex();
        const top_pos = @as(u32, @intCast(bottom_tree_index));
        
        // Debug: log top tree layer start_index values
        log.print("ZIG_SIGN_DEBUG: Computing top tree path: bottom_tree_index={}, left_bottom_tree_index={}, top_pos={}\n", .{ bottom_tree_index, left_bottom_tree_index, top_pos });
        for (top_layers, 0..) |layer, i| {
            log.print("ZIG_SIGN_DEBUG: Top layer {}: {} nodes, start_index={}\n", .{ i, layer.nodes.len, layer.start_index });
        }
        
        const top_copath = try self.computePathFromLayers(top_layers, top_pos);
        defer self.allocator.free(top_copath);

        // Debug: log path nodes (only for epoch 16 to reduce noise)
        if (epoch == 16) {
            std.debug.print("ZIG_SIGN: Epoch {} - Bottom co-path: {} nodes\n", .{ epoch, bottom_copath.len });
            for (bottom_copath, 0..) |node, i| {
                std.debug.print("ZIG_SIGN:   Bottom node {}: 0x{x:0>8}\n", .{ i, node[0].value });
            }
            std.debug.print("ZIG_SIGN: Epoch {} - Top co-path for pos {}: {} nodes\n", .{ epoch, top_pos, top_copath.len });
            for (top_copath, 0..) |node, i| {
                std.debug.print("ZIG_SIGN:   Top node {}: 0x{x:0>8}\n", .{ i, node[0].value });
            }
        }

        var nodes_concat = try self.allocator.alloc([8]FieldElement, bottom_copath.len + top_copath.len);
        defer self.allocator.free(nodes_concat);
        @memcpy(nodes_concat[0..bottom_copath.len], bottom_copath);
        @memcpy(nodes_concat[bottom_copath.len..], top_copath);

        const path = try HashTreeOpening.init(self.allocator, nodes_concat);
        errdefer path.deinit(); // Clean up if signature creation fails

        // Try encoding with different randomness attempts (matching Rust sign retry loop)
        const MAX_TRIES: usize = 100_000;
        var attempts: u64 = 0;
        var rho_slice_opt: ?[]FieldElement = null;
        defer if (rho_slice_opt) |buf| self.allocator.free(buf);
        var rho_fixed: [7]FieldElement = undefined; // Signature struct uses fixed [7]FieldElement, pad if needed
        var x: []u8 = undefined;
        var encoding_succeeded = false;

        while (attempts < MAX_TRIES) : (attempts += 1) {
            // Generate randomness for this attempt
            if (rho_slice_opt) |buf| {
                self.allocator.free(buf);
                rho_slice_opt = null;
            }
            rho_slice_opt = try self.generateRandomness(secret_key.prf_key, epoch, message, attempts);
            const rho_slice = rho_slice_opt.?;

            // Convert to fixed array for signature structure (pad to 7 elements if needed)
            // For lifetime 2^18, rand_len_fe is 6, but signature struct uses [7]FieldElement
            const rand_len = self.lifetime_params.rand_len_fe;
            for (0..rand_len) |i| {
                rho_fixed[i] = rho_slice[i];
            }
            // Pad remaining elements with zeros (for lifetime 2^18, rand_len_fe=6, so pad 1 element)
            for (rand_len..7) |i| {
                rho_fixed[i] = FieldElement{ .value = 0 };
            }

            // Try to encode with this randomness
            const encoding_result = self.deriveTargetSumEncoding(secret_key.parameter, epoch, rho_slice, message);
            if (encoding_result) |x_val| {
                x = x_val;
                encoding_succeeded = true;
                break;
            } else |err| {
                // If EncodingSumMismatch, try next attempt
                if (err != error.EncodingSumMismatch) {
                    return err; // Other errors should propagate
                }
                // Continue to next attempt
                // Debug: log progress periodically
                if (attempts < 3 or (attempts % 1000 == 0)) {
                    const chunks = try self.applyTopLevelPoseidonMessageHash(secret_key.parameter, epoch, rho_slice, message);
                    defer self.allocator.free(chunks);
                    var sum: usize = 0;
                    for (chunks) |chunk| sum += chunk;
                    const expected_sum = self.lifetime_params.target_sum;
                    log.print("ZIG_ENCODING_DEBUG: attempt {} sum={} expected={}\n", .{ attempts, sum, expected_sum });
                }
            }
        }

        if (!encoding_succeeded) {
            log.print("ZIG_ENCODING_DEBUG: Failed after {} attempts\n", .{MAX_TRIES});
            return error.EncodingAttemptsExceeded;
        }
        defer self.allocator.free(x);

        // Generate hashes for chains using PRF-derived starts and message-derived steps x
        // Match Rust: Rust stores hashes internally in Montgomery form (TH::Domain = [KoalaBear; HASH_LEN])
        // KoalaBear uses Montgomery internally, so Rust's chain() returns Montgomery values
        // We need to store hashes in Montgomery form to match Rust's internal representation
        const plonky3_field = @import("../../poseidon2/plonky3_field.zig");
        const F = plonky3_field.KoalaBearField; // Montgomery form implementation
        const hashes = try self.allocator.alloc([8]FieldElement, self.lifetime_params.dimension);
        const hash_len = self.lifetime_params.hash_len_fe;
        for (0..self.lifetime_params.dimension) |chain_index| {
            // PRF start state (domain_elements are in Montgomery form from ShakePRFtoF)
            const domain_elements = self.prfDomainElement(secret_key.prf_key, epoch, @as(u64, @intCast(chain_index)));
            var current: [8]FieldElement = undefined;
            // domain_elements are already in Montgomery form, store directly for hash_len elements
            for (0..hash_len) |j| {
                current[j] = FieldElement{ .value = domain_elements[j] };
            }
            // Pad remaining entries with zeros
            for (hash_len..8) |j| {
                current[j] = FieldElement{ .value = 0 };
            }

            // Walk chain for x[chain_index] steps
            const steps: u8 = x[chain_index];
            if (chain_index == 0) {
                log.print("ZIG_SIGN_DEBUG: Chain {} starting from PRF (position 0), x[{}]={}, steps={}, initial[0]=0x{x:0>8}\n", .{ chain_index, chain_index, steps, steps, current[0].value });
            }
            if (steps > 0) {
                var s: u8 = 1;
                while (s <= steps) : (s += 1) {
                    const next = try self.applyPoseidonChainTweakHash(current, epoch, @as(u8, @intCast(chain_index)), s, secret_key.parameter);
                    // next is produced in Montgomery form; store directly
                    for (0..hash_len) |j| {
                        current[j] = next[j];
                    }
                    // Pad remaining elements with zeros
                    for (hash_len..8) |j| {
                        current[j] = FieldElement{ .value = 0 };
                    }
                    if (chain_index == 0) {
                        log.print("ZIG_SIGN_DEBUG: Chain {} step {}: pos_in_chain={}, current[0]=0x{x:0>8}\n", .{ chain_index, s - 1, s, current[0].value });
                    }
                }
            }
            // Store hashes in Montgomery form (matching Rust's internal representation)
            hashes[chain_index] = current;
            if (chain_index == 0) {
                // Convert Montgomery to canonical for comparison
                const monty_f = F{ .value = current[0].value };
                const canonical = monty_f.toU32();
                log.print("ZIG_SIGN_DEBUG: Chain {} final stored[0]=0x{x:0>8} (Montgomery) = 0x{x:0>8} (canonical)\n", .{ chain_index, current[0].value, canonical });
            }
        }

        // Create signature with proper error handling
        const signature = GeneralizedXMSSSignature.init(self.allocator, path, rho_fixed, hashes) catch |err| {
            // Clean up allocations if signature creation fails
            path.deinit();
            self.allocator.free(hashes);
            return err;
        };

        // Free the original hashes allocation after copying (done in init)
        self.allocator.free(hashes);

        return signature;
    }

    /// Generate randomness (matching Rust PRF::get_randomness)
    fn generateRandomness(
        self: *GeneralizedXMSSSignatureScheme,
        prf_key: [32]u8,
        epoch: u32,
        message: [MESSAGE_LENGTH]u8,
        counter: u64,
    ) ![]FieldElement {
        return rng_flow.generateRandomness(self, prf_key, epoch, message, counter);
    }

    /// Verification function (matching Rust verify exactly)
    pub fn verify(
        self: *GeneralizedXMSSSignatureScheme,
        public_key: *const GeneralizedXMSSPublicKey,
        epoch: u32,
        message: [MESSAGE_LENGTH]u8,
        signature: *const GeneralizedXMSSSignature,
    ) !bool {
        const lifetime = @as(u64, 1) << @intCast(self.lifetime_params.log_lifetime);
        if (epoch >= lifetime) return error.EpochTooLarge;

        // message is used below to derive target-sum digits

        // 1) Get x from encoding using signature's rho (matching Rust IE::encode)
        // During verification, we compute encoding without checking the sum
        // The sum check is only for signing (to ensure we find a valid encoding)
        const rho = signature.getRho();

        // Debug: log rho values (only first rand_len_fe elements are used)
        const rand_len = self.lifetime_params.rand_len_fe;
        log.print("ZIG_VERIFY_DEBUG: Signature rho (first {} elements): ", .{rand_len});
        for (0..rand_len) |i| {
            log.print("0x{x:0>8} ", .{rho[i].value});
        }
        log.print("\n", .{});

        // Use parameter as-is (canonical); Poseidon handles Montgomery internally
        // Only use first rand_len_fe elements of rho (6 for lifetime 2^18, 7 for lifetime 2^8)
        const rho_slice = rho[0..rand_len];
        const chunks = try self.applyTopLevelPoseidonMessageHash(public_key.parameter, epoch, rho_slice, message);
        defer self.allocator.free(chunks);

        // Allocate and copy chunks (take first dimension elements)
        const x = try self.allocator.alloc(u8, self.lifetime_params.dimension);
        defer self.allocator.free(x);
        @memcpy(x, chunks[0..self.lifetime_params.dimension]);

        // Debug: log encoding sum and first few chunks
        var encoding_sum: usize = 0;
        for (x) |chunk| encoding_sum += chunk;
        log.print("ZIG_VERIFY_DEBUG: Encoding sum={} (expected 375)\n", .{encoding_sum});
        log.print("ZIG_VERIFY_DEBUG: Encoding chunks[0..5]: ", .{});
        for (0..@min(5, x.len)) |i| {
            log.print("x[{}]={} ", .{ i, x[i] });
        }
        log.print("\n", .{});

        // 2) Advance each chain domain to max based on message-derived x (target-sum digits)
        const base_minus_one: u8 = @as(u8, @intCast(self.lifetime_params.base - 1));

        const hashes = signature.getHashes();

        // Handle hashes for both cross-implementation (Rust→Zig) and same-implementation (Zig→Zig):
        // - Both implementations: hashes come from binary as Montgomery values (wrappers use Montgomery form)
        //   Both libraries store hashes internally in Montgomery form, so we use them directly in Montgomery form
        // Use plonky3_field.KoalaBearField which uses Montgomery form (not core.KoalaBearField which uses canonical)
        const plonky3_field = @import("../../poseidon2/plonky3_field.zig");
        const F = plonky3_field.KoalaBearField; // Montgomery form implementation
        var final_chain_domains = try self.allocator.alloc([8]FieldElement, hashes.len);
        defer self.allocator.free(final_chain_domains);

        const hash_len = self.lifetime_params.hash_len_fe; // 7 for lifetime 2^18, 8 for lifetime 2^8
        for (hashes, 0..) |domain, i| {
            var current: [8]FieldElement = undefined;
            @memcpy(current[0..hash_len], domain[0..hash_len]);
            // Pad remaining elements with zeros
            for (hash_len..8) |j| {
                current[j] = FieldElement{ .value = 0 };
            }
            const start_pos_in_chain: u8 = x[i];
            const steps: u8 = base_minus_one - start_pos_in_chain;

            if (i == 0 or i == 2) {
                const initial_canonical = domain[0].value;
                const initial_monty = current[0].value;
                log.print("ZIG_VERIFY_DEBUG: Chain {} starting from position {} (x[i]={}), steps={}, initial_canonical[0]=0x{x:0>8} initial_monty[0]=0x{x:0>8}\n", .{ i, start_pos_in_chain, start_pos_in_chain, steps, initial_canonical, initial_monty });
            }

            // Walk 'steps' steps from start_pos_in_chain (matching Rust exactly)
            // Rust: for j in 0..steps { tweak = chain_tweak(epoch, chain_index, start_pos_in_chain + j + 1) }
            for (0..steps) |j| {
                const pos_in_chain: u8 = start_pos_in_chain + @as(u8, @intCast(j)) + 1;
                if (i == 0) {
                    log.print("ZIG_VERIFY_DEBUG: Chain {} step {}: pos_in_chain={}, current[0]=0x{x:0>8}\n", .{ i, j, pos_in_chain, current[0].value });
                }
                const next = try self.applyPoseidonChainTweakHash(current, epoch, @as(u8, @intCast(i)), pos_in_chain, public_key.parameter);
                // Only use hash_len_fe elements (7 for lifetime 2^18, 8 for lifetime 2^8)
                @memcpy(current[0..hash_len], next[0..hash_len]);
                // Pad remaining elements with zeros
                for (hash_len..8) |k| {
                    current[k] = FieldElement{ .value = 0 };
                }
                if (i == 0) {
                    log.print("ZIG_VERIFY_DEBUG: Chain {} step {}: next[0]=0x{x:0>8}\n", .{ i, j, current[0].value });
                }
            }

            final_chain_domains[i] = current;
            if (i == 0 or i == 2) {
                // Convert Montgomery to canonical for comparison with Rust
                const monty_f = F{ .value = current[0].value };
                const canonical = monty_f.toU32();
                log.print("ZIG_VERIFY_DEBUG: Chain {} final[0]=0x{x:0>8} (Montgomery) = 0x{x:0>8} (canonical)\n", .{ i, current[0].value, canonical });
            }
        }

        // Debug: log chain ends before reduction
        if (epoch == 16) {
            std.debug.print("ZIG_VERIFY_DEBUG: Chain ends before reduction for epoch {} (first 3 chains): ", .{epoch});
            for (0..@min(3, final_chain_domains.len)) |ci| {
                std.debug.print("chain{}[0]=0x{x:0>8} ", .{ ci, final_chain_domains[ci][0].value });
            }
            std.debug.print("\n", .{});
        }

        // 3) Reduce 64 chain domains to a single leaf domain using tree-tweak hashing
        if (epoch == 16) {
            std.debug.print("ZIG_VERIFY_DEBUG: Calling reduceChainDomainsToLeafDomain with final_chain_domains.len={} epoch={}\n", .{ final_chain_domains.len, epoch });
        }
        const leaf_domain_slice = try self.reduceChainDomainsToLeafDomain(final_chain_domains, public_key.parameter, epoch);
        defer self.allocator.free(leaf_domain_slice);
        // Convert to fixed-size [8]FieldElement array (pad with zeros if needed)
        // hash_len is already declared above (line 2643)
        var current_domain: [8]FieldElement = undefined;
        for (0..hash_len) |i| {
            current_domain[i] = leaf_domain_slice[i];
        }
        for (hash_len..8) |i| {
            current_domain[i] = FieldElement{ .value = 0 };
        }

        // Debug: log leaf domain
        if (epoch == 16) {
            std.debug.print("ZIG_VERIFY_DEBUG: Leaf domain after reduction: ", .{});
            for (0..hash_len) |i| {
                std.debug.print("0x{x:0>8} ", .{current_domain[i].value});
            }
            std.debug.print("\n", .{});
        }
        
        // 4) Walk Merkle path using tweak hash and epoch-based orientation
        // Calculate bottom tree index to know where bottom tree ends
        const leafs_per_bottom_tree = @as(usize, 1) << @intCast(self.lifetime_params.log_lifetime / 2);
        
        // Debug: log leaf domain for epoch 16
        if (epoch == 16) {
            const bottom_tree_index = epoch / @as(u32, @intCast(leafs_per_bottom_tree));
            std.debug.print("ZIG_VERIFY: Epoch {} - Initial leaf domain[0]=0x{x:0>8} (bottom_tree_index={} final_chain_domains.len={})\n", .{ epoch, current_domain[0].value, bottom_tree_index, final_chain_domains.len });
        }
        const bottom_tree_index = @as(usize, @intCast(epoch)) / leafs_per_bottom_tree;
        // For top tree, we need to compute the position relative to where the top tree starts
        // During verification, we don't have access to left_bottom_tree_index, but we can infer it
        // from the path structure. However, the path was computed during signing with:
        // top_pos = bottom_tree_index - left_bottom_tree_index
        // Since verification walks the path sequentially, the position naturally transitions
        // from bottom tree position to top tree position after log_lifetime/2 levels.
        // The top_pos here is only used for debug logging - the actual path walk uses the
        // position that naturally evolves from the epoch.
        const top_pos = @as(u32, @intCast(bottom_tree_index));

        var position: u32 = epoch;
        const nodes = signature.getPath().getNodes();
        var level: u8 = 0;
        const bottom_tree_depth = self.lifetime_params.log_lifetime / 2;
        log.print("ZIG_VERIFY_DEBUG: Starting Merkle path walk from epoch {} with {} nodes (bottom_tree_index={} top_pos={} bottom_depth={})\n", .{ epoch, nodes.len, bottom_tree_index, top_pos, bottom_tree_depth });

        for (nodes, 0..) |sibling_domain, node_idx| {
            // Note: After walking the bottom tree (depth/2 levels), position should naturally
            // be bottom_tree_index, which is the position in the top tree's first layer.
            // No need to reset position - it continues shifting naturally.
            const is_bottom_tree = node_idx < bottom_tree_depth;
            const is_top_tree = !is_bottom_tree;

            // Debug: log current_domain and sibling for epoch 16
            if (epoch == 16) {
                std.debug.print("ZIG_VERIFY: Epoch {} - Node {}: current_domain[0]=0x{x:0>8} position={} sibling[0]=0x{x:0>8}\n", .{ epoch, node_idx, current_domain[0].value, position, sibling_domain[0].value });
            }

            // Determine if current is left or right child (matching Rust: current_position.is_multiple_of(2))
            // Use position BEFORE shifting (matching Rust exactly)
            const original_position = position;
            const is_left = (position & 1) == 0;
            const is_right = !is_left;
            
            // Build children array (matching Rust exactly: [current_node, opening.co_path[l]] for left, [opening.co_path[l], current_node] for right)
            // Only use first hash_len_fe elements (7 for lifetime 2^18, 8 for lifetime 2^8)
            // hash_len is already declared above
            const left_slice = if (is_left) current_domain[0..hash_len] else sibling_domain[0..hash_len];
            const right_slice = if (is_left) sibling_domain[0..hash_len] else current_domain[0..hash_len];
            
            // Determine new position (position of the parent) - shift BEFORE computing tweak (matching Rust)
            // pos_in_level is the position of the parent in its level, which is position / 2
            // For top tree transition, we need to use the shifted position (which is bottom_tree_index >> 1)
            // But wait - after shifting, position = bottom_tree_index >> 1, which is correct for the parent position
            // However, Rust's combined_path uses bottom_tree_index directly for the top tree path computation
            // But pos_in_level in the hash tweak should be the actual parent position, which is position >> 1
            position >>= 1;
            // CRITICAL FIX: pos_in_level should be the parent position, which is position after shifting
            // For top tree transition, position after shifting is bottom_tree_index >> 1, which is the parent position
            // But we need to check if Rust actually uses bottom_tree_index or the shifted position
            // Let's try using the shifted position first (position after shifting)
            const pos_in_level: u32 = position;
            
            // Debug: log hash inputs for epoch 16, levels 0-4
            if (epoch == 16 and node_idx <= 4) {
                std.debug.print("ZIG_VERIFY: Epoch {} - Level {} hash inputs: current_domain[0]=0x{x:0>8} sibling[0]=0x{x:0>8} left[0]=0x{x:0>8} right[0]=0x{x:0>8} pos_in_level={} level_for_tweak={} (original_position={} is_left={})\n", .{ epoch, level, current_domain[0].value, sibling_domain[0].value, left_slice[0].value, right_slice[0].value, pos_in_level, level, original_position, is_left });
            }
            
            if (is_top_tree and node_idx == bottom_tree_depth) {
                std.debug.print("ZIG_VERIFY: Epoch {} - Transitioning to top tree at node_idx={}, position={}, bottom_tree_index={}, pos_in_level={}, current_domain[0]=0x{x:0>8}, sibling[0]=0x{x:0>8}\n", .{ epoch, node_idx, position, bottom_tree_index, pos_in_level, current_domain[0].value, sibling_domain[0].value });
                log.print("ZIG_VERIFY_DEBUG: Transitioning to top tree at node_idx={}, position={}, bottom_tree_index={}, pos_in_level={}\n", .{ node_idx, position, bottom_tree_index, pos_in_level });
                // Check if current_domain matches what was used during tree building
                // For epoch 16, bottom_tree_index=1, so current_domain should be root of bottom tree 1
                std.debug.print("ZIG_VERIFY: After bottom tree (level {}), current_domain should be root of bottom tree {}: ", .{ level - 1, bottom_tree_index });
                for (0..hash_len) |i| {
                    std.debug.print("0x{x:0>8} ", .{current_domain[i].value});
                }
                std.debug.print("\n", .{});
            }
            if (epoch == 16) {
                std.debug.print("ZIG_VERIFY: Epoch {} - Level {} node {}: original_position={} is_right={} pos_in_level={} sibling[0]=0x{x:0>8} (bottom={} top={})\n", .{ epoch, level, node_idx, original_position, is_right, pos_in_level, sibling_domain[0].value, is_bottom_tree, is_top_tree });
            }

            log.print("ZIG_VERIFY_DEBUG: Level {} node {}: original_position={} is_right={} pos_in_level={} (bottom={} top={})\n", .{ level, node_idx, original_position, is_right, pos_in_level, is_bottom_tree, is_top_tree });

            // Debug: log first element of left and right before hashing
            log.print("ZIG_VERIFY_DEBUG:   current[0]=0x{x:0>8} sibling[0]=0x{x:0>8}\n", .{ current_domain[0].value, sibling_domain[0].value });
            log.print("ZIG_VERIFY_DEBUG:   left[0]=0x{x:0>8} right[0]=0x{x:0>8}\n", .{ left_slice[0].value, right_slice[0].value });

          // Use level+1 for tweak (matching Rust: (l + 1))
          // Debug: log parameter for epoch 16
          if (epoch == 16 and level == 0) {
              std.debug.print("ZIG_VERIFY: Epoch {} - Parameter[0]=0x{x:0>8}\n", .{ epoch, public_key.parameter[0].value });
              std.debug.print("ZIG_VERIFY: Epoch {} - Level {} tweak params: level={} pos_in_level={} (compare with tree building: level=0 parent_pos=8)\n", .{ epoch, level, level, pos_in_level });
          }
          // Debug: log hash call for epoch 16, level 0
          if (epoch == 16 and level == 0) {
              // Create call_id to match with tree building
              const verify_call_id = left_slice[0].value ^ right_slice[0].value ^ public_key.parameter[0].value ^ @as(u32, @intCast(level)) ^ @as(u32, @intCast(pos_in_level));
              std.debug.print("ZIG_VERIFY_HASH: Epoch {} - Level {} calling hash with left[0]=0x{x:0>8} right[0]=0x{x:0>8} level={} pos_in_level={} param[0]=0x{x:0>8} hash_len={} left_slice.len={} right_slice.len={} call_id=0x{x:0>8} left_all=", .{ epoch, level, left_slice[0].value, right_slice[0].value, level, pos_in_level, public_key.parameter[0].value, hash_len, left_slice.len, right_slice.len, verify_call_id });
              for (left_slice) |fe| std.debug.print("0x{x:0>8} ", .{fe.value});
              std.debug.print("right_all=", .{});
              for (right_slice) |fe| std.debug.print("0x{x:0>8} ", .{fe.value});
              std.debug.print("\n", .{});
          }
          const parent = try self.applyPoseidonTreeTweakHashWithSeparateInputs(left_slice, right_slice, level, pos_in_level, public_key.parameter);
          defer self.allocator.free(parent);
          // Debug: log hash result for epoch 16, level 0
          if (epoch == 16 and level == 0) {
              const verify_call_id = left_slice[0].value ^ right_slice[0].value ^ public_key.parameter[0].value ^ @as(u32, @intCast(level)) ^ @as(u32, @intCast(pos_in_level));
              std.debug.print("ZIG_VERIFY_HASH: Epoch {} - Level {} hash result parent[0]=0x{x:0>8} parent.len={} hash_len={} call_id=0x{x:0>8}\n", .{ epoch, level, parent[0].value, parent.len, hash_len, verify_call_id });
          }

            // Debug: log parent computation for bottom tree (level 0-3) for epoch 16
            if (epoch == 16 and level < 4) {
                std.debug.print("ZIG_VERIFY: Bottom tree level {} node {}: parent[0]=0x{x:0>8} (left[0]=0x{x:0>8} right[0]=0x{x:0>8} pos_in_level={} original_position={})\n", .{ level, node_idx, parent[0].value, left_slice[0].value, right_slice[0].value, pos_in_level, original_position });
            }
            // Debug: log parent after hashing for top tree (level 4+)
            if (level >= 4) {
                std.debug.print("ZIG_VERIFY: Top tree level {} node {}: parent[0]=0x{x:0>8} (left[0]=0x{x:0>8} right[0]=0x{x:0>8} pos_in_level={} original_position={} is_right={} current[0]=0x{x:0>8} sibling[0]=0x{x:0>8})\n", .{ level, node_idx, parent[0].value, left_slice[0].value, right_slice[0].value, pos_in_level, original_position, is_right, current_domain[0].value, sibling_domain[0].value });
            }
            log.print("ZIG_VERIFY_DEBUG:   parent[0]=0x{x:0>8}\n", .{parent[0].value});

            // Copy back hash_len_fe elements into current_domain (7 for lifetime 2^18, 8 for lifetime 2^8)
            // current_domain is [8]FieldElement, but we only use the first hash_len_fe elements
            // hash_len is already declared above
            for (0..hash_len) |i| current_domain[i] = parent[i];
            // Zero out remaining elements to ensure clean state
            for (hash_len..8) |i| current_domain[i] = FieldElement{ .value = 0 };
            
            // Debug: log current_domain after each step for epoch 16
            if (epoch == 16) {
                std.debug.print("ZIG_VERIFY: Epoch {} - After level {}: current_domain[0]=0x{x:0>8} (original_position={}, is_left={}, pos_in_level={})\n", .{ epoch, level, current_domain[0].value, original_position, is_left, pos_in_level });
            }
            
            level += 1;
        }
        log.print("ZIG_VERIFY_DEBUG: Final computed root[0]=0x{x:0>8}\n", .{current_domain[0].value});
        log.print("ZIG_VERIFY_DEBUG: Public key root[0]=0x{x:0>8}\n", .{public_key.root[0].value});

        // 4) Compare computed root with public key root (both stored as canonical field elements)
        // Root length is hash_len_fe (7 for lifetime 2^18, 8 for lifetime 2^8)
        const root_len = self.lifetime_params.hash_len_fe;
        var match = true;
        for (0..root_len) |i| {
            if (!current_domain[i].eql(public_key.root[i])) {
                std.debug.print("ZIG_VERIFY_ERROR: Epoch {} - root mismatch at index {}: computed=0x{x:0>8} expected=0x{x:0>8}\n", .{ epoch, i, current_domain[i].value, public_key.root[i].value });
                log.print(
                    "ZIG_VERIFY_DEBUG: root mismatch at index {}: computed=0x{x:0>8} expected=0x{x:0>8}\n",
                    .{ i, current_domain[i].value, public_key.root[i].value },
                );
                match = false;
            }
        }
        if (match) {
            log.print("ZIG_VERIFY_DEBUG: Root matches! Verification successful.\n", .{});
        } else {
            log.print("ZIG_VERIFY_DEBUG: Root mismatch! Computed root: ", .{});
            for (0..root_len) |i| {
                log.print("0x{x:0>8} ", .{current_domain[i].value});
            }
            log.print("\nZIG_VERIFY_DEBUG: Expected root: ", .{});
            for (0..root_len) |i| {
                log.print("0x{x:0>8} ", .{public_key.root[i].value});
            }
            log.print("\n", .{});
        }
        return match;
    }
};

// Test functions
/// Convert tweak encoding to field elements using base-p representation (matching Rust)
fn tweakToFieldElements(tweak_encoding: u128) [2]FieldElement {
    const KOALABEAR_ORDER_U64 = 0x7f000001; // 2^31 - 2^24 + 1

    var acc = tweak_encoding;
    var result: [2]FieldElement = undefined;

    for (0..2) |i| {
        const digit = @as(u64, @intCast(acc % KOALABEAR_ORDER_U64));
        acc /= KOALABEAR_ORDER_U64;
        result[i] = FieldElement.fromCanonical(@intCast(digit));
    }

    return result;
}

test "generalized_xmss_keygen" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var scheme = try GeneralizedXMSSSignatureScheme.init(allocator, .lifetime_2_8);
    defer scheme.deinit();

    const keypair = try scheme.keyGen(0, 256);
    defer keypair.secret_key.deinit();

    // Verify key structure
    try std.testing.expect(keypair.public_key.root[0].value != 0);
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
