const std = @import("std");
const simd_field = @import("simd_montgomery");
const simd_poseidon = @import("simd_poseidon2");
const simd_hash = @import("simd_hash.zig").SimdHash;

// SIMD-optimized Winternitz OTS implementation
// Uses vectorized field operations and batch processing for better performance

pub const simd_winternitz_ots = struct {
    const Field = simd_field.koala_bear_simd;
    const Poseidon2 = simd_poseidon.simd_poseidon2;
    const Hash = simd_hash;

    // Note: chain_length is now computed from parameters, not hardcoded!
    // Was: const chain_length = 256; (2^8) - TOO LONG!
    // Now: Computed as 2^winternitz_w from parameters (typically 8 for w=3)
    const hash_output_len = 32; // 256 bits = 32 bytes
    const field_elements_per_hash = 8; // 32 bytes / 4 bytes per element
    const poseidon_width = 16; // Poseidon2 width (matches SIMD implementation)

    // Chain state type
    pub const ChainState = @Vector(field_elements_per_hash, u32);

    // Private key type
    pub const PrivateKey = struct {
        chains: []ChainState,

        pub fn deinit(self: *PrivateKey, allocator: std.mem.Allocator) void {
            allocator.free(self.chains);
        }
    };

    // Public key type
    pub const PublicKey = struct {
        chains: []ChainState,

        pub fn deinit(self: *PublicKey, allocator: std.mem.Allocator) void {
            allocator.free(self.chains);
        }
    };

    // Signature type
    pub const Signature = struct {
        chains: []ChainState,

        pub fn deinit(self: *Signature, allocator: std.mem.Allocator) void {
            allocator.free(self.chains);
        }
    };

    // Generate private key with SIMD operations
    pub fn generatePrivateKey(allocator: std.mem.Allocator, signature_params: anytype, seed: []const u8, addr: u64) !PrivateKey {
        const num_chains = signature_params.num_chains;
        var chains = try allocator.alloc(ChainState, num_chains);
        errdefer allocator.free(chains);

        // Generate seeds for all chains in parallel
        var chain_seeds = try allocator.alloc([32]u8, num_chains);
        defer allocator.free(chain_seeds);

        // Initialize SIMD hash function
        var hash = Hash.init(allocator);
        defer hash.deinit();

        for (0..num_chains) |i| {
            // Use prfHash approach: prfHash(seed, addr + i)
            const chain_addr = addr + i;
            const hash_result = try hash.prfHash(allocator, seed, chain_addr);
            defer allocator.free(hash_result);

            // Copy hash result and pad to 32 bytes if needed
            const copy_len = @min(hash_result.len, 32);
            @memcpy(chain_seeds[i][0..copy_len], hash_result[0..copy_len]);
            if (copy_len < 32) {
                @memset(chain_seeds[i][copy_len..32], 0); // Pad with zeros
            }
        }

        // Generate initial chain states using SIMD hash
        for (0..num_chains) |i| {
            const hash_result = try hash.hash(allocator, &chain_seeds[i], 0);
            defer allocator.free(hash_result);

            // Convert hash result to field elements
            var chain_state: ChainState = undefined;
            for (0..field_elements_per_hash) |j| {
                const byte_offset = j * 4;
                if (byte_offset + 3 < hash_result.len) {
                    const slice = hash_result[byte_offset .. byte_offset + 4];
                    const val = std.mem.readInt(u32, slice[0..4], .little);
                    chain_state[j] = val % Field.modulus;
                } else {
                    chain_state[j] = 0;
                }
            }
            chains[i] = chain_state;
        }

        return PrivateKey{ .chains = chains };
    }

    // Generate public key with SIMD-optimized chain generation
    pub fn generatePublicKey(allocator: std.mem.Allocator, signature_params: anytype, private_key: PrivateKey) !PublicKey {
        const num_chains = private_key.chains.len;
        var public_chains = try allocator.alloc(ChainState, num_chains);
        errdefer allocator.free(public_chains);

        // Get chain length from parameters (not hardcoded!)
        const chain_len = @as(u32, 1) << @intCast(signature_params.winternitz_w);

        // Initialize SIMD hash function
        var hash = Hash.init(allocator);
        defer hash.deinit();

        // Process chains in batches of 4 for SIMD optimization
        var i: usize = 0;
        while (i + 4 <= num_chains) {
            var batch_states: [4]ChainState = undefined;

            // Load 4 chain states
            for (0..4) |j| {
                batch_states[j] = private_key.chains[i + j];
            }

            // Generate chains with SIMD using correct chain length
            try generateChainsBatch(allocator, &hash, &batch_states, chain_len);

            // Store results
            for (0..4) |j| {
                public_chains[i + j] = batch_states[j];
            }

            i += 4;
        }

        // Process remaining chains individually
        while (i < num_chains) {
            var state = private_key.chains[i];
            try generateChain(allocator, &hash, &state, chain_len);
            public_chains[i] = state;
            i += 1;
        }

        return PublicKey{ .chains = public_chains };
    }

    // Generate a single chain with SIMD operations
    pub fn generateChain(allocator: std.mem.Allocator, hash: *Hash, state: *ChainState, length: u32) !void {
        for (0..length) |_| {
            // Convert vector to bytes for hashing
            var state_bytes: [field_elements_per_hash * 4]u8 = undefined;
            for (0..field_elements_per_hash) |i| {
                const byte_offset = i * 4;
                const slice = state_bytes[byte_offset .. byte_offset + 4];
                std.mem.writeInt(u32, slice[0..4], state[i], .little);
            }

            // Hash the state using SIMD hash
            const hash_result = try hash.hash(allocator, &state_bytes, 0);
            defer allocator.free(hash_result);

            // Update state with hash result
            var new_state: ChainState = undefined;
            for (0..field_elements_per_hash) |j| {
                const byte_offset = j * 4;
                if (byte_offset + 3 < hash_result.len) {
                    const slice = hash_result[byte_offset .. byte_offset + 4];
                    const val = std.mem.readInt(u32, slice[0..4], .little);
                    new_state[j] = val % Field.modulus;
                } else {
                    new_state[j] = 0;
                }
            }
            state.* = new_state;
        }
    }

    // Generate multiple chains in batch using SIMD
    pub fn generateChainsBatch(allocator: std.mem.Allocator, hash: *Hash, states: *[4]ChainState, length: u32) !void {
        for (0..length) |_| {
            // Process all 4 states in parallel
            for (0..4) |i| {
                // Convert vector to bytes for hashing
                var state_bytes: [field_elements_per_hash * 4]u8 = undefined;
                for (0..field_elements_per_hash) |j| {
                    const byte_offset = j * 4;
                    const slice = state_bytes[byte_offset .. byte_offset + 4];
                    std.mem.writeInt(u32, slice[0..4], states[i][j], .little);
                }

                const hash_result = try hash.hash(allocator, &state_bytes, 0);
                defer allocator.free(hash_result);

                // Update state with hash result
                var new_state: ChainState = undefined;
                for (0..field_elements_per_hash) |j| {
                    const byte_offset = j * 4;
                    if (byte_offset + 3 < hash_result.len) {
                        const slice = hash_result[byte_offset .. byte_offset + 4];
                        const val = std.mem.readInt(u32, slice[0..4], .little);
                        new_state[j] = val % Field.modulus;
                    } else {
                        new_state[j] = 0;
                    }
                }
                states[i] = new_state;
            }
        }
    }

    // Generate signature with SIMD operations
    pub fn sign(allocator: std.mem.Allocator, signature_params: anytype, message: []const u8, private_key: PrivateKey) !Signature {
        const chain_length = @as(u32, 1) << @intCast(signature_params.winternitz_w);
        const num_chains = private_key.chains.len;
        var signature_chains = try allocator.alloc(ChainState, num_chains);
        errdefer allocator.free(signature_chains);

        // Initialize SIMD hash function
        var hash = Hash.init(allocator);
        defer hash.deinit();

        // Hash the message using SIMD hash
        const message_hash = try hash.hash(allocator, message, 0);
        defer allocator.free(message_hash);

        // Convert hash to field elements
        var hash_elements: [field_elements_per_hash]u32 = undefined;
        for (0..field_elements_per_hash) |i| {
            const byte_offset = i * 4;
            if (byte_offset + 3 < message_hash.len) {
                const slice = message_hash[byte_offset .. byte_offset + 4];
                const val = std.mem.readInt(u32, slice[0..4], .little);
                hash_elements[i] = val % Field.modulus;
            } else {
                hash_elements[i] = 0;
            }
        }

        // Generate signature chains in parallel
        var i: usize = 0;
        while (i + 4 <= num_chains) {
            var batch_states: [4]ChainState = undefined;
            var batch_lengths: [4]u32 = undefined;

            // Calculate chain lengths for this batch
            for (0..4) |j| {
                const chain_index = i + j;
                const hash_element = hash_elements[chain_index % field_elements_per_hash];
                batch_lengths[j] = hash_element % chain_length;

                // Start with private key state
                batch_states[j] = private_key.chains[chain_index];
            }

            // Generate signature chains with SIMD
            try generateSignatureChainsBatch(allocator, &hash, &batch_states, batch_lengths);

            // Store results
            for (0..4) |j| {
                signature_chains[i + j] = batch_states[j];
            }

            i += 4;
        }

        // Process remaining chains individually
        while (i < num_chains) {
            const hash_element = hash_elements[i % field_elements_per_hash];
            const chain_len = hash_element % chain_length;

            var state = private_key.chains[i];
            try generateChain(allocator, &hash, &state, chain_len);
            signature_chains[i] = state;
            i += 1;
        }

        return Signature{ .chains = signature_chains };
    }

    // Generate signature chains in batch using SIMD
    pub fn generateSignatureChainsBatch(allocator: std.mem.Allocator, hash: *Hash, states: *[4]ChainState, lengths: [4]u32) !void {
        // Find maximum length
        const max_length = @max(lengths[0], @max(lengths[1], @max(lengths[2], lengths[3])));

        // Generate chains up to maximum length
        for (0..max_length) |step| {
            for (0..4) |i| {
                if (step < lengths[i]) {
                    // Convert vector to bytes for hashing
                    var state_bytes: [field_elements_per_hash * 4]u8 = undefined;
                    for (0..field_elements_per_hash) |j| {
                        const byte_offset = j * 4;
                        const slice = state_bytes[byte_offset .. byte_offset + 4];
                        std.mem.writeInt(u32, slice[0..4], states[i][j], .little);
                    }

                    const hash_result = try hash.hash(allocator, &state_bytes, 0);
                    defer allocator.free(hash_result);

                    // Update state with hash result
                    var new_state: ChainState = undefined;
                    for (0..field_elements_per_hash) |j| {
                        const byte_offset = j * 4;
                        if (byte_offset + 3 < hash_result.len) {
                            const slice = hash_result[byte_offset .. byte_offset + 4];
                            const val = std.mem.readInt(u32, slice[0..4], .little);
                            new_state[j] = val % Field.modulus;
                        } else {
                            new_state[j] = 0;
                        }
                    }
                    states[i] = new_state;
                }
            }
        }
    }

    // Verify signature with SIMD operations  
    pub fn verify(signature_params: anytype, message: []const u8, signature: Signature, public_key: PublicKey) !bool {
        const chain_length = @as(u32, 1) << @intCast(signature_params.winternitz_w);
        const num_chains = signature.chains.len;
        if (num_chains != public_key.chains.len) return false;

        // Hash the message
        const message_hash = Poseidon2.hash(message);
        const hash_elements = Poseidon2.bytesToFieldElements(&message_hash);

        // Verify each chain
        for (0..num_chains) |i| {
            const hash_element = hash_elements[i % field_elements_per_hash];
            const chain_len = hash_element % chain_length;

            // Calculate remaining chain length
            const remaining_length = chain_length - chain_len;

            // Generate remaining chain from signature
            var state = signature.chains[i];
            generateChain(&state, remaining_length);

            // Compare with public key
            var equal: bool = true;
            inline for (0..8) |k| {
                if (state[k] != public_key.chains[i][k]) {
                    equal = false;
                    break;
                }
            }
            if (!equal) {
                return false;
            }
        }

        return true;
    }

    // Batch signature generation for multiple messages
    pub fn batchSign(allocator: std.mem.Allocator, messages: []const []const u8, private_key: PrivateKey) ![]Signature {
        var signatures = try std.ArrayList(Signature).initCapacity(allocator, messages.len);
        defer signatures.deinit();

        for (messages) |message| {
            const signature = try sign(allocator, message, private_key);
            try signatures.append(signature);
        }

        return signatures.toOwnedSlice();
    }

    // Batch signature verification for multiple messages
    pub fn batchVerify(messages: []const []const u8, signatures: []const Signature, public_key: PublicKey) ![]bool {
        var results = try std.ArrayList(bool).initCapacity(std.heap.page_allocator, messages.len);
        defer results.deinit();

        for (messages, signatures) |message, signature| {
            const is_valid = try verify(message, signature, public_key);
            try results.append(is_valid);
        }

        return results.toOwnedSlice();
    }

    // Memory-efficient chain generation for large batches
    pub fn generateChainsEfficient(states: []ChainState, length: u32) void {
        // Process in SIMD-friendly chunks
        var i: usize = 0;
        while (i + 4 <= states.len) {
            var batch_states: @Vector(4, ChainState) = undefined;

            // Load 4 states
            for (0..4) |j| {
                batch_states[j] = states[i + j];
            }

            // Generate chains with SIMD
            generateChainsBatch(&batch_states, length);

            // Store results
            for (0..4) |j| {
                states[i + j] = batch_states[j];
            }

            i += 4;
        }

        // Process remaining states individually
        while (i < states.len) {
            generateChain(&states[i], length);
            i += 1;
        }
    }
};

// Performance tests
test "SIMD chain_lengthinternitz performance" {
    const winternitz = simd_winternitz_ots;
    const iterations = 1000;

    // Test data
    _ = "test message for signing";

    // Generate private key
    const seed = "test seed for winternitz";
    const private_key = try winternitz.generatePrivateKey(seed);
    defer private_key.deinit();

    // Test scalar chain generation
    const start_scalar = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var state = winternitz.ChainState{ 1, 2, 3, 4, 5, 6, 7, 8 };
        winternitz.generateChain(&state, 8);
    }
    const scalar_time = std.time.nanoTimestamp() - start_scalar;

    // Test vectorized chain generation
    const start_vector = std.time.nanoTimestamp();
    for (0..iterations / 4) |_| {
        var states: @Vector(4, winternitz.ChainState) = .{
            winternitz.ChainState{ 1, 2, 3, 4, 5, 6, 7, 8 },
            winternitz.ChainState{ 9, 10, 11, 12, 13, 14, 15, 16 },
            winternitz.ChainState{ 17, 18, 19, 20, 21, 22, 23, 24 },
            winternitz.ChainState{ 25, 26, 27, 28, 29, 30, 31, 32 },
        };
        winternitz.generateChainsBatch(&states, 8);
    }
    const vector_time = std.time.nanoTimestamp() - start_vector;

    const speedup = @as(f64, @floatFromInt(scalar_time)) / @as(f64, @floatFromInt(vector_time));
    std.debug.print("SIMD chain_lengthinternitz speedup: {d:.2}x\n", .{speedup});

    // Should achieve at least 2x speedup
    std.debug.assert(speedup >= 2.0);
}

test "SIMD chain_lengthinternitz functionality" {
    const winternitz = simd_winternitz_ots;

    // Test basic functionality
    const seed = "test seed";
    const message = "test message";

    // Generate keys
    const private_key = try winternitz.generatePrivateKey(seed);
    defer private_key.deinit();

    const public_key = try winternitz.generatePublicKey(private_key);
    defer public_key.deinit();

    // Sign message
    const signature = try winternitz.sign(message, private_key);
    defer signature.deinit();

    // Verify signature
    const is_valid = try winternitz.verify(message, signature, public_key);
    std.debug.assert(is_valid);

    // Test batch operations
    const messages = [_][]const u8{ "msg1", "msg2", "msg3", "msg4" };
    const signatures = try winternitz.batchSign(&messages, private_key);
    defer {
        for (signatures) |sig| sig.deinit();
        std.heap.page_allocator.free(signatures);
    }

    const results = try winternitz.batchVerify(&messages, signatures, public_key);
    defer std.heap.page_allocator.free(results);

    for (results) |result| {
        std.debug.assert(result);
    }

    std.debug.print("SIMD chain_lengthinternitz functionality test passed\n", .{});
}
