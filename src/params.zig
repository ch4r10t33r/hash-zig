//! Parameters and type definitions for hash-zig
//! Parameters matching hash-sig Rust implementation: https://github.com/b-wagn/hash-sig

pub const SecurityLevel = enum {
    level_128, // Only 128-bit security supported
};

pub const HashFunction = enum {
    poseidon2, // Poseidon2 for 128-bit security
    sha3, // SHA3-256 for 128-bit security
};

pub const EncodingType = enum {
    binary, // Binary encoding for 128-bit security
};

/// Key lifetime configuration
/// Determines how many signatures can be generated with a single key
pub const KeyLifetime = enum {
    lifetime_2_10, // 2^10 = 1,024 signatures
    lifetime_2_16, // 2^16 = 65,536 signatures
    lifetime_2_18, // 2^18 = 262,144 signatures (for benchmarking)
    lifetime_2_20, // 2^20 = 1,048,576 signatures
    lifetime_2_28, // 2^28 = 268,435,456 signatures
    lifetime_2_32, // 2^32 = 4,294,967,296 signatures

    pub fn treeHeight(self: KeyLifetime) u32 {
        return switch (self) {
            .lifetime_2_10 => 10,
            .lifetime_2_16 => 16,
            .lifetime_2_18 => 18,
            .lifetime_2_20 => 20,
            .lifetime_2_28 => 28,
            .lifetime_2_32 => 32,
        };
    }

    pub fn maxSignatures(self: KeyLifetime) u64 {
        return @as(u64, 1) << @intCast(self.treeHeight());
    }
};

pub const Parameters = struct {
    security_level: SecurityLevel,
    hash_function: HashFunction,
    encoding_type: EncodingType,
    tree_height: u32,
    winternitz_w: u32, // Chunk size in bits (8 for w=8, means base 256)
    num_message_chains: u32, // Number of chains for message chunks (20 for w=8)
    num_checksum_chains: u32, // Number of chains for checksum chunks (2 for w=8)
    num_chains: u32, // Total chains = num_message_chains + num_checksum_chains (22 for w=8)
    hash_output_len: u32,
    key_lifetime: KeyLifetime,

    // Field-native parameters (for Rust compatibility)
    chain_hash_output_len_fe: usize, // Number of field elements in chain hash output (7 for KoalaBear)
    tree_hash_output_len_fe: usize, // Number of field elements in tree hash output (1 for KoalaBear)

    /// Initialize with Poseidon2 hash function (default)
    /// Parameters to match Rust hash-sig implementation:
    /// - 22 chains of length 256 (w=8) for 128-bit security
    /// - Binary encoding
    /// - 32-byte hash output
    /// - Poseidon2 with width=5, ext_rounds=7, int_rounds=2, sbox=9
    pub fn init(key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .poseidon2,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 8, // Chunk size in bits (8 bits = 1 byte per chunk, base 256)
            .num_message_chains = 20, // 20 chunks from 160-bit (20-byte) message hash
            .num_checksum_chains = 2, // 2 chunks for checksum (computed as ceil(log256(20*255)))
            .num_chains = 22, // Total: 20 message + 2 checksum = 22
            .hash_output_len = 32, // 256-bit output for 128-bit security
            .key_lifetime = key_lifetime,
            // Field-native parameters (matching Rust hash-sig)
            .chain_hash_output_len_fe = 7, // 7 KoalaBear field elements for chain hashes
            .tree_hash_output_len_fe = 1, // 1 KoalaBear field element for tree hashes
        };
    }

    /// Initialize with SHA3 hash function
    /// Uses different parameters optimized for SHA3 (64 chains of length 8)
    pub fn initWithSha3(key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .sha3,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 8, // Chunk size in bits
            .num_message_chains = 60, // For SHA3-based parameters
            .num_checksum_chains = 4,
            .num_chains = 64,
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
            // Field-native parameters (not used for SHA3)
            .chain_hash_output_len_fe = 0,
            .tree_hash_output_len_fe = 0,
        };
    }

    /// Initialize with Poseidon2 hash function using hypercube parameters
    /// Uses parameters from hypercube-hashsig-parameters: 64 chains of length 8
    /// Reference: https://github.com/b-wagn/hypercube-hashsig-parameters
    pub fn initHypercube(key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .poseidon2,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 3, // Chunk size in bits (3 bits = 8 values per chunk)
            .num_message_chains = 60, // Hypercube message chains
            .num_checksum_chains = 4, // Hypercube checksum chains
            .num_chains = 64, // Total: 60 + 4 = 64
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
            // Field-native parameters (for Poseidon2)
            .chain_hash_output_len_fe = 7,
            .tree_hash_output_len_fe = 1,
        };
    }

    /// Convenience initializer with default medium lifetime
    pub fn initDefault() Parameters {
        return init(.lifetime_2_16);
    }
};
