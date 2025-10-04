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
    winternitz_w: u32, // Chain length (8 or 16 supported)
    num_chains: u32, // Number of chains (48 or 64 supported)
    hash_output_len: u32,
    key_lifetime: KeyLifetime,

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
            .winternitz_w = 8, // Chain length (8 to match Rust)
            .num_chains = 22, // Number of chains (22 to match Rust)
            .hash_output_len = 32, // 256-bit output for 128-bit security
            .key_lifetime = key_lifetime,
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
            .winternitz_w = 8, // Chain length (8 matching Rust implementation)
            .num_chains = 64,
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
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
            .winternitz_w = 3, // Chain length 8 (2^3 = 8 as specified in hypercube parameters)
            .num_chains = 64, // Number of chains (64 as specified in hypercube parameters)
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
        };
    }

    /// Convenience initializer with default medium lifetime
    pub fn initDefault() Parameters {
        return init(.lifetime_2_16);
    }
};
