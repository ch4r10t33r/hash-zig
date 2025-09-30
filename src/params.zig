//! Parameters and type definitions for hash-zig
//! Based on hypercube hash-sig parameters: https://github.com/b-wagn/hypercube-hashsig-parameters

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
    lifetime_2_20, // 2^20 = 1,048,576 signatures
    lifetime_2_28, // 2^28 = 268,435,456 signatures
    lifetime_2_32, // 2^32 = 4,294,967,296 signatures

    pub fn treeHeight(self: KeyLifetime) u32 {
        return switch (self) {
            .lifetime_2_10 => 10,
            .lifetime_2_16 => 16,
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
    /// Parameters based on hypercube-hashsig-parameters:
    /// - 64 chains of length 8 (w=8) for 128-bit security
    ///   OR 48 chains of length 10 (w=10)
    /// - Binary encoding
    /// - 32-byte hash output
    /// Using 64 chains of length 8 as recommended
    pub fn init(key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .poseidon2,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 8, // Chain length (8 as per hypercube-hashsig-parameters)
            .num_chains = 64, // Number of chains
            .hash_output_len = 32, // 256-bit output for 128-bit security
            .key_lifetime = key_lifetime,
        };
    }

    /// Initialize with SHA3 hash function
    /// Uses same parameters as Poseidon2 variant (64 chains of length 8)
    pub fn initWithSha3(key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .sha3,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 8, // Chain length (8 as per hypercube-hashsig-parameters)
            .num_chains = 64,
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
        };
    }

    /// Convenience initializer with default medium lifetime
    pub fn initDefault() Parameters {
        return init(.lifetime_2_16);
    }
};
