//! Parameters and type definitions for hash-zig

pub const SecurityLevel = enum {
    level_128,
    level_192,
    level_256,
};

pub const HashFunction = enum {
    poseidon2_128,
    poseidon2_192,
    poseidon2_256,
    sha3_256,
    sha3_384,
    sha3_512,
};

pub const EncodingType = enum {
    binary,
    ternary,
    quaternary,
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
    winternitz_w: u32,
    hash_output_len: u32,
    key_lifetime: KeyLifetime,

    /// Initialize with security level and key lifetime
    pub fn init(security_level: SecurityLevel, key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return switch (security_level) {
            .level_128 => .{
                .security_level = security_level,
                .hash_function = .poseidon2_128,
                .encoding_type = .binary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 32,
                .key_lifetime = key_lifetime,
            },
            .level_192 => .{
                .security_level = security_level,
                .hash_function = .poseidon2_192,
                .encoding_type = .ternary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 48,
                .key_lifetime = key_lifetime,
            },
            .level_256 => .{
                .security_level = security_level,
                .hash_function = .poseidon2_256,
                .encoding_type = .quaternary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 64,
                .key_lifetime = key_lifetime,
            },
        };
    }

    /// Convenience initializer with default medium lifetime
    pub fn initDefault(security_level: SecurityLevel) Parameters {
        return init(security_level, .lifetime_2_16);
    }

    /// Initialize with SHA3 hash function and key lifetime
    pub fn initWithSha3(security_level: SecurityLevel, key_lifetime: KeyLifetime) Parameters {
        const tree_height = key_lifetime.treeHeight();

        return switch (security_level) {
            .level_128 => .{
                .security_level = security_level,
                .hash_function = .sha3_256,
                .encoding_type = .binary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 32,
                .key_lifetime = key_lifetime,
            },
            .level_192 => .{
                .security_level = security_level,
                .hash_function = .sha3_384,
                .encoding_type = .ternary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 48,
                .key_lifetime = key_lifetime,
            },
            .level_256 => .{
                .security_level = security_level,
                .hash_function = .sha3_512,
                .encoding_type = .quaternary,
                .tree_height = tree_height,
                .winternitz_w = 16,
                .hash_output_len = 64,
                .key_lifetime = key_lifetime,
            },
        };
    }
};
