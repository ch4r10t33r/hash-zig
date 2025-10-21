//! Rust-compatible parameters for hash-zig
//! Matches Rust hash-sig SIGTopLevelTargetSumLifetime8Dim64Base8 exactly

const std = @import("std");

pub const SecurityLevel = enum {
    level_128, // Only 128-bit security supported
};

pub const HashFunction = enum {
    poseidon2_rust_compat, // Rust-compatible Poseidon2
    poseidon2, // Standard Poseidon2
    sha3, // SHA3-256 for 128-bit security
};

pub const EncodingType = enum {
    target_sum, // Rust-compatible TargetSumEncoding
    binary, // Binary encoding for 128-bit security
};

/// Key lifetime configuration matching Rust
pub const KeyLifetime = enum {
    lifetime_2_3, // 2^3 = 8 signatures (matches Rust PR #91)
    lifetime_2_8, // 2^8 = 256 signatures (matches Rust SIGTopLevelTargetSumLifetime8Dim64Base8)
    lifetime_2_10, // 2^10 = 1,024 signatures
    lifetime_2_16, // 2^16 = 65,536 signatures
    lifetime_2_18, // 2^18 = 262,144 signatures
    lifetime_2_20, // 2^20 = 1,048,576 signatures
    lifetime_2_28, // 2^28 = 268,435,456 signatures
    lifetime_2_32, // 2^32 = 4,294,967,296 signatures

    pub fn treeHeight(self: KeyLifetime) u32 {
        return switch (self) {
            .lifetime_2_3 => 3,
            .lifetime_2_8 => 8,
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

pub const ParametersRustCompat = struct {
    security_level: SecurityLevel,
    hash_function: HashFunction,
    encoding_type: EncodingType,
    tree_height: u32,
    winternitz_w: u32,
    num_message_chains: u32,
    num_checksum_chains: u32,
    num_chains: u32,
    hash_output_len: u32,
    key_lifetime: KeyLifetime,
    
    // Rust-compatible parameters
    chain_hash_output_len_fe: usize, // Number of field elements in chain hash output
    tree_hash_output_len_fe: usize, // Number of field elements in tree hash output
    target_sum_value: u32, // TargetSumEncoding value (375 for Rust)
    
    // Rust Poseidon2 parameters
    poseidon_width: u32, // 5 for Rust
    poseidon_rate: u32, // 8 for Rust
    poseidon_capacity: u32, // 2 for Rust
    poseidon_rounds: u32, // 9 for Rust
    poseidon_output_len: u32, // 64 for Rust

    /// Initialize with Rust-compatible parameters
    /// Matches SIGTopLevelTargetSumLifetime8Dim64Base8 exactly
    pub fn init(key_lifetime: KeyLifetime) ParametersRustCompat {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .poseidon2_rust_compat,
            .encoding_type = .target_sum,
            .tree_height = tree_height,
            .winternitz_w = 8, // Chunk size in bits (8 bits = 1 byte per chunk, base 256)
            .num_message_chains = 20, // 20 chunks from 160-bit (20-byte) message hash
            .num_checksum_chains = 2, // 2 chunks for checksum (computed as ceil(log256(20*255)))
            .num_chains = 22, // Total: 20 message + 2 checksum = 22
            .hash_output_len = 32, // 256-bit output for 128-bit security
            .key_lifetime = key_lifetime,
            
            // Rust-compatible field element parameters
            .chain_hash_output_len_fe = 7, // 7 KoalaBear field elements for chain hashes
            .tree_hash_output_len_fe = 7, // 7 KoalaBear field elements for tree hashes
            .target_sum_value = 375, // Rust TargetSumEncoding value
            
            // Rust Poseidon2 parameters (PoseidonTweakHash<5, 8, 2, 9, 64>)
            .poseidon_width = 5,
            .poseidon_rate = 8,
            .poseidon_capacity = 2,
            .poseidon_rounds = 9,
            .poseidon_output_len = 64,
        };
    }

    /// Initialize with standard parameters (for comparison)
    pub fn initStandard(key_lifetime: KeyLifetime) ParametersRustCompat {
        const tree_height = key_lifetime.treeHeight();

        return .{
            .security_level = .level_128,
            .hash_function = .poseidon2,
            .encoding_type = .binary,
            .tree_height = tree_height,
            .winternitz_w = 8,
            .num_message_chains = 20,
            .num_checksum_chains = 2,
            .num_chains = 22,
            .hash_output_len = 32,
            .key_lifetime = key_lifetime,
            
            // Standard field element parameters
            .chain_hash_output_len_fe = 7,
            .tree_hash_output_len_fe = 7,
            .target_sum_value = 0, // Not used in standard mode
            
            // Standard Poseidon2 parameters
            .poseidon_width = 16,
            .poseidon_rate = 8,
            .poseidon_capacity = 8,
            .poseidon_rounds = 8,
            .poseidon_output_len = 8,
        };
    }
};
