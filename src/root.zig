//! Hash-based signatures with Poseidon2
//!
//! This library implements XMSS-like signatures using tweakable hash functions
//! and incomparable encodings, based on the framework from
//! https://eprint.iacr.org/2025/055.pdf

// Re-export all public APIs
pub const params = @import("params.zig");
pub const poseidon2_hash = @import("poseidon2_hash.zig");
pub const poseidon2_core = @import("poseidon2/root.zig");
pub const sha3 = @import("sha3.zig");
pub const encoding = @import("encoding.zig");
pub const tweakable_hash = @import("tweakable_hash.zig");
pub const winternitz = @import("winternitz.zig");
pub const merkle = @import("merkle.zig");
pub const signature = @import("signature.zig");

// Convenience exports
pub const SecurityLevel = params.SecurityLevel;
pub const Parameters = params.Parameters;
pub const HashFunction = params.HashFunction;
pub const EncodingType = params.EncodingType;

// Primary hash implementations
pub const Poseidon2 = poseidon2_hash.Poseidon2;
pub const Poseidon2KoalaBear16 = poseidon2_core.Poseidon2KoalaBear16;
pub const KoalaBearField = poseidon2_core.KoalaBearField;
pub const Sha3 = sha3.Sha3;
pub const IncomparableEncoding = encoding.IncomparableEncoding;
pub const TweakableHash = tweakable_hash.TweakableHash;
pub const WinternitzOTS = winternitz.WinternitzOTS;
pub const MerkleTree = merkle.MerkleTree;
pub const HashSignature = signature.HashSignature;

test {
    @import("std").testing.refAllDecls(@This());
}
