//! Hash-based signatures with Poseidon2
//!
//! This library implements XMSS-like signatures using tweakable hash functions
//! and incomparable encodings, based on the framework from
//! https://eprint.iacr.org/2025/055.pdf

// Re-export all public APIs
pub const params = @import("params.zig");
pub const poseidon2 = @import("poseidon2/hash.zig");
pub const field = @import("poseidon2/field.zig");
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

pub const FieldElement = field.FieldElement;
pub const Poseidon2 = poseidon2.Poseidon2;
pub const Sha3 = sha3.Sha3;
pub const IncomparableEncoding = encoding.IncomparableEncoding;
pub const TweakableHash = tweakable_hash.TweakableHash;
pub const WinternitzOTS = winternitz.WinternitzOTS;
pub const MerkleTree = merkle.MerkleTree;
pub const HashSignature = signature.HashSignature;

test {
    @import("std").testing.refAllDecls(@This());
}
