//! Hash-based signatures with Poseidon2
//!
//! This library implements XMSS-like signatures using tweakable hash functions
//! and incomparable encodings, based on the framework from
//! https://eprint.iacr.org/2025/055.pdf

// Re-export all public APIs
pub const params = @import("params.zig");
pub const poseidon2_hash = @import("poseidon2_hash.zig");
pub const poseidon2_core = @import("poseidon2/root.zig");
pub const poseidon2 = @import("poseidon2/poseidon2.zig");
pub const sha3 = @import("sha3.zig");
pub const encoding = @import("encoding.zig");
pub const tweakable_hash = @import("tweakable_hash.zig");
pub const winternitz = @import("winternitz.zig");
pub const merkle = @import("merkle.zig");
pub const signature = @import("signature.zig");

// Note: SIMD implementations (simd_signature, simd_winternitz, etc.) are available
// as separate modules in build.zig. Access them via:
//   const simd_signature = @import("simd_signature");
// They are not re-exported here to avoid module conflicts.

// Convenience exports
pub const SecurityLevel = params.SecurityLevel;
pub const Parameters = params.Parameters;
pub const HashFunction = params.HashFunction;
pub const EncodingType = params.EncodingType;

// Primary hash implementations
pub const Poseidon2 = poseidon2_hash.Poseidon2;
pub const poseidon2_koalabear16 = poseidon2_core.poseidon2_koalabear16;
pub const koalabear_field = poseidon2_core.koalabear_field;
pub const Sha3 = sha3.Sha3;
pub const IncomparableEncoding = encoding.IncomparableEncoding;
pub const TweakableHash = tweakable_hash.TweakableHash;
pub const WinternitzOTS = winternitz.WinternitzOTS;
pub const MerkleTree = merkle.MerkleTree;
pub const HashSignature = signature.HashSignature;

test {
    @import("std").testing.refAllDecls(@This());
}
