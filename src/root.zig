//! Hash-based signatures with Poseidon2
//!
//! This library implements XMSS-like signatures using tweakable hash functions
//! and incomparable encodings, based on the framework from
//! https://eprint.iacr.org/2025/055.pdf

// Re-export all public APIs via submodules
pub const core = @import("core/mod.zig");
pub const hash = @import("hash/mod.zig");
pub const prf = @import("prf/mod.zig");
pub const encoding = @import("encoding/mod.zig");
pub const wots = @import("wots/mod.zig");
pub const merkle = @import("merkle/mod.zig");
pub const signature = @import("signature/mod.zig");
pub const utils = @import("utils/mod.zig");
pub const poseidon = @import("poseidon");

// Note: SIMD implementations (simd_signature, simd_winternitz, etc.) are available
// as separate modules in build.zig. Access them via:
//   const simd_signature = @import("simd_signature");
// They are not re-exported here to avoid module conflicts.

// Convenience exports
pub const SecurityLevel = core.SecurityLevel;
pub const Parameters = core.Parameters;
pub const ParametersRustCompat = core.ParametersRustCompat;
pub const KeyLifetime = core.KeyLifetime;
pub const KeyLifetimeRustCompat = core.KeyLifetimeRustCompat;
pub const HashFunction = core.HashFunction;
pub const EncodingType = core.EncodingType;
pub const FieldElement = core.FieldElement;
pub const KoalaBearField = core.KoalaBearField;
pub const PoseidonTweak = hash.PoseidonTweak;

// Primary hash implementations
pub const Poseidon2 = hash.Poseidon2;
pub const Poseidon2RustCompat = hash.Poseidon2RustCompat;
pub const Sha3 = hash.Sha3;
pub const ShakePRF = prf.ShakePRF;
pub const IncomparableEncoding = encoding.IncomparableEncoding;
pub const TweakableHash = hash.TweakableHash;
pub const WinternitzOTS = wots.WinternitzOTS;
pub const WinternitzOTSNative = wots.WinternitzOTSNative;
pub const MerkleTree = merkle.MerkleTree;
pub const MerkleTreeNative = merkle.MerkleTreeNative;
pub const HashSignature = signature.HashSignature;
pub const HashSignatureNative = signature.HashSignatureNative;
pub const HashSignatureRustCompat = signature.HashSignatureRustCompat;
pub const HashSignatureShakeCompat = signature.HashSignatureShakeCompat;

// Rust-compatible exports from zig-poseidon
pub const TargetSumEncoding = poseidon.TargetSumEncoding;
pub const TopLevelPoseidonMessageHash = poseidon.TopLevelPoseidonMessageHash;

// Export modules for testing
pub const chacha12_rng = @import("prf/chacha12_rng.zig");
pub const ShakePRFtoF_8_7 = @import("prf/shake_prf_to_field.zig").ShakePRFtoF_8_7;

test {
    @import("std").testing.refAllDecls(@This());
}
