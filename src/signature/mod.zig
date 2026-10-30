pub const HashSignature = @import("signature.zig").HashSignatureRustCompat;
pub const HashSignatureNative = @import("signature_native.zig").GeneralizedXMSSSignatureScheme;
pub const HashSignatureRustCompat = @import("signature.zig").HashSignatureRustCompat;
pub const HashSignatureShakeCompat = @import("signature_native_legacy.zig").HashSignatureShakeCompat;

// Primary Rust-compatible GeneralizedXMSS implementation (now the main implementation)
pub const GeneralizedXMSSSignatureScheme = @import("signature_native.zig").GeneralizedXMSSSignatureScheme;
pub const GeneralizedXMSSPublicKey = @import("signature_native.zig").GeneralizedXMSSPublicKey;
pub const GeneralizedXMSSSecretKey = @import("signature_native.zig").GeneralizedXMSSSecretKey;
pub const GeneralizedXMSSSignature = @import("signature_native.zig").GeneralizedXMSSSignature;

// Legacy implementation (kept for compatibility)
pub const HashSignatureShakeCompatLegacy = @import("signature_native_legacy.zig").HashSignatureShakeCompat;
