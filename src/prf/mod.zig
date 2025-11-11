pub const ShakePRF = @import("prf.zig").ShakePRF;
pub const ChaCha12Rng = @import("chacha12_rng.zig").ChaCha12Rng;
pub const ShakePRFtoF = @import("shake_prf_to_field.zig").ShakePRFtoF;
pub const ShakePRFtoF_8_7 = @import("shake_prf_to_field.zig").ShakePRFtoF_8_7;
pub const ShakePRFtoF_7_6 = @import("shake_prf_to_field.zig").ShakePRFtoF_7_6;

// Re-export the init function
pub const init = @import("chacha12_rng.zig").ChaCha12Rng.init;
