// Optimized Poseidon2 implementation based on jsign/zig-poseidon
// Adapted to support KoalaBear field for compatibility with plonky3

pub const generic_montgomery = @import("fields/generic_montgomery.zig");
pub const poseidon2 = @import("poseidon2.zig");

// Field implementations
pub const koalabear_montgomery = @import("fields/koalabear/montgomery.zig");

// Instances
pub const koalabear16 = @import("instances/koalabear16.zig");

// Re-export the main types (snake_case per lint)
pub const poseidon2_koalabear16 = koalabear16.poseidon2_type;
pub const koalabear_field = koalabear_montgomery.montgomery_field;
