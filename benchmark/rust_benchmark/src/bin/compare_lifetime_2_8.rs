use hashsig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
    SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use serde_json;
use std::env;

// Program: Generate two keypairs for lifetime 2^8 using the same seed and compare public keys
// Usage: set SEED_HEX (64 hex chars). Defaults to 0x42 repeated.
fn main() {
    println!("Rust hash-sig Determinism Check (lifetime 2^8)\n================================================");

    // Seed handling (32-byte hex)
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "42".repeat(64));
    let mut seed = [0u8; 32];
    let used_seed_hex = if seed_hex.len() >= 64 {
        &seed_hex[..64]
    } else {
        &seed_hex
    };
    for i in 0..32 {
        let hi = u8::from_str_radix(&used_seed_hex[i * 2..i * 2 + 1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&used_seed_hex[i * 2 + 1..i * 2 + 2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    println!("SEED: {}", used_seed_hex);
    println!("SEED (bytes): {:02x?}", seed);

    // Two RNGs with identical seeds
    let mut rng1 = StdRng::from_seed(seed);
    let mut rng2 = StdRng::from_seed(seed);

    // Lifetime 2^8: activation_epoch=0, num_active_epochs=256
    println!("DEBUG: Generating keypair 1...");
    let (pk1, _sk1) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng1, 0, 256);
    println!("DEBUG: Generating keypair 2...");
    let (pk2, _sk2) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);

    // Compare serialized public keys (JSON) for exact equality
    let pk1_json = match serde_json::to_string(&pk1) {
        Ok(json) => json,
        Err(e) => {
            println!("Error serializing pk1: {}", e);
            return;
        }
    };
    let pk2_json = match serde_json::to_string(&pk2) {
        Ok(json) => json,
        Err(e) => {
            println!("Error serializing pk2: {}", e);
            return;
        }
    };
    let pk1_bytes = pk1_json.as_bytes();
    let pk2_bytes = pk2_json.as_bytes();

    let equal = pk1_bytes == pk2_bytes;
    println!("Public keys equal: {}", equal);

    if equal {
        println!("✅ Deterministic: same seed -> identical public keys (2^8)");
    } else {
        println!("❌ Non-deterministic with current path (2^8)");
        println!("Hint: ensure RNG is the only randomness source in keygen");
    }

    // Print the public key for inspection
    println!("\nPublic Key (JSON):");
    println!("{}", pk1_json);
    println!("\nPublic Key (JSON bytes):");
    println!("{:02x?}", &pk1_bytes[..std::cmp::min(32, pk1_bytes.len())]);
    if pk1_bytes.len() > 32 {
        println!("... (total {} bytes)", pk1_bytes.len());
    }
}
