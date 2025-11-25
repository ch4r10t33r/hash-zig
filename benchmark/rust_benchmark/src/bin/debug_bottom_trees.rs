use leansig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
    SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::Value;
use std::env;

fn main() {
    println!("Rust hash-sig Bottom Trees Debug (lifetime 2^8)\n================================================");

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
    println!("SEED (bytes): {:?}", seed);

    let mut rng = StdRng::from_seed(seed);

    // Generate keypair to access internal state
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);

    // Serialize public key for debugging since fields are private
    let pk_json = serde_json::to_string_pretty(&pk).expect("serialize pk");
    println!("Public key (JSON): {}", pk_json);

    // Extract notable fields if present
    if let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(&pk_json) {
        if let Some(root) = obj.remove("root") {
            println!("root: {}", root);
        }
        if let Some(parameter) = obj.remove("parameter") {
            println!("parameter: {}", parameter);
        }
    }

    println!("Keypair generated successfully");
}
