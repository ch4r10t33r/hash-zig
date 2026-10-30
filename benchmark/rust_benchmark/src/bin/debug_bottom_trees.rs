use hashsig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
    SignatureScheme,
};
use std::env;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    println!("Rust hash-sig Bottom Trees Debug (lifetime 2^8)\n================================================");

    // Seed handling (32-byte hex)
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "42".repeat(64));
    let mut seed = [0u8; 32];
    let used_seed_hex = if seed_hex.len() >= 64 { &seed_hex[..64] } else { &seed_hex };
    for i in 0..32 {
        let hi = u8::from_str_radix(&used_seed_hex[i*2..i*2+1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&used_seed_hex[i*2+1..i*2+2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    println!("SEED: {}", used_seed_hex);
    println!("SEED (bytes): {:?}", seed);

    let mut rng = StdRng::from_seed(seed);

    // Generate keypair to access internal state
    let (pk, sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    
    // Use getter methods to access internal state
    println!("Public key root: {:?}", pk.get_root());
    println!("Public key parameter: {:?}", pk.get_parameter());
    
    // Access secret key fields via getters if available
    // Note: These fields may not have public getters, so we'll skip them for now
    println!("Keypair generated successfully");
}
