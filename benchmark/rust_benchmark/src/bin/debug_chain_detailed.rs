use leansig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
    SignatureScheme,
};
use rand::{rngs::StdRng, SeedableRng};
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| {
        "4242424242424242424242424242424242424242424242424242424242424242".to_string()
    });
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

    println!("SEED (bytes): {:02x?}", seed);

    // Create two identical RNGs
    let mut rng = StdRng::from_seed(seed);

    // Generate keypair (activation_epoch=0, num_active_epochs=256)
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);

    println!("Public Key (JSON): {}", serde_json::to_string(&pk).unwrap());
}
