use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::env;

fn main() {
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

    println!("SEED (bytes): {:02x?}", seed);

    // Create two identical RNGs
    let mut rng1 = StdRng::from_seed(seed);
    let mut rng2 = StdRng::from_seed(seed);

    // Generate first keypair (activation_epoch=0, num_active_epochs=256)
    println!("Generating first keypair...");
    let (pk1, _sk1) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng1, 0, 256);

    // Generate second keypair
    println!("Generating second keypair...");
    let (pk2, _sk2) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);

    // Compare public keys
    let pk1_json = serde_json::to_string(&pk1).unwrap();
    let pk2_json = serde_json::to_string(&pk2).unwrap();

    println!("Public Key 1 (JSON): {}", pk1_json);
    println!("Public Key 2 (JSON): {}", pk2_json);

    if pk1_json == pk2_json {
        println!("✅ Public keys are identical!");
    } else {
        println!("❌ Public keys differ!");
        println!(
            "First 100 chars of pk1: {}",
            &pk1_json[..pk1_json.len().min(100)]
        );
        println!(
            "First 100 chars of pk2: {}",
            &pk2_json[..pk2_json.len().min(100)]
        );
    }
}
