use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== Full Key Generation RNG Debug ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    println!("SEED (bytes): {:?}", seed_array);
    
    // Create RNG
    let mut rng = StdRng::from_seed(seed_array);
    
    // Track RNG consumption
    println!("\nRNG state before key generation:");
    for i in 0..10 {
        let val = rng.gen::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Reset RNG to same seed
    let mut rng2 = StdRng::from_seed(seed_array);
    
    // Generate key pair
    println!("\nGenerating key pair...");
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    
    // Print the public key as JSON
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("\nPublic Key (JSON): {}", pk_json);
    
    // Check RNG state after key generation
    println!("\nRNG state after key generation:");
    for i in 0..10 {
        let val = rng2.gen::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
}
