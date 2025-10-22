use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use rand::rngs::StdRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== RNG Comparison: StdRng vs ChaCha12Rng ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    // Test 1: StdRng parameter generation
    println!("\n=== StdRng ===");
    let mut rng1 = StdRng::from_seed(seed_array);
    let param1 = rng1.random::<[u32; 5]>();
    println!("Parameters:");
    for (i, val) in param1.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Test 2: ChaCha12Rng parameter generation
    println!("\n=== ChaCha12Rng ===");
    let mut rng2 = ChaCha12Rng::from_seed(seed_array);
    let param2 = rng2.random::<[u32; 5]>();
    println!("Parameters:");
    for (i, val) in param2.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Compare
    println!("\n=== Comparison ===");
    if param1 == param2 {
        println!("✅ Both RNGs produce identical output!");
    } else {
        println!("❌ RNGs produce different output!");
        println!("Differences:");
        for i in 0..5 {
            if param1[i] != param2[i] {
                println!("  [{}]: StdRng={}, ChaCha12Rng={}", i, param1[i], param2[i]);
            }
        }
    }
}

