use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== RNG Array vs Individual Debug ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    println!("SEED (bytes): {:?}", seed_array);
    
    // Test 1: Generate array at once
    let mut rng1 = StdRng::from_seed(seed_array);
    let param_array = rng1.random::<[u32; 5]>();
    println!("\nMethod 1 - rng.random::<[u32; 5]>():");
    for (i, val) in param_array.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Test 2: Generate individual values
    let mut rng2 = StdRng::from_seed(seed_array);
    println!("\nMethod 2 - rng.random::<u32>() 5 times:");
    for i in 0..5 {
        let val = rng2.random::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Test 3: Check if they're the same
    let mut rng3 = StdRng::from_seed(seed_array);
    let param_array2 = rng3.random::<[u32; 5]>();
    let mut rng4 = StdRng::from_seed(seed_array);
    let mut individual_values = [0u32; 5];
    for i in 0..5 {
        individual_values[i] = rng4.random::<u32>();
    }
    
    println!("\nComparison:");
    println!("Array method: {:?}", param_array2);
    println!("Individual method: {:?}", individual_values);
    println!("Are they equal? {}", param_array2 == individual_values);
}
