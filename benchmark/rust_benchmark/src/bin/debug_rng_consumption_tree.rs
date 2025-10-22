use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== Rust RNG Consumption During Tree Building ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    let mut rng = StdRng::from_seed(seed_array);
    
    println!("\n=== RNG State Before Key Generation ===");
    println!("First 10 RNG values:");
    for i in 0..10 {
        let val = rng.random::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    println!("\n=== Key Generation ===");
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    
    // Parse the JSON to extract root values
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let root_array = pk_data["root"].as_array().unwrap();
    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }
    
    println!("Final root values: {:?}", root_values);
    
    println!("\n=== RNG State After Key Generation ===");
    let next_val = rng2.random::<u32>();
    println!("Next RNG value: {} (0x{:x})", next_val, next_val);
    
    // Let's also check a few more values to see the pattern
    println!("Next 5 RNG values after key generation:");
    for i in 0..5 {
        let val = rng2.random::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
}
