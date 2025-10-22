use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== Rust Bottom Tree Detailed Analysis ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    let mut rng = StdRng::from_seed(seed_array);
    
    // Generate keypair and extract detailed information
    let (pk, sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    
    println!("\n=== Public Key Analysis ===");
    println!("Public Key (JSON): {}", pk_json);
    
    // Parse the JSON to extract detailed information
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    
    // Extract root values
    let root_array = pk_data["root"].as_array().unwrap();
    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }
    
    // Extract parameter values
    let param_array = pk_data["parameter"].as_array().unwrap();
    let mut param_values = [0u32; 5];
    for (i, val) in param_array.iter().enumerate() {
        param_values[i] = val.as_u64().unwrap() as u32;
    }
    
    println!("\n=== Extracted Values ===");
    println!("Root values: {:?}", root_values);
    println!("Parameter values: {:?}", param_values);
    
    // Check if we can access secret key information
    println!("\n=== Secret Key Analysis ===");
    println!("Secret key type: {}", std::any::type_name::<std::boxed::Box<dyn std::any::Any>>());
    
    // Try to get more information about the key generation process
    println!("\n=== RNG State After Key Generation ===");
    let next_rng_val = rng.random::<u32>();
    println!("Next RNG value: {} (0x{:x})", next_rng_val, next_rng_val);
}
