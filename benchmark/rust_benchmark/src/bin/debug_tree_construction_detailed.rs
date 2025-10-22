use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== Rust Tree Construction Detailed Analysis ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    let mut rng = StdRng::from_seed(seed_array);
    
    println!("\n=== Key Generation with Tree Construction Analysis ===");
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    
    // Parse the JSON to extract values
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let root_array = pk_data["root"].as_array().unwrap();
    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }
    
    let param_array = pk_data["parameter"].as_array().unwrap();
    let mut param_values = [0u32; 5];
    for (i, val) in param_array.iter().enumerate() {
        param_values[i] = val.as_u64().unwrap() as u32;
    }
    
    println!("=== Final Results ===");
    println!("Root values: {:?}", root_values);
    println!("Parameter values: {:?}", param_values);
    
    // Show hex values for easy comparison
    println!("\n=== Hex Values for Comparison ===");
    println!("Root values (hex):");
    for (i, val) in root_values.iter().enumerate() {
        println!("  [{}] = 0x{:x} ({})", i, val, val);
    }
    
    println!("Parameter values (hex):");
    for (i, val) in param_values.iter().enumerate() {
        println!("  [{}] = 0x{:x} ({})", i, val, val);
    }
    
    // Show the exact values that should match
    println!("\n=== Expected Zig Values ===");
    println!("Zig should produce these exact values:");
    println!("Root values: [0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]", 
             root_values[0], root_values[1], root_values[2], root_values[3],
             root_values[4], root_values[5], root_values[6], root_values[7]);
    println!("Parameter values: [0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]", 
             param_values[0], param_values[1], param_values[2], param_values[3], param_values[4]);
}
