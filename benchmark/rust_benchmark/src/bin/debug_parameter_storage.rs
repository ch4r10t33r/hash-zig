use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== Parameter Storage Investigation ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    // Test 1: Direct parameter generation
    let mut rng = StdRng::from_seed(seed_array);
    let param_direct = rng.random::<[u32; 5]>();
    println!("\nDirect parameter generation:");
    for (i, val) in param_direct.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Test 2: Generate key and check parameters
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    
    // Test 3: Check if parameters are stored differently
    println!("\nPublic key parameters:");
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("Public Key (JSON): {}", pk_json);
    
    // Parse the JSON to extract parameters
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let pk_params = pk_data["parameter"].as_array().unwrap();
    let mut pk_param_array = [0u32; 5];
    for (i, val) in pk_params.iter().enumerate() {
        pk_param_array[i] = val.as_u64().unwrap() as u32;
        println!("  [{}] = {} (0x{:x})", i, pk_param_array[i], pk_param_array[i]);
    }
    
    // Test 4: Check the relationship
    println!("\nRelationship analysis:");
    for i in 0..5 {
        let direct = param_direct[i];
        let pk_param = pk_param_array[i];
        let half = direct / 2;
        
        println!("[{}]: Direct={}, PK={}, Half={}", i, direct, pk_param, half);
        
        if pk_param == half {
            println!("  -> ✅ PK parameter is exactly half of direct generation!");
        } else {
            println!("  -> ❌ No clear relationship");
        }
    }
    
    // Test 5: Check if this is a serialization issue
    println!("\nSerialization test:");
    let test_params = [2256995122u32, 3695018228, 3988498377, 3748849242, 2605096593];
    let test_json = serde_json::to_string(&test_params).unwrap();
    println!("Direct params JSON: {}", test_json);
    
    let parsed: [u32; 5] = serde_json::from_str(&test_json).unwrap();
    println!("Parsed back: {:?}", parsed);
    
    if parsed == test_params {
        println!("✅ Serialization preserves values");
    } else {
        println!("❌ Serialization changes values");
    }
}
