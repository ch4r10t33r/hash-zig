use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;
use p3_field::PrimeField32;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== KoalaBear Random Generation Investigation ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    let mut rng = StdRng::from_seed(seed_array);
    
    println!("\n=== Direct u32 generation ===");
    let param_u32 = rng.random::<[u32; 5]>();
    for (i, val) in param_u32.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    println!("\n=== KoalaBear field generation ===");
    let param_koalabear = rng.random::<[p3_koala_bear::KoalaBear; 5]>();
    for (i, val) in param_koalabear.iter().enumerate() {
        let val_u32 = val.as_canonical_u32();
        println!("  [{}] = {} (0x{:x}) - KoalaBear", i, val_u32, val_u32);
        
        // Check if this is half of the u32 value
        if i < param_u32.len() {
            let half = param_u32[i] / 2;
            if val_u32 == half {
                println!("    -> This is exactly half of u32 value!");
            } else {
                println!("    -> Not half: u32={}, half={}, koalabear={}", param_u32[i], half, val_u32);
            }
        }
    }
    
    println!("\n=== Key generation test ===");
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("Public Key (JSON): {}", pk_json);
    
    // Parse the JSON to extract parameters
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let pk_params = pk_data["parameter"].as_array().unwrap();
    let mut pk_param_array = [0u32; 5];
    for (i, val) in pk_params.iter().enumerate() {
        pk_param_array[i] = val.as_u64().unwrap() as u32;
    }
    
    println!("\n=== Comparison ===");
    println!("Direct u32: {:?}", param_u32);
    println!("KoalaBear: {:?}", param_koalabear.iter().map(|x| x.as_canonical_u32()).collect::<Vec<_>>());
    println!("Public key: {:?}", pk_param_array);
    
    // Check if KoalaBear generation matches public key
    let koalabear_vec: Vec<u32> = param_koalabear.iter().map(|x| x.as_canonical_u32()).collect();
    let koalabear_array: [u32; 5] = koalabear_vec.try_into().unwrap();
    if koalabear_array == pk_param_array {
        println!("✅ KoalaBear generation matches public key!");
    } else {
        println!("❌ KoalaBear generation does not match public key");
    }
}
