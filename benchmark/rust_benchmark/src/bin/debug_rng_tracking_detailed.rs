use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Detailed RNG Tracking Debug ===");
    println!("SEED: {}", seed_hex);

    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);

    // Test 1: Track RNG state step by step to match the exact flow
    let mut rng = StdRng::from_seed(seed_array);

    println!("\n=== Step-by-step RNG consumption to match Rust key_gen ===");

    // Step 1: Generate parameters directly (this should match the public key parameters)
    println!("Step 1: Direct parameter generation");
    let param_direct = rng.random::<[u32; 5]>();
    for (i, val) in param_direct.iter().enumerate() {
        println!("  Parameter[{}] = {} (0x{:x})", i, val, val);
    }

    // Step 2: Generate PRF key
    println!("\nStep 2: PRF key generation");
    let mut prf_key = [0u8; 32];
    rng.fill(&mut prf_key);
    println!("  PRF key: {:02x?}", prf_key);

    // Step 3: Check RNG state after parameter + PRF key generation
    println!("\nStep 3: RNG state after parameter + PRF key generation");
    for i in 0..10 {
        let val = rng.gen::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }

    // Step 4: Now try to match the key_gen flow
    println!("\nStep 4: Key generation flow");
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("Public Key (JSON): {}", pk_json);

    // Step 5: Check if the parameters in the public key match our direct generation
    println!("\nStep 5: Comparing parameters");
    println!("Direct generation: {:?}", param_direct);
    println!("Public key (JSON): {}", pk_json);

    // Parse the JSON to extract parameters
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let pk_params = pk_data["parameter"].as_array().unwrap();
    let mut pk_param_array = [0u32; 5];
    for (i, val) in pk_params.iter().enumerate() {
        pk_param_array[i] = val.as_u64().unwrap() as u32;
    }

    println!("Public key params: {:?}", pk_param_array);

    if param_direct == pk_param_array {
        println!("✅ Parameters match!");
    } else {
        println!("❌ Parameters differ!");
    }
}
