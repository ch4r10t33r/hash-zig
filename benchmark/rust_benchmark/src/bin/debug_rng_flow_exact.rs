use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Exact RNG Flow Debug ===");
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
        let val = rng.random::<u32>();
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

        // Step 6: Try to find where the difference comes from
        println!("\nStep 6: Investigating the difference");

        // Check if the parameters in the public key match the RNG state after padding consumption
        let mut rng3 = StdRng::from_seed(seed_array);
        let _param_direct3 = rng3.random::<[u32; 5]>();
        let _prf_key3 = {
            let mut key = [0u8; 32];
            rng3.fill(&mut key);
            key
        };

        // Consume RNG state for padding (8 elements for front + 8 elements for back)
        // This should match the Rust HashTreeLayer::padded consumption
        for _ in 0..8 {
            _ = rng3.random::<u32>();
        }
        for _ in 0..8 {
            _ = rng3.random::<u32>();
        }

        println!("RNG state after padding consumption:");
        for i in 0..5 {
            let val = rng3.random::<u32>();
            println!("  [{}] = {} (0x{:x})", i, val, val);
        }

        // Check if these match the public key parameters
        let mut rng4 = StdRng::from_seed(seed_array);
        let _param_direct4 = rng4.random::<[u32; 5]>();
        let _prf_key4 = {
            let mut key = [0u8; 32];
            rng4.fill(&mut key);
            key
        };

        // Consume RNG state for padding
        for _ in 0..8 {
            _ = rng4.random::<u32>();
        }
        for _ in 0..8 {
            _ = rng4.random::<u32>();
        }

        let param_after_padding = rng4.random::<[u32; 5]>();
        println!(
            "Parameters after padding consumption: {:?}",
            param_after_padding
        );

        if param_after_padding == pk_param_array {
            println!("✅ Parameters after padding consumption match public key!");
        } else {
            println!("❌ Parameters after padding consumption still differ!");
        }
    }
}
