use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::Rng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== RNG Consumption Order Debug ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    // Test 1: Generate parameters directly
    let mut rng1 = StdRng::from_seed(seed_array);
    let param_direct = rng1.random::<[u32; 5]>();
    println!("\nDirect parameter generation:");
    for (i, val) in param_direct.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    // Test 2: Generate parameters through key_gen
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("\nKey generation result:");
    println!("Public Key (JSON): {}", pk_json);
    
    // Test 3: Check RNG state difference
    let mut rng3 = StdRng::from_seed(seed_array);
    let _param_direct2 = rng3.random::<[u32; 5]>();
    let mut rng4 = StdRng::from_seed(seed_array);
    let _pk2 = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng4, 0, 256);
    
    println!("\nRNG state after direct parameter generation:");
    for i in 0..5 {
        let val = rng3.gen::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    println!("\nRNG state after key generation:");
    for i in 0..5 {
        let val = rng4.gen::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
}
