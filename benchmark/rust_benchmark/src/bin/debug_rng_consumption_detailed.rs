use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Rust Detailed RNG Consumption Analysis ===");
    println!("SEED: {}", seed_hex);

    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);

    let mut rng = StdRng::from_seed(seed_array);

    println!("\n=== RNG State Analysis ===");
    println!("First 20 RNG values:");
    for i in 0..20 {
        let val = rng.random::<u32>();
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }

    println!("\n=== Key Generation with RNG Tracking ===");
    let mut rng2 = StdRng::from_seed(seed_array);

    // Track RNG consumption during key generation
    println!("RNG values consumed during key generation:");
    let mut rng_values = Vec::new();
    for i in 0..50 {
        // Track first 50 values
        let val = rng2.random::<u32>();
        rng_values.push(val);
        if i < 20 {
            println!("  [{}] = {} (0x{:x})", i, val, val);
        }
    }

    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();

    // Parse the JSON to extract root values
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let root_array = pk_data["root"].as_array().unwrap();
    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }

    println!("\n=== Results ===");
    println!("Final root values: {:?}", root_values);

    println!("\n=== RNG State After Key Generation ===");
    let next_val = rng2.random::<u32>();
    println!("Next RNG value: {} (0x{:x})", next_val, next_val);

    // Calculate total RNG consumption
    let total_consumed = rng_values.len();
    println!("Total RNG values consumed: {}", total_consumed);

    // Show the pattern of RNG consumption
    println!("\n=== RNG Consumption Pattern ===");
    println!("First 10 values: {:?}", &rng_values[0..10]);
    println!("Values 10-20: {:?}", &rng_values[10..20]);
    println!("Values 20-30: {:?}", &rng_values[20..30]);
    println!("Values 30-40: {:?}", &rng_values[30..40]);
    if rng_values.len() > 40 {
        println!("Values 40-50: {:?}", &rng_values[40..50]);
    }
}
