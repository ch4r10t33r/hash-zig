use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Parameter Halving Investigation ===");
    println!("SEED: {}", seed_hex);

    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);

    let mut rng = StdRng::from_seed(seed_array);

    println!("\n=== Step 1: Direct u32 generation ===");
    let param_u32 = rng.random::<[u32; 5]>();
    println!("Direct u32: {:?}", param_u32);

    println!("\n=== Step 2: Check if public key uses halved values ===");
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();

    // Parse the JSON to extract parameters
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let pk_params = pk_data["parameter"].as_array().unwrap();
    let mut pk_param_array = [0u32; 5];
    for (i, val) in pk_params.iter().enumerate() {
        pk_param_array[i] = val.as_u64().unwrap() as u32;
    }

    println!("Public key params: {:?}", pk_param_array);

    println!("\n=== Step 3: Verify halving relationship ===");
    let mut all_match = true;
    for i in 0..5 {
        let expected = param_u32[i] / 2;
        let actual = pk_param_array[i];
        if expected == actual {
            println!("  [{}] ✅ {} / 2 = {} (matches)", i, param_u32[i], actual);
        } else {
            println!(
                "  [{}] ❌ {} / 2 = {} (expected) vs {} (actual)",
                i, param_u32[i], expected, actual
            );
            all_match = false;
        }
    }

    if all_match {
        println!(
            "\n🎯 CONFIRMED: Public key parameters are exactly half of direct u32 generation!"
        );
        println!("This means the Rust key_gen process:");
        println!("1. Generates u32 values from RNG");
        println!("2. Halves those values before storing in public key");
        println!("3. Our Zig implementation needs to apply the same halving operation");
    } else {
        println!("\n❌ The halving relationship is not consistent");
    }
}
