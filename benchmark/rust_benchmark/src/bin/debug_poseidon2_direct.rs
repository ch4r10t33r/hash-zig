use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Rust Poseidon2 Direct Test ===");
    println!("SEED: {}", seed_hex);

    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);

    let mut rng = StdRng::from_seed(seed_array);

    println!("\n=== Test Poseidon2 Tree Hash Directly ===");

    // Generate a key to get the exact parameters
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();

    // Parse the JSON to extract parameter values
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let param_array = pk_data["parameter"].as_array().unwrap();
    let mut param_values = [0u32; 5];
    for (i, val) in param_array.iter().enumerate() {
        param_values[i] = val.as_u64().unwrap() as u32;
    }

    println!("Parameter values: {:?}", param_values);

    // Test with the exact inputs that Zig is using
    let test_input = vec![
        0x1640cb16, 0x54503ce2, 0x7e118cb3, 0x6aeeecb5, 0x4ea08a17, 0x2c138707, 0x65d14fc6,
        0x2c5e70b5, 0x30ff8f32, 0x59e166e4, 0x7e8fc675, 0x60080f45, 0x5bbb59d8, 0x5d5742ec,
        0x1e0d8135, 0x4915976b,
    ];

    println!("Test input (16 elements):");
    for (i, val) in test_input.iter().enumerate() {
        println!("  [{}] = 0x{:x} ({})", i, val, val);
    }

    // Test tweak computation
    let level: u8 = 5;
    let pos_in_level: u32 = 0;
    let tweak_bigint = ((level as u128) << 40) | ((pos_in_level as u128) << 8) | 0x01;
    let p: u128 = 2130706433; // KoalaBear field modulus
    let tweak = [(tweak_bigint % p) as u32, ((tweak_bigint / p) % p) as u32];

    println!("\nTweak computation:");
    println!("  Level: {}, Pos: {}", level, pos_in_level);
    println!("  Tweak bigint: 0x{:x}", tweak_bigint);
    println!("  Tweak[0]: 0x{:x} ({})", tweak[0], tweak[0]);
    println!("  Tweak[1]: 0x{:x} ({})", tweak[1], tweak[1]);

    // Show the complete input that will be passed to Poseidon2
    println!("\nComplete Poseidon2 input (parameter + tweak + message):");
    println!("Parameter (5 elements):");
    for (i, val) in param_values.iter().enumerate() {
        println!("  [{}] = 0x{:x}", i, val);
    }
    println!("Tweak (2 elements):");
    for (i, val) in tweak.iter().enumerate() {
        println!("  [{}] = 0x{:x}", i, val);
    }
    println!("Message (16 elements):");
    for (i, val) in test_input.iter().enumerate() {
        println!("  [{}] = 0x{:x}", i, val);
    }

    // Test the hash function directly
    let mut rng2 = StdRng::from_seed(seed_array);
    let (pk2, _sk2) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    let pk_json2 = serde_json::to_string(&pk2).unwrap();

    // Parse the JSON to extract root values
    let pk_data2: serde_json::Value = serde_json::from_str(&pk_json2).unwrap();
    let root_array = pk_data2["root"].as_array().unwrap();
    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }

    println!("\nFinal root values: {:?}", root_values);
    println!("Expected Zig result: 0x31461cb0");
    println!("Actual Rust result: 0x{:x}", root_values[0]);
}
