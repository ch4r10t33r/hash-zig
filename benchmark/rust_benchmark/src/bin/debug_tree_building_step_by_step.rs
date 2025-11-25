use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::SignatureScheme;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());

    println!("=== Rust Tree Building Step-by-Step Debug ===");
    println!("SEED: {}", seed_hex);

    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);

    let mut rng = StdRng::from_seed(seed_array);

    println!("\n=== Generate Key and Extract Details ===");

    // Generate a key to get the exact parameters and root
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    let pk_json = serde_json::to_string(&pk).unwrap();

    // Parse the JSON to extract values
    let pk_data: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    let param_array = pk_data["parameter"].as_array().unwrap();
    let root_array = pk_data["root"].as_array().unwrap();

    let mut param_values = [0u32; 5];
    for (i, val) in param_array.iter().enumerate() {
        param_values[i] = val.as_u64().unwrap() as u32;
    }

    let mut root_values = [0u32; 8];
    for (i, val) in root_array.iter().enumerate() {
        root_values[i] = val.as_u64().unwrap() as u32;
    }

    println!("Parameter values: {:?}", param_values);
    println!("Root values: {:?}", root_values);

    // Test the specific tree hash operation that should produce 0x31461cb0
    println!("\n=== Test Specific Tree Hash Operation ===");

    // These are the exact values from the Zig debug output
    let left_child = 0x1640cb16;
    let right_child = 0x54503ce2;
    let level: u8 = 5;
    let pos_in_level: u32 = 0;

    println!("Left child: 0x{:x} ({})", left_child, left_child);
    println!("Right child: 0x{:x} ({})", right_child, right_child);
    println!("Level: {}, Position: {}", level, pos_in_level);

    // Test tweak computation
    let tweak_bigint = ((level as u128) << 40) | ((pos_in_level as u128) << 8) | 0x01;
    let p: u128 = 2130706433; // KoalaBear field modulus
    let tweak = [(tweak_bigint % p) as u32, ((tweak_bigint / p) % p) as u32];

    println!("Tweak bigint: 0x{:x}", tweak_bigint);
    println!("Tweak[0]: 0x{:x} ({})", tweak[0], tweak[0]);
    println!("Tweak[1]: 0x{:x} ({})", tweak[1], tweak[1]);

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
    println!("  [0] = 0x{:x}", left_child);
    println!("  [1] = 0x{:x}", right_child);
    println!("  [2-15] = 0x0 (padding)");

    println!("\nExpected result from Zig debug: 0x31461cb0");
    println!("Actual Rust root[0]: 0x{:x}", root_values[0]);
    println!("Match: {}", root_values[0] == 0x31461cb0);

    // Test if the issue is in the tree building algorithm by comparing intermediate results
    println!("\n=== Tree Building Algorithm Analysis ===");
    println!("The issue appears to be in the tree building algorithm itself.");
    println!("First hash operation should produce 0x31461cb0, but subsequent operations diverge.");
    println!("This suggests the tree building logic differs between Rust and Zig implementations.");
}
