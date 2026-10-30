use hashsig::signature::{
    generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8,
    SignatureScheme,
};
use rand::{SeedableRng, rngs::StdRng, Rng};
use std::env;

fn main() {
    println!("Debug RNG Flow in hash-sig library");
    println!("==================================");

    // Use the same seed as the compare program
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242".to_string());
    let mut seed = [0u8; 32];
    for i in 0..32 {
        let hi = u8::from_str_radix(&seed_hex[i*2..i*2+1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&seed_hex[i*2+1..i*2+2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    println!("SEED: {}", seed_hex);
    println!("SEED (bytes): {:02x?}", seed);

    let mut rng = StdRng::from_seed(seed);
    
    // Test 1: Generate parameter and PRF key directly
    println!("\n--- Test 1: Direct RNG calls ---");
    let parameter_direct: [u32; 5] = rng.random();
    let prf_key_direct: [u8; 32] = rng.random();
    println!("Parameter (direct): {:?}", parameter_direct.map(|x| x % 2130706433));
    println!("PRF key (direct): {:?}", prf_key_direct);

    // Reset RNG
    let mut rng2 = StdRng::from_seed(seed);
    
    // Test 2: Use hash-sig library
    println!("\n--- Test 2: hash-sig library ---");
    let (pk, _sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng2, 0, 256);
    
    // Serialize the public key to see the parameter
    let pk_json = serde_json::to_string(&pk).unwrap();
    println!("Public key JSON: {}", pk_json);
    
    // The issue is that we can't access the internal PRF key from the public key
    // But we can see that the parameters are different, which means the RNG state
    // is being consumed differently in the hash-sig library
}
