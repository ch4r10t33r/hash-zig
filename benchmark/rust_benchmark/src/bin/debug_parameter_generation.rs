use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

fn main() {
    println!("=== Parameter Generation Debug ===");

    // Use the same seed as the comparison test
    let seed = [0x42u8; 32];

    // Initialize RNG
    let mut rng = ChaCha12Rng::from_seed(seed);

    println!("SEED: {:02x?}", seed);
    println!("SEED (bytes): {:?}", seed);

    // Generate parameters exactly like in the key generation
    println!("\nGenerating parameters...");

    let mut parameter = [0u32; 5];
    for i in 0..5 {
        let val = rng.gen::<u32>();
        parameter[i] = val;
        println!("Parameter[{}] = {} (0x{:x})", i, val, val);
    }

    println!("\nParameter array: {:?}", parameter);

    // Generate PRF key
    println!("\nGenerating PRF key...");
    let mut prf_key = [0u8; 32];
    rng.fill(&mut prf_key);
    println!("PRF key: {:02x?}", prf_key);

    // Check RNG state after parameter and PRF key generation
    println!("\nRNG state after parameter and PRF key generation:");
    for i in 0..10 {
        let val = rng.gen::<u32>();
        println!("  [{}] = {}", i, val);
    }
}
