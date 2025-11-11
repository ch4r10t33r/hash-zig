use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {
    println!("=== RUST RNG COMPARISON TEST ===");

    // Use the same seed as the benchmarks
    let seed = [0x42u8; 32];
    println!("Seed: {:02x?}", seed);

    let mut rng = StdRng::from_seed(seed);

    println!("First 10 u32 values from StdRng:");
    for i in 0..10 {
        let value = rng.next_u32();
        println!("  [{}] = 0x{:08x} ({})", i, value, value);
    }
}
