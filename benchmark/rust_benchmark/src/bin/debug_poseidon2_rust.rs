use p3_field::PrimeField32;
use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;

fn main() {
    println!("=== Debugging Plonky3 Poseidon2-16 Implementation ===");

    // Test with the same input as our comparison
    let mut state: [KoalaBear; 16] = [
        KoalaBear::new(305419896),
        KoalaBear::new(2596069104),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
        KoalaBear::new(0),
    ];

    println!("Initial state:");
    for (i, elem) in state.iter().enumerate() {
        println!(
            "  state[{}] = {} (normal: {})",
            i,
            elem.as_canonical_u32(),
            elem.as_canonical_u32()
        );
    }

    // Get the Poseidon2 instance
    let poseidon2_16 = default_koalabear_poseidon2_16();

    // Apply first external round manually
    println!("\n=== First External Round ===");

    // Get the first round constants (this is tricky - we need to access the internal state)
    // For now, let's just apply the permutation and see the result
    println!("Applying full permutation...");

    // Apply permutation directly to the array
    poseidon2_16.permute_mut(&mut state);

    println!("Final state after permutation:");
    for (i, elem) in state.iter().enumerate() {
        println!(
            "  state[{}] = {} (normal: {})",
            i,
            elem.as_canonical_u32(),
            elem.as_canonical_u32()
        );
    }
}
