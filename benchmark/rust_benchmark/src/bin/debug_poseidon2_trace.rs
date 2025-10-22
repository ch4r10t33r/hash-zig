use p3_koala_bear::KoalaBear;
use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_symmetric::Permutation;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

fn main() {
    // Test with simple values to trace execution
    let mut state_16 = [KoalaBear::ZERO; 16];
    state_16[0] = KoalaBear::new(1);
    state_16[1] = KoalaBear::new(2);

    println!("=== Tracing Plonky3 Poseidon2-16 Execution ===");
    println!("Input: [1, 2, 0, 0, ...]");
    
    // Print initial state
    println!("\nInitial state:");
    for i in 0..4 {
        println!("  state[{}] = {} (normal: {})", i, state_16[i].as_canonical_u32(), state_16[i].as_canonical_u32());
    }

    // Get the Poseidon2 instance
    let poseidon2_16 = default_koalabear_poseidon2_16();

    // Run the permutation
    poseidon2_16.permute_mut(&mut state_16);

    println!("\n=== Final Output ===");
    for (i, elem) in state_16.iter().enumerate() {
        if i < 4 {
            println!("  state[{}] = {} (normal: {})", i, elem.as_canonical_u32(), elem.as_canonical_u32());
        }
    }

    // Test with the debug values
    println!("\n=== Debug Values Test ===");
    let mut state_16_debug = [KoalaBear::ZERO; 16];
    state_16_debug[0] = KoalaBear::new(0x12345678);  // 305419896
    state_16_debug[1] = KoalaBear::new(0x9abcdef0);  // 2596069104

    println!("Input: [0x12345678, 0x9abcdef0, 0, 0, ...]");
    
    // Print initial state
    println!("Initial state:");
    for i in 0..4 {
        println!("  state[{}] = {} (normal: {})", i, state_16_debug[i].as_canonical_u32(), state_16_debug[i].as_canonical_u32());
    }
    
    // Run the permutation
    poseidon2_16.permute_mut(&mut state_16_debug);
    
    println!("\n=== Final Output ===");
    for (i, elem) in state_16_debug.iter().enumerate() {
        if i < 4 {
            println!("  state[{}] = {} (normal: {})", i, elem.as_canonical_u32(), elem.as_canonical_u32());
        }
    }
}
