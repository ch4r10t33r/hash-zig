use p3_koala_bear::KoalaBear;
use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_symmetric::Permutation;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

fn main() {
    // Test with the same input as Zig
    let mut state_16 = [KoalaBear::ZERO; 16];
    state_16[0] = KoalaBear::new(0x12345678);  // 305419896
    state_16[1] = KoalaBear::new(0x9abcdef0);  // 2596069104

    println!("=== Plonky3 Poseidon2-16 Debug ===");
    println!("Initial state:");
    for (i, elem) in state_16.iter().enumerate() {
        println!("  state[{}] = {} (normal: {})", i, elem.as_canonical_u32(), elem.as_canonical_u32());
    }

    // Get the Poseidon2 instance
    let poseidon2_16 = default_koalabear_poseidon2_16();

    // Run the permutation
    poseidon2_16.permute_mut(&mut state_16);

    println!("\n=== Final Output ===");
    for (i, elem) in state_16.iter().enumerate() {
        println!("  state[{}] = {} (normal: {})", i, elem.as_canonical_u32(), elem.as_canonical_u32());
    }

    // Test with different input to see pattern
    println!("\n=== Test with Different Input ===");
    let mut state_16_2 = [KoalaBear::ZERO; 16];
    state_16_2[0] = KoalaBear::new(1);
    state_16_2[1] = KoalaBear::new(2);
    
    println!("Input: [1, 2, 0, 0, ...]");
    poseidon2_16.permute_mut(&mut state_16_2);
    
    println!("Output:");
    for (i, elem) in state_16_2.iter().enumerate() {
        if i < 4 {
            println!("  state[{}] = {} (normal: {})", i, elem.as_canonical_u32(), elem.as_canonical_u32());
        }
    }
}
