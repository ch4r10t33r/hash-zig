use p3_koala_bear::default_koalabear_poseidon2_16;
use p3_koala_bear::KoalaBear;

fn main() {
    println!("=== Verifying Round Constants ===");

    let poseidon2_16 = default_koalabear_poseidon2_16();

    // Get the external constants
    let external_constants = poseidon2_16.external_layer.external_constants;
    let initial_constants = external_constants.get_initial_constants();
    let terminal_constants = external_constants.get_terminal_constants();

    println!("External Initial Round 0 (first 4):");
    for i in 0..4 {
        print!("{}, ", initial_constants[0][i].as_canonical_u32());
    }
    println!();

    println!("External Final Round 0 (first 4):");
    for i in 0..4 {
        print!("{}, ", terminal_constants[0][i].as_canonical_u32());
    }
    println!();

    println!(
        "Internal Round 0: {}",
        poseidon2_16.internal_layer.internal_constants[0].as_canonical_u32()
    );

    // Expected values from our Zig implementation
    println!("\nExpected from Zig:");
    println!("External Initial Round 0: [2128964168, 288780357, 316938561, 2126233899, ...]");
    println!("External Final Round 0: [1423960925, 2101391318, 1915532054, 275400051, ...]");
    println!("Internal Round 0: 2102596038");
}
