use p3_field::PrimeField32;
use p3_koala_bear::{
    KOALABEAR_RC16_EXTERNAL_FINAL, KOALABEAR_RC16_EXTERNAL_INITIAL, KOALABEAR_RC16_INTERNAL,
};

fn main() {
    println!("=== Verifying KoalaBear Poseidon2 Round Constants ===");

    println!("External Initial Round 0 (first 4):");
    for val in KOALABEAR_RC16_EXTERNAL_INITIAL[0][0..4]
        .iter()
        .map(|f| f.as_canonical_u32())
    {
        print!("{}, ", val);
    }
    println!();

    println!("External Final Round 0 (first 4):");
    for val in KOALABEAR_RC16_EXTERNAL_FINAL[0][0..4]
        .iter()
        .map(|f| f.as_canonical_u32())
    {
        print!("{}, ", val);
    }
    println!();

    println!(
        "Internal Round 0: {}",
        KOALABEAR_RC16_INTERNAL[0].as_canonical_u32()
    );

    println!("\nReference values from Zig matcher:");
    println!("External Initial Round 0: [2128964168, 288780357, 316938561, 2126233899, ...]");
    println!("External Final Round 0: [1423960925, 2101391318, 1915532054, 275400051, ...]");
    println!("Internal Round 0: 2102596038");
}
