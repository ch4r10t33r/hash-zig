use plonky3::field::types::Field;
use plonky3::field::types::Field64;
use plonky3::field::koalabear::KoalaBear;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::env;

fn main() {
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242".to_string());
    
    println!("=== KoalaBear Field Investigation ===");
    println!("SEED: {}", seed_hex);
    
    // Parse seed
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid hex seed");
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes[..32]);
    
    let mut rng = StdRng::from_seed(seed_array);
    
    println!("\n=== Direct u32 generation ===");
    let param_u32 = rng.random::<[u32; 5]>();
    for (i, val) in param_u32.iter().enumerate() {
        println!("  [{}] = {} (0x{:x})", i, val, val);
    }
    
    println!("\n=== KoalaBear field generation ===");
    let param_koalabear = rng.random::<[KoalaBear; 5]>();
    for (i, val) in param_koalabear.iter().enumerate() {
        let val_u32 = val.to_canonical_u64() as u32;
        println!("  [{}] = {} (0x{:x}) - Montgomery form", i, val_u32, val_u32);
        
        // Check if this is half of the u32 value
        if i < param_u32.len() {
            let half = param_u32[i] / 2;
            if val_u32 == half {
                println!("    -> This is exactly half of u32 value!");
            } else {
                println!("    -> Not half: u32={}, half={}, koalabear={}", param_u32[i], half, val_u32);
            }
        }
    }
    
    println!("\n=== Field conversion test ===");
    for i in 0..5 {
        let u32_val = param_u32[i];
        let koalabear_from_u32 = KoalaBear::from_canonical_u64(u32_val as u64);
        let koalabear_to_u32 = koalabear_from_u32.to_canonical_u64() as u32;
        
        println!("u32[{}] = {} -> KoalaBear -> u32 = {}", i, u32_val, koalabear_to_u32);
        
        if koalabear_to_u32 == u32_val / 2 {
            println!("  -> KoalaBear conversion halves the value!");
        }
    }
}
