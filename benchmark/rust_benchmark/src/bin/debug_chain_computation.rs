use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use hashsig::symmetric::prf::ShakePRFtoF_8_7;

fn main() {
    println!("=== Chain Computation Debug ===");
    
    // Use the same seed as the comparison test
    let seed = [0x42u8; 32];
    
    // Initialize RNG
    let mut rng = ChaCha12Rng::from_seed(seed);
    
    println!("SEED: {:02x?}", seed);
    
    // Generate parameters and PRF key (same as before)
    let mut parameter = [0u32; 5];
    for i in 0..5 {
        parameter[i] = rng.gen::<u32>();
    }
    
    let mut prf_key = [0u8; 32];
    rng.fill(&mut prf_key);
    
    println!("Parameter: {:?}", parameter);
    println!("PRF key: {:02x?}", prf_key);
    
    // Test the first few domain elements and chain computations
    println!("\nTesting domain elements and chain computations:");
    
    // Test domain element generation for epoch 0, chain 0
    let domain_elements_0_0 = ShakePRFtoF_8_7::get_domain_element(&prf_key, 0, 0);
    println!("Domain elements for epoch 0, chain 0: {:?}", domain_elements_0_0);
    
    // Test domain element generation for epoch 0, chain 1
    let domain_elements_0_1 = ShakePRFtoF_8_7::get_domain_element(&prf_key, 0, 1);
    println!("Domain elements for epoch 0, chain 1: {:?}", domain_elements_0_1);
    
    // Test domain element generation for epoch 1, chain 0
    let domain_elements_1_0 = ShakePRFtoF_8_7::get_domain_element(&prf_key, 1, 0);
    println!("Domain elements for epoch 1, chain 0: {:?}", domain_elements_1_0);
    
    // Check RNG state after domain element generation
    println!("\nRNG state after domain element generation:");
    for i in 0..10 {
        let val = rng.gen::<u32>();
        println!("  [{}] = {}", i, val);
    }
}
