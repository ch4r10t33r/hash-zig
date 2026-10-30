use hashsig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8,
};
use hashsig::MESSAGE_LENGTH;
use std::time::Instant;
use std::env;
use std::fs::File;
use std::io::Write;
use rand::{SeedableRng, rngs::StdRng};
use sha3::Digest;
use sha3::Sha3_256;
use serde_json::json;

// NOTE: Cannot define custom signature type because hash-sig does not export:
// - GeneralizedXMSS, hash_functions, prf, encodings, ots modules
// Using SIGWinternitzLifetime18W8 which has IDENTICAL parameters to
// instantiations_poseidon_top_level.rs:212 (W=8, 22 chains, Poseidon2)

fn main() {
    println!("Rust hash-sig Key Generation Benchmark");
    println!("=======================================");
    println!("Lifetime: 2^18 = 262,144 signatures");
    println!("Architecture: Generalized XMSS with Winternitz OTS");
    println!("Type: SIGWinternitzLifetime18W8");
    println!("Parameters: W=8 (matches instantiations_poseidon_top_level.rs:212)");
    println!();

    // Read SEED_HEX env var (64 hex chars => 32 bytes). Default to 0x42 repeated
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "42".repeat(64));
    let mut seed = [0u8; 32];
    for i in 0..32 {
        let hi = u8::from_str_radix(&seed_hex[i*2..i*2+1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&seed_hex[i*2+1..i*2+2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    let mut rng = StdRng::from_seed(seed);
    
    // Use full lifetime 2^18 (all 262,144 signatures available)
    const FULL_LIFETIME: usize = 262_144;
    
    let used_seed_hex = if seed_hex.len() >= 64 { &seed_hex[..64] } else { &seed_hex };
    println!("SEED: {}", used_seed_hex);
    
    // Debug: Print actual parameters being used
    println!("DEBUG: Using lifetime: 2^18 = {}", FULL_LIFETIME);
    println!("DEBUG: RNG seed bytes: {:?}", seed);
    println!("DEBUG: Parameters (matching instantiations_poseidon_top_level.rs:212):");
    println!("  - Winternitz W=8 (22 chains, 256 chain length)");
    println!("  - Hash: Poseidon2KoalaBear");
    println!("  - Encoding: IncomparableBinary");
    
    println!("Generating keypair (Generalized XMSS)...");
    
    let start = Instant::now();
    let (pk, sk) = SIGWinternitzLifetime18W8::key_gen(
        &mut rng,
        0,              // activation_epoch  
        FULL_LIFETIME   // num_active_epochs (use full lifetime 2^18)
    );
    
    let duration = start.elapsed();
    
    let keygen_time = duration.as_secs_f64();
    println!("Key generation completed in {:.3} seconds", keygen_time);
    println!();
    
    // Prepare fixed-size message for signing
    let mut message = [0u8; MESSAGE_LENGTH];
    // Fill with deterministic bytes derived from seed for reproducibility
    for (i, b) in message.iter_mut().enumerate() {
        *b = seed[i % seed.len()];
    }

    // Sign
    let sign_start = Instant::now();
    let signature = SIGWinternitzLifetime18W8::sign(&sk, 0, &message)
        .expect("signing should succeed");
    let sign_time = sign_start.elapsed().as_secs_f64();

    // Verify
    let verify_start = Instant::now();
    let verify_ok = SIGWinternitzLifetime18W8::verify(&pk, 0, &message, &signature);
    let verify_time = verify_start.elapsed().as_secs_f64();

    // For compatibility testing, we need to access the root directly
    // bincode adds overhead and makes comparison difficult
    // Instead, hash just the root (32 bytes) to compare implementations
    
    // Serialize using bincode (for reference)
    let pk_bytes = bincode::serialize(&pk).expect("Failed to serialize public key");
    
    println!("DEBUG: Full bincode serialized size: {} bytes", pk_bytes.len());
    println!("DEBUG: First 32 bytes should be the root");
    
    // For comparison: just use the root (first 32 bytes)
    // This avoids bincode encoding differences
    let root_bytes = &pk_bytes[0..32];
    
    let mut hasher = Sha3_256::new();
    hasher.update(root_bytes);
    let out = hasher.finalize();
    let maybe_digest = Some(hex::encode(out));
    let pk_hex = Some(hex::encode(root_bytes));
    let pk_size = root_bytes.len();
    
    println!("PUBLIC_KEY_STRUCT_RUST:");
    println!("  Root size: {} bytes", root_bytes.len());
    println!("  Root hex: {}", hex::encode(root_bytes));
    println!("  Full bincode size: {} bytes", pk_bytes.len());
    
    // Create JSON output with all measurements
    let output_json = json!({
        "implementation": "rust-hash-sig",
        "type": "SIGWinternitzLifetime18W8",
        "parameters": {
            "winternitz_w": 8,
            "num_chains": 22,
            "chain_length": 256,
            "tree_height": 18,
            "lifetime": FULL_LIFETIME,
            "hash_function": "Poseidon2KoalaBear"
        },
        "timing": {
            "keygen_seconds": keygen_time,
            "sign_seconds": sign_time,
            "verify_seconds": verify_time
        },
        "keys": {
            "seed": used_seed_hex,
            "public_key_hex": pk_hex.clone().unwrap_or_default(),
            "public_key_sha3": maybe_digest.clone().unwrap_or_default(),
            "public_key_size_bytes": pk_size
        },
        "verification": {
            "signature_valid": verify_ok
        }
    });
    
    // Save to JSON file
    let json_filename = "rust_public_key.json";
    match File::create(json_filename) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(serde_json::to_string_pretty(&output_json).unwrap().as_bytes()) {
                eprintln!("Failed to write JSON file: {}", e);
            } else {
                println!("✅ Saved public key to {}", json_filename);
            }
        }
        Err(e) => eprintln!("Failed to create JSON file: {}", e),
    }
    println!();
    
    // Output in format compatible with benchmark script
    println!("BENCHMARK_SEED: {}", used_seed_hex);
    if let Some(d) = maybe_digest {
        println!("PUBLIC_SHA3: {}", d);
    }
    if let Some(hex_str) = pk_hex {
        println!("PUBLIC_KEY_HEX: {}", hex_str);
    }
    println!("VERIFY_OK: {}", verify_ok);
    println!("BENCHMARK_RESULT: {:.6}", keygen_time);
    
    println!();
    println!("✅ Benchmark completed successfully!");
    println!("Implementation: Rust hash-sig (Generalized XMSS)");
    println!("Type: SIGWinternitzLifetime18W8");
    println!("Parameters: W=8, 22 chains, 256 chain length");
    println!("Matches: instantiations_poseidon_top_level.rs:212");
    println!("Configured for: 2^18 = 262,144 signatures");
    println!("Note: Cannot use custom type - internal modules not exported by hash-sig");
}
