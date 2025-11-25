//! Rust tool for cross-language compatibility testing
//! 
//! This tool provides:
//! - Key generation (lifetime 2^8)
//! - Serialization of secret/public keys to bincode JSON
//! - Signing messages
//! - Verifying signatures from Zig

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json;
use rand::{SeedableRng, rngs::StdRng, RngCore};
use std::env;
use std::fs;
use std::io::Write;

type S = SIGTopLevelTargetSumLifetime8Dim64Base8;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} keygen [seed_hex]                    - Generate keypair and save to tmp/rust_sk.json and tmp/rust_pk.json", args[0]);
        eprintln!("  {} sign <message> <epoch>               - Sign message using tmp/rust_sk.json, save to tmp/rust_sig.bin (3116 bytes)", args[0]);
        eprintln!("  {} verify <zig_sig.bin> <zig_pk.json> <message> <epoch> - Verify Zig signature", args[0]);
        std::process::exit(1);
    }
    
    match args[1].as_str() {
        "keygen" => {
            let seed_hex = args.get(2);
            keygen_command(seed_hex)?;
        }
        "sign" => {
            if args.len() < 4 {
                eprintln!("Usage: {} sign <message> <epoch>", args[0]);
                std::process::exit(1);
            }
            let message = &args[2];
            let epoch: u32 = args[3].parse()?;
            sign_command(message, epoch)?;
        }
        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: {} verify <zig_sig.json> <zig_pk.json> <message> <epoch>", args[0]);
                std::process::exit(1);
            }
            let sig_path = &args[2];
            let pk_path = &args[3];
            let message = &args[4];
            let epoch: u32 = args[5].parse()?;
            verify_command(sig_path, pk_path, message, epoch)?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn keygen_command(seed_hex: Option<&String>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Generating keypair with lifetime 2^8...");
    
    // Create tmp directory if it doesn't exist
    fs::create_dir_all("tmp")?;
    
    let seed = if let Some(hex) = seed_hex {
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err("Seed must be 32 bytes (64 hex chars)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        // Generate random seed using getrandom crate
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("Failed to generate random seed: {}", e))?;
        seed
    };
    
    // Generate keypair using seeded RNG
    let mut rng = StdRng::from_seed(seed);
    let (public_key, mut secret_key) = S::key_gen(&mut rng, 0, 256);
    
    // Serialize secret key to bincode JSON
    let sk_json = serde_json::to_string_pretty(&secret_key)?;
    fs::write("tmp/rust_sk.json", &sk_json)?;
    eprintln!("✅ Secret key saved to tmp/rust_sk.json");
    
    // Serialize public key to bincode JSON
    let pk_json = serde_json::to_string_pretty(&public_key)?;
    fs::write("tmp/rust_pk.json", &pk_json)?;
    eprintln!("✅ Public key saved to tmp/rust_pk.json");
    
    eprintln!("Keypair generated successfully!");
    Ok(())
}

fn sign_command(message: &str, epoch: u32) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Signing message: '{}' (epoch: {})", message, epoch);
    
    // Load secret key from tmp/rust_sk.json
    let sk_json = fs::read_to_string("tmp/rust_sk.json")?;
    type SkType = <S as SignatureScheme>::SecretKey;
    let secret_key: SkType = serde_json::from_str(&sk_json)?;
    
    // Convert message to bytes (32 bytes)
    let mut msg_bytes = [0u8; 32];
    let msg_slice = message.as_bytes();
    let len = msg_slice.len().min(32);
    msg_bytes[..len].copy_from_slice(&msg_slice[..len]);
    
    // Sign the message
    let signature = S::sign(&secret_key, epoch, &msg_bytes)?;
    
    // Serialize signature to bincode binary format (3116 bytes per leanSignature spec)
    let mut sig_bytes = bincode::serialize(&signature)?;
    
    // Pad to exactly 3116 bytes as per leanSignature spec
    const SIG_LEN: usize = 3116;
    if sig_bytes.len() > SIG_LEN {
        return Err(format!("Signature too large: {} bytes (max {})", sig_bytes.len(), SIG_LEN).into());
    }
    sig_bytes.resize(SIG_LEN, 0);
    
    fs::write("tmp/rust_sig.bin", &sig_bytes)?;
    eprintln!("✅ Signature saved to tmp/rust_sig.bin ({} bytes)", sig_bytes.len());
    
    eprintln!("Message signed successfully!");
    Ok(())
}

fn verify_command(sig_path: &str, pk_path: &str, message: &str, epoch: u32) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Verifying signature from Zig...");
    eprintln!("  Signature: {}", sig_path);
    eprintln!("  Public key: {}", pk_path);
    eprintln!("  Message: '{}'", message);
    eprintln!("  Epoch: {}", epoch);
    
    // Load signature from binary format (bincode)
    let sig_bytes = fs::read(sig_path)?;
    
    // Deserialize from bincode (slice to expected size if needed, per leanSignature spec)
    const SIG_LEN: usize = 3116;
    let sig_data = if sig_bytes.len() > SIG_LEN {
        &sig_bytes[..SIG_LEN]
    } else {
        &sig_bytes
    };
    
    let signature: <S as SignatureScheme>::Signature = bincode::deserialize(sig_data)?;
    
    // Load public key from Zig
    let pk_json = fs::read_to_string(pk_path)?;
    let pk_value: serde_json::Value = serde_json::from_str(&pk_json)?;
    
    // Debug: Extract and print Poseidon inputs/outputs for comparison
    // This matches what Zig does in applyTopLevelPoseidonMessageHash
    // Note: We can't easily access rho from the signature struct here,
    // so we'll add debug output to show what Rust's verify function sees
    // The actual Poseidon computation happens inside S::verify
    eprintln!("RUST_VERIFY_DEBUG: About to call S::verify");
    eprintln!("RUST_VERIFY_DEBUG: Public key parameter (first 3): {:?}", 
              pk_value.get("parameter").and_then(|p| p.as_array())
                  .map(|arr| arr.iter().take(3).map(|v| v.as_u64()).collect::<Vec<_>>()));
    
    // Use fully qualified type to avoid ambiguity
    type PkType = <S as SignatureScheme>::PublicKey;
    let public_key: PkType = serde_json::from_value(pk_value)?;
    
    // Convert message to bytes (32 bytes)
    let mut msg_bytes = [0u8; 32];
    let msg_slice = message.as_bytes();
    let len = msg_slice.len().min(32);
    msg_bytes[..len].copy_from_slice(&msg_slice[..len]);
    
    eprintln!("RUST_VERIFY_DEBUG: Message: {:?}", &msg_bytes[..8]);
    eprintln!("RUST_VERIFY_DEBUG: Epoch: {}", epoch);
    
    // Verify the signature
    let is_valid = S::verify(&public_key, epoch, &msg_bytes, &signature);
    
    if is_valid {
        eprintln!("✅ Signature verification PASSED!");
        Ok(())
    } else {
        eprintln!("❌ Signature verification FAILED!");
        std::process::exit(1);
    }
}

