//! Rust tool for cross-language compatibility testing
//!
//! This tool provides:
//! - Key generation (supports lifetime 2^8, 2^18, 2^32)
//! - Serialization of secret/public keys to JSON
//! - Signing messages
//! - Verifying signatures from Zig

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::SignatureScheme;
use rand::{rngs::StdRng, SeedableRng};
use std::env;
use std::fs;
use ssz::{Decode, Encode};
use ssz::DecodeError;

#[derive(Debug, Clone, Copy)]
enum LifetimeTag {
    Pow8,
    Pow18,
    Pow32,
}

impl LifetimeTag {
    fn parse(raw: Option<&String>) -> Result<Self, Box<dyn std::error::Error>> {
        let provided = raw.map(|s| s.as_str()).unwrap_or("2^8");
        match provided {
            "2^8" => Ok(Self::Pow8),
            "2^18" => Ok(Self::Pow18),
            "2^32" => Ok(Self::Pow32),
            other => Err(format!("unsupported lifetime '{other}'. Must be one of: 2^8, 2^18, 2^32").into()),
        }
    }
    
    fn from_file() -> Result<Self, Box<dyn std::error::Error>> {
        let lifetime_str = fs::read_to_string("tmp/rust_lifetime.txt")
            .unwrap_or_else(|_| "2^8".to_string());
        Self::parse(Some(&lifetime_str.trim().to_string()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} keygen [seed_hex] [lifetime] [--ssz]  - Generate keypair (lifetime: 2^8, 2^18, or 2^32, default: 2^8)", args[0]);
        eprintln!("  {} sign <message> <epoch> [--ssz]       - Sign message using tmp/rust_sk.json, save to tmp/rust_sig.bin or tmp/rust_sig.ssz", args[0]);
        eprintln!("  {} verify <zig_sig.bin> <zig_pk.json> <message> <epoch> [--ssz] - Verify Zig signature", args[0]);
        eprintln!("\n  --ssz: Use SSZ serialization instead of JSON/bincode");
        std::process::exit(1);
    }
    
    // Check for --ssz flag
    let use_ssz = args.iter().any(|arg| arg == "--ssz");
    
    match args[1].as_str() {
        "keygen" => {
            let seed_hex = args.get(2);
            let lifetime_str = args.get(3);
            let lifetime = LifetimeTag::parse(lifetime_str)?;
            keygen_command(seed_hex, lifetime, use_ssz)?;
        }
        "sign" => {
            if args.len() < 4 {
                eprintln!("Usage: {} sign <message> <epoch> [--ssz]", args[0]);
                std::process::exit(1);
            }
            let message = &args[2];
            let epoch: u32 = args[3].parse()?;
            let lifetime = LifetimeTag::from_file()?;
            sign_command(message, epoch, lifetime, use_ssz)?;
        }
        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: {} verify <zig_sig.json> <zig_pk.json> <message> <epoch> [--ssz]", args[0]);
                std::process::exit(1);
            }
            let sig_path = &args[2];
            let pk_path = &args[3];
            let message = &args[4];
            let epoch: u32 = args[5].parse()?;
            let lifetime = LifetimeTag::from_file()?;
            verify_command(sig_path, pk_path, message, epoch, lifetime, use_ssz)?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn keygen_command(seed_hex: Option<&String>, lifetime: LifetimeTag, use_ssz: bool) -> Result<(), Box<dyn std::error::Error>> {
    let lifetime_str = match lifetime {
        LifetimeTag::Pow8 => "2^8",
        LifetimeTag::Pow18 => "2^18",
        LifetimeTag::Pow32 => "2^32",
    };
    eprintln!("Generating keypair with lifetime {}...", lifetime_str);
    
    // Create tmp directory if it doesn't exist
    fs::create_dir_all("tmp")?;
    
    // Save lifetime to file for sign/verify commands
    fs::write("tmp/rust_lifetime.txt", lifetime_str)?;
    
    // Read active epochs from file (default to 256 if not found)
    let num_active_epochs: usize = fs::read_to_string("tmp/rust_active_epochs.txt")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(256);
    
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
    match lifetime {
        LifetimeTag::Pow8 => {
            let mut rng = StdRng::from_seed(seed);
            let (public_key, secret_key) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, num_active_epochs);

            if use_ssz {
                // Serialize secret key to SSZ
                let sk_bytes = Encode::as_ssz_bytes(&secret_key);
                fs::write("tmp/rust_sk.ssz", &sk_bytes)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.ssz ({} bytes)", sk_bytes.len());
                
                // Serialize public key to SSZ
                let pk_bytes = Encode::as_ssz_bytes(&public_key);
                fs::write("tmp/rust_pk.ssz", &pk_bytes)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.ssz ({} bytes)", pk_bytes.len());
            } else {
                // Serialize secret key to bincode JSON
                let sk_json = serde_json::to_string_pretty(&secret_key)?;
                fs::write("tmp/rust_sk.json", &sk_json)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.json");
                
                // Serialize public key to bincode JSON
                let pk_json = serde_json::to_string_pretty(&public_key)?;
                fs::write("tmp/rust_pk.json", &pk_json)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.json");
            }
        }
        LifetimeTag::Pow18 => {
            let mut rng = StdRng::from_seed(seed);
            let (public_key, secret_key) = SIGTopLevelTargetSumLifetime18Dim64Base8::key_gen(&mut rng, 0, num_active_epochs);

            if use_ssz {
                // Serialize secret key to SSZ
                let sk_bytes = Encode::as_ssz_bytes(&secret_key);
                fs::write("tmp/rust_sk.ssz", &sk_bytes)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.ssz ({} bytes)", sk_bytes.len());
                
                // Serialize public key to SSZ
                let pk_bytes = Encode::as_ssz_bytes(&public_key);
                fs::write("tmp/rust_pk.ssz", &pk_bytes)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.ssz ({} bytes)", pk_bytes.len());
            } else {
                // Serialize secret key to bincode JSON
                let sk_json = serde_json::to_string_pretty(&secret_key)?;
                fs::write("tmp/rust_sk.json", &sk_json)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.json");
                
                // Serialize public key to bincode JSON
                let pk_json = serde_json::to_string_pretty(&public_key)?;
                fs::write("tmp/rust_pk.json", &pk_json)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.json");
            }
        }
        LifetimeTag::Pow32 => {
            let mut rng = StdRng::from_seed(seed);
            let (public_key, secret_key) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(&mut rng, 0, num_active_epochs);

            if use_ssz {
                // Serialize secret key to SSZ
                let sk_bytes = Encode::as_ssz_bytes(&secret_key);
                fs::write("tmp/rust_sk.ssz", &sk_bytes)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.ssz ({} bytes)", sk_bytes.len());
                
                // Serialize public key to SSZ
                let pk_bytes = Encode::as_ssz_bytes(&public_key);
                fs::write("tmp/rust_pk.ssz", &pk_bytes)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.ssz ({} bytes)", pk_bytes.len());
            } else {
                // Serialize secret key to JSON
                let sk_json = serde_json::to_string_pretty(&secret_key)?;
                fs::write("tmp/rust_sk.json", &sk_json)?;
                eprintln!("✅ Secret key saved to tmp/rust_sk.json");

                // Serialize public key to JSON
                let pk_json = serde_json::to_string_pretty(&public_key)?;
                fs::write("tmp/rust_pk.json", &pk_json)?;
                eprintln!("✅ Public key saved to tmp/rust_pk.json");
            }
        }
    }
    
    eprintln!("Keypair generated successfully!");
    Ok(())
}

fn sign_command(message: &str, epoch: u32, lifetime: LifetimeTag, use_ssz: bool) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Signing message: '{}' (epoch: {})", message, epoch);
    
    // Convert message to bytes (32 bytes)
    let mut msg_bytes = [0u8; 32];
    let msg_slice = message.as_bytes();
    let len = msg_slice.len().min(32);
    msg_bytes[..len].copy_from_slice(&msg_slice[..len]);
    
    match lifetime {
        LifetimeTag::Pow8 => {
            // Load secret key
            type SkType = <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::SecretKey;
            let secret_key: SkType = if use_ssz {
                let sk_bytes = fs::read("tmp/rust_sk.ssz")?;
                Decode::from_ssz_bytes(&sk_bytes).map_err(|e: DecodeError| format!("Failed to decode secret key from SSZ: {:?}", e))?
            } else {
                let sk_json = fs::read_to_string("tmp/rust_sk.json")?;
                serde_json::from_str(&sk_json)?
            };
            
            // Sign the message
            let signature = SIGTopLevelTargetSumLifetime8Dim64Base8::sign(&secret_key, epoch, &msg_bytes)?;
            
            if use_ssz {
                // Serialize signature to SSZ
                let sig_bytes = Encode::as_ssz_bytes(&signature);
                fs::write("tmp/rust_sig.ssz", &sig_bytes)?;
                eprintln!("✅ Signature saved to tmp/rust_sig.ssz ({} bytes)", sig_bytes.len());
            } else {
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
            }
        }
        LifetimeTag::Pow18 => {
            // Load secret key
            type SkType = <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::SecretKey;
            let secret_key: SkType = if use_ssz {
                let sk_bytes = fs::read("tmp/rust_sk.ssz")?;
                Decode::from_ssz_bytes(&sk_bytes).map_err(|e: DecodeError| format!("Failed to decode secret key from SSZ: {:?}", e))?
            } else {
                let sk_json = fs::read_to_string("tmp/rust_sk.json")?;
                serde_json::from_str(&sk_json)?
            };
            
            // Sign the message
            let signature = SIGTopLevelTargetSumLifetime18Dim64Base8::sign(&secret_key, epoch, &msg_bytes)?;
            
            if use_ssz {
                // Serialize signature to SSZ
                let sig_bytes = Encode::as_ssz_bytes(&signature);
                fs::write("tmp/rust_sig.ssz", &sig_bytes)?;
                eprintln!("✅ Signature saved to tmp/rust_sig.ssz ({} bytes)", sig_bytes.len());
            } else {
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
            }
        }
        LifetimeTag::Pow32 => {
            // Load secret key
            type SkType = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::SecretKey;
            let secret_key: SkType = if use_ssz {
                let sk_bytes = fs::read("tmp/rust_sk.ssz")?;
                Decode::from_ssz_bytes(&sk_bytes).map_err(|e: DecodeError| format!("Failed to decode secret key from SSZ: {:?}", e))?
            } else {
                let sk_json = fs::read_to_string("tmp/rust_sk.json")?;
                serde_json::from_str(&sk_json)?
            };
    
            // Sign the message
            let signature = SIGTopLevelTargetSumLifetime32Dim64Base8::sign(&secret_key, epoch, &msg_bytes)?;
    
            if use_ssz {
                // Serialize signature to SSZ
                let sig_bytes = Encode::as_ssz_bytes(&signature);
                fs::write("tmp/rust_sig.ssz", &sig_bytes)?;
                eprintln!("✅ Signature saved to tmp/rust_sig.ssz ({} bytes)", sig_bytes.len());
            } else {
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
            }
        }
    }
    
    eprintln!("Message signed successfully!");
    Ok(())
}

fn verify_command(sig_path: &str, pk_path: &str, message: &str, epoch: u32, lifetime: LifetimeTag, use_ssz: bool) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Verifying signature from Zig...");
    eprintln!("  Signature: {}", sig_path);
    eprintln!("  Public key: {}", pk_path);
    eprintln!("  Message: '{}'", message);
    eprintln!("  Epoch: {}", epoch);
    
    // Convert message to bytes (32 bytes)
    let mut msg_bytes = [0u8; 32];
    let msg_slice = message.as_bytes();
    let len = msg_slice.len().min(32);
    msg_bytes[..len].copy_from_slice(&msg_slice[..len]);
    
    match lifetime {
        LifetimeTag::Pow8 => {
            type SigType = <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::Signature;
            type PkType = <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::PublicKey;
            
            let signature: SigType = if use_ssz {
                let sig_bytes = fs::read(sig_path)?;
                Decode::from_ssz_bytes(&sig_bytes).map_err(|e: DecodeError| format!("Failed to decode signature from SSZ: {:?}", e))?
            } else {
                let sig_bytes = fs::read(sig_path)?;
                const SIG_LEN: usize = 3116;
                let sig_data = if sig_bytes.len() > SIG_LEN {
                    &sig_bytes[..SIG_LEN]
                } else {
                    &sig_bytes
                };
                bincode::deserialize(sig_data)?
            };
    
            let public_key: PkType = if use_ssz {
                let pk_bytes = fs::read(pk_path)?;
                Decode::from_ssz_bytes(&pk_bytes).map_err(|e: DecodeError| format!("Failed to decode public key from SSZ: {:?}", e))?
            } else {
                let pk_json = fs::read_to_string(pk_path)?;
                let pk_value: serde_json::Value = serde_json::from_str(&pk_json)?;
                serde_json::from_value(pk_value)?
            };
    
            // Verify the signature
            let is_valid = SIGTopLevelTargetSumLifetime8Dim64Base8::verify(&public_key, epoch, &msg_bytes, &signature);
            
            if is_valid {
                eprintln!("✅ Signature verification PASSED!");
                Ok(())
            } else {
                eprintln!("❌ Signature verification FAILED!");
                std::process::exit(1);
            }
        }
        LifetimeTag::Pow18 => {
            type SigType = <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::Signature;
            type PkType = <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::PublicKey;
            
            let signature: SigType = if use_ssz {
                let sig_bytes = fs::read(sig_path)?;
                Decode::from_ssz_bytes(&sig_bytes).map_err(|e: DecodeError| format!("Failed to decode signature from SSZ: {:?}", e))?
            } else {
                let sig_bytes = fs::read(sig_path)?;
                const SIG_LEN: usize = 3116;
                let sig_data = if sig_bytes.len() > SIG_LEN {
                    &sig_bytes[..SIG_LEN]
                } else {
                    &sig_bytes
                };
                bincode::deserialize(sig_data)?
            };
            
            let public_key: PkType = if use_ssz {
                let pk_bytes = fs::read(pk_path)?;
                Decode::from_ssz_bytes(&pk_bytes).map_err(|e: DecodeError| format!("Failed to decode public key from SSZ: {:?}", e))?
            } else {
                let pk_json = fs::read_to_string(pk_path)?;
                serde_json::from_str(&pk_json)?
            };
            
            // Verify the signature
            let is_valid = SIGTopLevelTargetSumLifetime18Dim64Base8::verify(&public_key, epoch, &msg_bytes, &signature);
    
            if is_valid {
                eprintln!("✅ Signature verification PASSED!");
                Ok(())
            } else {
                eprintln!("❌ Signature verification FAILED!");
                std::process::exit(1);
            }
        }
        LifetimeTag::Pow32 => {
            type SigType = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature;
            type PkType = <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey;
            
            let signature: SigType = if use_ssz {
                let sig_bytes = fs::read(sig_path)?;
                Decode::from_ssz_bytes(&sig_bytes).map_err(|e: DecodeError| format!("Failed to decode signature from SSZ: {:?}", e))?
            } else {
                let sig_bytes = fs::read(sig_path)?;
                const SIG_LEN: usize = 3116;
                let sig_data = if sig_bytes.len() > SIG_LEN {
                    &sig_bytes[..SIG_LEN]
                } else {
                    &sig_bytes
                };
                bincode::deserialize(sig_data)?
            };
            
            let public_key: PkType = if use_ssz {
                let pk_bytes = fs::read(pk_path)?;
                Decode::from_ssz_bytes(&pk_bytes).map_err(|e: DecodeError| format!("Failed to decode public key from SSZ: {:?}", e))?
            } else {
                let pk_json = fs::read_to_string(pk_path)?;
                serde_json::from_str(&pk_json)?
            };
            
            // Verify the signature
            let is_valid = SIGTopLevelTargetSumLifetime32Dim64Base8::verify(&public_key, epoch, &msg_bytes, &signature);
            
            if is_valid {
                eprintln!("✅ Signature verification PASSED!");
                Ok(())
            } else {
                eprintln!("❌ Signature verification FAILED!");
                std::process::exit(1);
            }
        }
    }
}

