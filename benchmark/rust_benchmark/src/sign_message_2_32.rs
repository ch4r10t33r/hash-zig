use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use hashsig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use rand::{rngs::StdRng, SeedableRng};
use serde_json;
use std::env;

fn main() {
    let message = env::var("MESSAGE").unwrap_or_default();
    let epoch: u32 = env::var("EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if message.is_empty() {
        eprintln!("Missing MESSAGE environment variable");
        std::process::exit(1);
    }

    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| {
        "4242424242424242424242424242424242424242424242424242424242424242".to_string()
    });
    let mut seed = [0u8; 32];
    for (i, chunk) in seed_hex.as_bytes().chunks(2).take(32).enumerate() {
        let hi = char::from(chunk.get(0).copied().unwrap_or(b'0'));
        let lo = char::from(chunk.get(1).copied().unwrap_or(b'0'));
        let hi_v = hi.to_digit(16).unwrap_or(0) as u8;
        let lo_v = lo.to_digit(16).unwrap_or(0) as u8;
        seed[i] = (hi_v << 4) | lo_v;
    }

    let mut rng = StdRng::from_seed(seed);
    let (pk, mut sk) = SIGTopLevelTargetSumLifetime32Dim64Base8::key_gen(&mut rng, 0, 256);

    let mut message_bytes = [0u8; 32];
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(32);
    message_bytes[..copy_len].copy_from_slice(&bytes[..copy_len]);
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }

    let signature = SIGTopLevelTargetSumLifetime32Dim64Base8::sign(&sk, epoch, &message_bytes)
        .expect("signing failed");

    let mut pk_value = serde_json::to_value(&pk).expect("serialize pk");
    let mut sig_value = serde_json::to_value(&signature).expect("serialize sig");

    if let Some(sig_obj) = sig_value.as_object_mut() {
        if let Some(path_val) = sig_obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(co_path) = path_obj.remove("co_path") {
                    path_obj.insert("nodes".to_string(), co_path);
                }
            }
        }
    }

    println!("SIGNATURE:{}", sig_value.to_string());
    println!("PUBLIC_KEY:{}", pk_value.to_string());
}

