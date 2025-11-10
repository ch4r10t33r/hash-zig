use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use rand::{rngs::StdRng, SeedableRng};
use serde_json;
use std::env;

const KOALABEAR_PRIME: u32 = 0x7f000001;
const KOALABEAR_MONTY_MU: u32 = 0x81000001;
const KOALABEAR_MONTY_MASK: u64 = 0xffffffff;
const KOALABEAR_MONTY_BITS: u32 = 32;

fn monty_reduce(x: u64) -> u32 {
    let t = x.wrapping_mul(KOALABEAR_MONTY_MU as u64) & KOALABEAR_MONTY_MASK;
    let u = t.wrapping_mul(KOALABEAR_PRIME as u64);
    let (x_sub_u, borrow) = x.overflowing_sub(u);
    let x_sub_u_hi = (x_sub_u >> KOALABEAR_MONTY_BITS) as u32;
    let corr = if borrow { KOALABEAR_PRIME } else { 0 };
    x_sub_u_hi.wrapping_add(corr)
}

fn from_monty(value: u32) -> u32 {
    monty_reduce(value as u64)
}

fn convert_monty_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                let canonical = from_monty(u as u32) as u64;
                let num = serde_json::Number::from(canonical);
                *value = serde_json::Value::Number(num);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                convert_monty_numbers(item);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                convert_monty_numbers(item);
            }
        }
        _ => {}
    }
}
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
    let (pk, mut sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);

    let mut message_bytes = [0u8; 32];
    let bytes = message.as_bytes();
    let copy_len = bytes.len().min(32);
    message_bytes[..copy_len].copy_from_slice(&bytes[..copy_len]);
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }

    let signature = SIGTopLevelTargetSumLifetime8Dim64Base8::sign(&sk, epoch, &message_bytes)
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

    convert_monty_numbers(&mut pk_value);
    convert_monty_numbers(&mut sig_value);

    println!("SIGNATURE:{}", sig_value.to_string());
    println!("PUBLIC_KEY:{}", pk_value.to_string());
}
