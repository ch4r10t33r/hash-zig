use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use serde_json::{self, Value};
use std::env;

fn main() {
    let public_key_data = env::var("PUBLIC_KEY").unwrap_or_default();
    let signature_data = env::var("SIGNATURE").unwrap_or_default();
    let message = env::var("MESSAGE").unwrap_or_default();
    let epoch_str = env::var("EPOCH").unwrap_or_else(|_| "0".to_string());

    let epoch: u32 = epoch_str.parse().unwrap_or(0);

    if public_key_data.is_empty() || signature_data.is_empty() || message.is_empty() {
        eprintln!("Missing PUBLIC_KEY, SIGNATURE, or MESSAGE environment variables");
        std::process::exit(1);
    }

    // Convert message to bytes (truncate/pad to 32 bytes)
    let mut message_bytes = [0u8; 32];
    let message_bytes_slice = message.as_bytes();
    let copy_len = std::cmp::min(message_bytes_slice.len(), 32);
    message_bytes[..copy_len].copy_from_slice(&message_bytes_slice[..copy_len]);

    // Parse the signature and public key data (Rust-native serde JSON)
    let sig_json = if signature_data.starts_with("SIGNATURE:") {
        &signature_data[10..]
    } else {
        &signature_data
    };
    let pk_json = if public_key_data.starts_with("PUBLIC_KEY:") {
        &public_key_data[11..]
    } else {
        &public_key_data
    };

    // Try to deserialize using serde (Rust-native shape)
    let pk: Result<<SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::PublicKey, _> =
        serde_json::from_str(pk_json);
    let signature: Result<
        <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::Signature,
        _,
    > = serde_json::from_str(sig_json);

    match (pk, signature) {
        (Ok(pk_val), Ok(sig_val)) => {
            let is_valid = SIGTopLevelTargetSumLifetime8Dim64Base8::verify(
                &pk_val,
                epoch,
                &message_bytes,
                &sig_val,
            );
            println!("VERIFY_RESULT:{}", is_valid);
        }
        _ => {
            // Try Zig-shaped JSON: pk { root:[hex], parameter:[hex] }, sig { path:{nodes:[[hex,..],..]}, rho:[hex], hashes:[[hex,..],..] }
            let mut pk_val: Value = match serde_json::from_str(pk_json) {
                Ok(v) => v,
                Err(_) => {
                    println!("VERIFY_RESULT:false");
                    return;
                }
            };
            let mut sig_val: Value = match serde_json::from_str(sig_json) {
                Ok(v) => v,
                Err(_) => {
                    println!("VERIFY_RESULT:false");
                    return;
                }
            };

            fn hex_array_to_numbers(arr: &mut Vec<Value>) {
                for v in arr.iter_mut() {
                    match v {
                        Value::String(s) => {
                            let ss = s.trim();
                            let clean = ss
                                .strip_prefix("0x")
                                .or(ss.strip_prefix("0X"))
                                .unwrap_or(ss);
                            if let Ok(u) = u32::from_str_radix(clean, 16) {
                                *v = Value::Number(serde_json::Number::from(u));
                            }
                        }
                        Value::Number(n) => {
                            if let Some(u) = n.as_u64() {
                                *v = Value::Number(serde_json::Number::from(u));
                            }
                        }
                        Value::Array(inner) => hex_array_to_numbers(inner),
                        _ => {}
                    }
                }
            }

            // Transform pk.root and pk.parameter
            if let Some(root) = pk_val.get_mut("root").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(root);
            }
            if let Some(param) = pk_val.get_mut("parameter").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(param);
            }

            // Transform sig.path.nodes, sig.rho, sig.hashes
            if let Some(nodes) = sig_val
                .get_mut("path")
                .and_then(|p| p.get_mut("nodes"))
                .and_then(|v| v.as_array_mut())
            {
                hex_array_to_numbers(nodes);
            }
            if let Some(rho) = sig_val.get_mut("rho").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(rho);
            }
            if let Some(hashes) = sig_val.get_mut("hashes").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(hashes);
            }

            // Remap path.nodes -> path.co_path to match Rust struct field name
            if let Some(path_obj) = sig_val.get_mut("path").and_then(|p| p.as_object_mut()) {
                if let Some(nodes_val) = path_obj.remove("nodes") {
                    path_obj.insert("co_path".to_string(), nodes_val);
                }
            }

            // Now try deserializing into native types
            let pk_built: <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::PublicKey =
                match serde_json::from_value(pk_val) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize PK: {}", e);
                        println!("VERIFY_RESULT:false");
                        return;
                    }
                };
            let sig_built: <SIGTopLevelTargetSumLifetime8Dim64Base8 as SignatureScheme>::Signature =
                match serde_json::from_value(sig_val) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize SIG: {}", e);
                        println!("VERIFY_RESULT:false");
                        return;
                    }
                };

            eprintln!("RUST_VERIFY_DEBUG: PK and SIG deserialized successfully");
            eprintln!(
                "RUST_VERIFY_DEBUG: Calling verify with epoch={}, message_len={}",
                epoch,
                message_bytes.len()
            );
            let is_valid = SIGTopLevelTargetSumLifetime8Dim64Base8::verify(
                &pk_built,
                epoch,
                &message_bytes,
                &sig_built,
            );
            eprintln!("RUST_VERIFY_DEBUG: Verification result: {}", is_valid);
            println!("VERIFY_RESULT:{}", is_valid);
        }
    }
}
