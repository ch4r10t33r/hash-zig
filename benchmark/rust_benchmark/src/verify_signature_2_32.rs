use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::SignatureScheme;
use serde_json::{self, Map, Value};
use std::env;

fn normalize_hex(value: &mut Value) {
    match value {
        Value::String(s) => {
            let trimmed = s.trim();
            let maybe_hex = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"));
            let body = maybe_hex.unwrap_or(trimmed);
            let radix = if maybe_hex.is_some() { 16 } else { 10 };
            if let Ok(num) = u32::from_str_radix(body, radix) {
                *value = Value::Number(serde_json::Number::from(num));
            }
        }
        Value::Array(arr) => arr.iter_mut().for_each(normalize_hex),
        Value::Object(obj) => obj.values_mut().for_each(normalize_hex),
        Value::Bool(_) | Value::Number(_) | Value::Null => {}
    }
}

fn rename_nodes_to_co_path(obj: &mut Map<String, Value>) {
    if let Some(path_val) = obj.get_mut("path") {
        if let Value::Object(path_obj) = path_val {
            if let Some(nodes_val) = path_obj.remove("nodes") {
                path_obj.insert("co_path".to_string(), nodes_val);
            }
        }
    }
}

fn main() {
    let public_key_data = env::var("PUBLIC_KEY").unwrap_or_default();
    let signature_data = env::var("SIGNATURE").unwrap_or_default();
    let message = env::var("MESSAGE").unwrap_or_default();
    let epoch: u32 = env::var("EPOCH")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(0);

    if public_key_data.is_empty() || signature_data.is_empty() || message.is_empty() {
        eprintln!("Missing PUBLIC_KEY, SIGNATURE, or MESSAGE environment variables");
        std::process::exit(1);
    }

    let mut message_bytes = [0u8; 32];
    let msg_slice = message.as_bytes();
    let copy_len = msg_slice.len().min(32);
    message_bytes[..copy_len].copy_from_slice(&msg_slice[..copy_len]);

    let sig_json = signature_data
        .strip_prefix("SIGNATURE:")
        .unwrap_or(&signature_data);
    let pk_json = public_key_data
        .strip_prefix("PUBLIC_KEY:")
        .unwrap_or(&public_key_data);

    let pk_direct: Result<
        <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey,
        _,
    > = serde_json::from_str(pk_json);
    let sig_direct: Result<
        <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature,
        _,
    > = serde_json::from_str(sig_json);

    if let (Ok(pk_val), Ok(sig_val)) = (pk_direct, sig_direct) {
        let is_valid = SIGTopLevelTargetSumLifetime32Dim64Base8::verify(
            &pk_val,
            epoch,
            &message_bytes,
            &sig_val,
        );
        println!("VERIFY_RESULT:{}", is_valid);
        return;
    }

    let mut pk_val: Value = match serde_json::from_str(pk_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("RUST_VERIFY_DEBUG: failed to parse PUBLIC_KEY JSON: {}", e);
            println!("VERIFY_RESULT:false");
            return;
        }
    };
    let mut sig_val: Value = match serde_json::from_str(sig_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("RUST_VERIFY_DEBUG: failed to parse SIGNATURE JSON: {}", e);
            println!("VERIFY_RESULT:false");
            return;
        }
    };

    normalize_hex(&mut pk_val);
    normalize_hex(&mut sig_val);

    if let Value::Object(ref mut pk_obj) = pk_val {
        rename_nodes_to_co_path(pk_obj);
    }
    if let Value::Object(ref mut sig_obj) = sig_val {
        rename_nodes_to_co_path(sig_obj);
    }

    let pk_built: <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::PublicKey =
        match serde_json::from_value(pk_val) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize PK: {}", e);
                println!("VERIFY_RESULT:false");
                return;
            }
        };
    let sig_built: <SIGTopLevelTargetSumLifetime32Dim64Base8 as SignatureScheme>::Signature =
        match serde_json::from_value(sig_val) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize SIG: {}", e);
                println!("VERIFY_RESULT:false");
                return;
            }
        };

    if let Ok(pk_dbg) = serde_json::to_string(&pk_built) {
        eprintln!("RUST_VERIFY_DEBUG: pk dbg {}", pk_dbg);
    }
    if let Ok(sig_dbg) = serde_json::to_string(&sig_built) {
        eprintln!("RUST_VERIFY_DEBUG: sig dbg {}", sig_dbg);
    }

    let is_valid = SIGTopLevelTargetSumLifetime32Dim64Base8::verify(
        &pk_built,
        epoch,
        &message_bytes,
        &sig_built,
    );
    println!("VERIFY_RESULT:{}", is_valid);
}
