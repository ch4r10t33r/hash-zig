use std::env;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use hashsig::symmetric::message_hash::top_level_poseidon::TopLevelPoseidonMessageHash;
use hashsig::symmetric::message_hash::MessageHash;
use serde_json::{self, Value};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    let key_data = env::var("KEY_DATA").unwrap_or_default();
    let message = env::var("MESSAGE").unwrap_or_default();
    let epoch_str = env::var("EPOCH").unwrap_or_else(|_| "0".to_string());
    
    let epoch: u32 = epoch_str.parse().unwrap_or(0);
    
    if message.is_empty() {
        eprintln!("Missing MESSAGE environment variable");
        std::process::exit(1);
    }
    
    // Use fixed seed for deterministic key generation (for cross-compatibility testing)
    // In production, use a secure random seed
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "4242424242424242424242424242424242424242424242424242424242424242".to_string());
    let mut seed = [0u8; 32];
    let used_seed_hex = if seed_hex.len() >= 64 { &seed_hex[..64] } else { &seed_hex };
    for i in 0..32 {
        let hi = u8::from_str_radix(&used_seed_hex[i*2..i*2+1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&used_seed_hex[i*2+1..i*2+2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let (pk, mut sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);
    
    // Convert message to bytes (truncate/pad to 32 bytes)
    let mut message_bytes = [0u8; 32];
    let message_bytes_slice = message.as_bytes();
    let copy_len = std::cmp::min(message_bytes_slice.len(), 32);
    message_bytes[..copy_len].copy_from_slice(&message_bytes_slice[..copy_len]);
    
    // Prepare the secret key for the epoch
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }
    
    // Constants matching lifetime_2_to_the_8 instantiation
    const TARGET_SUM: usize = 375;
    const MAX_TRIES: usize = 100_000;
    
    // Retry loop: sign until we get a signature with encoding sum == TARGET_SUM
    let signature = loop {
        // Sign the message
        let signature_result = SIGTopLevelTargetSumLifetime8Dim64Base8::sign(&sk, epoch, &message_bytes);
        
        // Handle the result
        let sig = match signature_result {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Signing failed: {:?}", e);
                std::process::exit(1);
            }
        };
        
        // Validate encoding sum: compute chunks from rho and check sum
        let parameter = pk.get_parameter();
        let rho = sig.get_rho();
        
        // Use TopLevelPoseidonMessageHash to compute chunks
        // Type parameters: POS_OUTPUT_LEN_PER_INV_FE=15, POS_INVOCATIONS=1, POS_OUTPUT_LEN_FE=15,
        // DIMENSION=64, BASE=8, FINAL_LAYER=77, TWEAK_LEN_FE=2, MSG_LEN_FE=9, PARAMETER_LEN=5, RAND_LEN_FE=7
        type MH = TopLevelPoseidonMessageHash<15, 1, 15, 64, 8, 77, 2, 9, 5, 7>;
        let chunks = MH::apply(&parameter, epoch, &rho, &message_bytes);
        
        // Compute sum of chunks
        let sum: usize = chunks.iter().map(|&x| x as usize).sum();
        
        if sum == TARGET_SUM {
            eprintln!("RUST_WRAPPER_DEBUG: Found valid signature with encoding sum={}", sum);
            break sig;
        } else {
            eprintln!("RUST_WRAPPER_DEBUG: Signature has encoding sum={} (expected {}), retrying...", sum, TARGET_SUM);
            // Continue loop to retry
        }
    };

    // Helper: parse FE into u32 then hex string 0x........ using generic serde per element
    fn fe_to_hex(v: &Value) -> Option<String> {
        match v {
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    let u32v = (u as u64).min(u32::MAX as u64) as u32;
                    return Some(format!("0x{:08x}", u32v));
                }
                if let Some(i) = n.as_i64() {
                    if i < 0 { return None; }
                    let u32v = (i as u64).min(u32::MAX as u64) as u32;
                    return Some(format!("0x{:08x}", u32v));
                }
                None
            }
            Value::String(s) => {
                let ss = s.trim();
                let clean = if ss.starts_with("0x") || ss.starts_with("0X") { &ss[2..] } else { ss };
                // try decimal
                if let Ok(dec) = clean.parse::<u32>() { return Some(format!("0x{:08x}", dec)); }
                // try hex
                if let Ok(v) = u32::from_str_radix(clean, 16) { return Some(format!("0x{:08x}", v)); }
                None
            }
            Value::Array(arr) => {
                if arr.len() == 1 { return fe_to_hex(&arr[0]); }
                None
            }
            Value::Object(obj) => {
                if let Some(inner) = obj.get("value") { return fe_to_hex(inner); }
                // unwrap first value
                if let Some((_k, inner)) = obj.iter().next() { return fe_to_hex(inner); }
                None
            }
            _ => None,
        }
    }

    fn map_array_to_hex(vec_val: &Value) -> Vec<String> {
        match vec_val {
            Value::Array(items) => items.iter().filter_map(|it| fe_to_hex(it)).collect(),
            _ => vec![],
        }
    }

    // Map PublicKey using getters; emit canonical u32 hex for field elements
    let pk_root_val = serde_json::to_value(pk.get_root()).unwrap_or(Value::Null);
    // Allow both array and single-element root encodings for root
    let root_hex: Vec<String> = match &pk_root_val {
        Value::Array(arr) => arr.iter().filter_map(|it| fe_to_hex(it)).collect(),
        _ => fe_to_hex(&pk_root_val).into_iter().collect(),
    };
    // Parameter: use as_canonical_u32 explicitly to avoid serde emitting Montgomery form
    let parameter = pk.get_parameter();
    use p3_field::PrimeField32;
    let param_hex: Vec<String> = parameter
        .iter()
        .map(|fe| format!("0x{:x}", fe.as_canonical_u32()))
        .collect();
    eprintln!("RUST_WRAPPER_DEBUG: pk.root_len={} pk.param_len={}", root_hex.len(), param_hex.len());
    let pk_zig = serde_json::json!({
        "root": root_hex,
        "parameter": param_hex,
    });

    // Map Signature to Zig-shaped JSON
    let mut path_nodes_hex: Vec<Vec<String>> = vec![];
    let mut rho_hex: Vec<String> = vec![];
    let mut hashes_hex: Vec<Vec<String>> = vec![];

    // Path nodes: use as_canonical_u32 explicitly to avoid serde emitting Montgomery form
    let co_path = signature.get_path().co_path();
    path_nodes_hex = co_path
        .iter()
        .map(|domain| {
            domain
                .iter()
                .map(|fe| format!("0x{:x}", fe.as_canonical_u32()))
                .collect::<Vec<String>>()
        })
        .collect();

    // Rho: use as_canonical_u32 explicitly to avoid serde emitting Montgomery form
    let rho = signature.get_rho();
    rho_hex = rho
        .iter()
        .map(|fe| format!("0x{:x}", fe.as_canonical_u32()))
        .collect();

    // Hashes: use as_canonical_u32 explicitly to avoid serde emitting Montgomery form
    let hashes = signature.get_hashes();
    hashes_hex = hashes
        .iter()
        .map(|domain| {
            domain
                .iter()
                .map(|fe| format!("0x{:x}", fe.as_canonical_u32()))
                .collect::<Vec<String>>()
        })
        .collect();

    // Debug: log lengths and first few entries
    fn head2(v: &Vec<Vec<String>>, n: usize) -> Vec<Vec<String>> {
        v.iter().take(n).cloned().collect()
    }
    eprintln!(
        "RUST_WRAPPER_DEBUG: path_nodes_len={} head={:?}",
        path_nodes_hex.len(),
        head2(&path_nodes_hex, 1)
    );
    eprintln!(
        "RUST_WRAPPER_DEBUG: rho_len={} head={:?}",
        rho_hex.len(),
        &rho_hex[..std::cmp::min(3, rho_hex.len())]
    );
    eprintln!(
        "RUST_WRAPPER_DEBUG: hashes_len={} head0_len={}",
        hashes_hex.len(),
        hashes_hex.get(0).map(|v| v.len()).unwrap_or(0)
    );
    eprintln!(
        "RUST_WRAPPER_DEBUG: pk.root_len={} pk.param_len={}",
        root_hex.len(),
        param_hex.len()
    );
    // Log parameter and rho explicitly for external encoding probes
    eprintln!("RUST_PARAM_HEX:{}", param_hex.join(" "));
    eprintln!("RUST_RHO_HEX:{}", rho_hex.join(" "));

    eprintln!("RUST_WRAPPER_DEBUG: path_nodes_len={}, rho_len={}, hashes_len={}", path_nodes_hex.len(), rho_hex.len(), hashes_hex.len());

    let sig_zig = serde_json::json!({
        "path": { "nodes": path_nodes_hex },
        "rho": rho_hex,
        "hashes": hashes_hex,
    });

    let signature_json = sig_zig.to_string();
    let public_key_json = pk_zig.to_string();

    println!("SIGNATURE:{}", signature_json);
    println!("PUBLIC_KEY:{}", public_key_json);
}
