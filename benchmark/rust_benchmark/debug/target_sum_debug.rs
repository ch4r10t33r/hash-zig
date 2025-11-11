use std::env;

use hashsig::symmetric::message_hash::{
    poseidon::{encode_epoch, encode_message},
    top_level_poseidon::TopLevelPoseidonMessageHash,
    MessageHash,
};
use hashsig::symmetric::tweak_hash::poseidon::poseidon_compress;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_24, KoalaBear};

fn parse_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("Missing {name} environment variable"))
}

fn parse_hex_string(s: &str) -> Result<u32, String> {
    let trimmed = s.trim();
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(clean, 16).map_err(|e| format!("Failed to parse hex {s}: {e}"))
}

fn extract_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> Result<&'a Vec<serde_json::Value>, String> {
    value
        .get(field)
        .ok_or_else(|| format!("Missing field {field}"))?
        .as_array()
        .ok_or_else(|| format!("Field {field} is not an array"))
}

fn parse_field_array<const N: usize>(
    arr: &Vec<serde_json::Value>,
) -> Result<[KoalaBear; N], String> {
    if arr.len() != N {
        return Err(format!("Expected array of length {N}, found {}", arr.len()));
    }
    let mut result = [KoalaBear::ZERO; N];
    for (i, item) in arr.iter().enumerate() {
        let value = if let Some(s) = item.as_str() {
            parse_hex_string(s)?
        } else if let Some(n) = item.as_u64() {
            n as u32
        } else {
            return Err(format!("Array entry {i} is neither string nor number"));
        };
        result[i] = KoalaBear::from_u32(value);
    }
    Ok(result)
}

fn build_message_bytes(message_env: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let src = message_env.as_bytes();
    let len = src.len().min(32);
    bytes[..len].copy_from_slice(&src[..len]);
    bytes
}

fn main() -> Result<(), String> {
    let public_key_env = parse_env("PUBLIC_KEY")?;
    let signature_env = parse_env("SIGNATURE")?;
    let message_env = parse_env("MESSAGE")?;
    let epoch_env = parse_env("EPOCH").unwrap_or_else(|_| "0".to_string());
    let epoch: u32 = epoch_env
        .parse()
        .map_err(|e| format!("Failed to parse epoch: {e}"))?;

    let pk_json_str = public_key_env
        .strip_prefix("PUBLIC_KEY:")
        .unwrap_or(&public_key_env);
    let sig_json_str = signature_env
        .strip_prefix("SIGNATURE:")
        .unwrap_or(&signature_env);

    let pk_json: serde_json::Value = serde_json::from_str(pk_json_str)
        .map_err(|e| format!("Failed to parse PUBLIC_KEY JSON: {e}"))?;
    let sig_json: serde_json::Value = serde_json::from_str(sig_json_str)
        .map_err(|e| format!("Failed to parse SIGNATURE JSON: {e}"))?;

    let parameter_arr = extract_array(&pk_json, "parameter")?;
    let rho_arr = extract_array(&sig_json, "rho")?;

    const PARAMETER_LEN: usize = 5;
    const RAND_LEN_FE: usize = 7;

    let parameter: [KoalaBear; PARAMETER_LEN] = parse_field_array(parameter_arr)?;
    let randomness: [KoalaBear; RAND_LEN_FE] = parse_field_array(rho_arr)?;

    let message_bytes = build_message_bytes(&message_env);

    type MH = TopLevelPoseidonMessageHash<
        15, // POS_OUTPUT_LEN_PER_INV_FE
        1,  // POS_INVOCATIONS
        15, // POS_OUTPUT_LEN_FE
        64, // DIMENSION
        8,  // BASE
        77, // FINAL_LAYER
        2,  // TWEAK_LEN_FE
        9,  // MSG_LEN_FE
        5,  // PARAMETER_LEN
        7,  // RAND_LEN_FE
    >;

    let chunks = MH::apply(&parameter, epoch, &randomness, &message_bytes);

    // Debug: reproduce poseidon outputs
    let perm = default_koalabear_poseidon2_24();
    let message_fe = encode_message::<9>(&message_bytes);
    let epoch_fe = encode_epoch::<2>(epoch);
    let iteration_index = [KoalaBear::from_u8(0)];
    let combined_input: Vec<KoalaBear> = randomness
        .iter()
        .chain(parameter.iter())
        .chain(epoch_fe.iter())
        .chain(message_fe.iter())
        .chain(iteration_index.iter())
        .copied()
        .collect();
    println!(
        "POSEIDON_INPUT:{}",
        combined_input
            .iter()
            .map(|fe| format!("0x{:08x}", fe.as_canonical_u32()))
            .collect::<Vec<_>>()
            .join(",")
    );
    let pos_outputs = poseidon_compress::<_, 24, 15>(&perm, &combined_input);
    println!(
        "POS_OUTPUTS:{}",
        pos_outputs
            .iter()
            .map(|fe| format!("0x{:08x}", fe.as_canonical_u32()))
            .collect::<Vec<_>>()
            .join(",")
    );

    let sum: usize = chunks.iter().map(|&x| x as usize).sum();
    println!("CHUNKS_SUM:{}", sum);
    println!(
        "CHUNKS:{}",
        chunks
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );

    Ok(())
}
