use rand::{SeedableRng, rngs::StdRng};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{self, Value};
use std::convert::TryFrom;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};

// KoalaBear field parameters for Montgomery conversion
const KOALABEAR_PRIME: u64 = 0x7f000001; // 2^31 - 2^24 + 1
const KOALABEAR_MONTY_BITS: u32 = 32;

// Convert canonical to Montgomery form
fn canonical_to_montgomery(canonical: u32) -> u32 {
    // to_monty: (((x as u64) << MONTY_BITS) % PRIME) as u32
    let shifted = (canonical as u64) << KOALABEAR_MONTY_BITS;
    (shifted % KOALABEAR_PRIME) as u32
}

// Convert Montgomery to canonical form
fn montgomery_to_canonical(montgomery: u32) -> u32 {
    // from_monty: monty_reduce(x as u64)
    monty_reduce(montgomery as u64)
}

// Montgomery reduction - converts Montgomery form to canonical
// Algorithm: montgomery_reduce(x) = ((x - ((x * MU) & MASK) * P) >> 32) mod P
fn monty_reduce(x: u64) -> u32 {
    const MONTY_MU: u64 = 0x81000001; // Modular inverse of PRIME mod 2^32
    const MONTY_MASK: u64 = 0xffffffff;
    
    // t = (x * MU) mod 2^32
    let t = (x.wrapping_mul(MONTY_MU)) & MONTY_MASK;
    
    // u = t * P
    let u = t.wrapping_mul(KOALABEAR_PRIME);
    
    // result = (x - u) >> 32, handling underflow
    let (x_sub_u, overflow) = x.overflowing_sub(u);
    let mut result = (x_sub_u >> KOALABEAR_MONTY_BITS) as u32;
    
    // If underflow occurred, add PRIME back
    if overflow {
        result = result.wrapping_add(KOALABEAR_PRIME as u32);
    }
    
    // Ensure result is in range [0, PRIME)
    if result >= KOALABEAR_PRIME as u32 {
        result -= KOALABEAR_PRIME as u32;
    }
    
    result
}

#[derive(Debug, Clone, Copy)]
enum LifetimeTag {
    Pow8,
    Pow18,
    Pow32,
}

impl LifetimeTag {
    fn parse(raw: Option<String>) -> Result<Self, Box<dyn Error>> {
        let provided = raw.unwrap_or_else(|| "2^8".to_string());
        let cleaned = provided.trim().to_ascii_lowercase();
        match cleaned.as_str() {
            "2^8" | "256" | "lifetime_2_8" => Ok(Self::Pow8),
            "2^18" | "262144" | "lifetime_2_18" => Ok(Self::Pow18),
            "2^32" | "4294967296" | "lifetime_2_32" => Ok(Self::Pow32),
            other => Err(format!("unsupported lifetime '{other}'").into()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LifetimeMetadata {
    rand_len: usize,
    hash_len: usize,
}

impl LifetimeTag {
    fn metadata(&self) -> LifetimeMetadata {
        match self {
            LifetimeTag::Pow8 => LifetimeMetadata {
                rand_len: 7,
                hash_len: 8,
            },
            LifetimeTag::Pow18 => LifetimeMetadata {
                rand_len: 6,
                hash_len: 7,
            },
            LifetimeTag::Pow32 => LifetimeMetadata {
                rand_len: 7,
                hash_len: 8,
            },
        }
    }
}

#[derive(Debug)]
enum Command {
    Sign {
        message: String,
        pk_json: String,
        sig_bin: String,
        seed_hex: Option<String>,
        epoch: u32,
        start_epoch: usize,
        num_active_epochs: usize,
        lifetime: LifetimeTag,
    },
    Verify {
        message: String,
        pk_json: String,
        sig_bin: String,
        epoch: u32,
        lifetime: LifetimeTag,
    },
}

fn print_usage() {
    eprintln!(
        "Usage:\n  remote_hashsig_tool sign <message> <pk_json_out> <sig_bin_out> [seed_hex] [epoch] [num_active_epochs] [start_epoch] [lifetime]\n  remote_hashsig_tool verify <message> <pk_json_path> <sig_bin_path> [epoch] [lifetime]"
    );
}

fn parse_args() -> Result<Command, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("missing command")?;
    match command.as_str() {
        "sign" => {
            let message = args.next().ok_or("missing message")?;
            let pk_json = args.next().ok_or("missing pk_json_out path")?;
            let sig_bin = args.next().ok_or("missing sig_bin_out path")?;
            let seed_hex = args.next();
            let epoch = args
                .next()
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            let num_active_epochs = args
                .next()
                .map(|v| v.parse::<usize>())
                .transpose()?
                .unwrap_or(256);
            let start_epoch = args
                .next()
                .map(|v| v.parse::<usize>())
                .transpose()?
                .unwrap_or(0);
            let lifetime = LifetimeTag::parse(args.next())?;
            Ok(Command::Sign {
                message,
                pk_json,
                sig_bin,
                seed_hex,
                epoch,
                start_epoch,
                num_active_epochs,
                lifetime,
            })
        }
        "verify" => {
            let message = args.next().ok_or("missing message")?;
            let pk_json = args.next().ok_or("missing pk_json path")?;
            let sig_bin = args.next().ok_or("missing sig_bin path")?;
            let epoch = args
                .next()
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            let lifetime = LifetimeTag::parse(args.next())?;
            Ok(Command::Verify {
                message,
                pk_json,
                sig_bin,
                epoch,
                lifetime,
            })
        }
        _ => Err("unknown command".into()),
    }
}

fn parse_seed_hex(seed_hex: Option<String>) -> Result<[u8; 32], Box<dyn Error>> {
    let default_seed =
        "4242424242424242424242424242424242424242424242424242424242424242".to_string();
    let cleaned = seed_hex.unwrap_or(default_seed);
    let cleaned = cleaned.trim_start_matches("0x").trim_start_matches("0X");
    if cleaned.len() < 64 {
        return Err("seed hex must be at least 64 hex characters".into());
    }
    let mut seed = [0u8; 32];
    for (i, chunk) in cleaned.as_bytes().chunks(2).take(32).enumerate() {
        let hi = char::from(chunk.get(0).copied().unwrap_or(b'0'));
        let lo = char::from(chunk.get(1).copied().unwrap_or(b'0'));
        let hi_v = hi.to_digit(16).ok_or("invalid hex in seed")? as u8;
        let lo_v = lo.to_digit(16).ok_or("invalid hex in seed")? as u8;
        seed[i] = (hi_v << 4) | lo_v;
    }
    Ok(seed)
}

fn message_to_bytes(message: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let msg_bytes = message.as_bytes();
    let copy_len = msg_bytes.len().min(32);
    bytes[..copy_len].copy_from_slice(&msg_bytes[..copy_len]);
    bytes
}

// Convert field elements in JSON from canonical (serde format) to Montgomery (JSON format)
fn convert_field_elements_to_montgomery(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                convert_field_elements_to_montgomery(item);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                convert_field_elements_to_montgomery(v);
            }
        }
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u <= u32::MAX as u64 {
                    let canonical = u as u32;
                    let montgomery = canonical_to_montgomery(canonical);
                    *value = Value::Number(montgomery.into());
                }
            }
        }
        _ => {}
    }
}

// Convert field elements in JSON from Montgomery (JSON format) to canonical (serde format)
fn convert_field_elements_to_canonical(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                convert_field_elements_to_canonical(item);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                convert_field_elements_to_canonical(v);
            }
        }
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u <= u32::MAX as u64 {
                    let montgomery = u as u32;
                    let canonical = montgomery_to_canonical(montgomery);
                    *value = Value::Number(canonical.into());
                }
            }
        }
        _ => {}
    }
}

fn serialize_public_key_to_file<P, K>(
    pk: &K,
    path: P,
    meta: LifetimeMetadata,
) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
    K: Serialize,
{
    let mut pk_value = serde_json::to_value(pk)?;
    trim_public_key_value(&mut pk_value, meta);
    // JSON serialization uses canonical form (matching Rust's serde default)
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &pk_value)?;
    writer.flush()?;
    Ok(())
}

fn deserialize_public_key_from_file<P, PK>(
    path: P,
    meta: LifetimeMetadata,
) -> Result<PK, Box<dyn Error>>
where
    P: AsRef<Path>,
    PK: for<'de> DeserializeOwned,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut pk_value: serde_json::Value = serde_json::from_reader(reader)?;
    trim_public_key_value(&mut pk_value, meta);
    // JSON deserialization uses canonical form (matching Rust's serde default)
    let pk = serde_json::from_value(pk_value)?;
    Ok(pk)
}

fn trim_public_key_value(value: &mut Value, meta: LifetimeMetadata) {
    if let Some(obj) = value.as_object_mut() {
        if let Some(Value::Array(root)) = obj.get_mut("root") {
            if root.len() > meta.hash_len {
                root.truncate(meta.hash_len);
            }
        }
    }
}

fn signature_to_json<S>(signature: &S, meta: LifetimeMetadata) -> Result<Value, Box<dyn Error>>
where
    S: Serialize,
{
    let mut value = serde_json::to_value(signature)?;
    trim_signature_value(&mut value, meta);
    if let Some(obj) = value.as_object_mut() {
        if let Some(path_val) = obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(co_path) = path_obj.remove("co_path") {
                    path_obj.insert("nodes".to_string(), co_path);
                }
            }
        }
    }
    // JSON serialization uses canonical form (matching Rust's serde default)
    Ok(value)
}

fn signature_from_json<S>(mut value: Value, meta: LifetimeMetadata) -> Result<S, Box<dyn Error>>
where
    S: for<'de> DeserializeOwned,
{
    trim_signature_value(&mut value, meta);
    if let Some(obj) = value.as_object_mut() {
        if let Some(path_val) = obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(nodes) = path_obj.remove("nodes") {
                    path_obj.insert("co_path".to_string(), nodes);
                }
            }
        }
    }
    // JSON deserialization uses canonical form (matching Rust's serde default)
    Ok(serde_json::from_value(value)?)
}

fn trim_signature_value(value: &mut Value, meta: LifetimeMetadata) {
    if let Some(obj) = value.as_object_mut() {
        if let Some(path_val) = obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(Value::Array(nodes)) = path_obj.get_mut("nodes") {
                    for node in nodes.iter_mut() {
                        if let Value::Array(ref mut node_arr) = node {
                            if node_arr.len() > meta.hash_len {
                                node_arr.truncate(meta.hash_len);
                            }
                        }
                    }
                }
            }
        }
        if let Some(Value::Array(hashes)) = obj.get_mut("hashes") {
            for domain in hashes.iter_mut() {
                if let Value::Array(ref mut arr) = domain {
                    if arr.len() > meta.hash_len {
                        arr.truncate(meta.hash_len);
                    }
                }
            }
        }
        if let Some(Value::Array(rho)) = obj.get_mut("rho") {
            if rho.len() > meta.rand_len {
                rho.truncate(meta.rand_len);
            }
        }
    }
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> Result<(), Box<dyn Error>> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> Result<(), Box<dyn Error>> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, Box<dyn Error>> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, Box<dyn Error>> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn write_signature_binary<P>(
    value: &Value,
    path: P,
    meta: LifetimeMetadata,
) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let path_obj = value
        .get("path")
        .and_then(|p| p.as_object())
        .ok_or("signature JSON missing path")?;
    let nodes_array = path_obj
        .get("nodes")
        .and_then(|n| n.as_array())
        .ok_or("signature JSON missing path.nodes")?;

    let rho_array = value
        .get("rho")
        .and_then(|r| r.as_array())
        .ok_or("signature JSON missing rho array")?;

    let hashes_array = value
        .get("hashes")
        .and_then(|h| h.as_array())
        .ok_or("signature JSON missing hashes array")?;

    if rho_array.len() < meta.rand_len {
        return Err(format!(
            "rho length {} shorter than expected {}",
            rho_array.len(),
            meta.rand_len
        )
        .into());
    }

    let mut writer = BufWriter::new(File::create(path)?);

    write_u64(&mut writer, u64::try_from(nodes_array.len())?)?;
    for node in nodes_array {
        let node_arr = node.as_array().ok_or("path node is not an array")?;
        if node_arr.len() < meta.hash_len {
            return Err(format!(
                "path node length {} shorter than expected {}",
                node_arr.len(),
                meta.hash_len
            )
            .into());
        }
        for entry in node_arr.iter().take(meta.hash_len) {
            let num = entry
                .as_u64()
                .ok_or("path node entry is not an unsigned integer")?;
            let canonical = u32::try_from(num).map_err(|_| "path node entry exceeds u32")?;
            // Convert canonical (from serde) to Montgomery (for binary format)
            let montgomery = canonical_to_montgomery(canonical);
            write_u32(&mut writer, montgomery)?;
        }
    }

    for entry in rho_array.iter().take(meta.rand_len) {
        let num = entry
            .as_u64()
            .ok_or("rho entry is not an unsigned integer")?;
        let canonical = u32::try_from(num).map_err(|_| "rho entry exceeds u32")?;
        // Convert canonical (from serde) to Montgomery (for binary format)
        let montgomery = canonical_to_montgomery(canonical);
        write_u32(&mut writer, montgomery)?;
    }

    write_u64(&mut writer, u64::try_from(hashes_array.len())?)?;
    for domain in hashes_array {
        let domain_arr = domain.as_array().ok_or("hash domain is not an array")?;
        if domain_arr.len() < meta.hash_len {
            return Err(format!(
                "hash domain length {} shorter than expected {}",
                domain_arr.len(),
                meta.hash_len
            )
            .into());
        }
        for entry in domain_arr.iter().take(meta.hash_len) {
            let num = entry
                .as_u64()
                .ok_or("hash entry is not an unsigned integer")?;
            let canonical = u32::try_from(num).map_err(|_| "hash entry exceeds u32")?;
            // Convert canonical (from serde) to Montgomery (for binary format)
            let montgomery = canonical_to_montgomery(canonical);
            write_u32(&mut writer, montgomery)?;
        }
    }

    writer.flush()?;
    Ok(())
}

fn read_signature_binary<P>(path: P, meta: LifetimeMetadata) -> Result<Value, Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let path_len = read_u64(&mut reader)? as usize;
    let mut nodes = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        let mut node = Vec::with_capacity(meta.hash_len);
        for _ in 0..meta.hash_len {
            let montgomery = read_u32(&mut reader)?;
            // Convert Montgomery (from binary) to canonical (for serde deserialization)
            // Rust's signature struct deserializes canonical values and converts to Montgomery internally
            let canonical = montgomery_to_canonical(montgomery);
            node.push(Value::from(canonical));
        }
        nodes.push(Value::Array(node));
    }

    let mut rho = Vec::with_capacity(meta.rand_len);
    for _ in 0..meta.rand_len {
        let montgomery = read_u32(&mut reader)?;
        // Convert Montgomery (from binary) to canonical (for serde deserialization)
        let canonical = montgomery_to_canonical(montgomery);
        rho.push(Value::from(canonical));
    }

    let hashes_len = read_u64(&mut reader)? as usize;
    let mut hashes = Vec::with_capacity(hashes_len);
    for _ in 0..hashes_len {
        let mut domain = Vec::with_capacity(meta.hash_len);
        for _ in 0..meta.hash_len {
            let montgomery = read_u32(&mut reader)?;
            // Convert Montgomery (from binary) to canonical (for serde deserialization)
            let canonical = montgomery_to_canonical(montgomery);
            domain.push(Value::from(canonical));
        }
        hashes.push(Value::Array(domain));
    }

    let mut path_obj = serde_json::Map::new();
    path_obj.insert("nodes".to_string(), Value::Array(nodes));

    let mut sig_obj = serde_json::Map::new();
    sig_obj.insert("path".to_string(), Value::Object(path_obj));
    sig_obj.insert("rho".to_string(), Value::Array(rho));
    sig_obj.insert("hashes".to_string(), Value::Array(hashes));

    Ok(Value::Object(sig_obj))
}

fn sign_for_scheme<S>(
    message: String,
    pk_json_out: String,
    sig_bin_out: String,
    seed: [u8; 32],
    epoch: u32,
    start_epoch: usize,
    num_active_epochs: usize,
    meta: LifetimeMetadata,
) -> Result<(), Box<dyn Error>>
where
    S: SignatureScheme,
    S::PublicKey: Serialize + for<'de> DeserializeOwned,
    S::SecretKey: SignatureSchemeSecretKey + Serialize + for<'de> DeserializeOwned,
    S::Signature: Serialize + for<'de> DeserializeOwned,
{
    let mut rng = StdRng::from_seed(seed);
    let (pk, mut sk) = S::key_gen(&mut rng, start_epoch, num_active_epochs);

    let msg_bytes = message_to_bytes(&message);
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }

    let signature = S::sign(&sk, epoch, &msg_bytes)
        .map_err(|e| format!("failed to sign message at epoch {epoch}: {e:?}"))?;

    serialize_public_key_to_file(&pk, pk_json_out, meta)?;
    let sig_json = signature_to_json(&signature, meta)?;
    write_signature_binary(&sig_json, sig_bin_out, meta)?;

    Ok(())
}

fn verify_for_scheme<S>(
    message: String,
    pk_json_path: String,
    sig_bin_path: String,
    epoch: u32,
    meta: LifetimeMetadata,
) -> Result<bool, Box<dyn Error>>
where
    S: SignatureScheme,
    S::PublicKey: Serialize + for<'de> DeserializeOwned,
    S::SecretKey: SignatureSchemeSecretKey + Serialize + for<'de> DeserializeOwned,
    S::Signature: Serialize + for<'de> DeserializeOwned,
{
    eprintln!("RUST_VERIFY_DEBUG: Entering verify function, epoch={}", epoch);
    let pk: S::PublicKey = deserialize_public_key_from_file(pk_json_path, meta)?;
    eprintln!("RUST_VERIFY_DEBUG: Public key deserialized");
    let sig_json = read_signature_binary(sig_bin_path, meta)?;
    
    // Debug: print rho values
    if let Some(rho_array) = sig_json.get("rho").and_then(|r| r.as_array()) {
        eprintln!("RUST_VERIFY_DEBUG: Signature rho values (first {}):", rho_array.len().min(7));
        for (i, val) in rho_array.iter().take(7).enumerate() {
            if let Some(num) = val.as_u64() {
                eprintln!("RUST_VERIFY_DEBUG:   rho[{}] = {} (0x{:x})", i, num, num);
            }
        }
    }
    
    // Debug: print first hash domain
    if let Some(hashes_array) = sig_json.get("hashes").and_then(|h| h.as_array()) {
        if let Some(first_hash) = hashes_array.get(0).and_then(|h| h.as_array()) {
            eprintln!("RUST_VERIFY_DEBUG: First hash domain (first {}):", first_hash.len().min(8));
            for (i, val) in first_hash.iter().take(8).enumerate() {
                if let Some(num) = val.as_u64() {
                    eprintln!("RUST_VERIFY_DEBUG:   hash[0][{}] = {} (0x{:x})", i, num, num);
                }
            }
        }
    }
    
    let signature: S::Signature = match signature_from_json(sig_json, meta) {
        Ok(sig) => {
            eprintln!("RUST_VERIFY_DEBUG: Signature deserialized successfully");
            sig
        }
        Err(e) => {
            eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize signature: {}", e);
            return Err(e);
        }
    };
    let msg_bytes = message_to_bytes(&message);
    eprintln!("RUST_VERIFY_DEBUG: Calling S::verify with message={:?}", &msg_bytes[..8]);
    
    // Debug: Extract and print Poseidon outputs before verification
    // This matches what Zig does in applyTopLevelPoseidonMessageHash
    use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::message_hash::TopLevelPoseidonMessageHash;
    use leansig::symmetric::message_hash::poseidon::{encode_epoch, encode_message};
    use p3_field::PrimeField32;
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::poseidon2::{poseidon_compress, Poseidon2};
    
    // Get parameter and randomness from signature
    if let Some(rho_array) = sig_json.get("rho").and_then(|r| r.as_array()) {
        if let Some(param_array) = pk_json.get("parameter").and_then(|p| p.as_array()) {
            if rho_array.len() >= 7 && param_array.len() >= 5 {
                let mut randomness: Vec<KoalaBear> = Vec::new();
                for val in rho_array.iter().take(7) {
                    if let Some(u) = val.as_u64() {
                        if u <= u32::MAX as u64 {
                            randomness.push(KoalaBear::from_canonical_u32(u as u32));
                        }
                    }
                }
                let mut parameter: Vec<KoalaBear> = Vec::new();
                for val in param_array.iter().take(5) {
                    if let Some(u) = val.as_u64() {
                        if u <= u32::MAX as u64 {
                            parameter.push(KoalaBear::from_canonical_u32(u as u32));
                        }
                    }
                }
                
                if randomness.len() == 7 && parameter.len() == 5 {
                    let parameter_arr: [KoalaBear; 5] = [parameter[0], parameter[1], parameter[2], parameter[3], parameter[4]];
                    let randomness_arr: [KoalaBear; 7] = [randomness[0], randomness[1], randomness[2], randomness[3], randomness[4], randomness[5], randomness[6]];
                    
                    let perm = Poseidon2::new();
                    let message_fe = encode_message::<9>(&msg_bytes);
                    let epoch_fe = encode_epoch::<2>(epoch);
                    let iteration_index = [KoalaBear::ZERO];
                    let combined_input: Vec<KoalaBear> = randomness_arr
                        .iter()
                        .chain(parameter_arr.iter())
                        .chain(epoch_fe.iter())
                        .chain(message_fe.iter())
                        .chain(iteration_index.iter())
                        .copied()
                        .collect();
                    
                    let pos_outputs = poseidon_compress::<KoalaBear, _, 24, 15>(&perm, &combined_input);
                    
                    eprint!("RUST_POSEIDON_OUTPUT (canonical): ");
                    for (i, fe) in pos_outputs.iter().enumerate() {
                        eprint!("0x{:08x} ", <KoalaBear as PrimeField32>::as_canonical_u32(fe));
                        if (i + 1) % 8 == 0 {
                            eprintln!();
                            eprint!("RUST_POSEIDON_OUTPUT (canonical): ");
                        }
                    }
                    eprintln!();
                }
            }
        }
    }
    
    let ok = S::verify(&pk, epoch, &msg_bytes, &signature);
    if !ok {
        eprintln!("RUST_VERIFY_DEBUG: Verification returned false - encoding or chain verification failed");
    } else {
        eprintln!("RUST_VERIFY_DEBUG: Verification succeeded");
    }
    Ok(ok)
}

fn sign_command(
    message: String,
    pk_json_out: String,
    sig_bin_out: String,
    seed_hex: Option<String>,
    epoch: u32,
    start_epoch: usize,
    num_active_epochs: usize,
    lifetime: LifetimeTag,
) -> Result<(), Box<dyn Error>> {
    let seed = parse_seed_hex(seed_hex)?;
    let meta = lifetime.metadata();
    match lifetime {
        LifetimeTag::Pow8 => sign_for_scheme::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
            message,
            pk_json_out,
            sig_bin_out,
            seed,
            epoch,
            start_epoch,
            num_active_epochs,
            meta,
        ),
        LifetimeTag::Pow18 => sign_for_scheme::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
            message,
            pk_json_out,
            sig_bin_out,
            seed,
            epoch,
            start_epoch,
            num_active_epochs,
            meta,
        ),
        LifetimeTag::Pow32 => sign_for_scheme::<SIGTopLevelTargetSumLifetime32Dim64Base8>(
            message,
            pk_json_out,
            sig_bin_out,
            seed,
            epoch,
            start_epoch,
            num_active_epochs,
            meta,
        ),
    }
}

fn verify_command(
    message: String,
    pk_json_path: String,
    sig_bin_path: String,
    epoch: u32,
    lifetime: LifetimeTag,
) -> Result<(), Box<dyn Error>> {
    let meta = lifetime.metadata();
    let ok = match lifetime {
        LifetimeTag::Pow8 => verify_for_scheme::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
            message,
            pk_json_path,
            sig_bin_path,
            epoch,
            meta,
        )?,
        LifetimeTag::Pow18 => verify_for_scheme::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
            message,
            pk_json_path,
            sig_bin_path,
            epoch,
            meta,
        )?,
        LifetimeTag::Pow32 => verify_for_scheme::<SIGTopLevelTargetSumLifetime32Dim64Base8>(
            message,
            pk_json_path,
            sig_bin_path,
            epoch,
            meta,
        )?,
    };
    println!("VERIFY_RESULT:{}", ok);
    Ok(())
}

fn main() {
    let command = match parse_args() {
        Ok(cmd) => cmd,
        Err(e) => {
            print_usage();
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let result = match command {
        Command::Sign {
            message,
            pk_json,
            sig_bin,
            seed_hex,
            epoch,
            start_epoch,
            num_active_epochs,
            lifetime,
        } => sign_command(
            message,
            pk_json,
            sig_bin,
            seed_hex,
            epoch,
            start_epoch,
            num_active_epochs,
            lifetime,
        ),
        Command::Verify {
            message,
            pk_json,
            sig_bin,
            epoch,
            lifetime,
        } => verify_command(message, pk_json, sig_bin, epoch, lifetime),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
