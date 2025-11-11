use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{self, Value};
use std::convert::TryFrom;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::{SignatureScheme, SignatureSchemeSecretKey};

#[derive(Debug, Clone, Copy)]
enum LifetimeTag {
    Pow8,
    Pow18,
}

impl LifetimeTag {
    fn parse(raw: Option<String>) -> Result<Self, Box<dyn Error>> {
        let provided = raw.unwrap_or_else(|| "2^8".to_string());
        let cleaned = provided.trim().to_ascii_lowercase();
        match cleaned.as_str() {
            "2^8" | "256" | "lifetime_2_8" => Ok(Self::Pow8),
            "2^18" | "262144" | "lifetime_2_18" => Ok(Self::Pow18),
            other => Err(format!("unsupported lifetime '{other}'").into()),
        }
    }
}

#[derive(Debug)]
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

fn serialize_public_key_to_file<P, K>(pk: &K, path: P) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
    K: Serialize,
{
    let pk_value = serde_json::to_value(pk)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &pk_value)?;
    writer.flush()?;
    Ok(())
}

fn deserialize_public_key_from_file<P, K>(path: P) -> Result<K, Box<dyn Error>>
where
    P: AsRef<Path>,
    K: for<'de> DeserializeOwned,
{
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let pk_value: serde_json::Value = serde_json::from_reader(reader)?;
    let pk = serde_json::from_value(pk_value)?;
    Ok(pk)
}

fn signature_to_json<S>(signature: &S) -> Result<Value, Box<dyn Error>>
where
    S: Serialize,
{
    let mut value = serde_json::to_value(signature)?;
    if let Some(obj) = value.as_object_mut() {
        if let Some(path_val) = obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(co_path) = path_obj.remove("co_path") {
                    path_obj.insert("nodes".to_string(), co_path);
                }
            }
        }
    }
    Ok(value)
}

fn signature_from_json<S>(mut value: Value) -> Result<S, Box<dyn Error>>
where
    S: for<'de> DeserializeOwned,
{
    if let Some(obj) = value.as_object_mut() {
        if let Some(path_val) = obj.get_mut("path") {
            if let Some(path_obj) = path_val.as_object_mut() {
                if let Some(nodes) = path_obj.remove("nodes") {
                    path_obj.insert("co_path".to_string(), nodes);
                }
            }
        }
    }
    Ok(serde_json::from_value(value)?)
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
            let value = u32::try_from(num).map_err(|_| "path node entry exceeds u32")?;
            write_u32(&mut writer, value)?;
        }
    }

    for entry in rho_array.iter().take(meta.rand_len) {
        let num = entry
            .as_u64()
            .ok_or("rho entry is not an unsigned integer")?;
        let value = u32::try_from(num).map_err(|_| "rho entry exceeds u32")?;
        write_u32(&mut writer, value)?;
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
            let value = u32::try_from(num).map_err(|_| "hash entry exceeds u32")?;
            write_u32(&mut writer, value)?;
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
            node.push(Value::from(read_u32(&mut reader)?));
        }
        nodes.push(Value::Array(node));
    }

    let mut rho = Vec::with_capacity(meta.rand_len);
    for _ in 0..meta.rand_len {
        rho.push(Value::from(read_u32(&mut reader)?));
    }

    let hashes_len = read_u64(&mut reader)? as usize;
    let mut hashes = Vec::with_capacity(hashes_len);
    for _ in 0..hashes_len {
        let mut domain = Vec::with_capacity(meta.hash_len);
        for _ in 0..meta.hash_len {
            domain.push(Value::from(read_u32(&mut reader)?));
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
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (pk, mut sk) = S::key_gen(&mut rng, start_epoch, num_active_epochs);

    let msg_bytes = message_to_bytes(&message);
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }

    let signature = S::sign(&sk, epoch, &msg_bytes)
        .map_err(|e| format!("failed to sign message at epoch {epoch}: {e:?}"))?;

    serialize_public_key_to_file(&pk, pk_json_out)?;
    let sig_json = signature_to_json(&signature)?;
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
    let pk: S::PublicKey = deserialize_public_key_from_file(pk_json_path)?;
    let sig_json = read_signature_binary(sig_bin_path, meta)?;
    let signature: S::Signature = signature_from_json(sig_json)?;
    let msg_bytes = message_to_bytes(&message);
    let ok = S::verify(&pk, epoch, &msg_bytes, &signature);
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
