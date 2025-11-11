use bincode;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{de::DeserializeOwned, Serialize};
use serde_json;
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

fn write_signature_bincode<P, S>(signature: &S, path: P) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
    S: Serialize,
{
    let encoded = bincode::serialize(signature)?;
    let mut file = File::create(path)?;
    file.write_all(&encoded)?;
    Ok(())
}

fn read_signature_bincode<P, S>(path: P) -> Result<S, Box<dyn Error>>
where
    P: AsRef<Path>,
    S: for<'de> DeserializeOwned,
{
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let signature = bincode::deserialize(&buffer)?;
    Ok(signature)
}

fn sign_for_scheme<S>(
    message: String,
    pk_json_out: String,
    sig_bin_out: String,
    seed: [u8; 32],
    epoch: u32,
    start_epoch: usize,
    num_active_epochs: usize,
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
    write_signature_bincode(&signature, sig_bin_out)?;

    Ok(())
}

fn verify_for_scheme<S>(
    message: String,
    pk_json_path: String,
    sig_bin_path: String,
    epoch: u32,
) -> Result<bool, Box<dyn Error>>
where
    S: SignatureScheme,
    S::PublicKey: Serialize + for<'de> DeserializeOwned,
    S::SecretKey: SignatureSchemeSecretKey + Serialize + for<'de> DeserializeOwned,
    S::Signature: Serialize + for<'de> DeserializeOwned,
{
    let pk: S::PublicKey = deserialize_public_key_from_file(pk_json_path)?;
    let signature: S::Signature = read_signature_bincode(sig_bin_path)?;
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
    match lifetime {
        LifetimeTag::Pow8 => sign_for_scheme::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
            message,
            pk_json_out,
            sig_bin_out,
            seed,
            epoch,
            start_epoch,
            num_active_epochs,
        ),
        LifetimeTag::Pow18 => sign_for_scheme::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
            message,
            pk_json_out,
            sig_bin_out,
            seed,
            epoch,
            start_epoch,
            num_active_epochs,
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
    let ok = match lifetime {
        LifetimeTag::Pow8 => verify_for_scheme::<SIGTopLevelTargetSumLifetime8Dim64Base8>(
            message,
            pk_json_path,
            sig_bin_path,
            epoch,
        )?,
        LifetimeTag::Pow18 => verify_for_scheme::<SIGTopLevelTargetSumLifetime18Dim64Base8>(
            message,
            pk_json_path,
            sig_bin_path,
            epoch,
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
