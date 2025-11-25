use hashsig::symmetric::tweak_hash::poseidon::poseidon_compress;
use hashsig::symmetric::message_hash::poseidon::{encode_epoch, encode_message};
use p3_field::PrimeField32;
use p3_koala_bear::{default_koalabear_poseidon2_24, KoalaBear};
use std::env;
use std::fs;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 4 {
        eprintln!("Usage: {} <pk_json> <sig_bin> <message> <epoch>", args[0]);
        eprintln!("Example: {} /tmp/rust_public_2pow8.key.json /tmp/rust_signature_2pow8.bin \"Cross-language benchmark message\" 0", args[0]);
        std::process::exit(1);
    }
    
    let pk_path = &args[1];
    let sig_bin_path = &args[2];
    let message = &args[3];
    let epoch: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    
    // Read public key
    let pk_json_str = fs::read_to_string(pk_path)?;
    let pk_json: serde_json::Value = serde_json::from_str(&pk_json_str)?;
    let parameter_arr = pk_json.get("parameter")
        .and_then(|v| v.as_array())
        .ok_or("Missing 'parameter' array")?;
    
    // Read signature binary
    let mut sig_file = fs::File::open(sig_bin_path)?;
    let mut sig_bytes = Vec::new();
    sig_file.read_to_end(&mut sig_bytes)?;
    
    // Parse signature binary format:
    // - path_len: u64 (little endian)
    // - path nodes: path_len * hash_len * u32 (Montgomery form)
    // - rho: rand_len * u32 (Montgomery form)
    // - hashes_len: u64 (little endian)
    // - hashes: hashes_len * hash_len * u32 (Montgomery form)
    
    let mut offset = 0;
    
    // Read path_len
    if sig_bytes.len() < offset + 8 {
        return Err("Signature too short for path_len".into());
    }
    let path_len = u64::from_le_bytes([
        sig_bytes[offset], sig_bytes[offset + 1], sig_bytes[offset + 2], sig_bytes[offset + 3],
        sig_bytes[offset + 4], sig_bytes[offset + 5], sig_bytes[offset + 6], sig_bytes[offset + 7],
    ]) as usize;
    offset += 8;
    
    // Skip path nodes (hash_len = 8 for lifetime 2^8)
    let hash_len = 8;
    offset += path_len * hash_len * 4;
    
    // Read rho (rand_len = 7 for lifetime 2^8)
    let rand_len = 7;
    if sig_bytes.len() < offset + rand_len * 4 {
        return Err("Signature too short for rho".into());
    }
    
    let mut randomness: Vec<KoalaBear> = Vec::new();
    for i in 0..rand_len {
        let montgomery = u32::from_le_bytes([
            sig_bytes[offset + i * 4],
            sig_bytes[offset + i * 4 + 1],
            sig_bytes[offset + i * 4 + 2],
            sig_bytes[offset + i * 4 + 3],
        ]);
        // Convert Montgomery to canonical for KoalaBear
        let canonical = montgomery_to_canonical(montgomery);
        randomness.push(KoalaBear::from_canonical_u32(canonical));
    }
    offset += rand_len * 4;
    
    // Extract parameter
    let mut parameter: Vec<KoalaBear> = Vec::new();
    for val in parameter_arr.iter().take(5) {
        let u32_val = val.as_u64().ok_or("Invalid parameter value")? as u32;
        parameter.push(KoalaBear::from_canonical_u32(u32_val));
    }
    
    // Encode message and epoch
    let msg_bytes = message.as_bytes();
    let message_fe = encode_message::<9>(msg_bytes);
    let epoch_fe = encode_epoch::<2>(epoch);
    let iteration_index = [KoalaBear::ZERO];
    
    // Build combined input: randomness (7) + parameter (5) + epoch (2) + message (9) + iteration (1) = 24
    let combined_input: Vec<KoalaBear> = randomness
        .iter()
        .chain(parameter.iter())
        .chain(epoch_fe.iter())
        .chain(message_fe.iter())
        .chain(iteration_index.iter())
        .copied()
        .collect();
    
    // Print input for comparison
    eprintln!("RUST_COMPARE_INPUT (canonical, 24 values):");
    for (i, fe) in combined_input.iter().enumerate() {
        eprint!("0x{:08x} ", <KoalaBear as PrimeField32>::as_canonical_u32(fe));
        if (i + 1) % 8 == 0 {
            eprintln!();
            eprint!("RUST_COMPARE_INPUT (canonical): ");
        }
    }
    eprintln!();
    
    // Run poseidon_compress
    // Use Poseidon2::new() which creates the default permutation
    use p3_symmetric::poseidon2::Poseidon2;
    let perm = Poseidon2::new();
    
    // Debug: print input length
    eprintln!("RUST_COMPARE_DEBUG: Input length: {}", combined_input.len());
    eprintln!("RUST_COMPARE_DEBUG: First 3 inputs: {:?}", 
        combined_input.iter().take(3).map(|fe| <KoalaBear as PrimeField32>::as_canonical_u32(fe)).collect::<Vec<_>>());
    
    let pos_outputs = poseidon_compress::<KoalaBear, _, 24, 15>(&perm, &combined_input);
    
    // Print output
    eprintln!("RUST_COMPARE_OUTPUT (canonical, 15 values):");
    for (i, fe) in pos_outputs.iter().enumerate() {
        eprint!("0x{:08x} ", <KoalaBear as PrimeField32>::as_canonical_u32(fe));
        if (i + 1) % 8 == 0 {
            eprintln!();
            eprint!("RUST_COMPARE_OUTPUT (canonical): ");
        }
    }
    eprintln!();
    
    Ok(())
}

// Convert Montgomery form to canonical form for KoalaBear
// KoalaBear modulus: 2^31 - 2^27 + 1 = 2130706433
fn montgomery_to_canonical(montgomery: u32) -> u32 {
    const MODULUS: u64 = 2130706433;
    const R_INV: u64 = 2147483648; // 2^31 mod MODULUS
    
    let mont_u64 = montgomery as u64;
    let canonical = (mont_u64 * R_INV) % MODULUS;
    canonical as u32
}

