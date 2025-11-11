use hashsig::hypercube::{hypercube_find_layer, hypercube_part_size, map_to_vertex};
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8;
use hashsig::signature::SignatureScheme;
use hashsig::symmetric::message_hash::poseidon::{encode_epoch, encode_message};
use hashsig::symmetric::message_hash::top_level_poseidon::TopLevelPoseidonMessageHash;
use hashsig::symmetric::message_hash::MessageHash;
use hashsig::symmetric::tweak_hash::chain as tweak_chain;
use hashsig::symmetric::tweak_hash::poseidon::{poseidon_compress, PoseidonTweakHash};
use hashsig::symmetric::tweak_hash::TweakableHash;
use num_bigint::BigUint;
use num_traits::Zero;
use p3_field::{PrimeCharacteristicRing, PrimeField32, PrimeField64};
use p3_koala_bear::default_koalabear_poseidon2_24;
use p3_koala_bear::KoalaBear;
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

    let mut message_bytes = [0u8; 32];
    let message_bytes_slice = message.as_bytes();
    let copy_len = std::cmp::min(message_bytes_slice.len(), 32);
    message_bytes[..copy_len].copy_from_slice(&message_bytes_slice[..copy_len]);

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

    let pk: Result<<SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::PublicKey, _> =
        serde_json::from_str(pk_json);
    let signature: Result<
        <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::Signature,
        _,
    > = serde_json::from_str(sig_json);

    match (pk, signature) {
        (Ok(pk_val), Ok(sig_val)) => {
            let is_valid = SIGTopLevelTargetSumLifetime18Dim64Base8::verify(
                &pk_val,
                epoch,
                &message_bytes,
                &sig_val,
            );
            println!("VERIFY_RESULT:{}", is_valid);
        }
        _ => {
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

            if let Some(root) = pk_val.get_mut("root").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(root);
            }
            if let Some(param) = pk_val.get_mut("parameter").and_then(|v| v.as_array_mut()) {
                hex_array_to_numbers(param);
            }

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

            if let Some(path_obj) = sig_val.get_mut("path").and_then(|p| p.as_object_mut()) {
                if let Some(nodes_val) = path_obj.remove("nodes") {
                    path_obj.insert("co_path".to_string(), nodes_val);
                }
            }

            let pk_built: <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::PublicKey =
                match serde_json::from_value(pk_val) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize PK: {}", e);
                        println!("VERIFY_RESULT:false");
                        return;
                    }
                };
            let sig_built: <SIGTopLevelTargetSumLifetime18Dim64Base8 as SignatureScheme>::Signature =
                match serde_json::from_value(sig_val) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("RUST_VERIFY_DEBUG: Failed to deserialize SIG: {}", e);
                    println!("VERIFY_RESULT:false");
                    return;
                }
            };

            let pk_dbg = serde_json::to_value(&pk_built).ok();
            let sig_dbg = serde_json::to_value(&sig_built).ok();

            if let Some(ref pk_dbg_val) = pk_dbg {
                eprintln!("RUST_VERIFY_DEBUG: pk dbg {}", pk_dbg_val);
            }
            if let Some(ref sig_dbg_val) = sig_dbg {
                eprintln!("RUST_VERIFY_DEBUG: sig dbg {}", sig_dbg_val);
            }
            if let (Some(pk_dbg_val), Some(sig_dbg_val)) = (pk_dbg.as_ref(), sig_dbg.as_ref()) {
                const PARAMETER_LEN: usize = 5;
                const RAND_LEN_FE: usize = 6;
                const HASH_LEN_FE: usize = 7;
                if let (Some(param_arr), Some(rho_arr)) =
                    (pk_dbg_val.get("parameter"), sig_dbg_val.get("rho"))
                {
                    if let Some(rho_values) = rho_arr.as_array() {
                        let mut parameter = [KoalaBear::ZERO; PARAMETER_LEN];
                        for (idx, val) in param_arr
                            .as_array()
                            .unwrap()
                            .iter()
                            .take(PARAMETER_LEN)
                            .enumerate()
                        {
                            parameter[idx] = serde_json::from_value(val.clone()).unwrap();
                        }
                        let mut rho = [KoalaBear::ZERO; RAND_LEN_FE];
                        for (idx, val) in rho_values.iter().take(RAND_LEN_FE).enumerate() {
                            rho[idx] = serde_json::from_value(val.clone()).unwrap();
                        }

                        eprintln!(
                            "RUST_POSEIDON_DEBUG: parameter canonical={:?}",
                            parameter
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );
                        eprintln!(
                            "RUST_POSEIDON_DEBUG: rho canonical={:?}",
                            rho.iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );

                        let message_fe = encode_message::<9>(&message_bytes);
                        let epoch_fe = encode_epoch::<2>(epoch);

                        eprintln!(
                            "RUST_POSEIDON_DEBUG: message_fe canonical={:?}",
                            message_fe
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );
                        eprintln!(
                            "RUST_POSEIDON_DEBUG: epoch_fe canonical={:?}",
                            epoch_fe
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );

                        let perm = default_koalabear_poseidon2_24();
                        let mut combined_input = Vec::with_capacity(
                            RAND_LEN_FE + PARAMETER_LEN + epoch_fe.len() + message_fe.len() + 1,
                        );
                        combined_input.extend_from_slice(&rho);
                        combined_input.extend_from_slice(&parameter);
                        combined_input.extend_from_slice(&epoch_fe);
                        combined_input.extend_from_slice(&message_fe);
                        combined_input.push(KoalaBear::from_u64(0));

                        eprintln!(
                            "RUST_POSEIDON_DEBUG: combined_input canonical={:?}",
                            combined_input
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );

                        let iteration_pos_output =
                            poseidon_compress::<_, 24, 15>(&perm, &combined_input);
                        eprintln!(
                            "RUST_POSEIDON_DEBUG: pos_output canonical={:?}",
                            iteration_pos_output
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect::<Vec<_>>()
                        );

                        let mut acc = BigUint::zero();
                        for fe in &iteration_pos_output {
                            acc = acc * BigUint::from(KoalaBear::ORDER_U64)
                                + BigUint::from(fe.as_canonical_u32());
                        }
                        let dom_size = hypercube_part_size(8, 64, 77);
                        eprintln!("RUST_POSEIDON_DEBUG: dom_size {}", dom_size);
                        acc %= dom_size;
                        let (layer, offset) = hypercube_find_layer(8, 64, acc.clone());
                        let vertex = map_to_vertex(8, 64, layer, offset.clone());
                        eprintln!("RUST_POSEIDON_DEBUG: layer={} offset={}", layer, offset);
                        eprintln!("RUST_POSEIDON_DEBUG: vertex {:?}", vertex);

                        let chunk_values =
                            TopLevelPoseidonMessageHash::<15, 1, 15, 64, 8, 77, 2, 9, 5, 6>::apply(
                                &parameter,
                                epoch,
                                &rho,
                                &message_bytes,
                            );
                        let chunk_sum: u32 = chunk_values.iter().map(|&x| x as u32).sum();
                        eprintln!("RUST_VERIFY_DEBUG: chunk_values {:?}", chunk_values);
                        eprintln!("RUST_VERIFY_DEBUG: chunk_sum {}", chunk_sum);

                        let hashes_vec: Vec<[KoalaBear; HASH_LEN_FE]> = sig_dbg_val
                            .get("hashes")
                            .and_then(|h| h.as_array())
                            .map(|domains| {
                                domains
                                    .iter()
                                    .map(|domain_val| {
                                        let domain_items =
                                            domain_val.as_array().expect("hash domain");
                                        let mut arr = [KoalaBear::ZERO; HASH_LEN_FE];
                                        for (j, value) in
                                            domain_items.iter().take(HASH_LEN_FE).enumerate()
                                        {
                                            arr[j] = serde_json::from_value(value.clone()).unwrap();
                                        }
                                        arr
                                    })
                                    .collect()
                            })
                            .expect("hashes array present");

                        type TH = PoseidonTweakHash<PARAMETER_LEN, HASH_LEN_FE, 2, 9, 64>;
                        const BASE_MINUS_ONE: u8 = 7;
                        let mut chain_ends: Vec<[KoalaBear; HASH_LEN_FE]> =
                            Vec::with_capacity(chunk_values.len());
                        for (chain_index, &xi) in chunk_values.iter().enumerate() {
                            let hash_start = hashes_vec[chain_index];
                            let steps_to_walk = BASE_MINUS_ONE.saturating_sub(xi);
                            let recomputed = tweak_chain::<TH>(
                                &parameter,
                                epoch,
                                chain_index as u8,
                                xi,
                                steps_to_walk as usize,
                                &hash_start,
                            );
                            chain_ends.push(recomputed);
                            let start_first = hash_start[0].as_canonical_u32();
                            let end_first = chain_ends[chain_index][0].as_canonical_u32();
                            eprintln!(
                                "RUST_CHAIN_DEBUG: chain={} xi={} steps={} start[0]=0x{:08x} end[0]=0x{:08x}",
                                chain_index, xi, steps_to_walk, start_first, end_first
                            );
                        }

                        let co_path_vals = sig_dbg_val
                            .get("path")
                            .and_then(|p| p.get("co_path"))
                            .and_then(|v| v.as_array())
                            .expect("co_path array present");
                        let mut co_path = Vec::with_capacity(co_path_vals.len());
                        for node_val in co_path_vals {
                            let node_items = node_val.as_array().expect("co_path node");
                            let mut arr = [KoalaBear::ZERO; HASH_LEN_FE];
                            for (j, value) in node_items.iter().take(HASH_LEN_FE).enumerate() {
                                arr[j] = serde_json::from_value(value.clone()).unwrap();
                            }
                            co_path.push(arr);
                        }

                        let fmt_domain = |domain: &[KoalaBear; HASH_LEN_FE]| -> String {
                            let parts: Vec<String> = domain
                                .iter()
                                .map(|f| format!("0x{:08x}", f.as_canonical_u32()))
                                .collect();
                            format!("[{}]", parts.join(", "))
                        };

                        for (idx, end) in chain_ends.iter().take(3).enumerate() {
                            eprintln!(
                                "RUST_CHAIN_END_DEBUG: chain={} end={}",
                                idx,
                                fmt_domain(end)
                            );
                        }

                        let mut current_node =
                            TH::apply(&parameter, &TH::tree_tweak(0, epoch), &chain_ends);
                        let mut current_position = epoch;
                        for (level, sibling) in co_path.iter().enumerate() {
                            let is_left = current_position % 2 == 0;
                            let children = if is_left {
                                [current_node, *sibling]
                            } else {
                                [*sibling, current_node]
                            };
                            eprintln!(
                                "RUST_TREE_DEBUG: level={} position={} left={} right={}",
                                level,
                                current_position,
                                fmt_domain(&children[0]),
                                fmt_domain(&children[1])
                            );
                            current_position >>= 1;
                            current_node = TH::apply(
                                &parameter,
                                &TH::tree_tweak((level + 1) as u8, current_position),
                                &children,
                            );
                            eprintln!(
                                "RUST_TREE_DEBUG: level={} parent={}",
                                level,
                                fmt_domain(&current_node)
                            );
                        }

                        let expected_root_values = pk_dbg_val
                            .get("root")
                            .and_then(|r| r.as_array())
                            .expect("root array present");
                        let mut expected_root = [KoalaBear::ZERO; HASH_LEN_FE];
                        for (idx, value) in
                            expected_root_values.iter().take(HASH_LEN_FE).enumerate()
                        {
                            expected_root[idx] = serde_json::from_value(value.clone()).unwrap();
                        }

                        eprintln!(
                            "RUST_TREE_DEBUG: final_computed={} final_expected={}",
                            fmt_domain(&current_node),
                            fmt_domain(&expected_root)
                        );
                    }
                }
            }

            eprintln!("RUST_VERIFY_DEBUG: PK and SIG deserialized successfully");
            eprintln!(
                "RUST_VERIFY_DEBUG: Calling verify with epoch={}, message_len={}",
                epoch,
                message_bytes.len()
            );
            let is_valid = SIGTopLevelTargetSumLifetime18Dim64Base8::verify(
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
