use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::SignatureScheme;
use hashsig::symmetric::prf::shake_to_field::ShakePRFtoF;
use hashsig::symmetric::prf::Pseudorandom;
use hashsig::symmetric::tweak_hash::poseidon::PoseidonTweakHash;
use hashsig::symmetric::tweak_hash::TweakableHash;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField64;

fn main() {
    type PRF = ShakePRFtoF<8, 7>;
    type TH = PoseidonTweakHash<5, 8, 2, 9, 64>;
    type Sig = SIGTopLevelTargetSumLifetime8Dim64Base8;

    // Parameter and PRF key (deterministic if FIXED_DEBUG=1)
    let fixed = std::env::var("FIXED_DEBUG")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);
    let (parameter, prf_key) = if fixed {
        // Fixed parameter (5 F elements) matching Zig debug output
        let param_u32: [u32; 5] = [0x6787429d, 0x3d8d2d52, 0x1d33d160, 0x5d6a9570, 0x2db82524];
        // Construct parameter directly from u32 values
        // Parameter is [F; 5] where F is the field element type
        // We can extract the element type from Domain which is [F; 8]
        type Domain = <TH as TweakableHash>::Domain;
        type F = Domain; // This is actually [F_elem; 8], so we need F_elem
                         // Actually, let's use a workaround: create a dummy domain and extract its element type
                         // Or better: use the fact that we can call from_canonical_u64 on the field element
                         // Let's construct the parameter using a helper that extracts the element type
                         // For now, use serde_json but with proper construction
        let param_json = serde_json::json!([
            param_u32[0] as u64,
            param_u32[1] as u64,
            param_u32[2] as u64,
            param_u32[3] as u64,
            param_u32[4] as u64
        ]);
        let parameter: <PoseidonTweakHash<5, 8, 2, 9, 64> as TweakableHash>::Parameter =
            serde_json::from_value(param_json).expect("failed to build TH::Parameter");
        let prf_key: [u8; 32] = [0x42u8; 32];
        (parameter, prf_key)
    } else {
        let mut rng = rand::rng();
        (TH::rand_parameter(&mut rng), PRF::key_gen(&mut rng))
    };

    // Epoch to debug
    let epoch: u32 = 0;

    // Compute chain ends for all 64 chains by walking BASE-1 steps
    let base: u8 = 8;
    let num_chains: u8 = 64;

    let mut chain_ends: Vec<<PoseidonTweakHash<5, 8, 2, 9, 64> as TweakableHash>::Domain> =
        Vec::with_capacity(num_chains as usize);
    for chain_index in 0..num_chains {
        // Start domain from PRF
        let start_domain = PRF::get_domain_element(&prf_key, epoch, chain_index as u64);
        let mut current: <PoseidonTweakHash<5, 8, 2, 9, 64> as TweakableHash>::Domain =
            start_domain.into();

        // Debug: print PRF start for chain 0
        if chain_index == 0 {
            print!("RUST_DEBUG: Chain 0 PRF start: [");
            for (i, f) in start_domain.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("0x{:08x}", f.as_canonical_u64() as u32);
            }
            println!("]");
        }

        // Walk 1..base-1
        for pos_in_chain in 1..base {
            let tweak = TH::chain_tweak(epoch, chain_index, pos_in_chain);
            current = TH::apply(&parameter, &tweak, std::slice::from_ref(&current));
        }

        // Debug: print chain 0 end
        if chain_index == 0 {
            print!("RUST_DEBUG: Chain 0 end: [");
            for (i, f) in current.iter().enumerate() {
                if i > 0 {
                    print!(", ");
                }
                print!("0x{:08x}", f.as_canonical_u64() as u32);
            }
            println!("]");
        }

        chain_ends.push(current);
    }

    // Compute leaf domain via tree tweak sponge
    let tree_tweak = TH::tree_tweak(0, epoch);
    let tweak_fe = tree_tweak.to_field_elements::<2>();
    println!(
        "RUST_TWEAK_FE:[\"0x{:08x}\",\"0x{:08x}\"]",
        tweak_fe[0].as_canonical_u64() as u32,
        tweak_fe[1].as_canonical_u64() as u32
    );

    // Build combined_input = parameter (5) + tweak (2) + flatten(chain_ends)
    let mut combined: Vec<_> = parameter.iter().copied().collect();
    combined.extend_from_slice(&tweak_fe);
    for dom in &chain_ends {
        combined.extend_from_slice(dom);
    }
    // Print first RATE=15 elements
    let head = 15usize.min(combined.len());
    print!("RUST_COMBINED_INPUT_HEAD_RATE:{}:", head);
    for i in 0..head {
        let v = combined[i].as_canonical_u64() as u32;
        if i > 0 {
            print!(",");
        }
        print!("{}:0x{:08x}", i, v);
    }
    println!("");

    let leaf = TH::apply(&parameter, &tree_tweak, &chain_ends);

    // Print in hex
    let to_hex = |x: &<PoseidonTweakHash<5, 8, 2, 9, 64> as TweakableHash>::Domain| -> Vec<String> {
        x.iter()
            .map(|f| format!("0x{:08x}", f.as_canonical_u64() as u32))
            .collect()
    };

    let leaf_hex = to_hex(&leaf);
    println!(
        "RUST_LEAF_DOMAIN_EPOCH0:{}",
        serde_json::to_string(&leaf_hex).unwrap()
    );

    // Also print parameter for comparison
    let param_hex: Vec<String> = parameter
        .iter()
        .map(|f| format!("0x{:08x}", f.as_canonical_u64() as u32))
        .collect();
    println!(
        "RUST_PARAMETER:{}",
        serde_json::to_string(&param_hex).unwrap()
    );
}
