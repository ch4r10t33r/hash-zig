use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
use hashsig::signature::{SignatureScheme, SignatureSchemeSecretKey};
fn main() {
    println!("Testing Rust internal signing and verification...");

    let mut rng = rand::rng();
    let (pk, mut sk) = SIGTopLevelTargetSumLifetime8Dim64Base8::key_gen(&mut rng, 0, 256);

    // Test message
    let test_message = "Hello, Rust internal test!";
    let epoch = 0u32;

    // Convert message to bytes (truncate/pad to 32 bytes)
    let mut message_bytes = [0u8; 32];
    let message_bytes_slice = test_message.as_bytes();
    let copy_len = std::cmp::min(message_bytes_slice.len(), 32);
    message_bytes[..copy_len].copy_from_slice(&message_bytes_slice[..copy_len]);

    println!("Generating keypair...");
    println!("Signing message...");

    // Prepare the secret key for the epoch
    while !sk.get_prepared_interval().contains(&(epoch as u64)) {
        sk.advance_preparation();
    }

    // Sign the message
    let signature_result =
        SIGTopLevelTargetSumLifetime8Dim64Base8::sign(&sk, epoch, &message_bytes);

    let signature = match signature_result {
        Ok(sig) => sig,
        Err(e) => {
            println!("❌ FAILED: Rust signing failed: {:?}", e);
            return;
        }
    };

    println!("Verifying signature...");

    // Verify the signature
    let is_valid =
        SIGTopLevelTargetSumLifetime8Dim64Base8::verify(&pk, epoch, &message_bytes, &signature);

    println!("Result: {}", is_valid);

    if is_valid {
        println!("✅ SUCCESS: Rust internal signing and verification works!");
    } else {
        println!("❌ FAILED: Rust internal verification failed!");
    }
}
