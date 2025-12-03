# Pre-Generated Keys

This directory contains pre-generated Generalized XMSS keys for testing and benchmarking purposes.

## Key Specifications

- **Lifetime**: 2^32 signatures per key
- **Active Epochs**: 1024
- **Serialization Format**: SSZ (Simple Serialize)
- **Number of Validators**: 3

## File Structure

Each validator has two files:
- `validator_N_sk.ssz` - Secret key (8,390,660 bytes / ~8.0 MB)
- `validator_N_pk.ssz` - Public key (52 bytes)

Where `N` is the validator ID (0, 1, 2).

## Key Information

### Secret Key
- **Size**: 8,390,660 bytes (~8.0 MB per validator)
- **Contains**: 1024 bottom tree secret keys (one per active epoch)
- **Format**: SSZ-serialized `GeneralizedXMSSSecretKey`

### Public Key
- **Size**: 52 bytes
- **Contains**: 
  - Top tree root (32 bytes / 8 field elements)
  - Parameter (16 bytes / 4 field elements)
  - Lifetime tag (4 bytes)
- **Format**: SSZ-serialized `GeneralizedXMSSPublicKey`

## Cross-Language Compatibility

These keys have been tested for full cross-language compatibility between Rust and Zig implementations:

✅ **Rust sign → Rust verify**  
✅ **Rust sign → Zig verify**  
✅ **Zig sign → Zig verify**  
✅ **Zig sign → Rust verify**

## Usage

### Inspect Keys

To inspect and test all pre-generated keys:

```bash
python3 benchmark/inspect_pregenerated_keys.py
```

This script will:
1. Report key sizes and information
2. Run cross-language compatibility tests for all validators
3. Test signing and verification in both directions (Rust↔Zig)

### Manual Testing

#### Using Rust Tool

```bash
# Sign with pre-generated key
cp benchmark/pre-generated-keys/validator_0_sk.ssz tmp/rust_sk.ssz
cp benchmark/pre-generated-keys/validator_0_pk.ssz tmp/rust_pk.ssz
echo "2^32" > tmp/rust_lifetime.txt
./benchmark/rust_benchmark/target/release/cross_lang_rust_tool sign "Test message" 0 --ssz

# Verify signature
./benchmark/rust_benchmark/target/release/cross_lang_rust_tool verify \
  tmp/rust_sig.ssz \
  tmp/rust_pk.ssz \
  "Test message" \
  0 \
  --ssz
```

#### Using Zig Tool

```bash
# Sign with pre-generated key
cp benchmark/pre-generated-keys/validator_0_sk.ssz tmp/zig_sk.ssz
cp benchmark/pre-generated-keys/validator_0_pk.ssz tmp/zig_pk.ssz
echo "2^32" > tmp/zig_lifetime.txt
echo "1024" > tmp/zig_active_epochs.txt
./zig-out/bin/cross-lang-zig-tool sign "Test message" 0 --ssz

# Verify signature
./zig-out/bin/cross-lang-zig-tool verify \
  tmp/zig_sig.ssz \
  tmp/zig_pk.ssz \
  "Test message" \
  0 \
  --ssz
```

## Generation

These keys were generated using:

```bash
# Rust (reference implementation)
cargo run --release --bin cross_lang_rust_tool -- keygen <seed_hex> 2^32 --ssz
```

With 1024 active epochs configured in the key generation parameters.

## Performance

### Signing Performance
- **Rust**: ~5-6ms per signature
- **Zig**: ~650-720ms per signature (includes keypair regeneration)

### Verification Performance
- **Rust**: ~3-4ms per verification
- **Zig**: ~8-11ms per verification

### Key Generation Performance
- **Rust**: ~5.3s for 2^32 with 1024 active epochs
- **Zig**: ~17.7s for 2^32 with 1024 active epochs

## Notes

- These keys are for **testing purposes only**
- The secret keys contain sensitive cryptographic material
- In production, keys should be generated with proper entropy and stored securely
- The Zig implementation regenerates the keypair during signing to ensure consistency
- All tests use epoch 0 for simplicity; production usage should increment epochs

## Related Files

- `../inspect_pregenerated_keys.py` - Inspection and testing script
- `../benchmark.py` - Main cross-language compatibility benchmark
- `../rust_benchmark/` - Rust reference implementation
- `../zig_benchmark/` - Zig implementation tools

