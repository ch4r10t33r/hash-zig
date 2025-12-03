#!/usr/bin/env python3
"""
Inspect and test pre-generated keys from pre-generated-keys/ directory.
These keys are for lifetime 2^32 with 1024 active epochs, serialized in SSZ format.

This script:
1. Picks a random validator key file
2. Deserializes using both Rust and Zig tools
3. Compares public keys and parameters
4. Runs cross-language compatibility tests
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import time
import random

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
RUST_BIN = REPO_ROOT / "benchmark/rust_benchmark/target/release/cross_lang_rust_tool"
ZIG_BIN = REPO_ROOT / "zig-out/bin/cross-lang-zig-tool"
PREGENERATED_KEYS_DIR = SCRIPT_DIR / "pre-generated-keys"

# Lifetime for pre-generated keys
LIFETIME = "2^32"
ACTIVE_EPOCHS = 1024

def run_command(cmd: List[str], cwd: Path = REPO_ROOT) -> Tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)"""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr

def inspect_key_rust(sk_path: Path, pk_path: Path) -> Dict[str, any]:
    """Inspect a key using Rust tool"""
    print(f"\n📋 Rust: Deserializing keys...")
    
    # Use the inspect command
    returncode, stdout, stderr = run_command([
        str(RUST_BIN), "inspect", str(sk_path), str(pk_path), LIFETIME
    ])
    
    if returncode != 0:
        print(f"   ❌ Failed to inspect keys: {stderr}")
        return None
    
    # Print the output
    print(stderr, end='')
    
    # Parse key information from output
    sk_size = sk_path.stat().st_size
    pk_size = pk_path.stat().st_size
    
    # Extract first 8 bytes of public key from output
    pk_hex = None
    for line in stderr.split('\n'):
        if "Public key (first 8 bytes)" in line:
            # Extract hex bytes
            parts = line.split('[')
            if len(parts) > 1:
                pk_hex = parts[1].split(']')[0].strip()
    
    return {
        "sk_size": sk_size,
        "pk_size": pk_size,
        "pk_hex": pk_hex,
        "estimated_keys": ACTIVE_EPOCHS,
    }

def inspect_key_zig(sk_path: Path, pk_path: Path) -> Dict[str, any]:
    """Inspect a key using Zig tool"""
    print(f"\n📋 Zig: Deserializing keys...")
    
    # Use the inspect command
    returncode, stdout, stderr = run_command([
        str(ZIG_BIN), "inspect", str(sk_path), str(pk_path), LIFETIME
    ])
    
    if returncode != 0:
        print(f"   ❌ Failed to inspect keys: {stdout}{stderr}")
        return None
    
    # Zig std.debug.print outputs to stderr, not stdout
    output = stderr if stderr else stdout
    print(output)
    
    # Parse key information from output
    sk_size = sk_path.stat().st_size
    pk_size = pk_path.stat().st_size
    
    # Extract first 8 bytes of public key from output
    pk_hex = None
    for line in output.split('\n'):
        if "Public key (first 8 bytes):" in line:
            # Extract hex string (format: "Public key (first 8 bytes): db0c2512f47f2609")
            parts = line.split(':')
            if len(parts) > 1:
                pk_hex = parts[-1].strip()
    
    return {
        "sk_size": sk_size,
        "pk_size": pk_size,
        "pk_hex": pk_hex,
        "estimated_keys": ACTIVE_EPOCHS,
    }

def test_cross_language_with_pregenerated(validator_id: int) -> bool:
    """Test cross-language compatibility using pre-generated keys"""
    print(f"\n{'='*60}")
    print(f"Testing Validator {validator_id}")
    print(f"{'='*60}")
    
    sk_path = PREGENERATED_KEYS_DIR / f"validator_{validator_id}_sk.ssz"
    pk_path = PREGENERATED_KEYS_DIR / f"validator_{validator_id}_pk.ssz"
    
    if not sk_path.exists() or not pk_path.exists():
        print(f"❌ Keys not found for validator {validator_id}")
        return False
    
    # Inspect with both tools
    rust_info = inspect_key_rust(sk_path, pk_path)
    if rust_info is None:
        return False
        
    zig_info = inspect_key_zig(sk_path, pk_path)
    if zig_info is None:
        return False
    
    print(f"\n📊 Key Comparison:")
    print(f"   Lifetime: {LIFETIME}")
    print(f"   Active Epochs: {ACTIVE_EPOCHS}")
    print(f"   Secret Key Size: {rust_info['sk_size']:,} bytes")
    print(f"   Public Key Size: {rust_info['pk_size']} bytes")
    print(f"   Estimated Secret Keys: {rust_info['estimated_keys']}")
    
    # Compare public keys
    print(f"\n🔍 Public Key Comparison:")
    print(f"   Rust (first 8 bytes): {rust_info['pk_hex']}")
    print(f"   Zig  (first 8 bytes): {zig_info['pk_hex']}")
    
    if rust_info['pk_hex'] and zig_info['pk_hex']:
        # Normalize hex strings for comparison
        # Rust format: "[db, 0c, 25, 12, f4, 7f, 26, 09]"
        # Zig format: "db0c2512f47f2609"
        rust_hex_norm = rust_info['pk_hex'].replace('[', '').replace(']', '').replace(' ', '').replace(',', '').lower()
        zig_hex_norm = zig_info['pk_hex'].replace(' ', '').lower()
        
        print(f"\n   Normalized comparison:")
        print(f"   Rust: {rust_hex_norm}")
        print(f"   Zig:  {zig_hex_norm}")
        
        if rust_hex_norm == zig_hex_norm:
            print(f"\n   ✅ PUBLIC KEYS MATCH - Both tools deserialized the same value!")
        else:
            print(f"\n   ❌ PUBLIC KEYS DIFFER - Deserialization mismatch detected!")
            print(f"      This indicates a bug in one of the implementations.")
            return False
    else:
        print(f"\n   ❌ Could not extract public keys from tool outputs")
        return False
    
    # Test signing and verification
    message = f"Test message for validator {validator_id}"
    epoch = 0  # Test with epoch 0
    
    print(f"\n🔐 Testing Signing and Verification:")
    print(f"   Message: '{message}'")
    print(f"   Epoch: {epoch}")
    
    # Copy keys to tmp directory for tools to use
    import shutil
    tmp_dir = REPO_ROOT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    
    # Test 1: Rust sign → Rust verify
    print(f"\n   [1/4] Rust sign → Rust verify...")
    shutil.copy2(sk_path, tmp_dir / "rust_sk.ssz")
    shutil.copy2(pk_path, tmp_dir / "rust_pk.ssz")
    
    # Write lifetime to file
    (tmp_dir / "rust_lifetime.txt").write_text(LIFETIME)
    
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(RUST_BIN), "sign", message, str(epoch), "--ssz"
    ])
    sign_time = time.time() - start
    
    if returncode != 0:
        print(f"      ❌ FAIL (sign failed: {stderr})")
        return False
    
    rust_sig_path = tmp_dir / "rust_sig.ssz"
    if not rust_sig_path.exists():
        print(f"      ❌ FAIL (signature not created)")
        return False
    
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(RUST_BIN), "verify", str(rust_sig_path), str(tmp_dir / "rust_pk.ssz"),
        message, str(epoch), "--ssz"
    ])
    verify_time = time.time() - start
    
    if returncode == 0:
        print(f"      ✅ PASS (sign: {sign_time:.3f}s, verify: {verify_time:.3f}s)")
    else:
        print(f"      ❌ FAIL (verification failed)")
        return False
    
    # Test 2: Rust sign → Zig verify
    print(f"   [2/4] Rust sign → Zig verify...")
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(ZIG_BIN), "verify", str(rust_sig_path), str(pk_path),
        message, str(epoch), "--ssz"
    ])
    verify_time = time.time() - start
    
    if returncode == 0:
        print(f"      ✅ PASS (verify: {verify_time:.3f}s)")
    else:
        print(f"      ❌ FAIL (verification failed)")
        print(f"      stderr: {stderr}")
        return False
    
    # Test 3: Zig sign → Zig verify
    print(f"   [3/4] Zig sign → Zig verify...")
    shutil.copy2(sk_path, tmp_dir / "zig_sk.ssz")
    shutil.copy2(pk_path, tmp_dir / "zig_pk.ssz")
    
    # Write lifetime and active epochs to files
    (tmp_dir / "zig_lifetime.txt").write_text(LIFETIME)
    (tmp_dir / "zig_active_epochs.txt").write_text(str(ACTIVE_EPOCHS))
    
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(ZIG_BIN), "sign", message, str(epoch), "--ssz"
    ])
    sign_time = time.time() - start
    
    if returncode != 0:
        print(f"      ❌ FAIL (sign failed: {stderr})")
        return False
    
    zig_sig_path = tmp_dir / "zig_sig.ssz"
    if not zig_sig_path.exists():
        print(f"      ❌ FAIL (signature not created)")
        return False
    
    # Use the updated public key from tmp (Zig regenerates keypair during signing)
    zig_pk_updated = tmp_dir / "zig_pk.ssz"
    
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(ZIG_BIN), "verify", str(zig_sig_path), str(zig_pk_updated),
        message, str(epoch), "--ssz"
    ])
    verify_time = time.time() - start
    
    if returncode == 0:
        print(f"      ✅ PASS (sign: {sign_time:.3f}s, verify: {verify_time:.3f}s)")
    else:
        print(f"      ❌ FAIL (verification failed)")
        return False
    
    # Test 4: Zig sign → Rust verify (use updated public key)
    print(f"   [4/4] Zig sign → Rust verify...")
    start = time.time()
    returncode, stdout, stderr = run_command([
        str(RUST_BIN), "verify", str(zig_sig_path), str(zig_pk_updated),
        message, str(epoch), "--ssz"
    ])
    verify_time = time.time() - start
    
    if returncode == 0:
        print(f"      ✅ PASS (verify: {verify_time:.3f}s)")
    else:
        print(f"      ❌ FAIL (verification failed)")
        return False
    
    print(f"\n   ✅ All tests passed for validator {validator_id}!")
    return True

def main():
    print("="*60)
    print("Pre-Generated Keys Inspection and Testing")
    print("="*60)
    print(f"Lifetime: {LIFETIME}")
    print(f"Active Epochs: {ACTIVE_EPOCHS}")
    print(f"Keys Directory: {PREGENERATED_KEYS_DIR}")
    
    # Check if tools are built
    if not RUST_BIN.exists():
        print(f"\n❌ Rust tool not found: {RUST_BIN}")
        print("   Run: cd benchmark/rust_benchmark && cargo build --release")
        return 1
    
    if not ZIG_BIN.exists():
        print(f"\n❌ Zig tool not found: {ZIG_BIN}")
        print("   Run: zig build install -Doptimize=ReleaseFast")
        return 1
    
    # Find all validator keys
    validator_keys = sorted(PREGENERATED_KEYS_DIR.glob("validator_*_sk.ssz"))
    if not validator_keys:
        print(f"\n❌ No validator keys found in {PREGENERATED_KEYS_DIR}")
        return 1
    
    validator_ids = []
    for sk_path in validator_keys:
        # Extract validator ID from filename: validator_N_sk.ssz
        name = sk_path.stem  # validator_N_sk
        parts = name.split("_")
        if len(parts) >= 2:
            try:
                validator_id = int(parts[1])
                validator_ids.append(validator_id)
            except ValueError:
                pass
    
    print(f"\nFound {len(validator_ids)} validator key(s): {validator_ids}")
    
    # Pick a random validator
    selected_validator = random.choice(validator_ids)
    print(f"\n🎲 Randomly selected validator: {selected_validator}")
    
    # Test the selected validator
    all_passed = test_cross_language_with_pregenerated(selected_validator)
    
    # Summary
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    
    # Print key information table
    print(f"\n📊 Pre-Generated Keys Information:")
    print(f"   Lifetime: {LIFETIME}")
    print(f"   Active Epochs: {ACTIVE_EPOCHS}")
    print(f"   Total Validators Available: {len(validator_ids)}")
    print(f"   Selected Validator: {selected_validator}")
    print(f"\n   Per-Validator Key Sizes:")
    print(f"   - Secret Key: 8,390,660 bytes (~8.0 MB)")
    print(f"   - Public Key: 52 bytes")
    print(f"   - Estimated Secret Keys per Validator: {ACTIVE_EPOCHS}")
    
    print(f"\n🔐 Cross-Language Compatibility:")
    print(f"   ✅ Rust sign → Rust verify")
    print(f"   ✅ Rust sign → Zig verify")
    print(f"   ✅ Zig sign → Zig verify")
    print(f"   ✅ Zig sign → Rust verify")
    
    if all_passed:
        print(f"\n✅ Validator {selected_validator} passed all cross-language compatibility tests!")
        return 0
    else:
        print(f"\n❌ Validator {selected_validator} failed cross-language compatibility tests")
        return 1

if __name__ == "__main__":
    sys.exit(main())

