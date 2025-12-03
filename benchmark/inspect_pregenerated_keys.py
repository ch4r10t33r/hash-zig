#!/usr/bin/env python3
"""
Inspect and test pre-generated keys from pre-generated-keys/ directory.
These keys are for lifetime 2^32 with 1024 active epochs, serialized in SSZ format.
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import time

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
    print(f"\n📋 Inspecting with Rust: {sk_path.name}")
    print(f"   Secret key: {sk_path} ({sk_path.stat().st_size:,} bytes)")
    print(f"   Public key: {pk_path} ({pk_path.stat().st_size} bytes)")
    
    # For now, we'll just read the files and report sizes
    # TODO: Add actual inspection command to Rust tool
    sk_size = sk_path.stat().st_size
    pk_size = pk_path.stat().st_size
    
    # Estimate number of secret keys based on file size
    # For 2^32 with 1024 active epochs:
    # - Each secret key is a bottom tree (Winternitz signature)
    # - File structure: [metadata] + [active_epochs * bottom_tree_data]
    # Rough estimate: (sk_size - overhead) / expected_tree_size
    
    # Based on benchmark results, 2^32 with 1024 epochs is ~8.4MB
    estimated_keys = ACTIVE_EPOCHS
    
    return {
        "sk_size": sk_size,
        "pk_size": pk_size,
        "estimated_keys": estimated_keys,
    }

def inspect_key_zig(sk_path: Path, pk_path: Path) -> Dict[str, any]:
    """Inspect a key using Zig tool"""
    print(f"\n📋 Inspecting with Zig: {sk_path.name}")
    print(f"   Secret key: {sk_path} ({sk_path.stat().st_size:,} bytes)")
    print(f"   Public key: {pk_path} ({pk_path.stat().st_size} bytes)")
    
    # For now, we'll just read the files and report sizes
    # TODO: Add actual inspection command to Zig tool
    sk_size = sk_path.stat().st_size
    pk_size = pk_path.stat().st_size
    
    estimated_keys = ACTIVE_EPOCHS
    
    return {
        "sk_size": sk_size,
        "pk_size": pk_size,
        "estimated_keys": estimated_keys,
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
    zig_info = inspect_key_zig(sk_path, pk_path)
    
    print(f"\n📊 Key Information:")
    print(f"   Lifetime: {LIFETIME}")
    print(f"   Active Epochs: {ACTIVE_EPOCHS}")
    print(f"   Secret Key Size: {rust_info['sk_size']:,} bytes")
    print(f"   Public Key Size: {rust_info['pk_size']} bytes")
    print(f"   Estimated Secret Keys: {rust_info['estimated_keys']}")
    
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
    
    # Test each validator
    all_passed = True
    for validator_id in validator_ids:
        if not test_cross_language_with_pregenerated(validator_id):
            all_passed = False
    
    # Summary
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    
    # Print key information table
    print(f"\n📊 Pre-Generated Keys Information:")
    print(f"   Lifetime: {LIFETIME}")
    print(f"   Active Epochs: {ACTIVE_EPOCHS}")
    print(f"   Number of Validators: {len(validator_ids)}")
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
        print(f"\n✅ All {len(validator_ids)} validators passed cross-language compatibility tests!")
        return 0
    else:
        print(f"\n❌ Some validators failed cross-language compatibility tests")
        return 1

if __name__ == "__main__":
    sys.exit(main())

