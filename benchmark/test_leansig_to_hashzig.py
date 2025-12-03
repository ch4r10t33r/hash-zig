#!/usr/bin/env python3
"""
Test cross-compatibility between leansig (Rust) and hash-zig using
pre-generated keys from hash-sig-cli.

This script:
1. Uses pre-generated SSZ keys from lean-quickstart
2. Has leansig sign a message
3. Has hash-zig verify the signature
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
RUST_PROJECT = REPO_ROOT / "benchmark" / "rust_benchmark"
RUST_BIN = RUST_PROJECT / "target" / "release" / "cross_lang_rust_tool"
ZIG_BIN = REPO_ROOT / "zig-out" / "bin" / "cross-lang-zig-tool"

# Default path to lean-quickstart keys
DEFAULT_KEY_DIR = Path.home() / "Documents" / "zig" / "lean-quickstart" / "local-devnet" / "genesis" / "hash-sig-keys"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test leansig sign → hash-zig verify compatibility using pre-generated keys.",
    )
    parser.add_argument(
        "--key-dir",
        type=Path,
        default=DEFAULT_KEY_DIR,
        help=f"Directory containing validator_*_pk.ssz and validator_*_sk.ssz files (default: {DEFAULT_KEY_DIR})",
    )
    parser.add_argument(
        "--validator-index",
        type=int,
        default=0,
        help="Validator index to test (default: 0)",
    )
    parser.add_argument(
        "--message",
        default="Test message for cross-compatibility",
        help="Message to sign and verify",
    )
    parser.add_argument(
        "--epoch",
        type=int,
        default=5,
        help="Epoch to sign/verify at (default: 5)",
    )
    return parser.parse_args()


def run_command(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result


def ensure_rust_binary() -> None:
    print("Building cross-lang-rust-tool (Rust)...")
    result = run_command(
        ["cargo", "build", "--release", "--bin", "cross_lang_rust_tool"],
        cwd=RUST_PROJECT,
        timeout=600,
    )
    if result.returncode != 0 or not RUST_BIN.exists():
        raise RuntimeError("Failed to build cross-lang-rust-tool")


def ensure_zig_binary() -> None:
    print("Building cross-lang-zig-tool (Zig)...")
    result = run_command(
        ["zig", "build", "install", "-Doptimize=ReleaseFast", "-Ddebug-logs=false"],
        cwd=REPO_ROOT,
        timeout=600,
    )
    if result.returncode != 0 or not ZIG_BIN.exists():
        raise RuntimeError("Failed to build cross-lang-zig-tool")


def test_leansig_to_hashzig(
    key_dir: Path,
    validator_index: int,
    message: str,
    epoch: int,
) -> bool:
    """
    Test leansig sign → hash-zig verify using pre-generated keys.
    
    Returns True if verification succeeds, False otherwise.
    """
    print(f"\n=== Testing leansig → hash-zig with validator {validator_index} ===\n")
    
    # Check if keys exist
    pk_path = key_dir / f"validator_{validator_index}_pk.ssz"
    sk_path = key_dir / f"validator_{validator_index}_sk.ssz"
    
    if not pk_path.exists():
        print(f"❌ Public key not found: {pk_path}")
        return False
    if not sk_path.exists():
        print(f"❌ Secret key not found: {sk_path}")
        return False
    
    print(f"📂 Using keys from: {key_dir}")
    print(f"   Public key:  {pk_path.name} ({pk_path.stat().st_size} bytes)")
    print(f"   Secret key:  {sk_path.name} ({sk_path.stat().st_size} bytes)")
    print(f"   Message:     '{message}'")
    print(f"   Epoch:       {epoch}\n")
    
    # Setup tmp directory for signature output
    tmp_dir = RUST_PROJECT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    sig_path = tmp_dir / f"leansig_sig_validator_{validator_index}_epoch_{epoch}.ssz"
    
    # Copy keys to rust tmp directory (so rust tool can find them)
    import shutil
    rust_pk = tmp_dir / "rust_pk.ssz"
    rust_sk = tmp_dir / "rust_sk.ssz"
    shutil.copy2(pk_path, rust_pk)
    shutil.copy2(sk_path, rust_sk)
    
    # Write lifetime file for rust tool
    (tmp_dir / "rust_lifetime.txt").write_text("2^32")
    
    # 1. Sign with leansig (Rust)
    print("-- Step 1: Leansig (Rust) signing --")
    start = time.perf_counter()
    sign_cmd = [
        str(RUST_BIN),
        "sign",  # The 'sign' command loads from tmp/rust_sk.ssz
        message,
        str(epoch),
        "--ssz",
    ]
    sign_result = run_command(sign_cmd, cwd=RUST_PROJECT)
    sign_duration = time.perf_counter() - start
    
    if sign_result.returncode != 0:
        print(f"❌ Leansig signing FAILED (exit code: {sign_result.returncode})")
        return False
    
    # Copy signature to our output path
    if (tmp_dir / "rust_sig.ssz").exists():
        shutil.copy2(tmp_dir / "rust_sig.ssz", sig_path)
        print(f"✅ Leansig signing SUCCESS ({sign_duration:.3f}s)")
        print(f"   Signature saved to: {sig_path} ({sig_path.stat().st_size} bytes)\n")
    else:
        print(f"❌ Signature file not created: {tmp_dir / 'rust_sig.ssz'}")
        return False
    
    # 2. Verify with hash-zig (Zig)
    print("-- Step 2: Hash-zig (Zig) verification --")
    
    # Write lifetime to file so verify command can read it
    zig_tmp_dir = REPO_ROOT / "tmp"
    zig_tmp_dir.mkdir(exist_ok=True)
    (zig_tmp_dir / "zig_lifetime.txt").write_text("2^32")  # hash-sig-cli uses lifetime 2^32
    
    start = time.perf_counter()
    verify_cmd = [
        str(ZIG_BIN),
        "verify",
        str(sig_path),
        str(pk_path),
        message,
        str(epoch),
        "--ssz",
    ]
    verify_result = run_command(verify_cmd, cwd=REPO_ROOT)
    verify_duration = time.perf_counter() - start
    
    # Check for success
    success = verify_result.returncode == 0 and "✅" in (verify_result.stdout + verify_result.stderr)
    
    if success:
        print(f"✅ Hash-zig verification SUCCESS ({verify_duration:.3f}s)")
        print("\n🎉 Cross-compatibility test PASSED: leansig sign → hash-zig verify ✅")
        return True
    else:
        print(f"❌ Hash-zig verification FAILED (exit code: {verify_result.returncode})")
        print("\n❌ Cross-compatibility test FAILED: leansig sign → hash-zig verify")
        return False


def main() -> int:
    args = parse_args()
    
    try:
        ensure_rust_binary()
        ensure_zig_binary()
    except Exception as exc:
        print(f"❌ Error preparing binaries: {exc}")
        return 1
    
    try:
        success = test_leansig_to_hashzig(
            args.key_dir,
            args.validator_index,
            args.message,
            args.epoch,
        )
        return 0 if success else 1
    except Exception as exc:
        print(f"\n❌ Test failed with exception: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

