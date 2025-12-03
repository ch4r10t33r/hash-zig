#!/usr/bin/env python3
"""
Cross-language XMSS compatibility helper.

Builds required helper binaries, then runs signing/verifying flows for both
lifetime 2^8 and 2^18 configurations with 256 active epochs. Final output
includes a formatted summary of every operation.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional
import os

REPO_ROOT = Path(__file__).resolve().parent.parent
RUST_PROJECT = REPO_ROOT / "benchmark" / "rust_benchmark"
RUST_BIN = RUST_PROJECT / "target" / "release" / "cross_lang_rust_tool"
ZIG_BIN = REPO_ROOT / "zig-out" / "bin" / "cross-lang-zig-tool"

TMP_DIR = Path("/tmp")
DEFAULT_SEED = "4242424242424242424242424242424242424242424242424242424242424242"
DEFAULT_LIFETIMES = ("2^8", "2^18")
SUPPORTED_LIFETIMES = {"2^8", "2^18", "2^32"}

DEBUG_LOG_ENV = os.environ.get("BENCHMARK_DEBUG_LOGS", "").lower()
VERBOSE_LOGS = DEBUG_LOG_ENV in {"1", "true", "yes", "on"}
DEBUG_MARKERS = (
    "HASH_SIG_DEBUG:",
    "RUST_TREE_DEBUG:",
    "RUST_POSEIDON_CHAIN_DEBUG:",
    "RUST_MAP_VERTEX_DEBUG:",
    "RUST_VERIFY_DEBUG:",
    "RUST_SPONGE_DEBUG:",
    "ZIG_SIGN_DEBUG:",
    "ZIG_ENCODING_DEBUG:",
    "ZIG_HYPERCUBE_DEBUG:",
    "ZIG_VERIFY_DEBUG:",
    "ZIG_READ_DEBUG:",
    "ZIG_MAP_VERTEX_DEBUG:",
    "ZIG_POS_IN:",
    "ZIG_POS_OUT:",
    "ZIG_POS_CONTEXT",
    "ZIG_POS_INPUTS:",
    "ZIG_POS_INPUT_CANONICAL",
    "ZIG_POS_OUTPUT_CANONICAL",
    "ZIG_SPONGE_DEBUG:",
    "ZIG_SPONGE_DEBUG",  # Also match without colon for some messages
)


@dataclass
class OperationResult:
    success: bool
    duration: float
    stdout: str = ""
    stderr: str = ""


@dataclass
class ScenarioConfig:
    lifetime: str
    label: str
    message: str
    epoch: int
    start_epoch: int
    num_active_epochs: int
    seed_hex: str

    @property
    def tag(self) -> str:
        return self.lifetime.replace("^", "pow")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run cross-language XMSS compatibility scenarios.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-l",
        "--lifetime",
        dest="lifetimes",
        help="Comma-separated list of lifetimes to benchmark (choices: 2^8, 2^18, 2^32).",
    )
    parser.add_argument(
        "--seed-hex",
        default=DEFAULT_SEED,
        help="Deterministic seed (64 hex chars) used for both Zig and Rust key generation.",
    )
    parser.add_argument(
        "--timeout-2-32",
        type=int,
        default=2400,
        help="Timeout (seconds) for Zig signing when exercising lifetime 2^32.",
    )
    parser.add_argument(
        "--ssz",
        action="store_true",
        help="(Deprecated: SSZ is now always used) Kept for backward compatibility.",
    )
    args = parser.parse_args()

    if args.lifetimes is None:
        lifetimes = list(DEFAULT_LIFETIMES)
    else:
        lifetimes = [part.strip() for part in args.lifetimes.split(",") if part.strip()]
        if not lifetimes:
            parser.error("At least one lifetime must be specified.")

    for lifetime in lifetimes:
        if lifetime not in SUPPORTED_LIFETIMES:
            supported = ", ".join(sorted(SUPPORTED_LIFETIMES))
            parser.error(f"Unsupported lifetime '{lifetime}'. Choose from: {supported}.")

    # Deduplicate while preserving order.
    args.lifetime_values = list(dict.fromkeys(lifetimes))
    return args


def build_scenarios(lifetimes: list[str], seed_hex: str) -> list[ScenarioConfig]:
    scenarios: list[ScenarioConfig] = []
    for lifetime in lifetimes:
        # Use appropriate active epochs for each lifetime
        # Note: Zig/Rust multiply by 128 internally, so actual = input * 128
        # 2^8: max 256 signatures, so max input = 256/128 = 2
        # 2^18: max 262,144 signatures, so we can use 256 (256*128=32,768)
        # 2^32: max 4B+ signatures, so we can use 1024 (1024*128=131,072)
        if lifetime == "2^32":
            num_active_epochs = 1024
        elif lifetime == "2^18":
            num_active_epochs = 256
        else:  # 2^8
            num_active_epochs = 2
        scenarios.append(
            ScenarioConfig(
                lifetime=lifetime,
                label=f"Lifetime {lifetime}",
                message="Cross-language benchmark message",
                epoch=0,
                start_epoch=0,
                num_active_epochs=num_active_epochs,
                seed_hex=seed_hex,
            )
        )
    return scenarios


SUMMARY_ORDER = [
    "rust_sign",
    "rust_self",
    "rust_to_zig",
    "zig_sign",
    "zig_self",
    "zig_to_rust",
]

SUMMARY_LABELS = {
    "rust_sign": "Rust sign (keygen)",
    "rust_self": "Rust sign → Rust verify",
    "rust_to_zig": "Rust sign → Zig verify",
    "zig_sign": "Zig sign (keygen)",
    "zig_self": "Zig sign → Zig verify",
    "zig_to_rust": "Zig sign → Rust verify",
}


def sanitize_output(blob: str) -> str:
    if not blob:
        return ""
    if VERBOSE_LOGS:
        return blob.strip()
    filtered_lines = [
        line for line in blob.splitlines() if not any(marker in line for marker in DEBUG_MARKERS)
    ]
    return "\n".join(filtered_lines).strip()


def run_command(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[dict] = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    stdout = sanitize_output(result.stdout)
    stderr = sanitize_output(result.stderr)
    if stdout:
        print(stdout)
    if stderr:
        print(stderr)
    return result


def zig_sign_timeout(cfg: ScenarioConfig, timeout_2_32: int) -> int:
    return timeout_2_32 if cfg.lifetime == "2^32" else 180


def ensure_rust_binary() -> None:
    print("Building cross-lang-rust-tool (Rust)...")
    # Always force a fresh build of the Rust helper binary.
    # This avoids accidentally reusing a stale binary from a previous run.
    if RUST_BIN.exists():
        print(f"Removing existing Rust binary: {RUST_BIN}")
        RUST_BIN.unlink()
    result = run_command(
        ["cargo", "build", "--release", "--bin", "cross_lang_rust_tool"],
        cwd=RUST_PROJECT,
        timeout=600,
    )
    if result.returncode != 0 or not RUST_BIN.exists():
        raise RuntimeError("Failed to build cross-lang-rust-tool")


def ensure_zig_binary() -> None:
    print("Building cross-lang-zig-tool (Zig)...")
    # Always force a fresh build of the Zig helper binary.
    # This avoids accidentally reusing a stale binary from a previous run.
    if ZIG_BIN.exists():
        print(f"Removing existing Zig binary: {ZIG_BIN}")
        ZIG_BIN.unlink()
    result = run_command(
        ["zig", "build", "install", "-Doptimize=ReleaseFast", "-Ddebug-logs=false"],
        cwd=REPO_ROOT,
        timeout=600,
    )
    if result.returncode != 0 or not ZIG_BIN.exists():
        raise RuntimeError("Failed to build cross-lang-zig-tool")


def scenario_paths(cfg: ScenarioConfig) -> Dict[str, Path]:
    tag = cfg.tag
    return {
        "rust_pk": TMP_DIR / f"rust_public_{tag}.key.ssz",
        "rust_sig": TMP_DIR / f"rust_signature_{tag}.ssz",
        "zig_pk": TMP_DIR / f"zig_public_{tag}.key.ssz",
        "zig_sig": TMP_DIR / f"zig_signature_{tag}.ssz",
    }


def prepare_tmp_files(paths: Dict[str, Path]) -> None:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    for path in paths.values():
        if path.exists():
            path.unlink()


def command_duration(start: float) -> float:
    return time.perf_counter() - start


def run_rust_sign(cfg: ScenarioConfig, paths: Dict[str, Path]) -> OperationResult:
    print(f"\n-- Rust key generation & signing ({cfg.lifetime}) --")
    
    # Setup tmp directory in project root
    tmp_dir = RUST_PROJECT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    
    # Save active epochs to file for the tool to read
    # Note: Rust leansig multiplies by 128 internally, Zig now does the same
    # So we pass the same value to both
    (tmp_dir / "rust_active_epochs.txt").write_text(str(cfg.num_active_epochs))
    
    # Generate keypair first
    start = time.perf_counter()
    keygen_cmd = [str(RUST_BIN), "keygen", cfg.seed_hex, cfg.lifetime, "--ssz"]
    keygen_result = run_command(
        keygen_cmd,
        cwd=RUST_PROJECT,
    )
    if keygen_result.returncode != 0:
        return OperationResult(False, command_duration(start), keygen_result.stdout, keygen_result.stderr)
    
    # Sign message
    sign_cmd = [str(RUST_BIN), "sign", cfg.message, str(cfg.epoch), "--ssz"]
    sign_result = run_command(
        sign_cmd,
        cwd=RUST_PROJECT,
    )
    duration = command_duration(start)
    success = sign_result.returncode == 0
    
    # Copy files to /tmp with expected names
    if success:
        import shutil
        if (tmp_dir / "rust_pk.ssz").exists():
            shutil.copy2(tmp_dir / "rust_pk.ssz", paths["rust_pk"])
        if (tmp_dir / "rust_sig.ssz").exists():
            shutil.copy2(tmp_dir / "rust_sig.ssz", paths["rust_sig"])
        print(f"Rust public key saved to: {paths['rust_pk']}")
        print(f"Rust signature saved to : {paths['rust_sig']}")
    
    return OperationResult(success, duration, sign_result.stdout, sign_result.stderr)


def run_zig_sign(cfg: ScenarioConfig, paths: Dict[str, Path], timeout_2_32: int) -> OperationResult:
    print(f"\n-- Zig key generation & signing ({cfg.lifetime}) --")
    
    # Setup tmp directory in project root
    tmp_dir = REPO_ROOT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    
    # CRITICAL: Clear all serialized files before generation to ensure fresh trees are built
    import shutil
    # Remove entire tmp directory to clear everything including cache directories
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(exist_ok=True)
    print(f"Cleared tmp directory: {tmp_dir}")
    
    # Save active epochs to file for the tool to read
    (tmp_dir / "zig_active_epochs.txt").write_text(str(cfg.num_active_epochs))
    
    # Generate keypair first
    start = time.perf_counter()
    keygen_cmd = [str(ZIG_BIN), "keygen", cfg.seed_hex, cfg.lifetime, "--ssz"]
    keygen_result = run_command(
        keygen_cmd,
        cwd=REPO_ROOT,
        timeout=zig_sign_timeout(cfg, timeout_2_32),
    )
    if keygen_result.returncode != 0:
        return OperationResult(False, command_duration(start), keygen_result.stdout, keygen_result.stderr)
    
    # Sign message (this will update tmp/zig_pk.ssz with the regenerated keypair)
    sign_cmd = [str(ZIG_BIN), "sign", cfg.message, str(cfg.epoch), "--ssz"]
    sign_result = run_command(
        sign_cmd,
        cwd=REPO_ROOT,
        timeout=zig_sign_timeout(cfg, timeout_2_32),
    )
    duration = command_duration(start)
    success = sign_result.returncode == 0
    
    # Copy files to /tmp with expected names
    # IMPORTANT: Copy AFTER signing because signing updates zig_pk.ssz with the regenerated keypair
    if success:
        import shutil
        if (tmp_dir / "zig_pk.ssz").exists():
            shutil.copy2(tmp_dir / "zig_pk.ssz", paths["zig_pk"])
        if (tmp_dir / "zig_sig.ssz").exists():
            shutil.copy2(tmp_dir / "zig_sig.ssz", paths["zig_sig"])
        print(f"Zig public key saved to: {paths['zig_pk']}")
        print(f"Zig signature saved to : {paths['zig_sig']}")
    
    return OperationResult(success, duration, sign_result.stdout, sign_result.stderr)


def verify_success(result: subprocess.CompletedProcess) -> bool:
    blob = (result.stdout or "") + (result.stderr or "")
    # Support both old format (VERIFY_RESULT:true) and new format (✅)
    return result.returncode == 0 and ("VERIFY_RESULT:true" in blob or "✅" in blob)


def run_zig_verify(
    cfg: ScenarioConfig,
    pk_path: Path,
    sig_path: Path,
    label: str,
) -> OperationResult:
    print(f"\n-- {label} ({cfg.lifetime}) --")
    
    # Write lifetime to file so verify command can read it
    tmp_dir = REPO_ROOT / "tmp"
    tmp_dir.mkdir(exist_ok=True)
    (tmp_dir / "zig_lifetime.txt").write_text(cfg.lifetime)
    
    start = time.perf_counter()
    verify_cmd = [
        str(ZIG_BIN),
        "verify",
        str(sig_path),
        str(pk_path),
        cfg.message,
        str(cfg.epoch),
        "--ssz",
    ]
    result = run_command(
        verify_cmd,
        cwd=REPO_ROOT,
    )
    duration = command_duration(start)
    # Check for success message in output
    success = result.returncode == 0 and "✅" in (result.stdout + result.stderr)
    return OperationResult(success, duration, result.stdout, result.stderr)


def run_rust_verify(
    cfg: ScenarioConfig,
    pk_path: Path,
    sig_path: Path,
    label: str,
) -> OperationResult:
    print(f"\n-- {label} ({cfg.lifetime}) --")
    
    start = time.perf_counter()
    verify_cmd = [
        str(RUST_BIN),
        "verify",
        str(sig_path),
        str(pk_path),
        cfg.message,
        str(cfg.epoch),
        "--ssz",
    ]
    result = run_command(
        verify_cmd,
        cwd=RUST_PROJECT,
    )
    duration = command_duration(start)
    # Check for success message in output
    success = result.returncode == 0 and "✅" in (result.stdout + result.stderr)
    return OperationResult(success, duration, result.stdout, result.stderr)


def compare_file_sizes(cfg: ScenarioConfig, paths: Dict[str, Path]) -> bool:
    """Compare file sizes between Rust and Zig generated files"""
    print(f"\n-- Comparing file sizes --")
    
    discrepancies = []
    
    # Compare public keys
    rust_pk_size = paths["rust_pk"].stat().st_size if paths["rust_pk"].exists() else 0
    zig_pk_size = paths["zig_pk"].stat().st_size if paths["zig_pk"].exists() else 0
    
    print(f"Public key sizes:")
    print(f"  Rust: {rust_pk_size} bytes")
    print(f"  Zig:  {zig_pk_size} bytes")
    
    if rust_pk_size != zig_pk_size:
        discrepancies.append(f"Public key size mismatch: Rust={rust_pk_size} vs Zig={zig_pk_size}")
        print(f"  ⚠️  WARNING: Public key sizes differ!")
    else:
        print(f"  ✅ Public key sizes match")
    
    # Compare signatures
    rust_sig_size = paths["rust_sig"].stat().st_size if paths["rust_sig"].exists() else 0
    zig_sig_size = paths["zig_sig"].stat().st_size if paths["zig_sig"].exists() else 0
    
    print(f"Signature sizes:")
    print(f"  Rust: {rust_sig_size} bytes")
    print(f"  Zig:  {zig_sig_size} bytes")
    
    if rust_sig_size != zig_sig_size:
        discrepancies.append(f"Signature size mismatch: Rust={rust_sig_size} vs Zig={zig_sig_size}")
        print(f"  ⚠️  WARNING: Signature sizes differ!")
    else:
        print(f"  ✅ Signature sizes match")
    
    # Compare secret keys (check both project tmp and rust_benchmark tmp)
    rust_sk_path = REPO_ROOT / "benchmark" / "rust_benchmark" / "tmp" / "rust_sk.ssz"
    zig_sk_path = REPO_ROOT / "tmp" / "zig_sk.ssz"
    
    if rust_sk_path.exists() and zig_sk_path.exists():
        rust_sk_size = rust_sk_path.stat().st_size
        zig_sk_size = zig_sk_path.stat().st_size
        
        print(f"Secret key sizes:")
        print(f"  Rust: {rust_sk_size:,} bytes")
        print(f"  Zig:  {zig_sk_size:,} bytes")
        
        if rust_sk_size != zig_sk_size:
            discrepancies.append(f"Secret key size mismatch: Rust={rust_sk_size:,} vs Zig={zig_sk_size:,}")
            print(f"  ⚠️  WARNING: Secret key sizes differ!")
            print(f"           This indicates incompatible SSZ serialization formats!")
            print(f"           Rust includes full trees, Zig may only save metadata.")
        else:
            print(f"  ✅ Secret key sizes match")
    
    if discrepancies:
        print(f"\n⚠️  {len(discrepancies)} size discrepanc{'y' if len(discrepancies) == 1 else 'ies'} detected:")
        for disc in discrepancies:
            print(f"     - {disc}")
        return False
    
    return True

def run_scenario(cfg: ScenarioConfig, timeout_2_32: int) -> tuple[Dict[str, OperationResult], Dict[str, Path]]:
    print(f"\n=== Scenario: {cfg.label} ===")
    paths = scenario_paths(cfg)
    prepare_tmp_files(paths)

    results: Dict[str, OperationResult] = {}
    # Rust generates keypair and signs
    results["rust_sign"] = run_rust_sign(cfg, paths)
    results["rust_self"] = run_rust_verify(cfg, paths["rust_pk"], paths["rust_sig"], "Rust sign → Rust verify")
    
    # Zig verifies using Rust's public key (no key generation needed)
    results["rust_to_zig"] = run_zig_verify(cfg, paths["rust_pk"], paths["rust_sig"], "Rust sign → Zig verify")

    # Zig generates keypair and signs (for reverse direction test)
    results["zig_sign"] = run_zig_sign(cfg, paths, timeout_2_32)
    results["zig_self"] = run_zig_verify(cfg, paths["zig_pk"], paths["zig_sig"], "Zig sign → Zig verify")
    
    # Rust verifies using Zig's public key (same behavior for all lifetimes)
    # This exercises full cross-language compatibility: Zig-generated public key and
    # signature must be accepted by the Rust verifier.
    results["zig_to_rust"] = run_rust_verify(cfg, paths["zig_pk"], paths["zig_sig"], "Zig sign → Rust verify")

    # Compare file sizes to detect serialization format mismatches
    sizes_match = compare_file_sizes(cfg, paths)
    if not sizes_match:
        print("\n⚠️  WARNING: File size mismatches detected. This may indicate serialization format issues.")

    return results, paths


def print_summary(
    scenarios: list[ScenarioConfig],
    all_results: Dict[str, tuple[Dict[str, OperationResult], Dict[str, Path]]],
) -> bool:
    print("\n=== Summary ===")
    overall_success = True
    for cfg in scenarios:
        results, paths = all_results[cfg.lifetime]
        print(f"\n{cfg.label} (lifetime {cfg.lifetime}):")
        for key in SUMMARY_ORDER:
            result = results[key]
            status = "PASS" if result.success else "FAIL"
            overall_success &= result.success
            print(f"  {SUMMARY_LABELS[key]:<30} {status:>4}  ({result.duration:.3f}s)")
        print(f"  Rust public key: {paths['rust_pk']}")
        print(f"  Zig public key : {paths['zig_pk']}")
    return overall_success


def main() -> int:
    args = parse_args()
    scenarios = build_scenarios(args.lifetime_values, args.seed_hex)

    try:
        ensure_rust_binary()
        ensure_zig_binary()
    except Exception as exc:  # pragma: no cover - defensive output path
        print(f"Error preparing binaries: {exc}")
        return 1

    scenario_results: Dict[str, tuple[Dict[str, OperationResult], Dict[str, Path]]] = {}
    overall_success = True
    for cfg in scenarios:
        try:
            results, paths = run_scenario(cfg, args.timeout_2_32)
        except Exception as exc:
            print(f"\n❌ Scenario {cfg.lifetime} failed: {exc}")
            return 1
        scenario_results[cfg.lifetime] = (results, paths)
        overall_success &= all(op.success for op in results.values())

    overall_success &= print_summary(scenarios, scenario_results)

    if overall_success:
        print("\n✅ Cross-language signing and verification complete.")
        return 0

    print("\n❌ One or more verification steps failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
