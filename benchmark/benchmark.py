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

REPO_ROOT = Path(__file__).resolve().parent.parent
RUST_PROJECT = REPO_ROOT / "benchmark" / "rust_benchmark"
RUST_BIN = RUST_PROJECT / "target" / "release" / "remote_hashsig_tool"
ZIG_BIN = REPO_ROOT / "zig-out" / "bin" / "zig-remote-hash-tool"

TMP_DIR = Path("/tmp")
DEFAULT_SEED = "4242424242424242424242424242424242424242424242424242424242424242"
DEFAULT_LIFETIMES = ("2^8", "2^18")
SUPPORTED_LIFETIMES = {"2^8", "2^18", "2^32"}


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
        scenarios.append(
            ScenarioConfig(
                lifetime=lifetime,
                label=f"Lifetime {lifetime}",
                message="Cross-language benchmark message",
                epoch=0,
                start_epoch=0,
                num_active_epochs=256,
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
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())
    return result


def zig_sign_timeout(cfg: ScenarioConfig, timeout_2_32: int) -> int:
    return timeout_2_32 if cfg.lifetime == "2^32" else 180


def ensure_rust_binary() -> None:
    if RUST_BIN.exists():
        return
    print("Building remote_hashsig_tool (Rust)...")
    result = run_command(
        ["cargo", "build", "--release", "--bin", "remote_hashsig_tool"],
        cwd=RUST_PROJECT,
        timeout=600,
    )
    if result.returncode != 0 or not RUST_BIN.exists():
        raise RuntimeError("Failed to build remote_hashsig_tool")


def ensure_zig_binary() -> None:
    if ZIG_BIN.exists():
        return
    print("Building zig-remote-hash-tool (Zig)...")
    result = run_command(["zig", "build", "zig-remote-hash-tool", "-Doptimize=ReleaseFast"], cwd=REPO_ROOT, timeout=600)
    if result.returncode != 0 or not ZIG_BIN.exists():
        raise RuntimeError("Failed to build zig-remote-hash-tool")


def scenario_paths(cfg: ScenarioConfig) -> Dict[str, Path]:
    tag = cfg.tag
    return {
        "rust_pk": TMP_DIR / f"rust_public_{tag}.key.json",
        "rust_sig": TMP_DIR / f"rust_signature_{tag}.bin",
        "zig_pk": TMP_DIR / f"zig_public_{tag}.key.json",
        "zig_sig": TMP_DIR / f"zig_signature_{tag}.bin",
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
    start = time.perf_counter()
    result = run_command(
        [
            str(RUST_BIN),
            "sign",
            cfg.message,
            str(paths["rust_pk"]),
            str(paths["rust_sig"]),
            cfg.seed_hex,
            str(cfg.epoch),
            str(cfg.num_active_epochs),
            str(cfg.start_epoch),
            cfg.lifetime,
        ],
        cwd=RUST_PROJECT,
    )
    duration = command_duration(start)
    success = result.returncode == 0
    if success:
        print(f"Rust public key saved to: {paths['rust_pk']}")
        print(f"Rust signature saved to : {paths['rust_sig']}")
    return OperationResult(success, duration, result.stdout, result.stderr)


def run_zig_sign(cfg: ScenarioConfig, paths: Dict[str, Path], timeout_2_32: int) -> OperationResult:
    print(f"\n-- Zig key generation & signing ({cfg.lifetime}) --")
    start = time.perf_counter()
    result = run_command(
        [
            str(ZIG_BIN),
            "sign",
            cfg.message,
            str(paths["zig_pk"]),
            str(paths["zig_sig"]),
            cfg.seed_hex,
            str(cfg.epoch),
            str(cfg.num_active_epochs),
            str(cfg.start_epoch),
            cfg.lifetime,
        ],
        cwd=REPO_ROOT,
        timeout=zig_sign_timeout(cfg, timeout_2_32),
    )
    duration = command_duration(start)
    success = result.returncode == 0
    if success:
        print(f"Zig public key saved to: {paths['zig_pk']}")
        print(f"Zig signature saved to : {paths['zig_sig']}")
    return OperationResult(success, duration, result.stdout, result.stderr)


def verify_success(result: subprocess.CompletedProcess) -> bool:
    blob = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0 and "VERIFY_RESULT:true" in blob


def run_zig_verify(
    cfg: ScenarioConfig,
    pk_path: Path,
    sig_path: Path,
    label: str,
) -> OperationResult:
    print(f"\n-- {label} ({cfg.lifetime}) --")
    start = time.perf_counter()
    result = run_command(
        [
            str(ZIG_BIN),
            "verify",
            cfg.message,
            str(pk_path),
            str(sig_path),
            str(cfg.epoch),
            cfg.lifetime,
        ],
        cwd=REPO_ROOT,
    )
    duration = command_duration(start)
    success = verify_success(result)
    return OperationResult(success, duration, result.stdout, result.stderr)


def run_rust_verify(
    cfg: ScenarioConfig,
    pk_path: Path,
    sig_path: Path,
    label: str,
) -> OperationResult:
    print(f"\n-- {label} ({cfg.lifetime}) --")
    start = time.perf_counter()
    result = run_command(
        [
            str(RUST_BIN),
            "verify",
            cfg.message,
            str(pk_path),
            str(sig_path),
            str(cfg.epoch),
            cfg.lifetime,
        ],
        cwd=RUST_PROJECT,
    )
    duration = command_duration(start)
    success = verify_success(result)
    return OperationResult(success, duration, result.stdout, result.stderr)


def run_scenario(cfg: ScenarioConfig, timeout_2_32: int) -> tuple[Dict[str, OperationResult], Dict[str, Path]]:
    print(f"\n=== Scenario: {cfg.label} ===")
    paths = scenario_paths(cfg)
    prepare_tmp_files(paths)

    results: Dict[str, OperationResult] = {}
    results["rust_sign"] = run_rust_sign(cfg, paths)
    results["rust_self"] = run_rust_verify(cfg, paths["rust_pk"], paths["rust_sig"], "Rust sign → Rust verify")
    results["rust_to_zig"] = run_zig_verify(cfg, paths["rust_pk"], paths["rust_sig"], "Rust sign → Zig verify")

    results["zig_sign"] = run_zig_sign(cfg, paths, timeout_2_32)
    results["zig_self"] = run_zig_verify(cfg, paths["zig_pk"], paths["zig_sig"], "Zig sign → Zig verify")
    results["zig_to_rust"] = run_rust_verify(cfg, paths["zig_pk"], paths["zig_sig"], "Zig sign → Rust verify")

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
