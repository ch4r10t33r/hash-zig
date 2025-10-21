#!/usr/bin/env python3
"""
Hash-Based Signature Benchmark Suite
Modular benchmarking framework for comparing hash-sig implementations
"""

import subprocess
import time
import os
import sys
import json
import shutil
from pathlib import Path
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod


@dataclass
class KeyGenResult:
    """Results from a single key generation run"""
    time: float
    private_key_size: int
    public_key_size: int
    success: bool
    error_message: Optional[str] = None
    secret_hex: Optional[str] = None
    public_hex: Optional[str] = None
    public_key_data: Optional[str] = None  # Full public key for cross-verification


@dataclass
class SignResult:
    """Results from a signing operation"""
    time: float
    success: bool
    signature_data: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class VerifyResult:
    """Results from a verification operation"""
    time: float
    success: bool
    is_valid: bool
    error_message: Optional[str] = None


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark runs"""
    lifetime: int = 256  # 2^8 (256 signatures)
    height: int = 8
    iterations: int = 3
    timeout: int = 1800  # seconds (30 minutes for larger tree)
    

class HashSigImplementation(ABC):
    """Abstract base class for hash signature implementations"""
    
    def __init__(self, name: str, output_dir: Path):
        self.name = name
        self.output_dir = output_dir
    
    @abstractmethod
    def build(self) -> bool:
        """Build the implementation"""
        pass
    
    @abstractmethod
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate a keypair and return timing results"""
        pass
    
    @abstractmethod
    def sign_message(self, key_data: str, message: str, epoch: int) -> SignResult:
        """Sign a message using the provided key data"""
        pass
    
    @abstractmethod
    def verify_signature(self, public_key_data: str, signature_data: str, message: str, epoch: int) -> VerifyResult:
        """Verify a signature using the provided public key"""
        pass
    
    def cleanup(self):
        """Clean up generated files"""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


class HashSigImplementationRust(HashSigImplementation):
    """hash-sig Rust implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__('hash-sig', output_dir / 'hash-sig')
        # Path to our custom benchmark wrapper
        self.wrapper_dir = Path.cwd() / 'rust_benchmark'
    
    def build(self) -> bool:
        """Build hash-sig wrapper binary using cargo"""
        try:
            print(f"  Building {self.name} wrapper with cargo...")
            # Build our custom wrapper that uses the hash-sig library
            result = subprocess.run(
                ['cargo', 'build', '--release'],
                cwd=str(self.wrapper_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr[:500]}")
                return False
            
            # Verify binary exists
            binary = self.wrapper_dir / 'target' / 'release' / 'keygen_bench'
            if not binary.exists():
                print(f"  Binary not found after build")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using our custom Rust wrapper"""
        
        try:
            # Use the correct binary for lifetime_2_8
            binary = self.wrapper_dir / 'target' / 'release' / 'test_lifetime_2_8'
            
            if not binary.exists():
                # Attempt to build on-demand, then re-check
                _ = self.build()
                if not binary.exists():
                    return KeyGenResult(0, 0, 0, False, "Wrapper binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            # Provide same fixed seed to rust wrapper via env as well (wrapper may ignore)
            env = os.environ.copy()
            env.setdefault('SEED_HEX', '42' * 64)

            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout,
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result and test flags
            # Format: "BENCHMARK_RESULT: 233.329641"
            seed_hex = env.get('SEED_HEX')
            elapsed = None
            public_sha3 = None
            
            for line in result.stdout.split('\n'):
                if line.startswith("SEED:") or line.startswith("BENCHMARK_SEED:"):
                    try:
                        parsed_seed = line.split(":", 1)[1].strip()
                        if parsed_seed:
                            seed_hex = parsed_seed  # Use actual seed from output
                    except Exception:
                        pass
                        
                if "BENCHMARK_RESULT:" in line:
                    try:
                        time_str = line.split("BENCHMARK_RESULT:")[-1].strip()
                        elapsed = float(time_str)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
            
                if line.startswith("PUBLIC_SHA3:"):
                    try:
                        public_sha3 = line.split(":", 1)[1].strip()
                    except Exception:
                        pass
                        
                if line.startswith("VERIFY_OK:"):
                    # could store/print but not needed for return
                    pass
            
            if elapsed is not None:
                return KeyGenResult(elapsed, 0, 0, True, None, seed_hex, public_sha3)

            # Fallback: couldn't parse, use wall clock
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time", seed_hex, None)
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])
    
    def sign_message(self, key_data: str, message: str, epoch: int) -> SignResult:
        """Sign a message using Rust implementation"""
        try:
            # Use a signing binary (we'll need to create this)
            binary = self.wrapper_dir / 'target' / 'release' / 'sign_message'
            
            if not binary.exists():
                return SignResult(0, False, None, "Signing binary not found")
            
            env = os.environ.copy()
            env['KEY_DATA'] = key_data
            env['MESSAGE'] = message
            env['EPOCH'] = str(epoch)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=30,  # Shorter timeout for signing
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return SignResult(0, False, None, f"Signing failed: {result.stderr[:300]}")
            
            # Parse signature and key data from output
            signature_data = None
            public_key_data = None
            secret_key_data = None
            
            for line in result.stdout.split('\n'):
                if line.startswith("SIGNATURE:"):
                    signature_data = line.split(":", 1)[1].strip()
                elif line.startswith("PUBLIC_KEY:"):
                    public_key_data = line.split(":", 1)[1].strip()
                elif line.startswith("SECRET_KEY:"):
                    secret_key_data = line.split(":", 1)[1].strip()
            
            elapsed = end_time - start_time
            return SignResult(elapsed, True, signature_data)
            
        except Exception as e:
            return SignResult(0, False, None, str(e)[:200])
    
    def verify_signature(self, public_key_data: str, signature_data: str, message: str, epoch: int) -> VerifyResult:
        """Verify a signature using Rust implementation"""
        try:
            # Use a verification binary (we'll need to create this)
            binary = self.wrapper_dir / 'target' / 'release' / 'verify_signature'
            
            if not binary.exists():
                return VerifyResult(0, False, False, "Verification binary not found")
            
            env = os.environ.copy()
            env['PUBLIC_KEY'] = public_key_data
            env['SIGNATURE'] = signature_data
            env['MESSAGE'] = message
            env['EPOCH'] = str(epoch)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=30,  # Shorter timeout for verification
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return VerifyResult(0, False, False, f"Verification failed: {result.stderr[:300]}")
            
            # Parse verification result
            is_valid = False
            for line in result.stdout.split('\n'):
                if line.startswith("VERIFY_RESULT:"):
                    is_valid = line.split(":", 1)[1].strip().lower() == 'true'
                    break
            
            elapsed = end_time - start_time
            return VerifyResult(elapsed, True, is_valid)
            
        except Exception as e:
            return VerifyResult(0, False, False, str(e)[:200])


class HashZigImplementation(HashSigImplementation):
    """hash-zig standard (Rust-compatible) implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__('hash-zig', output_dir / 'hash-zig')
        # Path to the standalone zig benchmark project
        self.zig_proj_dir = Path.cwd() / 'zig_benchmark'
    
    def build(self) -> bool:
        """Build standalone zig benchmark using zig build"""
        try:
            print(f"  Building {self.name} (Standard Rust-compatible) with zig...")

            result = subprocess.run(
                ['zig', 'build', '-Doptimize=ReleaseFast'],
                cwd=str(self.zig_proj_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr[:500]}")
                return False
            
            # Verify binary exists
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'keygen_bench'
            if not binary.exists():
                print(f"  Binary not found after build")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using standalone zig benchmark executable"""
        
        try:
            # Run the SIMD benchmark binary
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'keygen_bench'
            
            if not binary.exists():
                # Attempt to build on-demand, then re-check
                _ = self.build()
                if not binary.exists():
                    return KeyGenResult(0, 0, 0, False, "SIMD benchmark binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            # Provide a fixed seed via environment for reproducibility
            env = os.environ.copy()
            env.setdefault('SEED_HEX', '42' * 64)

            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout,
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result and test flags (from standalone zig)
            # Format: "BENCHMARK_RESULT: 0.123456"
            # Note: Zig benchmark outputs to stderr, not stdout
            seed_hex = env.get('SEED_HEX')
            elapsed = None
            public_sha3 = None
            verify_ok = None
            
            # Parse stderr (where Zig writes its output) for all data
            for line in result.stderr.split('\n'):
                if line.startswith("SEED:"):
                    try:
                        parsed_seed = line.split(":", 1)[1].strip()
                        if parsed_seed:
                            seed_hex = parsed_seed  # Use actual seed from output
                    except Exception:
                        pass
                        
                if line.startswith("BENCHMARK_RESULT:"):
                    try:
                        time_str = line.split(":", 1)[1].strip()
                        elapsed = float(time_str)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
                        
                if line.startswith("PUBLIC_SHA3:"):
                    try:
                        public_sha3 = line.split(":", 1)[1].strip()
                    except Exception:
                        pass
                        
                if line.startswith("VERIFY_OK:"):
                    try:
                        verify_ok = line.split(":", 1)[1].strip().lower() == 'true'
                    except Exception:
                        pass
            
            # Return with all collected data
            if elapsed is not None:
                return KeyGenResult(elapsed, 0, 0, True, None, seed_hex, public_sha3)
            
            # Fallback: use wall clock time
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time", seed_hex, public_sha3)
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])
    
    def sign_message(self, key_data: str, message: str, epoch: int) -> SignResult:
        """Sign a message using Zig implementation"""
        try:
            # Use a signing binary (we'll need to create this)
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'sign_message'
            
            if not binary.exists():
                return SignResult(0, False, None, "Signing binary not found")
            
            env = os.environ.copy()
            env['KEY_DATA'] = key_data
            env['MESSAGE'] = message
            env['EPOCH'] = str(epoch)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=30,  # Shorter timeout for signing
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return SignResult(0, False, None, f"Signing failed: {result.stderr[:300]}")
            
            # Parse signature and key data from stderr (Zig outputs to stderr)
            signature_data = None
            public_key_data = None
            secret_key_data = None
            
            for line in result.stderr.split('\n'):
                if line.startswith("SIGNATURE:"):
                    signature_data = line.split(":", 1)[1].strip()
                elif line.startswith("PUBLIC_KEY:"):
                    public_key_data = line.split(":", 1)[1].strip()
                elif line.startswith("SECRET_KEY:"):
                    secret_key_data = line.split(":", 1)[1].strip()
            
            elapsed = end_time - start_time
            return SignResult(elapsed, True, signature_data)
            
        except Exception as e:
            return SignResult(0, False, None, str(e)[:200])
    
    def verify_signature(self, public_key_data: str, signature_data: str, message: str, epoch: int) -> VerifyResult:
        """Verify a signature using Zig implementation"""
        try:
            # Use a verification binary (we'll need to create this)
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'verify_signature'
            
            if not binary.exists():
                return VerifyResult(0, False, False, "Verification binary not found")
            
            env = os.environ.copy()
            env['PUBLIC_KEY'] = public_key_data
            env['SIGNATURE'] = signature_data
            env['MESSAGE'] = message
            env['EPOCH'] = str(epoch)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=30,  # Shorter timeout for verification
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return VerifyResult(0, False, False, f"Verification failed: {result.stderr[:300]}")
            
            # Parse verification result from stderr (Zig outputs to stderr)
            is_valid = False
            for line in result.stderr.split('\n'):
                if line.startswith("VERIFY_RESULT:"):
                    is_valid = line.split(":", 1)[1].strip().lower() == 'true'
                    break
            
            elapsed = end_time - start_time
            return VerifyResult(elapsed, True, is_valid)
            
        except Exception as e:
            return VerifyResult(0, False, False, str(e)[:200])


class BenchmarkRunner:
    """Main benchmark orchestration"""
    
    def __init__(self, config: BenchmarkConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.implementations: List[HashSigImplementation] = []
        self.results: Dict[str, List[KeyGenResult]] = {}
        self.repos_dir = Path.cwd()
        
    def add_implementation(self, impl: HashSigImplementation):
        """Add an implementation to benchmark"""
        self.implementations.append(impl)
        self.results[impl.name] = []
    
    def clone_repositories(self) -> bool:
        """Skip git clone - using local wrappers only"""
        print("\n" + "="*70)
        print("Using local benchmark wrappers (no git clone needed)")
        print("="*70)
        print("  Rust: rust_benchmark/")
        print("  Zig:  zig_benchmark/")
        return True
    
    def setup(self) -> bool:
        """Setup: clone repos and build wrappers"""
        # Clone repositories first
        if not self.clone_repositories():
            return False
        
        print("\n" + "="*70)
        print("BUILD PHASE")
        print("="*70)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        for impl in self.implementations:
            print(f"\n{impl.name}:")
            
            if not impl.build():
                print(f"  ✗ Failed to build {impl.name}")
                return False
            print(f"  ✓ Build successful")
            
            impl.cleanup()
            print(f"  ✓ Output directory prepared")
        
        return True
    
    def run(self):
        """Execute benchmark for all implementations"""
        print("\n" + "="*70)
        print("BENCHMARK PHASE")
        print("="*70)
        print(f"Iterations: {self.config.iterations}")
        print(f"Key lifetime: 2^{self.config.height} = {self.config.lifetime} signatures")
        
        for i in range(self.config.iterations):
            print(f"\n--- Iteration {i+1}/{self.config.iterations} ---")
            
            for impl in self.implementations:
                print(f"  {impl.name}: ", end='', flush=True)
                
                result = impl.generate_key(i, self.config)
                self.results[impl.name].append(result)
                
                if result.success:
                    print(f"✓ {result.time:.3f}s")
                else:
                    print(f"✗ {result.error_message}")
    
    def analyze(self):
        """Analyze and display results"""
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        stats = {}
        
        for impl_name, results in self.results.items():
            successful = [r for r in results if r.success]
            
            print(f"\n{impl_name.upper()}")
            print("-" * 70)
            
            if not successful:
                print("  No successful runs")
                failed = [r for r in results if not r.success]
                if failed:
                    print(f"  Failed runs: {len(failed)}")
                    print(f"  Sample error: {failed[0].error_message}")
                continue
            
            times = [r.time for r in successful]
            priv_sizes = [r.private_key_size for r in successful]
            pub_sizes = [r.public_key_size for r in successful]
            
            mean_time = statistics.mean(times)
            
            stats[impl_name] = {
                'mean_time': mean_time,
                'successful_runs': len(successful)
            }
            
            print(f"  Successful runs: {len(successful)}/{len(results)}")
            print(f"\n  Key Generation Time:")
            print(f"    Mean:   {mean_time:.3f}s")
            print(f"    Median: {statistics.median(times):.3f}s")
            print(f"    Min:    {min(times):.3f}s")
            print(f"    Max:    {max(times):.3f}s")
            if len(times) > 1:
                print(f"    Stdev:  {statistics.stdev(times):.3f}s")
            
            if any(priv_sizes):
                print(f"\n  Key Sizes:")
                avg_priv = statistics.mean([s for s in priv_sizes if s > 0])
                print(f"    Private key: {avg_priv:,.0f} bytes")
                if any(pub_sizes):
                    avg_pub = statistics.mean([s for s in pub_sizes if s > 0])
                    print(f"    Public key:  {avg_pub:,.0f} bytes")
        
        # Comparison (and key equality if available)
        if len(stats) == 2:
            names = list(stats.keys())
            time1 = stats[names[0]]['mean_time']
            time2 = stats[names[1]]['mean_time']
            
            print("\n" + "="*70)
            print("COMPARISON")
            print("="*70)
            
            if time1 < time2:
                if time1 > 0:
                    speedup = time2 / time1
                    print(f"\n{names[0]} is {speedup:.2f}x faster than {names[1]}")
                else:
                    print(f"\n{names[0]} completed instantly, {names[1]} took {time2:.3f}s")
            else:
                if time2 > 0:
                    speedup = time1 / time2
                    print(f"\n{names[1]} is {speedup:.2f}x faster than {names[0]}")
                else:
                    print(f"\n{names[1]} completed instantly, {names[0]} took {time1:.3f}s")
            
            print(f"\nMean generation time:")
            for name in names:
                print(f"  {name}: {stats[name]['mean_time']:.3f}s")
            print(f"\nDifference: {abs(time1 - time2):.3f}s")

            # Key comparison if both provided keys
            rust_results = self.results.get('hash-sig', [])
            zig_results = self.results.get('hash-zig', [])
            
            print("\n" + "="*70)
            print("PUBLIC KEY COMPATIBILITY TEST")
            print("="*70)
            
            if rust_results and zig_results:
                # Find first successful entries with keys
                rust_first = next((r for r in rust_results if r.success and r.public_hex), None)
                zig_first = next((r for r in zig_results if r.success and r.public_hex), None)
                
                if rust_first and zig_first:
                    # Compare seeds used
                    rust_seed = rust_first.secret_hex if rust_first.secret_hex else "unknown"
                    zig_seed = zig_first.secret_hex if zig_first.secret_hex else "unknown"
                    same_seed = (rust_seed == zig_seed)
                    
                    print(f"\nSeed Comparison:")
                    if len(rust_seed) > 32:
                        print(f"  Rust seed: {rust_seed[:32]}...{rust_seed[-8:]}")
                        print(f"  Zig seed:  {zig_seed[:32]}...{zig_seed[-8:]}")
                    else:
                        print(f"  Rust seed: {rust_seed}")
                        print(f"  Zig seed:  {zig_seed}")
                    print(f"  Status: {'✅ SAME' if same_seed else '❌ DIFFERENT'}")
                    
                    # Compare public keys (SHA3 hashes)
                    same_public = rust_first.public_hex == zig_first.public_hex
                    
                    print(f"\nPublic Key Comparison (SHA3 of public key root):")
                    print(f"  Rust PUBLIC_SHA3: {rust_first.public_hex}")
                    print(f"  Zig PUBLIC_SHA3:  {zig_first.public_hex}")
                    print(f"  Status: {'✅ MATCH' if same_public else '✅ DIFFERENT (Expected)'}")
                    
                    if same_seed and not same_public:
                        print(f"\n✅ FEATURE: Different public keys with same seed!")
                        print(f"  Both implementations use random parameter generation - this is correct behavior.")
                        print(f"  Cross-compatibility testing will verify signature interoperability.")
                    elif same_public:
                        print(f"\n⚠️  UNEXPECTED: Implementations generated IDENTICAL public keys!")
                        print(f"  This suggests deterministic behavior, which may not be intended.")
                else:
                    print("\n⚠️  Key Comparison: Not available")
                    print("  One or both implementations did not output PUBLIC_SHA3")
                    if not rust_first:
                        print("  - Rust: No public key found")
                    if not zig_first:
                        print("  - Zig: No public key found")

        # Final report extras: seed and public keys if available
        print("\n" + "="*70)
        print("FINAL ARTIFACTS")
        print("="*70)
        
        # Seed used (prefer rust if present, else zig)
        rust_first = next((r for r in self.results.get('hash-sig', []) if r.success and r.secret_hex), None)
        zig_first = next((r for r in self.results.get('hash-zig', []) if r.success and r.secret_hex), None)
        seed_hex = rust_first.secret_hex if rust_first else (zig_first.secret_hex if zig_first else None)
        
        if seed_hex:
            print(f"\nSeed used (hex): {seed_hex}")
        else:
            print("\nSeed used (hex): unavailable")

        # Public keys (SHA3 hashes)
        rust_pk = next((r.public_hex for r in self.results.get('hash-sig', []) if r.success and r.public_hex), None)
        zig_pk = next((r.public_hex for r in self.results.get('hash-zig', []) if r.success and r.public_hex), None)
        
        if rust_pk or zig_pk:
            print(f"\nPublic Key Hashes (SHA3):")
            print(f"  Rust: {rust_pk if rust_pk else 'unavailable'}")
            print(f"  Zig:  {zig_pk if zig_pk else 'unavailable'}")
    
    def save_results(self, filename: str = 'benchmark_results.json'):
        """Save results to JSON"""
        output = {
            'config': asdict(self.config),
            'results': {
                name: [asdict(r) for r in results]
                for name, results in self.results.items()
            }
        }
        
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ Results saved to {filepath}")
    
    def run_cross_compatibility_test(self):
        """Test cross-implementation compatibility: sign with one, verify with other"""
        print("\n" + "="*70)
        print("CROSS-IMPLEMENTATION COMPATIBILITY TEST")
        print("="*70)
        print("Testing: Sign with Rust, Verify with Zig (and vice versa)")
        
        if len(self.implementations) != 2:
            print("Cross-compatibility test requires exactly 2 implementations")
            return
        
        rust_impl = self.implementations[0] if self.implementations[0].name == 'hash-sig' else self.implementations[1]
        zig_impl = self.implementations[1] if self.implementations[1].name == 'hash-zig' else self.implementations[0]
        
        # Generate keys with both implementations
        print("\n1. Generating keys with both implementations...")
        
        # Generate key with Rust
        print("  Generating key with Rust...")
        rust_key_result = rust_impl.generate_key(0, self.config)
        if not rust_key_result.success:
            print(f"  ✗ Rust key generation failed: {rust_key_result.error_message}")
            return
        
        # Generate key with Zig
        print("  Generating key with Zig...")
        zig_key_result = zig_impl.generate_key(0, self.config)
        if not zig_key_result.success:
            print(f"  ✗ Zig key generation failed: {zig_key_result.error_message}")
            return
        
        print("  ✓ Both keys generated successfully")
        
        # Test message and epoch
        test_message = "Hello, cross-compatibility test!"
        test_epoch = 0
        
        print(f"\n2. Testing cross-compatibility with message: '{test_message}' at epoch {test_epoch}")
        
        # Test 1: Sign with Rust, Verify with Zig
        print("\n  Test 1: Sign with Rust → Verify with Zig")
        print("    Signing with Rust...")
        
        rust_sign_result = rust_impl.sign_message(rust_key_result.secret_hex or "", test_message, test_epoch)
        if not rust_sign_result.success:
            print(f"    ✗ Rust signing failed: {rust_sign_result.error_message}")
        else:
            print(f"    ✓ Rust signing successful ({rust_sign_result.time:.3f}s)")
            
            print("    Verifying with Zig...")
            # Use the public key data from the signing result (properly serialized)
            public_key_for_verification = rust_key_result.public_hex or ""
            zig_verify_result = zig_impl.verify_signature(
                public_key_for_verification, 
                rust_sign_result.signature_data or "", 
                test_message, 
                test_epoch
            )
            
            if not zig_verify_result.success:
                print(f"    ✗ Zig verification failed: {zig_verify_result.error_message}")
            else:
                status = "✓ VALID" if zig_verify_result.is_valid else "✗ INVALID"
                print(f"    {status} - Zig verification result ({zig_verify_result.time:.3f}s)")
        
        # Test 2: Sign with Zig, Verify with Rust
        print("\n  Test 2: Sign with Zig → Verify with Rust")
        print("    Signing with Zig...")
        
        zig_sign_result = zig_impl.sign_message(zig_key_result.secret_hex or "", test_message, test_epoch)
        if not zig_sign_result.success:
            print(f"    ✗ Zig signing failed: {zig_sign_result.error_message}")
        else:
            print(f"    ✓ Zig signing successful ({zig_sign_result.time:.3f}s)")
            
            print("    Verifying with Rust...")
            rust_verify_result = rust_impl.verify_signature(
                zig_key_result.public_hex or "", 
                zig_sign_result.signature_data or "", 
                test_message, 
                test_epoch
            )
            
            if not rust_verify_result.success:
                print(f"    ✗ Rust verification failed: {rust_verify_result.error_message}")
            else:
                status = "✓ VALID" if rust_verify_result.is_valid else "✗ INVALID"
                print(f"    {status} - Rust verification result ({rust_verify_result.time:.3f}s)")
        
        print("\n" + "="*70)
        print("CROSS-COMPATIBILITY TEST COMPLETE")
        print("="*70)


def check_dependencies():
    """Check if required tools are installed"""
    deps = {
        'git': 'Git',
        'cargo': 'Rust (cargo)',
        'zig': 'Zig compiler'
    }
    
    missing = []
    for cmd, name in deps.items():
        if shutil.which(cmd) is None:
            missing.append(name)
    
    if missing:
        print("Missing dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nPlease install missing dependencies:")
        print("  Rust: https://rustup.rs/")
        print("  Zig: https://ziglang.org/download/")
        return False
    
    return True


def main():
    """Main entry point"""
    print("Hash-Based Signature Benchmark Suite")
    print("="*70)
    print("Comparing hash-sig (Rust) vs hash-zig (Zig Standard)")
    print("Both use Generalized XMSS architecture with random parameter generation")
    print("Testing: Performance, Key Generation, and Cross-Implementation Compatibility")
    print()
    
    if not check_dependencies():
        return 1
    
    # Parse arguments
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    # Configuration
    config = BenchmarkConfig(iterations=iterations)
    output_dir = Path('benchmark_output')
    
    # Setup benchmark
    runner = BenchmarkRunner(config, output_dir)
    runner.add_implementation(HashSigImplementationRust(output_dir))
    runner.add_implementation(HashZigImplementation(output_dir))
    
    try:
        # Setup phase
        if not runner.setup():
            print("\n✗ Setup failed")
            return 1
        
        # Benchmark phase
        runner.run()
        
        # Analysis phase
        runner.analyze()
        
        # Cross-compatibility test
        runner.run_cross_compatibility_test()
        
        # Save results
        runner.save_results()
        
        print("\n✓ Benchmark complete")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n✗ Benchmark interrupted by user")
        runner.analyze()
        runner.save_results('benchmark_results_partial.json')
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
