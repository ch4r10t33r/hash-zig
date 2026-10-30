# Hash-Based Signature Benchmark Suite

A modular benchmarking framework for comparing hash-based signature implementations, specifically designed to evaluate key generation performance between [hash-sig](https://github.com/b-wagn/hash-sig/) (Rust) and [hash-zig](https://github.com/ch4r10t33r/hash-zig) (Zig) with **exact Rust compatibility**.

## Features

- **Rust-Compatible Architecture**: Both implementations use identical Generalized XMSS architecture with PRF-based key derivation, epoch management, and encoding randomness
- **Recommended Parameters**: Both use Winternitz parameters (22 chains of length 256, w=8) from [hash-sig](https://github.com/b-wagn/hash-sig/) recommended configuration
- **Automated Setup**: Automatically builds both implementations with proper dependencies
- **Modular Architecture**: Easy to extend with additional implementations
- **Statistical Analysis**: Comprehensive performance metrics including mean, median, min, max, and standard deviation
- **Key Verification**: SHA3-256 public key hashing for cross-implementation verification
- **JSON Export**: Results saved in machine-readable format for further analysis
- **Robust Error Handling**: Timeout protection and detailed error reporting

## Requirements

- Python 3.7+
- Git
- Rust (cargo) for hash-sig
- Zig compiler (0.14.0+) for hash-zig

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y git python3

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Zig from https://ziglang.org/download/
```

**macOS:**
```bash
brew install git python3 rust zig
```

**Arch Linux:**
```bash
sudo pacman -S git python rust zig
```

**Windows:**
- Install Rust from https://rustup.rs/
- Install Zig from https://ziglang.org/download/
- Install Git from https://git-scm.com/download/win
- Python 3 from https://www.python.org/downloads/

## Quick Start

1. **Clone this repository:**
   ```bash
   git clone <this-repo-url>
   cd hash-sig-benchmark
   ```

2. **Run the benchmark:**
   ```bash
   python3 benchmark.py
   ```

   Or specify the number of iterations:
   ```bash
   python3 benchmark.py 20
   ```

The script will automatically:
- Build both Rust and Zig implementations with proper dependencies
- Run the benchmark suite with Rust-compatible parameters
- Display detailed results including key verification
- Save results to `benchmark_output/benchmark_results.json`

## Usage

### Basic Usage

```bash
# Run with default 10 iterations
python3 benchmark.py

# Run with custom iteration count
python3 benchmark.py 50
```

### Output

The benchmark produces:
- Console output with real-time progress and results
- `benchmark_output/benchmark_results.json` - Detailed results in JSON format
- Generated keys in `benchmark_output/hash-sig/` and `benchmark_output/hash-zig/`

### Configuration

Edit the `BenchmarkConfig` dataclass in `benchmark.py` to adjust:

```python
@dataclass
class BenchmarkConfig:
    lifetime: int = 1024  # 2^10 signatures
    height: int = 10       # Tree height
    iterations: int = 10   # Number of runs
    timeout: int = 300     # Timeout per key generation (seconds)
```

## Architecture

### Class Structure

- **`HashSigImplementation`** (ABC): Base class for implementations
  - `HashSigImplementationRust`: Wrapper for Rust implementation (hash-sig)
  - `HashZigImplementation`: Wrapper for Zig implementation (hash-zig)

- **`BenchmarkRunner`**: Orchestrates the benchmark process
  - Setup phase: Clone and build
  - Benchmark phase: Run key generation
  - Analysis phase: Calculate statistics
  - Export phase: Save results

- **`KeyGenResult`**: Data class for individual run results
- **`BenchmarkConfig`**: Configuration parameters

### Adding New Implementations

To add a new hash-based signature implementation:

```python
class MyNewImplementation(HashSigImplementation):
    def __init__(self, output_dir: Path):
        super().__init__(
            'my-impl',
            'https://github.com/user/my-impl.git',
            output_dir / 'my-impl'
        )
    
    def clone(self) -> bool:
        # Implementation
        pass
    
    def build(self) -> bool:
        # Implementation
        pass
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        # Implementation
        pass
```

Then add it to the runner in `main()`:

```python
runner.add_implementation(MyNewImplementation(output_dir))
```

## Benchmark Parameters

The benchmark is configured for **exact parameter matching**:

| Parameter | Value | Source |
|-----------|-------|--------|
| **Lifetime** | 2^10 = 1,024 signatures | Standard test configuration |
| **Tree Height** | 10 | Derived from lifetime |
| **Winternitz w** | 8 | Recommended by hash-sig |
| **Number of Chains** | 22 | Recommended by hash-sig |
| **Chain Length** | 256 (2^8) | Derived from w=8 |
| **Hash Function** | Poseidon2 | Width=16, KoalaBear field |
| **Encoding** | Binary | Incomparable encoding with randomness |
| **Security Level** | 128-bit | Post-quantum secure |

**Reference**: Parameters match the recommended Winternitz configuration from [hash-sig instantiations](https://github.com/b-wagn/hash-sig/blob/main/src/signature/generalized_xmss/instantiations_poseidon_top_level.rs)

## Results Interpretation

### Key Metrics

- **Mean Time**: Average key generation time across all successful runs
- **Median Time**: Middle value, less affected by outliers
- **Standard Deviation**: Measures consistency of performance
- **Key Sizes**: Size of private and public keys in bytes
- **Speedup Factor**: Relative performance between implementations

### Example Output

```
RESULTS
======================================================================

HASH-SIG
----------------------------------------------------------------------
  Successful runs: 10/10

  Key Generation Time:
    Mean:   1.234s
    Median: 1.230s
    Min:    1.150s
    Max:    1.350s
    Stdev:  0.045s

  Key Sizes:
    Private key: 4,096 bytes
    Public key:  60 bytes

HASH-ZIG
----------------------------------------------------------------------
  Successful runs: 10/10

  Key Generation Time:
    Mean:   0.987s
    Median: 0.985s
    Min:    0.920s
    Max:    1.050s
    Stdev:  0.032s

  Key Sizes:
    Private key: 4,096 bytes
    Public key:  60 bytes

COMPARISON
======================================================================
hash-zig is 1.25x faster than hash-sig

Mean generation time:
  hash-sig: 1.234s
  hash-zig: 0.987s

Difference: 0.247s
```

## Troubleshooting

### Build Failures

If a build fails:

1. **Check dependencies are installed** (Rust via rustup, Zig)
2. **Manually build the implementation:**
   ```bash
   cd hash-sig && cargo build --release
   cd ../hash-zig && zig build -Doptimize=ReleaseFast
   ```
3. **Check for compilation errors** in the output

### Executable Not Found

The benchmark tries to find executables in common locations. If it fails:

1. Check the build output directory
2. Update the `keygen_candidates` or `exe_candidates` lists in the implementation class
3. Ensure the build was successful

### Permission Errors

```bash
chmod +x benchmark.py
```

## Performance Considerations

- First run may be slower due to cold caches
- Run with higher iteration counts (20-50) for more stable results
- Ensure system is not under heavy load during benchmarking
- Consider running multiple times and comparing results

## Contributing

To contribute improvements or add new implementations:

1. Fork the repository
2. Create a feature branch
3. Implement changes following the existing architecture
4. Test thoroughly
5. Submit a pull request

## License

This benchmark suite is provided as-is for research and comparison purposes.
Individual implementations retain their original licenses:
- hash-sig: Check repository for license
- hash-zig: Check repository for license

## References

- [hash-sig repository](https://github.com/b-wagn/hash-sig/)
- [hash-zig repository](https://github.com/ch4r10t33r/hash-zig)
- [LMS RFC 8554](https://datatracker.ietf.org/doc/html/rfc8554)
- [XMSS RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
