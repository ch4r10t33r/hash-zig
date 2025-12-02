# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-02

### Added
- **SSZ (Simple Serialize) Support**: Full implementation of SSZ serialization/deserialization for all signature scheme types
  - Added `ssz.zig` dependency for Ethereum-compatible SSZ encoding
  - Implemented SSZ methods for `PublicKey`, `SecretKey`, `Signature`, and `MerklePath` types
  - Cross-language compatibility tests now pass for both bincode and SSZ encodings
  - CI pipeline updated to test SSZ encoding by default alongside bincode
  - Benchmark tools support `--ssz` flag for testing SSZ encoding

### Fixed
- Corrected rho serialization for cross-language compatibility
- Fixed 2^18 SSZ cross-language compatibility issues
- Fixed 2^32 SSZ cross-language compatibility and locked Rust toolchain
- Updated CI to use Rust nightly toolchain matching rust-toolchain.toml

### Changed
- README updated with SSZ support documentation
- Cross-language compatibility tools now support both bincode and SSZ encodings
- CI switched to SSZ as default encoding for compatibility tests

### Removed
- Cleaned up unused Rust code from previous implementations

## [1.0.0] - 2024-11-XX

### Added
- Initial release of hash-zig
- Pure Zig implementation of Generalized XMSS signatures
- Wire-compatible with Rust reference implementation (leanSig)
- Support for lifetimes 2^8, 2^18, and 2^32
- Bincode serialization support
- Cross-language compatibility tests (Rust ↔ Zig)
- Performance optimizations:
  - Parallel bottom tree generation
  - SIMD chain computation (4-wide and 8-wide AVX-512)
  - Parallel top tree building
  - Parallel leaf computation
  - Bottom tree caching
- Comprehensive test suite and benchmarks
- GitHub Actions CI/CD pipeline
- Cross-platform support (Linux, macOS, Windows)

[1.1.0]: https://github.com/blockblaz/hash-zig/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/blockblaz/hash-zig/releases/tag/v1.0.0

