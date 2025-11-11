# Why we need Rust-side constructors or vendoring for Zig → Rust verification

Date: 2025-11-05

## Context
- We have two implementations of Generalized XMSS:
  - Rust (`hash-sig` crate) used by the wrapper under `benchmark/rust_benchmark`.
  - Zig (`hash-zig`) with JSON serializers/deserializers in `src/signature/serialization.zig`.
- Goal: Cross-compat tests in both directions under `benchmark/`:
  - Rust sign → Zig verify
  - Zig sign → Rust verify

## Current state
- Rust types (`GeneralizedXMSSPublicKey`, `GeneralizedXMSSSignature`, `GeneralizedXMSSSecretKey`) derive `Serialize`/`Deserialize`, but their fields are private and there are no public constructors/getters to rebuild these types from external JSON in the wrapper.
- Zig provides JSON serializers/deserializers that use a Zig-specific, human-readable shape (arrays of 0x-prefixed hex field elements for `root`, `parameter`, `path.nodes`, `rho`, `hashes`).
- The Rust wrapper is outside the `hash-sig` crate and cannot access private fields, so it cannot construct these types from Zig JSON without crate support.

## Why this blocks Zig → Rust verification
- Verification in Rust requires actual typed values: `SIG::verify(&pk, epoch, &msg, &sig)`.
- To call this with Zig-produced artifacts, the Rust wrapper must:
  1) Parse Zig JSON into Rust equivalents of the same logical data.
  2) Construct `GeneralizedXMSSPublicKey` and `GeneralizedXMSSSignature` values.
- Because struct fields are private and there are no public smart constructors taking raw components, step (2) is not possible from the wrapper.

## Options to unblock
1) Add public constructors/getters in `hash-sig`:
   - Provide `pub fn new(root: TH::Domain, parameter: TH::Parameter) -> GeneralizedXMSSPublicKey<TH>` and an analogous constructor for `GeneralizedXMSSSignature` taking `(path, rho, hashes)`.
   - Provide typed getters to avoid relying on private fields during serialization if needed.
   - Pros: Minimal maintenance; preserves crate ownership; clean API.
   - Cons: Requires upstream changes (PR/release or temporary branch).

2) Feature-gated serde adapter in `hash-sig`:
   - Introduce a cargo feature (e.g., `interop-json`) that enables custom `serde` implementations matching Zig’s JSON shape (0x-hex strings for field elements, fixed array lengths).
   - Pros: Perfect shape compatibility with Zig; fewer changes in the wrapper.
   - Cons: Slight complexity in the crate; requires upstream acceptance.

3) Vendor (fork) `hash-sig` inside the benchmark wrapper:
   - Fork the crate into `benchmark/rust_benchmark` and expose the minimal constructors/serde impls locally.
   - Pros: Full control, immediate path forward.
   - Cons: Duplication/maintenance burden and divergence risk from upstream.

## Recommendation
- Short term (to unblock): vendor or PR minimal constructors in `hash-sig` for `PublicKey` and `Signature` types.
- Medium term: agree on a stable, documented JSON shape and add an optional feature to `hash-sig` to support it directly via serde, matching Zig’s serializers.

## What we’ll do now (Step 1)
- Emit real serde JSON from the Rust wrapper for keys/signatures.
- Extend the Zig deserializer to accept the Rust JSON shape in addition to the existing Zig shape.
- This enables Rust sign → Zig verify immediately.
- We will then circle back to implement one of the options above to enable Zig sign → Rust verify.

## Risks and mitigations
- Risk: Rust serde JSON shape may change if upstream types change.
  - Mitigation: Pin crate rev and/or add a stable feature/adapter in upstream.
- Risk: Parsing multiple JSON shapes in Zig adds complexity.
  - Mitigation: Keep parsers layered: try Zig shape first, then Rust shape; validate lengths and domains strictly.


