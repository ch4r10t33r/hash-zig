# Enabling Zig → Rust verification: why local changes are needed and what to ask upstream

Date: 2025-11-05

## Problem summary
Our benchmark aims for bidirectional interoperability:
- Rust sign → Zig verify (works only if Rust emits true structural signature/key data)
- Zig sign → Rust verify (requires Rust to reconstruct internal types from Zig JSON)

Currently, the Rust `hash-sig` crate exposes types (`GeneralizedXMSSPublicKey`, `GeneralizedXMSSSignature`, `GeneralizedXMSSSecretKey`, `HashTreeOpening`) with private fields and no public constructors or accessors. While these types derive `Serialize`/`Deserialize`, serde output is not sufficient to reconstruct the exact structures we need on the Zig side, and serde input does not match Zig’s JSON shape on the Rust side.

In practice:
- Rust wrapper serde output for signatures did not contain the real co-path and hashes in a usable form for Zig (we observed empty `path.nodes` and placeholder-like `hashes`).
- On the Rust side, without public constructors, we cannot build `GeneralizedXMSS*` types from the Zig JSON for verification.

Therefore, purely wrapper-side transformations are not enough; we need minimal, well-scoped public APIs in `hash-sig` to expose and construct values.

## Ideal question to upstream maintainers
> We’re integrating `hash-sig` with a Zig implementation for cross-language verification. Today, core structs like `GeneralizedXMSSSignature` and `GeneralizedXMSSPublicKey` have private fields and no public constructors/accessors. Would you consider exposing minimal, read-only getters (e.g., `get_path`, `get_rho`, `get_hashes`, `get_root`, `get_parameter`) and minimal constructors (e.g., `HashTreeOpening::from_co_path`, `GeneralizedXMSSSignature::new`, `GeneralizedXMSSPublicKey::new`) for interoperability? Our goal is to serialize/deserialize keys and signatures in a stable, documented shape for cross-language verification, without altering internal invariants. If not, could you share the rationale (soundness, invariants, future refactors), and suggest an alternative interop mechanism you’d prefer (e.g., feature-gated serde adapters or crate-provided import/export helpers)?

This question is respectful of encapsulation while making the interop need explicit, and it offers alternatives (feature-gated serde or helper APIs) if direct constructors are undesirable.

## Local changes we plan to make
- Add read-only getters:
  - `GeneralizedXMSSSignature::{get_path, get_rho, get_hashes}`
  - `GeneralizedXMSSPublicKey::{get_root, get_parameter}`
  - `HashTreeOpening::co_path`
- Optionally add constructors for controlled reconstruction:
  - `HashTreeOpening::from_co_path(Vec<TH::Domain>)`
  - `GeneralizedXMSSSignature::new(HashTreeOpening<TH>, IE::Randomness, Vec<TH::Domain>)`
  - `GeneralizedXMSSPublicKey::new(TH::Domain, TH::Parameter)`

These are minimal, do not mutate invariants, and unlock clean interop:
- Rust can emit true Zig-shaped JSON by reading internal arrays exactly.
- Rust can later accept Zig JSON and rebuild types safely.

## Risks and mitigations
- API surface growth: keep methods small and clearly marked as interop helpers.
- Future refactors: document the JSON shape and API expectations, or gate under a feature (e.g., `interop-json`).
- Type constraints: remain generic; do not leak concrete types in the public API.

## Outcome
With these getters/constructors, we can finish Rust sign → Zig verify and later implement Zig sign → Rust verify without forking behavior or relying on brittle serde heuristics.


