# Epact compiler agent rules

This crate turns portable Epact programs into deterministic program images. It may depend on
`concord-protocol`, but never on the harness, a product kernel, storage, providers, credentials, or
private campaign data.

- Structural invalidity is a compiler error. Missing activation authority is a structured finding.
- Normalization may remove irrelevant ordering and duplicate set members; it must never choose
  between conflicting declarations.
- Every accepted program image is content-addressed and independently recompilable.
- Keep source authoring syntax outside this crate until a canonical representation is proven by a
  real workflow.
- Add positive, negative, mutation, and determinism tests for semantic changes.

Run `cargo test -p epact-compiler` before the workspace suite.
