# Concord harness agent rules

This directory owns model-neutral context composition, provider-envelope translation, and
non-authoritative agent mechanics. It consumes protocol meaning and must not redefine it.

- Model output is a proposal. The harness does not grant authority or manufacture evidence.
- Keep credentials, network dispatch, persistence policy, spend authority, and private product state
  in the embedding runtime.
- A provider adapter must render and normalize a bounded implemented format with fixtures for success,
  malformed output, and information-preserving failure. Do not add placeholder adapters.
- Preserve provider-specific information needed for audit without leaking it into canonical request
  semantics.
- Keep transient convenience state reconstructable from canonical records.
- Measure parsing, allocation, or latency claims on a named payload or workflow; keep the reproduction
  command with the review note or benchmark.

Run `cargo test -p concord-harness` before the workspace suite.
