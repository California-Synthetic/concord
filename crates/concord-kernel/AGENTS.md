# Concord kernel agent rules

This crate is the public, runnable authority center for a local Concord campaign. It owns durable
identity, Epact activation and replay, budget reservations, dispatch authorization, hash-chained
receipts, and verification. It must remain usable without the California Synthetic product.

- Keep every accepted transition durable, attributable, replayable, and fail-closed.
- Treat Epact eligibility as a prerequisite for dispatch, never as an advisory result.
- Keep clocks, tokens, credentials, effect execution, UI policy, and hosted operations behind small
  explicit boundaries.
- A private product may extend storage and operations, but it may not redefine public record meaning.
- Add mutation, idempotency, restart, and illegal-transition tests for changes to authority.

Run `cargo test -p concord-kernel` before the workspace suite.
