# Concord protocol agent rules

This directory owns portable meaning. Changes here are wire and semantic commitments that compatible
implementations must be able to validate without the private product.

- Begin a semantic change with the invariant, counterexample, or workflow it serves.
- Preserve deterministic serialization, identity, transition, and replay behavior.
- Compatible additions are optional. Changed field meaning, hash input, or transition semantics
  require a new contract identifier and parallel conformance fixtures.
- Keep storage engines, UI policy, network clients, credentials, and private product assumptions out.
- Add positive and negative conformance tests. A fixture distinguishes structural validity from
  scientific truth and from proof that an external effect occurred.
- Do not introduce a general abstraction until at least one portable workflow requires it and its
  failure behavior can be stated precisely.

Run `cargo test -p concord-protocol` before the workspace suite.
