# Contributing to Concord

Concord is an open scientific agent harness and protocol. Contributions should make a scientific
workflow more useful, correct, inspectable, portable, performant, or pleasant to maintain.

We welcome small fixes, counterexamples, measurements, conformance cases, documentation repairs, and
larger proposals grounded in a real workflow. A large diff does not carry more authority than a small
one, and polished generated prose is not evidence that a design belongs in the system.

## Before writing code

Read [`AGENTS.md`](AGENTS.md), the [architecture](docs/architecture.md), and the current
[protocol surface](docs/protocol.md). Then locate the owning layer:

- `concord-protocol` owns portable meaning, validation, deterministic identity, transition rules,
  and replay.
- `concord-harness` owns context composition, model-envelope translation, and non-authoritative agent
  mechanics.
- An embedding product owns credentials, network dispatch, persistence, budgets, and human authority.

Obvious corrections can go directly to a pull request. For a new contract, a changed wire meaning,
or a broad abstraction, open a proposal first with one representative workflow or counterexample.
This lets us settle the owning layer before either side invests in a large implementation.

## What makes a change reviewable

Explain the user or maintainer consequence, make the smallest coherent change, and show the evidence
needed for the claim. Depending on the change, evidence may be a regression test, a conformance
fixture, reproduction steps, a profile, or a benchmark command and result.

The pull-request template is intentionally short. Delete prompts that do not help explain your
change. A two-line note is enough for an obvious fix. The description is context for a reviewer, not
a second specification and not a substitute for code or tests.

Performance claims must name the workload, environment, command, and before-and-after result. Avoid
optimizations that make the protocol harder to understand without material evidence. Conversely,
do not add benchmark ceremony to documentation, test-only, or straightforward correctness changes.

## Design expectations

- Begin with an invariant or concrete failure, not a preferred dependency.
- New concepts must enable a workflow that existing concepts cannot express cleanly.
- Provider adapters must be complete and tested; placeholder transports are not useful.
- Effects, authority, evidence, and replay remain explicit and fail closed.
- Public contracts must not depend on the private Concord application.
- Errors should preserve enough context for a stranger to recover.
- Comments explain why a boundary exists; tests demonstrate what must remain true.
- Generated code or prose receives the same scrutiny as handwritten work. The contributor remains
  responsible for understanding and verifying every submitted line.

## Review and attention

Maintainer attention is part of the project's operating budget. We may close changes that lack a
concrete use case, duplicate an owning document, introduce speculative surfaces, or make claims
without proportionate evidence. When we do, we should identify the failed boundary plainly so useful
work can be redirected rather than buried in vague feedback.

Disagreement is welcome. A counterexample, failing fixture, or measurement is often the fastest way
to change an architectural decision. Critique the mechanism and evidence, not the contributor.

## Running checks

```bash
cargo fmt --all -- --check
cargo test --workspace
```

Add the narrowest relevant test first, then run the workspace suite. Do not commit credentials,
provider payloads, private data, runtime state, or generated build output.
