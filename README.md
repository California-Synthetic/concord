# Concord Harness

Concord Harness is the open scientific protocol and agent-harness substrate for Concord. It defines
portable contracts for composing model reasoning, scientific tools, evidence, artifacts, execution,
and decisions without allowing a model provider or application database to become the scientific
record.

This repository is at the beginning of its extraction from the private Concord product. The first
published implementation slice is `concord-protocol`, which defines effect classes, approval
cadence, reversibility semantics, and portable capability permissions.

## Repository direction

The public repository will contain:

- Concord's implementation-independent scientific protocol;
- Epact's canonical intermediate representation and transition semantics;
- model, capability, context, artifact, evidence, and execution contracts;
- a Pi-based, model-neutral scientific harness;
- a local reference engine and replay verifier; and
- conformance fixtures for compatible products, plugins, and runtimes.

The closed Concord application is one implementation of these contracts. It may provide stronger
operational guarantees and a more complete experience, but it does not own or privately redefine
the portable meaning of a Concord record.

## Current development

```bash
cargo test --workspace
```

The current code is intentionally small. A public release is useful only when an outside developer
can run, inspect, export, and verify a complete bounded scientific workflow using public code. That
is the governing completion test for this repository.

## License

MIT
