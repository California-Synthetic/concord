# Concord

Concord is the open scientific agent harness and protocol developed by California Synthetic. It
defines portable contracts for composing model reasoning, scientific tools, evidence, artifacts,
execution, and decisions without allowing a model provider or application database to become the
scientific record.

The repository contains two independently buildable public layers and consumes Epact at an exact
reviewed revision:

- `concord-protocol`: effect and approval policy; canonical model, context, run, and event
  contracts; bounded dispatch authority; deterministic event hashing; transition rules; and replay
  verification.
- [`Epact`](https://github.com/California-Synthetic/epact): separately versioned protocol,
  deterministic compiler, program image verifier, and reference CLI.
- `concord-harness`: provider-envelope adapters that translate canonical requests and responses
  plus checked dispatch allocation, Epact eligibility, and replay, without owning credentials,
  network execution, storage, clocks, or authority.

## Repository direction

The public project is growing toward:

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

The current code is intentionally narrow. A public release is useful only when an outside developer
can run, inspect, export, and verify a complete bounded scientific workflow using public code. That
is the governing completion test for this repository.

See [`docs/architecture.md`](docs/architecture.md) for the dependency boundary and
[`docs/protocol.md`](docs/protocol.md) for the contracts that are executable today.

## Contributing

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Concord favors concrete workflows, explicit
invariants, reproducible evidence, and the smallest complete mechanism. Automated contributors must
also follow the scoped `AGENTS.md` rules in the area they change.

## License

MIT
