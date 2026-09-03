# Concord

Concord is a public kernel and agent runtime for coherent scientific campaigns. It compiles
scientific authority through Epact, turns model output into bounded proposals, authorizes effects,
and preserves a durable record that can be replayed and independently verified.

The repository contains three public layers and consumes Epact at an exact reviewed revision:

- `concord-protocol`: effect and approval policy; canonical model, context, run, and event
  contracts; bounded dispatch authority; deterministic event hashing; transition rules; and replay
  verification.
- [`Epact`](https://github.com/California-Synthetic/epact): separately versioned protocol,
  deterministic compiler, replay and eligibility runtime, conformance vectors, and reference CLI.
- `concord-harness`: provider-envelope adapters that translate canonical requests and responses
  plus checked dispatch allocation, while re-exporting the exact pinned Epact runtime.
- `concord-kernel`: a runnable SQLite-backed reference kernel that owns local campaign identity,
  activated Epact images, accepted facts, budgets, dispatch authority, interruption recovery,
  hash-chained receipts, snapshots, and verification.

## Repository direction

The public project owns:

- Concord's implementation-independent scientific protocol;
- Epact's canonical intermediate representation and transition semantics;
- model, capability, context, artifact, evidence, and execution contracts;
- a Pi-based, model-neutral scientific harness;
- a local durable kernel and replay verifier; and
- conformance fixtures for compatible products, plugins, and runtimes.

California Synthetic's product embeds and extends these public layers with a desktop workbench,
credential custody, managed execution, collaboration, commercial integrations, and private
research programs. Product policy may narrow authority. It does not privately redefine a Concord
record.

## Run the public kernel

```bash
state_dir=$(mktemp -d)
cargo run -p concord-kernel --bin concord -- demo "$state_dir/concord.db"
```

The command runs a complete deterministic fixture through Epact compilation, campaign creation,
budget reservation, dispatch settlement, accepted runtime events, durable restart, and independent
verification. The fixture demonstrates machinery; it is not scientific evidence.

## Current development

```bash
cargo test --workspace
```

The current code is intentionally narrow, but the authority path is complete. An outside developer
can run, inspect, snapshot, and verify a bounded campaign using only this repository and the exact
pinned Epact revision.

See the [`kernel charter`](docs/kernel-charter.md) for the stable semantic commitments,
[`docs/architecture.md`](docs/architecture.md) for the dependency boundary, and
[`docs/protocol.md`](docs/protocol.md) for the contracts that are executable today.

## Contributing

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Concord favors concrete workflows, explicit
invariants, reproducible evidence, and the smallest complete mechanism. Automated contributors must
also follow the scoped `AGENTS.md` rules in the area they change.

## License

MIT
