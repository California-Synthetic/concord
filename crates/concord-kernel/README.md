# Concord Kernel

`concord-kernel` is the public, runnable authority center for a local Concord campaign. It persists
campaign identity, one exact Epact program image, accepted Epact events, budgets, dispatch permits,
and a hash-chained kernel event record in SQLite.

The reference kernel is intentionally local and small. It does not hold provider credentials, call
models, execute effects, render an interface, coordinate an organization, or provide hosted
operations. Those concerns connect through the public protocol and harness boundaries.

## Run the complete fixture

```bash
state_dir=$(mktemp -d)
cargo run -p concord-kernel --bin concord -- demo "$state_dir/concord.db"
```

The demo compiles the checked-in Epact program, creates a campaign and budget, reserves and settles
a dispatch, accepts the receipt-bound Epact events, restarts through the durable database, and
verifies both event chains. Its result is a deterministic product fixture, not a scientific
observation.

## Commands

```text
concord demo <state.db>
concord compile <program.json>
concord init <state.db>
concord campaign-create <state.db> <campaign-id> <name> <objective> <image.json>
concord budget-create <state.db> <campaign-id> <budget-id> <total-usd>
concord event-accept <state.db> <campaign-id> <event.json>
concord dispatch-authorize <state.db> <campaign-id> <request.json>
concord dispatch-consume <state.db> <token>
concord dispatch-settle <state.db> <token> <actual-cost-usd> <basis>
concord dispatch-interrupt <state.db> <token> <reason>
concord dispatch-release <state.db> <token>
concord dispatch-resolve <state.db> <campaign-id> <token> <request.json>
concord snapshot <state.db> <campaign-id>
concord verify <state.db> <campaign-id>
```

See [`../../docs/architecture.md`](../../docs/architecture.md) for the product boundary and
[`../../docs/protocol.md`](../../docs/protocol.md) for the authority lifecycle.
