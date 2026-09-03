# Public architecture

Concord separates public scientific authority from product-specific utilization.

```text
California Synthetic product            another compatible client
              |                                  |
              +----------------+-----------------+
                               |
                       Concord core
       campaigns, artifacts, review, supervision, storage
                    /                    \
          Concord harness          Concord kernel
    context, proposals, handles   authority, budgets, receipts
                    \                    /
                    Epact program image
       obligations, eligibility, replay, terminal state
                               |
                qualified capability boundary
          compute, data, instruments, external effects
```

Epact and all four Concord crates are public. Dependencies point toward portable meaning: a client
may use the integrated core or the smaller kernel and harness directly, and no public package
imports the California Synthetic product, its credentials, or company operations.

The California Synthetic workbench is a private utilization layer. It adds interface, managed
execution, credential custody, collaboration, commercial integrations, and private research
programs without becoming the sole implementation of Concord authority.

## Protocol responsibilities

The protocol defines serialized meaning, validation, deterministic identity, transition rules, and
replay behavior. Compatible implementations can exchange and verify records without sharing a
database or model provider.

A compatible implementation may persist a record in SQLite, Postgres, an object store, or an
append-only log. The legality of the transition and its digest cannot vary with that storage choice.

## Harness responsibilities

The harness compiles canonical scientific context for a model, presents qualified capabilities,
turns model output into proposals, and records the relationship between context, proposal, action,
observation, evidence, and decision. It does not grant itself authority or treat transient model
memory as canonical state.

The first harness adapter renders and normalizes one widely implemented chat envelope. It has no
HTTP client and accepts no credential value. Network dispatch, secret resolution, retry policy, and
provider placement remain responsibilities of the embedding environment.

`DispatchAllocator` is the user-space boundary between high-level agent or capability code and
typed kernel transitions. It composes authorization, reservation, single consumption, settlement,
interruption, and release without becoming the authority itself. Its `DispatchKernel` trait is
implemented by the public reference kernel and may be implemented by a compatible store.

## Epact responsibilities

Epact defines programs, principals, objects, capabilities, obligations, gates, evidence rules,
resource ceilings, effects, and lawful amendment. Its compiler produces a deterministic program
image. Its runtime evaluates typed operations and reconstructs the same projection from
hash-chained accepted events.

The kernel supplies authenticated principals and canonical time, persists accepted facts, and binds
receipt identities. Capability implementations perform effects only after consuming bounded
authority.

## Kernel responsibilities

`concord-kernel::ReferenceKernel` is the runnable public authority center. Its SQLite record owns:

- campaign identity and one exact active Epact image;
- accepted Epact events and their independently replayable projection;
- budget accounts, exposure, settlement, and cost-overrun blocking;
- idempotent dispatch authorization and single-consumer permits;
- fail-closed interruption and evidence-bound reconciliation;
- a second hash chain covering every accepted kernel transition; and
- complete snapshots and restart-time verification.

The reference implementation is deliberately local. It contains no provider client, credential
value, network effect executor, interface policy, telemetry service, or hosted control plane.

## Integrated runtime responsibilities

`concord-core::Database` is the complete public workbench runtime. It composes the protocol and
harness contracts with durable campaign, artifact, evidence, research-plan, source-gate, standing
review, capability-qualification, execution-control, and supervision records. It implements the
same checked dispatch boundary as the minimal reference kernel.

The integrated runtime owns portable product behavior, not product presentation. It contains no
desktop interface, credential value, provider HTTP client, commercial adapter, or hosted service.

## Product responsibilities

A product decides how records are presented, where qualified capabilities run, how credentials are
held, and how organizations collaborate. It may add stricter approval, isolation, retention, and
deployment policy. It may not widen an Epact grant, change portable record meaning, or manufacture
evidence that the public kernel cannot verify.

## Public usefulness gate

The release boundary is coherent only while public code can:

1. run a bounded local scientific workflow;
2. inspect every model-visible context and proposed effect;
3. snapshot the canonical authority and event record;
4. verify identity, ancestry, and replay independently; and
5. accept third-party providers, capabilities, and clients through documented contracts.

The checked-in quickstart exercises the durable authority, snapshot, and replay path. The integrated
runtime additionally carries context receipts, artifact lineage, source gates, standing review, and
qualified capability-package records with their executable tests.
