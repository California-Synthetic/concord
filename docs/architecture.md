# Public architecture

Concord separates portable scientific meaning from product-specific authority and operations.

```text
Concord product or another compatible application
        |
        v
Concord harness
  model loop, context composition, checked runtime composition, capabilities, plugins
        |
        +---- Epact compiler
              validation, normalization, program images, prospective amendments
        |
        v
Concord Protocol
  effects, events, artifacts, evidence, decisions, replay and lawful change
```

Dependencies point downward only. Public packages do not import the private Concord application,
production persistence, provider credentials, or California Synthetic services.

The compiler depends only on the protocol. The harness may consume both; the compiler never imports
the harness or an embedding product. This keeps language meaning independent from whichever model,
agent loop, scheduler, or product happens to execute an eligible obligation.

## Protocol responsibilities

The protocol defines serialized meaning, validation, deterministic identity, transition rules, and
replay behavior. Compatible implementations should be able to exchange and verify records without
sharing a database or model provider.

The protocol is also where fail-closed state transitions live. A product may persist an agent event
in SQLite, Postgres, an object store, or an append-only log; the legality of the transition and the
event digest cannot vary with that storage choice.

## Harness responsibilities

The harness compiles canonical scientific context for a model, presents qualified capabilities,
turns model output into proposals, and records the relationship between context, proposal, action,
observation, evidence, and decision. It does not grant itself authority or treat transient model
memory as canonical state.

The first harness adapter renders and normalizes OpenAI-compatible envelopes. It has no HTTP client
and accepts no credential value. Network dispatch, secret resolution, retry policy, and authority
remain responsibilities of the embedding runtime.

The harness also provides the portable runtime-library boundary between high-level agent or
capability code and typed kernel transitions. `DispatchAllocator` is the first complete path. Like a
user-space allocator over operating-system primitives, it composes authorization, reservation,
single consumption, settlement, interruption, and release without becoming the authority itself.
Its `DispatchKernel` trait is implemented by a product kernel or reference engine; it does not
prescribe HTTP, SQLite, clocks, credentials, or provider placement.

The Epact runtime is another pure boundary. It evaluates typed operation requests against a frozen
program image and reconstructs obligation, object, evidence, and terminal projections from
hash-chained accepted events. The embedding kernel supplies authenticated principals and canonical
time, persists accepted facts, resolves receipt contents, and performs effects.

## Product responsibilities

A product decides which principal may authorize an action, how credentials and budgets are managed,
which implementation satisfies a capability, and how records are stored and presented. Product
policy may narrow a public contract. It may not change its wire meaning or manufacture evidence that
the public record cannot express.

## Public usefulness gate

The extraction is complete only when public code can:

1. run a bounded local scientific workflow;
2. inspect every model-visible context and proposed effect;
3. export the canonical event and artifact record;
4. verify identity, ancestry, and replay independently; and
5. accept third-party providers, capabilities, stores, and viewers through documented contracts.
