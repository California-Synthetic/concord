# Concord Protocol

`concord-protocol` contains implementation-independent types and conformance rules for portable
Concord scientific records.

The crate follows three rules:

1. It remains useful without the Concord desktop application or production runtime.
2. It does not depend on product persistence, provider SDKs, or private services.
3. An implementation may enforce or extend a contract but may not silently redefine its serialized
   meaning.

The current implementation defines:

- effect classes, approval cadence, reversibility semantics, and capability permissions;
- provider-neutral model requests, responses, routing decisions, and context receipts;
- agent budgets, runs, statuses, and canonical event transitions; and
- bounded dispatch authorization, reservation, consumption, settlement, interruption, and release;
- deterministic event hashing and independent event-chain replay verification.

Artifact, evidence, general Epact, and cross-language fixture contracts remain to be extracted.
