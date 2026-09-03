# Concord kernel charter

Type: principle

Status: accepted

Updated: 2026-09-03

## Purpose

The Concord kernel is the public, permanent authority center for consequential scientific work.
Models, harnesses, interfaces, databases, capability implementations, and deployment environments
must remain replaceable around its record.

The kernel does not determine scientific truth. It determines whether a proposed transition is
admissible under the exact program, authority, resources, and causal history that govern it, then
preserves the accepted result so another implementation can verify it later.

## Governing invariant

> No consequential change becomes accepted Concord state, and no conclusion becomes accepted
> Concord knowledge, except through an attributable transition valid under the exact authority,
> program, and history that governed it.

Accepted knowledge means a scoped claim with the declared relationship to observations, evidence,
decisions, and review. It does not mean that software has established truth.

The kernel controls authority issued through Concord and the transitions Concord recognizes as
conformant. An external action that bypasses Concord may be recorded as an observation or incident;
its occurrence does not make it authorized history.

## Responsibilities

The kernel owns six semantic responsibilities.

### Identity

Programs, campaigns, principals, capabilities, obligations, dispatches, objects, observations,
evidence, decisions, receipts, and amendments have stable, versioned identities. Identity must
survive renaming, relocation, provider replacement, and storage migration.

### Authority

Every consequential operation is evaluated against a principal, program, scope, capability,
effect, resource ceiling, validity window, and current history. Authentication and possession of a
credential do not imply scientific authority.

### Effects

Dispatch identity and bounded authority are durable before an external start. A permit is consumed
once. An effect with uncertain completion becomes interrupted and requires evidence-bound
reconciliation; it is never silently retried or called successful.

### Obligations

Epact declares what must be done, what may be done, what evidence or review discharges an
obligation, and what makes a program terminal. Open, failed, cancelled, ambiguous, and satisfied
states remain distinct.

### Evidence

The kernel preserves these boundaries:

```text
artifact != observation
observation != evidence
evidence != decision
decision != scientific truth
```

It verifies declared relationships, identity, provenance, and conformance. It cannot manufacture
ground truth from a successful computation or persuasive model response.

### History

Accepted history is append-only, causally ordered, attributable, and replayable. Amendments govern
future work from an explicit causal point. Corrections and retractions change current reliance
without erasing prior existence.

## Transition vocabulary

The semantic vocabulary remains deliberately small:

```text
declare   freeze    authorize   delegate   propose
reserve   dispatch  observe     attest     evaluate
decide    amend     publish     retract
```

Typed Epact programs and events give each operation its exact meaning. There is no general JSON
mutation path around validation.

Every accepted request resolves an actor, active program image, expected generation or causal head,
scope, operation, required receipts, idempotency identity, and canonical time. The result is an
accepted event, a deterministic rejection, a causal conflict, or an explicit unresolved state.

## Trusted boundary

Inside the kernel:

- canonical identity and serialization;
- transition validation and deterministic projection;
- Epact image selection, eligibility, and replay;
- authority and delegation verification;
- reservation, dispatch, effect, and ambiguity state;
- causal history integrity; and
- deterministic explanations for acceptance and rejection.

Outside the kernel:

- model inference and agent deliberation;
- context construction and transient memory;
- scientific computation and domain algorithms;
- provider clients, schedulers, instrument drivers, and arbitrary capability code;
- credentials and secret resolution;
- artifact rendering and interfaces;
- collaboration, analytics, and notifications; and
- scientific judgment about what is true.

External components propose transitions or return receipts and observations. They receive no
private mutation path around the public semantic center.

## Safety properties

- Unknown authority, identity, cost, effect, or state fails closed.
- Authority is no broader than the declared scope and duration.
- Accepted history is monotonic and replayable.
- Idempotency cannot produce duplicate authority.
- External ambiguity remains visible until reconciled.
- Amendments do not reinterpret earlier events.
- Failed, missing, and invalid units remain in the declared denominator.
- Every rejection has a stable, inspectable reason.
- Loss of a projection cannot alter canonical history.

Liveness is subordinate to legitimacy. Inconclusive, impossible, invalid, refused, and unresolved
are acceptable outcomes.

## Public and product boundary

The kernel, protocol, harness, reference storage, CLI, and compatibility tests are public. A
California Synthetic product may provide stricter policy, optimized storage, a workbench, managed
execution, collaboration, credential custody, and commercial integrations. It may not widen a
public grant or privately redefine a public record.

The practical test is independent substitution: another implementation must be able to run the
same bounded program, verify the same history, and derive the same authority and terminal state
without California Synthetic infrastructure.

## Design filter

A rule belongs in the kernel only when:

1. it is necessary to decide whether a transition is legitimate or what an accepted event means;
2. conformant implementations must agree on the answer;
3. the answer is deterministic, versioned, and explainable from canonical history;
4. moving it outward would create a path around identity, authority, effects, obligations, or
   evidence integrity; and
5. it remains meaningful after the current interface, provider, and storage implementation disappear.

If those conditions do not hold, the mechanism belongs in the harness, a capability, or a product.
