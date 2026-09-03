# Executable protocol surface

Status: alpha implementation in progress

The public protocol currently owns five coherent contract families.

## Effects and authority vocabulary

`EffectClass`, `ApprovalMode`, `ReversibilityClass`, `ReversibilityPolicy`, and
`CapabilityPermission` describe what a capability can change and what must be known before an
operator authorizes it. These types contain no credentials and do not grant authority by
themselves.

## Model and context contracts

`ModelProviderSpec` describes a provider by reference. Raw credentials are invalid; only `env:` and
`keychain:` references are portable. `ModelExecutionRequest` contains the scientific messages,
tools, context identities, required capabilities, and hard limits, but no provider identity.
`ModelExecutionResponse` normalizes provider output. `ContextCompilationReceipt` hash-binds the
canonical records selected, omitted, or truncated when compiling model-visible context.

`concord-harness::openai_chat_payload` and
`concord-harness::normalize_openai_chat_response` are transport codecs, not network clients. This
keeps provider envelopes replaceable and the scientific request provider-neutral.

## Agent event contracts and replay

`AgentRunStatus` and `AgentEventKind` define the legal transition graph. `AgentEvent::build`
hash-binds the event identity, run identity, sequence, idempotency key, transition, payload,
ancestry, and creation time. `verify_agent_event_chain` independently checks every digest,
sequence, previous-hash link, run identity, and status continuation.

Replay verification proves record integrity and transition consistency. It does not prove that a
scientific claim is true, that an external side effect occurred, or that the actor was authorized.
Those require evidence and authority contracts that are still being extracted.

## Dispatch authority and allocation

`AuthorizeCampaignDispatchRequest` and `CampaignDispatchPermit` define the first executable kernel
transition family. Authorization atomically binds an actor, campaign generation, target,
idempotency identity, elapsed-time ceiling, and optional spend reservation before an external
provider or worker may start. A permit then advances through:

```text
authorized -> consumed -> settled
                       \-> interrupted -> operator resolution
authorized -> released
```

`consumed` is the decisive external-start boundary. An unconsumed permit may be released. A
consumed permit without trustworthy completion accounting becomes interrupted; dropping a client
handle cannot manufacture a release receipt. `concord-harness::DispatchAllocator` composes this
lifecycle over an embedding runtime's `DispatchKernel` implementation and rejects invalid ordering
or changed permit bindings before returning them to an agent or capability.

This is the first concrete member of the kernel's small transition vocabulary. It is deliberately
not a generic JSON syscall: later `declare`, `freeze`, `observe`, `attest`, `decide`, and `publish`
families must earn their own typed contracts and conformance fixtures.

## Epact programs, compilation, and replay

`EpactProgram` is the canonical, provider-neutral declaration of principals, objects,
capabilities, scoped authority, finite obligations, gates, evidence rules, resource ceilings,
reversibility, lawful amendment, and terminal conditions. The core is intentionally not
Turing-complete; general computation remains behind qualified capabilities.

`epact-compiler::compile_program` validates references, cycles, capability effects, authority,
resources, amendment safety, and terminal reachability inputs before producing a deterministic
`EpactProgramImage`. Set-like ordering is normalized, object keys use canonical Epact JSON, and both
the source program and compiled image receive stable SHA-256 identities. A structurally valid draft
may compile for review, but activation findings prevent it from becoming executable authority.

`concord-harness::evaluate_epact_operation` checks a kernel-timestamped request against the exact
image, current obligation projection, effect and resource declaration, capability binding, scoped
principal authority, and authority validity window. It returns stable blockers rather than choosing
a provider or performing the effect.

`EpactRuntimeEvent` records receipt-bound object, evidence, and obligation transitions in an
image-bound hash chain. `replay_epact_events` rejects broken order, unknown identities, premature
discharge, missing output or evidence requirements, and changed receipt contracts, then rebuilds
the same projection after restart. Integrity is not scientific truth: kernels and reviewers must
still inspect the referenced receipts and evidence.

An `EpactAmendment` links an independently immutable successor image to the predecessor's exact
program identity and event head. The predecessor's whole-program amendment authority must cover the
principal. Old events remain bound to the old image; an amendment cannot retroactively rewrite what
made them eligible.

The public command-line reference paths are deliberately small:

```bash
cargo run -p epact-compiler --bin epactc -- compile program.json > image.json
cargo run -p epact-compiler --bin epactc -- verify-image image.json
cargo run -p concord-harness --bin concord-verify -- replay image.json events.json
```

They compile, independently verify, and replay portable JSON without a Concord product database or
provider connection.

## Version rule

The `/1` contract identifiers are wire commitments. Compatible additions must be optional and must
preserve existing validation. A change that alters the meaning of an existing field, hash input, or
transition requires a new contract identifier and parallel conformance fixtures.
