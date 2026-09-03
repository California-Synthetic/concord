# Executable protocol surface

Status: alpha implementation

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
scientific claim is true or that an external side effect occurred. Those require the referenced
receipts and evidence.

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
lifecycle over a `DispatchKernel` implementation and rejects invalid ordering or changed permit
bindings before returning them to an agent or capability. `concord-kernel::ReferenceKernel` is the
public durable implementation.

This is the first concrete member of the kernel's small transition vocabulary. It is deliberately
not a generic JSON syscall: `declare`, `freeze`, `observe`, `attest`, `decide`, and `publish`
semantics enter through Epact's typed program and event contracts rather than an unvalidated command
bus.

## Durable reference kernel

`concord-kernel` persists one active Epact image per campaign, accepted runtime events, budgets,
dispatch permits, and kernel events. A dispatch is authorized only when all of these agree:

1. the campaign is open at the requested generation;
2. the request is bound to the exact active image and one obligation;
3. replay reconstructs a valid current Epact state;
4. Epact eligibility covers the principal, operation, capability, effects, placement, and resources;
5. the budget can reserve the maximum cost; and
6. the idempotency key has not named different authority.

Every accepted mutation appends a hash-bound kernel event. `verify_campaign` rechecks the Epact
image, Epact replay, kernel chain, campaign reconciliation digest, permit contracts, budget shape,
and terminal projection after a restart.

## Epact programs, compilation, and replay

`EpactProgram` is the canonical, provider-neutral declaration of principals, objects,
capabilities, scoped authority, finite obligations, gates, evidence rules, resource ceilings,
reversibility, lawful amendment, and terminal conditions. The core is intentionally not
Turing-complete; general computation remains behind qualified capabilities.

The separately versioned `epact-compiler::compile_program` validates references, cycles, capability effects, authority,
resources, amendment safety, and terminal reachability inputs before producing a deterministic
`EpactProgramImage`. Set-like ordering is normalized, object keys use canonical Epact JSON, and both
the source program and compiled image receive stable SHA-256 identities. A structurally valid draft
may compile for review, but activation findings prevent it from becoming executable authority.

`epact-runtime::evaluate_epact_operation` checks a kernel-timestamped request against the exact
image, current obligation projection, effect and resource declaration, capability binding, scoped
principal authority, and authority validity window. It returns stable blockers rather than choosing
a provider or performing the effect.

`EpactRuntimeEvent` records receipt-bound object, evidence, and obligation transitions in an
image-bound hash chain. `replay_epact_events` rejects broken order, unknown or unauthorized actors,
premature discharge, missing output or evidence requirements, and changed receipt contracts, then
rebuilds the same projection after restart. Integrity is not scientific truth: kernels and
reviewers must still inspect the referenced receipts and evidence.

An `EpactAmendment` links an independently immutable successor image to the predecessor's exact
program identity and event head. The predecessor's whole-program amendment authority must cover the
principal. Old events remain bound to the old image; an amendment cannot retroactively rewrite what
made them eligible.

The public command-line reference paths are deliberately small:

```bash
cargo install --git https://github.com/California-Synthetic/epact.git --rev 715b1f29323523e56f497573fb5b60692ec393ee epact-cli
epact compile program.json > image.json
epact verify-image image.json
epact replay image.json events.json

state_dir=$(mktemp -d)
cargo run -p concord-kernel --bin concord -- demo "$state_dir/concord.db"
```

They compile, independently verify, and replay portable JSON without a Concord product database or
provider connection.

## Version rule

The `/1` contract identifiers are wire commitments. Compatible additions must be optional and must
preserve existing validation. A change that alters the meaning of an existing field, hash input, or
transition requires a new contract identifier and parallel conformance fixtures.
