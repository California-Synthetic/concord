# Executable protocol surface

Status: extraction in progress

The public protocol currently owns four coherent contract families.

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

## Version rule

The `/1` contract identifiers are wire commitments. Compatible additions must be optional and must
preserve existing validation. A change that alters the meaning of an existing field, hash input, or
transition requires a new contract identifier and parallel conformance fixtures.
