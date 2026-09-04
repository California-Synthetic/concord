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

## Researcher input versions

`concord-core` owns `concord.project-input/1`. `Database::attach_project_input` verifies the stored
bytes against their SHA-256 digest and accepts their artifact identity, project ownership, logical
relative path, author, event, and immutable version in one transaction. The contract records no
machine-specific source path and grants no model disclosure or execution authority. Input names
and record metadata may be selected by context compilation; raw content is stored separately.

A replacement names the current predecessor ID. Concurrent stale replacements fail with a version
conflict; history is never overwritten. The record hash includes the predecessor hash and byte
digest. A repeated idempotency key returns its accepted record only when the request still matches.
Accepted artifact metadata and semantic projections cannot be overwritten through generic upserts.
New versions cannot be attached after campaign closeout. Readers validate record hashes and lineage.

Campaign archives include the input records and corresponding artifact metadata. Artifact bytes
remain in the artifact store: this addition alone is not a self-contained transfer format. Transport
adapters choose file-size, folder traversal, and media-preview limits; they must explain those limits
and preserve per-file failures when an attachment batch is only partially accepted.

### Ordinary research execution bindings

A research task may freeze `execution` with a provider ID, exact model, budget account, optional Epact
agent binding, and exact `{inputId, recordSha256}` input versions. This optional hash-covered field is
omitted for historical fixture plans, preserving their recorded hashes. New ordinary tasks require
it; historical unbound ordinary plans remain readable but must be amended before new authorization
or dispatch. Ordinary tasks cannot select a declared fixture or deterministic transport.

Plan recording and approval validate project ownership and input hashes. Phase dispatch creates the
coordinator, children, frozen briefs and all spend reservations atomically. Paid tasks require an
explicit account; there is no default-account selection in this path. A repeated phase dispatch
returns its receipt without reserving again. Dispatch does not itself invoke a model. The disabled
coordinator records lineage and does not incur inference spend. Actual effects retain the existing
Epact, supervision, dispatch and tool-approval paths. Withdrawal remains possible when a provider is
unavailable and prevents new phase dispatch; it does not cancel previously created children.

`Database::project_input_for_agent` resolves a project input against any inherited plan scope.
Continuation forks retain that scope. A newer version of the same logical file requires a new plan
binding; an approved task does not silently switch to it. This resolution precedes separately
approved byte reads; the product still owns local byte access and verifies content against the
accepted input record. Provider readiness and budget availability are checked again at dispatch;
plan approval cannot guarantee that either remains available later.
