# Concord public repository protocol

This repository owns portable protocol meaning, the scientific agent harness, reference execution,
conformance fixtures, and public integration documentation. It must remain independently useful and
must not depend on the private Concord product or California Synthetic operations.

## Engineering culture

Build for the scientist using the workflow and the unknown maintainer extending it later. Start from
first principles, measure what is claimed, and prefer a small complete mechanism over a broad
scaffold. New abstractions must answer a demonstrated workflow or repeated pressure in the code.

Keep names precise, modules locally understandable, errors useful, and tests fast enough to run as a
habit. Performance work names its workload and reports reproducible before-and-after evidence.
Changes that make no performance claim do not need benchmark theater. Review attention is finite;
remove incidental churn and make the important part of a diff easy to verify.

Canonical records are provider-neutral. Exact names may appear only in implemented wire adapters,
configuration that requires them, license notices, or reproducible compatibility tests. Tracked
positioning and requirements must not name comparison products. Keep raw competitive material in
the ignored `.private/` overlay, never in public history.

Effects fail closed. Credentials are referenced rather than stored, transient agent state is not
scientific authority, and every accepted transition must remain inspectable and replayable.

For a non-trivial handoff, summarize what improves, what changed, and the evidence. Add a tradeoff,
failure mode, or deliberate non-goal only when it helps the reviewer. This note is context, not proof,
and it does not need empty headings or ceremonial completeness.

Before editing, read `git status`, preserve existing changes, and run `cargo fmt --all -- --check`
and `cargo test --workspace` for Rust changes. Stage exact paths and keep commits single-purpose.
