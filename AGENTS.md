# Concord public repository protocol

This repository owns portable protocol meaning, the scientific agent harness, reference execution,
conformance fixtures, and public integration documentation. It must remain independently useful and
must not depend on the private Concord product or California Synthetic operations.

Canonical records are provider-neutral. Exact names may appear only in implemented wire adapters,
configuration that requires them, license notices, or reproducible compatibility tests. Tracked
positioning and requirements must not name comparison products. Keep raw competitive material in
the ignored `.private/` overlay, never in public history.

Effects fail closed. Credentials are referenced rather than stored, transient agent state is not
scientific authority, and every accepted transition must remain inspectable and replayable.

Before editing, read `git status`, preserve existing changes, and run `cargo fmt --all -- --check`
and `cargo test --workspace` for Rust changes. Stage exact paths and keep commits single-purpose.
