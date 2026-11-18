# Rust Style Guide

## Architecture

Bommer is one Cargo package with one binary. Keep the dependency graph in
the dependency graph in `docs/IMPLEMENTATION.md` acyclic. A module never depends on its parent or any ancestor,
including through qualified paths, aliases, callbacks, or shared types. Parents
compose children. Children return results instead of calling their coordinator.
Tests belong in independent sibling modules, not nested modules importing a parent.

Shared domain contracts belong in `model`. Leaf modules own their own specialized
types. Do not introduce a trait hierarchy, plugin framework, or generic abstraction
without a concrete second use. Changes to dependency direction must be documented.
Strict JSON decoding belongs in the independent root `json` module, shared by BOM
validation and import. `main` may compose `model` contracts. The collectors parent
may depend on `process` to classify typed error sources into `model::Failure`;
neither error classification nor persistence should parse `Display` strings.

## Interfaces

Use structs, enums, and `impl` blocks to expose small operations with private data.
Constructors enforce invariants; do not expose mutable fields that bypass them.
Use enums for finite states and error categories. Prefer operations to getters when
the operation hides a meaningful implementation detail. Do not obscure orchestration:
the runner should read as collection, validation, publication, and recording.

Keep errors typed across boundaries, preserving useful structured context and source
errors. User-facing formatting is presentation, not an interface to test against.
Never put scanned certificate/key contents or raw untrusted stderr in terminal errors.
Manifest v2's additive `failure` object exposes a stable `kind` and applicable
`exitCode`, `stream`, and `limit` fields. Preserve human-readable `error` text, but
assert structured fields rather than wording.

Use `model::path_text` for filesystem paths represented in JSON. Valid UTF-8 is
unchanged except that literals starting with `bommer:unix-bytes:` or `bommer:utf8:`
are escaped as `bommer:utf8:<literal>`. Invalid UTF-8 paths are represented as
`bommer:unix-bytes:<hex>` for the entire original byte sequence. Do not use lossy
UTF-8 conversion or serialize raw `PathBuf` values at these JSON boundaries.

Use ordinary synchronous functions unless concurrency solves an observed need.
Keep functions together until extraction makes ownership or reuse clearer. Avoid
compatibility layers except for actual configuration, persisted artifacts, and CLI
contracts. Do not add fallback collectors that silently change inventory coverage.

## Resource Safety

One owner controls each lock, temporary artifact, process group, and run session.
Use RAII for cleanup and explicit normal-path child reaping. Run argv directly,
never through shell expansion. Apply deadlines, cancellation, and output bounds.
Never publish an artifact before offline validation and hashing succeed.
External BOM output has a 64 MiB bound and stderr logs a 1 MiB bound. Nix query
stderr has a 16 KiB bound; overflow is a typed failure, not silent truncation.

Certificate paths require descriptor-relative no-follow traversal, including every
ancestor. Do not weaken filesystem safety to make a test pass. Coverage gaps are
diagnostics and partial outcomes, not proof of absence. Imported producer claims
remain explicitly unverified.

## Behavioral Tests

Each test defines its input and expected semantic result, directly or through
test-owned fixtures. Never generate expected values using the production operation
being tested. Never test a constant-return function against its own literal.

Assert typed return/error variants and structured fields. For integration tests,
assert observable behavior: artifact publication, permissions, lock exclusion,
process cleanup, exact imported bytes, and graph semantics. Do not assert user-facing
wording, help text, `Display`, incidental JSON layout, or private implementation shape.

Helpers may handle setup, not hide the scenario or calculate its expected answer.
Use deterministic synchronization instead of arbitrary sleeps. Host inventory,
network scanners, and live Nix tests are explicitly opt-in; normal tests use fixtures.

## Checks

Use `cargo fmt`, strict Clippy, behavioral tests, and the dependency-boundary check.
Do not suppress warnings globally to conceal unfinished implementation. Comments
explain non-obvious constraints, not assignments. Keep documentation honest about
coverage and unsupported behavior.
