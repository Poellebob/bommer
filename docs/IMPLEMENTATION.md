# Implementation Plan

Bommer uses Rust for orchestration, Nix/devenv for the development environment,
just for recipes, and nFPM for native packages.
Application identities, scopes, and enabled collectors belong in
configuration, not compiled application-specific code.

## Baseline

Initial target: x86_64 Linux. Intended integration matrix: Ubuntu 26.04 LTS,
Debian 13 stable, Rocky Linux 10 latest supported minor, and NixOS 26.05 stable.
These are targets, not a claim that integration tests already pass. Pin exact
images before release; update deliberately. NixOS has no LTS channel.

## Progress

The Rust implementation now backs the default build. The capabilities below
describe the implemented pipeline, not a claim of full parity with the reference
or completed live integration verification. See
the [style guide](STYLE.md).

- Implemented: strict configuration parsing, application targets, collector
  selection, executable/directory preflight, process-group timeouts and
  cancellation, output locking, private artifacts, hashes, run manifests.
- Implemented: named `host.inventories` and `applications[].inventories` lists
  of `{name, kind, collector}`, explicitly enabled with `enabled: true`, alongside
  existing host HBOM/SBOM and application SBOM/CBOM configuration.
- Implemented adapters: Syft SBOM and cdxgen hbom. These still need live-host
  integration testing and version pinning.
- Implemented Syft scope controls: explicit exclusions, opt-in Git ignore
  evaluation, application name/version metadata, and effective exclusions in
  manifests. Integration fixtures verify negation and literal path escaping.
- Implemented escape hatch: explicitly configured external command collectors
  producing CycloneDX JSON on stdout, including application CBOM and Nix-aware
  collectors. No automatic backend downloads or shell expansion.
- Implemented: offline CycloneDX 1.6/1.7 validation using embedded schemas and
  references. Manifest v2 records `json-schema-offline`, scope, inventory,
  findings, coverage, available collector versions, diagnostics, and evidence.
- Implemented: additive manifest v2 `failure` objects with stable `kind` and
  applicable `exitCode`, `stream`, and `limit` fields; human-readable `error`
  remains, but its wording is not a test or consumer interface. Collectors classify
  typed process errors into shared model failures before persistence.
- Implemented: byte-preserving JSON path representation through `model::path_text`.
  Ordinary UTF-8 paths remain unchanged; reserved-prefix literals are escaped as
  `bommer:utf8:<literal>`, and invalid UTF-8 paths use `bommer:unix-bytes:<hex>`.
  See the path contract in `model::path_text` documentation.
- Implemented: 64 MiB external BOM and 1 MiB stderr-log bounds. Nix query stderr
  is limited to 16 KiB; overflow fails rather than using the Go reference's
  truncation behavior. This is an intentional behavioral difference, not parity.
- Implemented native Nix SBOM: explicitly configured existing local `/nix/store`
  closures, host `nix.roots`, and application `nix-closure` targets. Queries are
  offline/local only, with no evaluation, builds, downloads, or whole-store
  discovery. NAR hash/size are properties, not ordinary file hashes. Rust tests
  use fake Nix executables and current/legacy metadata fixtures; live version
  compatibility remains to be verified independently.
- Implemented native certificate CBOM: explicit PEM/DER X.509 paths, no-follow
  traversal for all path components, 4 MiB default/64 MiB maximum file size,
  100,000-entry/depth-128 bounds, deduplication, and partial-result diagnostics.
  Identity export is opt-in; private-key PEM blocks are not decoded or parsed.
  Observations do not evaluate trust or prove application crypto usage.
- Implemented CBOM-only import: trusted existing regular files up to 64 MiB,
  original bytes/source hash preserved, known private material rejected. Coverage
  and application association remain producer/configuration-declared, unverified.
  Import and BOM validation share strict decoding in independent root `json.rs`;
  fixtures exercise deep documents and typed depth-limit rejection.
- Implemented result statuses: `collected`, `partial`, `no-findings`, and
  `failed`. Partial artifacts survive but partial/failure exits `1`. Native
  backends alone can assert no-findings; empty external output still fails.
- Added: Rust behavioral and architecture tests, devenv shell, Rust flake package,
  NixOS module, nFPM package definitions,
  opt-in systemd timer.
- Added: `just schema-test`, `just integration-test`, and `just architecture-test`
  using Cargo filters for internal sibling test modules in the single binary.
  Native fixtures use fake collectors/Nix, require no live Nix, and never select
  a closure root automatically. The reference Go live test is explicitly gated
  by `BOMMER_TEST_NIX_ROOT`; that variable does not enable a Rust live test.
- Deferred proof of concept, NOT implemented: source-code cryptography scanner
  integration. The `command` and `import` boundaries are not source scanners.
- Remaining: external collector version/diagnostic capture and incomplete
  discovery reporting; broader Nix version/OS verification; dependency bundling
  with license review; installed-package lifecycle and broader VM integration tests.

## Verification Scope

`just check` checks rustfmt, strict Clippy, the binary's tests, and black-box CLI
tests using the committed Cargo lockfile. The flake package runs the same tests in
its check phase. `just build` writes `dist/bommer` for the unchanged nFPM recipes.
These checks are not Go's race detector. `just build` explicitly uses the static
musl target for native packages; the Nix package uses its native GNU target.
`just portable-test` runs the same tests against musl. Passing builds does not guarantee integration on the
target distributions; installed binaries still require distro-specific testing.

[`cyclonedx-bom` 0.9](https://crates.io/crates/cyclonedx-bom/0.9.0) was evaluated
and supports 1.6/1.7 cryptographic assets. The implementation keeps official offline
schemas plus a small native writer to preserve exact imported bytes and explicit
empty `dependsOn` versus omission, rather than normalizing every input through
a typed BOM model.

Previous Go live-host, VM, Syft, and package-generation observations do not verify
the Rust replacement. Re-run those checks explicitly before claiming Rust parity.
Live Nix must remain read-only and opt-in with an existing local closure root;
native fixture success is not a live test. Installed-package lifecycle, supported
OS/collector versions, dependency/license review, and broader failure/security
coverage remain release work.

## Next Milestones

1. Verify and pin Syft and hbom on the supported OS matrix. Determine how each
   reports incomplete discovery and preserve that evidence in manifests.
2. Maintain embedded schema provenance and fixture coverage as CycloneDX evolves.
   Schema validation must never be represented as completeness verification.
3. Evaluate the deferred source-code CBOM scanner proof of concept using multiple
   configurable fixture applications before implementing an adapter. Verify
   producer association for imported artifacts separately. Runtime tracing needs
   a separate explicit opt-in design, not a default application scan.
4. Expand explicit Nix closure verification across query versions and supported
   systems, including mixed dpkg/RPM plus Nix hosts. Never substitute an
   indiscriminate `/nix/store` scan or claim package/source coverage from NAR data.
5. Package pinned collectors where practical; test native binaries without Nix
   installed. Add install/upgrade/remove tests and a manual hardware smoke test.
6. Add ARM64 after equivalent collector and packaging verification.

## Release Gates

No empty results claimed as collected inventories; native no-findings is an
explicit observation, not proof of absence. No silent fallback between
collectors; no auto-installation or privilege escalation; no private key material
in output. Collection status, schema validity, and completeness are distinct.
Collector stdout and stderr can contain sensitive information: collector trust,
redaction, output limits, and retention need review before production use.

Keep separate BOM documents initially. Fleet management, a web UI, vulnerability
analysis, remediation, and merged BOMs are outside the first release.
