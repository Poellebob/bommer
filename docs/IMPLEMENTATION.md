# Implementation Plan

Bommer uses Go for orchestration, Nix/devenv for the development environment,
just for recipes, and nFPM for native packages.
Application identities, scopes, and enabled collectors belong in
configuration, not compiled application-specific code.

## Baseline

Initial target: x86_64 Linux. Intended integration matrix: Ubuntu 26.04 LTS,
Debian 13 stable, Rocky Linux 10 latest supported minor, and NixOS 26.05 stable.
These are targets, not a claim that integration tests already pass. Pin exact
images before release; update deliberately. NixOS has no LTS channel.

## Progress

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
- Implemented native Nix SBOM: explicitly configured existing local `/nix/store`
  closures, host `nix.roots`, and application `nix-closure` targets. Queries are
  offline/local only, with no evaluation, builds, downloads, or whole-store
  discovery. NAR hash/size are properties, not ordinary file hashes. Nix 2.34 is
  live-tested (2.34.8 contract); older JSON shapes have fixture coverage only.
- Implemented native certificate CBOM: explicit PEM/DER X.509 paths, no-follow
  traversal for all path components, 4 MiB default/64 MiB maximum file size,
  100,000-entry/depth-128 bounds, deduplication, and partial-result diagnostics.
  Identity export is opt-in; private-key PEM blocks are not decoded or parsed.
  Observations do not evaluate trust or prove application crypto usage.
- Implemented CBOM-only import: trusted existing regular files up to 64 MiB,
  original bytes/source hash preserved, known private material rejected. Coverage
  and application association remain producer/configuration-declared, unverified.
- Implemented result statuses: `collected`, `partial`, `no-findings`, and
  `failed`. Partial artifacts survive but partial/failure exits `1`. Native
  backends alone can assert no-findings; empty external output still fails.
- Added: Go tests, devenv shell, flake, NixOS module, nFPM package definitions,
  opt-in systemd timer.
- Added: `just schema-test` and `just integration-test`; Syft integration skips
  without Syft, and live Nix requires explicit `BOMMER_TEST_NIX_ROOT`. Portable
  tests do not require Nix or choose a closure root automatically.
- Deferred proof of concept, NOT implemented: source-code cryptography scanner
  integration. The `command` and `import` boundaries are not source scanners.
- Remaining: external collector version/diagnostic capture and incomplete
  discovery reporting; broader Nix version/OS verification; dependency bundling
  with license review; installed-package lifecycle and broader VM integration tests.

## Verified This Iteration

- Full formatting, static analysis, and race-enabled Go test suite.
- Flake build runs every Go package's tests, including embedded-schema fixtures.
- Local NixOS system closure: 9,469 store outputs, collected using Nix 2.34.9
  and validated offline against CycloneDX 1.6.
- Ubuntu 26.04 LTS VM without Nix: standalone certificate collector found 120
  certificates in the system trust bundle. Empty scope reported no-findings;
  missing scope retained a partial inventory and exited 1. CBOM import succeeded.
- Existing Syft quickstart passed full schema validation. Debian and RPM package
  generation succeeded; installed-package lifecycle remains a release gate.

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
