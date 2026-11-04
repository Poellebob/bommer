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
- Implemented adapters: Syft SBOM and cdxgen hbom. These still need live-host
  integration testing and version pinning.
- Implemented Syft scope controls: explicit exclusions, opt-in Git ignore
  evaluation, application name/version metadata, and effective exclusions in
  manifests. Integration fixtures verify negation and literal path escaping.
- Implemented escape hatch: explicitly configured external command collectors
  producing CycloneDX JSON on stdout, including application CBOM and Nix-aware
  collectors. No automatic backend downloads or shell expansion.
- Added: Go tests, devenv shell, flake, NixOS module, nFPM package definitions,
  opt-in systemd timer.
- Remaining: full offline CycloneDX schema validation; collector version and
  diagnostic capture; explicit partial/unsupported discovery reporting;
  verified CBOM adapters; Nix closure collector integration; dependency bundling
  with license review; package lifecycle and VM integration tests.

## Next Milestones

1. Verify and pin Syft and hbom on the supported OS matrix. Determine how each
   reports incomplete discovery and preserve that evidence in manifests.
2. Embed CycloneDX 1.6 and 1.7 schemas and their referenced schemas. Structural
   validation must not be represented as full schema or coverage validation.
3. Verify source/artifact CBOM collectors using multiple configurable fixture
   applications. Document backend capabilities. Runtime tracing requires a
   separate explicit opt-in design, not a default application scan.
4. Implement explicit Nix system/application closure inventory. Never substitute
   an indiscriminate /nix/store scan. Support mixed dpkg/RPM plus Nix hosts.
5. Package pinned collectors where practical; test native binaries without Nix
   installed. Add install/upgrade/remove tests and a manual hardware smoke test.
6. Add ARM64 after equivalent collector and packaging verification.

## Release Gates

No empty results claimed as successful inventories; no silent fallback between
collectors; no auto-installation or privilege escalation; no private key material
in output. Collection status, schema validity, and completeness are distinct.
Collector stdout and stderr can contain sensitive information: collector trust,
redaction, output limits, and retention need review before production use.

Keep separate BOM documents initially. Fleet management, a web UI, vulnerability
analysis, remediation, and merged BOMs are outside the first release.
