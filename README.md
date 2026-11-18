# What A Bommer

Bommer collects software, hardware, and application cryptography inventories
in CycloneDX format through configurable collectors.

**Early development, not production-ready.** Syft is included in the development
environment and flake. Built-in backends inventory explicit local Nix closures,
observe X.509 certificates, and import trusted CBOM artifacts. Hardware collection
requires an external collector; source-code cryptography scanner integration is
a deferred proof of concept, not implemented.

> [!WARNING]
> Most and if not all of this early code is written by AI.
> I will go over all of it by hand and rewrite/audit it but as of now it is just a proof of concept.

## Quick Start

You need Git, [Nix](https://nixos.org/download/) with flakes enabled.
> deb and rpm is being worked on.

```sh
git clone https://codeberg.org/Poellebob/bommer.git
cd bommer
```

Run a software inventory of this checkout using the supplied test configuration:

```sh
nix run . --  doctor --config examples/quickstart.yaml
nix run . -- scan --config examples/quickstart.yaml
```

Run these commands from the repository root. The configuration respects Git
ignore rules and excludes development caches, build outputs, and previous results.

The scan prints a directory under `results/` containing the SBOM, collector log,
and a version 2 manifest describing the run. CycloneDX 1.6/1.7 JSON is validated
against embedded schemas offline; schema validity does not prove inventory
completeness. Partial results are retained but cause exit code `1`.
Manifest v2 retains human-readable `error` text and adds structured `failure`
details for automation. Filesystem paths in JSON use a lossless tagged form when
needed; see `model::path_text` in source.

## Development

For development i strongly recommend using [devenv](https://devenv.sh/getting-started/),
as it is the only ting used for environment management in this repo.

Inside `devenv shell`, use `just` for recipes:

```sh
just                   # List recipes
just check             # Check formatting, run static analysis and tests
just fmt               # Format Rust source
just build             # Build dist/bommer
just portable-test     # Run tests against the static musl target
just schema-test       # Test embedded schemas and offline validation
just integration-test  # Run fixtures with fake collectors and Nix
just architecture-test # Check module dependency boundaries
```

The default build and flake package use Rust with the committed `Cargo.lock`.
The Go source remains a reference implementation, not the default build. Cargo
builds, Clippy, and tests use `--locked`; `just build` publishes `dist/bommer`,
also used by `just deb` and `just rpm` through nFPM. Native packages use a static
x86_64 musl executable with no Nix-store loader dependency. The Nix package uses
its native GNU toolchain. Installed-package and distro testing remain release work.

Tests do not require Nix or select a host closure automatically. Rust native tests
use fixtures and fake Nix executables; `just integration-test` does not run live
Nix, even when `BOMMER_TEST_NIX_ROOT` is set. Any live check must be explicitly
requested with an existing local closure root; the reference Go live test uses
`BOMMER_TEST_NIX_ROOT`. Live Rust/Go parity and the supported OS matrix remain
verification work, not claims made by the native test suite.

## Further Reading

- [Configuration, collectors, results, and packaging](docs/REFERENCE.md)
- [Configuration template](examples/config.yaml)
- [Native inventory examples](examples/native.yaml) (choose local scopes first)
- [Implementation status and roadmap](docs/IMPLEMENTATION.md)
- [Rust implementation status](docs/IMPLEMENTATION.md)
- [Rust style guide](docs/STYLE.md)
