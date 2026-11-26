# 💥 What A Bommer

Collect software, hardware, and application cryptography inventories in **CycloneDX** format through configurable collectors.

> [!CAUTION]
> **Early development, not production-ready.** Most, if not all, of this code was written by AI. I will review, rewrite, and audit it by hand, but for now it is a proof of concept.

## Features

| Area | Status |
| --- | --- |
| Software (SBOM) | Syft is bundled in the dev environment and flake |
| Nix closures | Built-in backend for explicit local closures |
| Certificates | Built-in X.509 observation |
| Cryptography (CBOM) | Built-in import of trusted CBOM artifacts |
| Hardware | Requires an external collector |
| Source-code crypto scanning | Deferred proof of concept, not implemented |

## Quick Start

**Prebuilt packages:** binaries, `.deb`, and `.rpm` are on the [releases page](https://codeberg.org/Poellebob/bommer/releases). They bundle no collectors and weakly recommend `syft`. If your distro doesn't package it, install Anchore's `.deb`/`.rpm` from [their releases](https://github.com/anchore/syft/releases) first. See the [packaging notes](docs/REFERENCE.md#packaging).

**From source:** you need Git and [Nix](https://nixos.org/download/) with flakes enabled.

```sh
git clone https://codeberg.org/Poellebob/bommer.git
cd bommer

nix run . -- doctor --config examples/quickstart.yaml
nix run . -- scan   --config examples/quickstart.yaml
```

Run from the repository root. The quickstart config respects Git ignore rules and skips caches, build outputs, and previous results.

## Output

Each scan prints a directory under `results/` containing:

- the **SBOM**
- a **collector log**
- a **v2 manifest** describing the run

Notes:

- CycloneDX 1.6/1.7 JSON is validated offline against embedded schemas. A valid schema does not prove the inventory is complete.
- Partial results are kept, but the exit code is `1`.
- The manifest has human-readable `error` text plus structured `failure` details for automation.
- Paths in JSON use a lossless tagged form when needed (see `path_encoding::path_text`).

## Development

I strongly recommend [devenv](https://devenv.sh/getting-started/), the only environment manager used in this repo. Inside `devenv shell`, run `just` for recipes:

| Recipe | Purpose |
| --- | --- |
| `just check` | Formatting, static analysis, tests |
| `just fmt` | Format Rust source |
| `just build` | Build `dist/bommer` |
| `just portable-test` | Test the static musl target |
| `just schema-test` | Test embedded schemas and offline validation |
| `just integration-test` | Run fixtures with fake collectors and Nix |
| `just architecture-test` | Check module dependency boundaries |

**Builds**

- Cargo builds, Clippy, and tests use `--locked` with the committed `Cargo.lock`.
- `just build` publishes `dist/bommer`, which `just deb` and `just rpm` package through nFPM.
- Native packages use a static x86_64 musl executable with no Nix-store loader dependency; the Nix package uses its native GNU toolchain.
- Installed-package and distro testing are still release work.

**Tests**

- Unit tests live inline in their modules; `tests/architecture.rs` checks cross-module boundaries and `tests/cli.rs` tests the binary as a black box.
- Tests use fixtures and fake Nix executables, and never select a host closure automatically. `just integration-test` does not run live Nix, even if `BOMMER_TEST_NIX_ROOT` is set. A live check must be requested explicitly with an existing local closure root.
- Historical Go parity and the supported OS matrix remain verification work, not claims made by the test suite.

## Docs

- [Configuration, collectors, results, and packaging](docs/REFERENCE.md)
- [Configuration template](examples/config.yaml)
- [Native inventory examples](examples/native.yaml) (choose local scopes first)
- [Implementation status and roadmap](docs/IMPLEMENTATION.md)
- [Rust style guide](docs/STYLE.md)