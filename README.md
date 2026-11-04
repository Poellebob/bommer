# What A Bommer

Bommer collects software, hardware, and application cryptography inventories
in CycloneDX format through configurable collectors.

**Early development, not production-ready.** Syft is included in the development
environment and flake. Built-in backends inventory explicit local Nix closures,
observe X.509 certificates, and import trusted CBOM artifacts. Hardware collection
requires an external collector; source-code cryptography scanner integration is
a deferred proof of concept, not implemented.

## Quick Start

You need Git, [Nix](https://nixos.org/download/), and
[devenv](https://devenv.sh/getting-started/). Enable Nix flakes.

```sh
git clone https://codeberg.org/Poellebob/bommer.git
cd bommer
devenv shell
just build
```

Run a software inventory of this checkout using the supplied test configuration:

```sh
./dist/bommer doctor --config examples/quickstart.yaml
./dist/bommer scan --config examples/quickstart.yaml
```

Run these commands from the repository root. The configuration respects Git
ignore rules and excludes development caches, build outputs, and previous results.

The scan prints a directory under `results/` containing the SBOM, collector log,
and a version 2 manifest describing the run. CycloneDX 1.6/1.7 JSON is validated
against embedded schemas offline; schema validity does not prove inventory
completeness. Partial results are retained but cause exit code `1`.

With Nix alone, you can also run the same scan without building manually:

```sh
nix run . -- scan --config examples/quickstart.yaml
```

## Run From Codeberg

```sh
nix run 'git+https://codeberg.org/Poellebob/bommer.git?ref=devel/master' -- --help
```

## Development

Inside `devenv shell`, use `just` for recipes:

```sh
just                   # List recipes
just check             # Check formatting, run static analysis and tests
just fmt               # Format Go source
just build             # Build dist/bommer
just schema-test       # Test embedded schemas and offline validation
just integration-test  # Run integration fixtures; live Nix is opt-in
```

Tests do not require Nix by default. For read-only live Nix coverage, explicitly
set `BOMMER_TEST_NIX_ROOT` to an existing local closure root when running
`just integration-test`. No root is selected automatically.

## Further Reading

- [Configuration, collectors, results, and packaging](docs/REFERENCE.md)
- [Configuration template](examples/config.yaml)
- [Native inventory examples](examples/native.yaml) (choose local scopes first)
- [Implementation status and roadmap](docs/IMPLEMENTATION.md)
