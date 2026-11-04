# What A Bommer

Configurable Linux HBOM, SBOM, and application CBOM collection, written in Go.
**Early implementation, not production-ready.** See
[the implementation plan](docs/IMPLEMENTATION.md) for release gates and gaps.

## Development

```sh
devenv shell
just check
just build
./dist/bommer version
```

Devenv provides the tools; `just` owns the development and packaging recipes.
Run `just` to list recipes, `just fmt` to format Go files, or `just test` to run
tests with the race detector.

The shell provides Go, just, Syft, and nFPM. `hbom` and CBOM/Nix-aware collectors must
currently be provisioned separately. Lock files pin the development environment
and flake inputs; production collector version pinning remains to be implemented.

## Configuration

Start with [examples/config.yaml](examples/config.yaml). Everything is disabled
by default. Enable the desired collectors, specify application directories or
container images, and select a writable output directory.

```sh
./dist/bommer doctor --config examples/config.yaml
./dist/bommer scan --config /etc/bommer/config.yaml
./dist/bommer scan --config /etc/bommer/config.yaml --only hbom
./dist/bommer scan --config /etc/bommer/config.yaml --application payments
```

A configuration with no enabled collectors fails rather than producing an empty
run. `doctor` checks executables and directory targets; READY does not mean that
permissions, application crypto coverage, image access, or hardware discovery
have been verified. Container targets use Syft's registry source (no daemon
socket is mounted or accessed implicitly).

Supported backends:

| Kind | Backend | Behavior |
| --- | --- | --- |
| Host HBOM | `hbom` | Executes `hbom -p` |
| Host/application SBOM | `syft` | Emits CycloneDX JSON from a directory or registry image |
| Any configured inventory | `command` | Runs an administrator-supplied collector |

For `command`, configure an executable followed by separate arguments. `{target}`
is substituted in arguments only: a directory path, `registry:<image>` for a
container, `dir:/` for a host SBOM, or empty for a host HBOM. The collector must
write **only CycloneDX JSON to stdout** and diagnostics to stderr. There is no
shell expansion. A wrapper can adapt collectors that require output files.
Configuration is trusted executable policy; do not accept it from untrusted users.
Bommer does not sandbox arbitrary collectors or prevent them accessing keys or
networks. Do not configure collectors that export secret material.

NixOS host software inventory refuses the Syft backend: use an explicitly
configured Nix-aware command collector. Nix on Debian/RPM hosts also requires
separate explicit scopes; conventional package discovery is not a Nix closure.
There is not yet a built-in verified Nix or CBOM collector.

## Results

Each scan creates a private unique run directory with separate `.cdx.json`
documents, stderr logs, and a `manifest.json` containing timestamps, backends,
target scopes, artifact SHA-256 hashes, and per-job status. A failed job does not
discard other jobs' valid results. Only one scan per output directory may run.

Currently output is checked for JSON structure, CycloneDX 1.6/1.7 identifiers,
positive document version, and nonempty components. **This is not full schema
validation or proof of inventory completeness.** Status `collected` means only
that the collector exited successfully and passed this structural gate. Full
schema validation and collector-specific partial-result reporting are pending.
Invalid/failed stdout is removed; private stderr logs remain for troubleshooting.

Exit codes: `0` collected/ready, `1` execution/preflight failure, `2` usage or
configuration error. Each collector has a positive timeout (default `10m`).
Signals and timeouts kill its process group. Scans do not install dependencies,
escalate privileges, or automatically execute application workloads. Custom
collectors are trusted and can execute whatever is explicitly configured.

## Packaging

```sh
nix build path:.#default
devenv shell
just deb
just rpm
```

Native package recipes default to version `0.1.0-dev`; override it with, for
example, `VERSION=0.1.0 just deb`. They build the CLI before packaging it.

The flake wraps Bommer with Syft. Native packages currently contain the CLI,
disabled example configuration, and systemd units, **not collector binaries**;
provision those explicitly. Native binaries use `CGO_ENABLED=0`, not a copied
Nix-linked executable. Packages do not enable or start scanning on installation.
The service uses a dynamic unprivileged user, so inaccessible scopes fail or may
yield incomplete collector evidence. Privileged hardware probes require a
deliberate administrator policy change.

For NixOS, import `inputs.bommer.nixosModules.default`, enable
`services.bommer.enable`, and set `services.bommer.settings`. Supply external
collectors through `extraPackages`. `schedule = "daily"` opts into the timer;
otherwise the service is manual. Settings are stored in the Nix store and must
not contain secrets. The service's writable state is `/var/lib/bommer`; retain
that output location unless explicitly adjusting service sandbox permissions.

Native systems can opt into scheduling with `systemctl enable --now bommer.timer`
after configuring and testing their collectors. Results have no automatic
retention policy, and scanner output sizes are not yet bounded.
