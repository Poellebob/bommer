# Bommer Reference

Configurable Linux HBOM, SBOM, and application CBOM collection, written in Go.
**Early implementation, not production-ready.** See
[the implementation plan](IMPLEMENTATION.md) for release gates and gaps.
For a first scan, follow the [quick start](../README.md).

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

The shell provides Go, just, Syft, Nix, and nFPM. `hbom` and custom command collectors
must be provisioned separately. The native `certificates` and `import` backends
need no external scanner; `nix` needs a local Nix executable and existing store.
Lock files pin the development environment and flake inputs; production external
collector version pinning remains to be implemented.

`just schema-test` runs the `internal/bom` tests, including schema fixtures,
embedded resource hashes, and offline loading. `just integration-test` runs
`Test.*Integration` and `TestNixLive`. Syft integration skips when Syft is missing;
live Nix skips unless `BOMMER_TEST_NIX_ROOT` is explicitly set:

```sh
BOMMER_TEST_NIX_ROOT=/nix/var/nix/profiles/example just integration-test
```

Choose an existing local closure root, not an installable or an arbitrary
directory. The recipe does not discover a root, build one, or require Nix for
portable tests. Verbose output distinguishes skipped tests from live coverage.

## Configuration

Start with [examples/config.yaml](../examples/config.yaml). Everything is disabled
by default. Enable the desired collectors, specify application directories or
container images, and select a writable output directory. Configuration remains
`version: 1` (independent of manifest version 2). Unknown YAML fields are rejected.
See [examples/native.yaml](../examples/native.yaml) for explicit native scopes;
its site-specific paths must be changed before use.

```sh
./dist/bommer doctor --config examples/config.yaml
./dist/bommer scan --config /etc/bommer/config.yaml
./dist/bommer scan --config /etc/bommer/config.yaml --only hbom
./dist/bommer scan --config /etc/bommer/config.yaml --application payments
```

A configuration with no enabled collectors fails rather than producing an empty
run. `doctor` checks executables and directory targets; READY does not mean that
permissions, application crypto coverage, image access, or hardware discovery
have been verified. Certificate preflight checks options, not traversal or
readability; import preflight checks file type/size, not its contents. Container
targets use Syft's registry source (no daemon socket is mounted or accessed
implicitly).

Supported backends:

| Kind | Backend | Behavior |
| --- | --- | --- |
| Host HBOM | `hbom` | Executes `hbom -p` |
| Host/application SBOM | `syft` | Emits CycloneDX JSON from a directory or registry image |
| Host/application SBOM | `nix` | Queries an explicitly scoped existing local store-reference closure |
| Host/application CBOM | `certificates` | Observes public X.509 certificates in explicit local paths |
| Host/application CBOM | `import` | Preserves a trusted existing CycloneDX CBOM file |
| Any configured inventory | `command` | Runs an administrator-supplied collector |

### Named Inventories

`host.inventories` and `applications[].inventories` are lists of
`{name, kind, collector}` entries. Set `collector.enabled: true` explicitly;
omitting it leaves the inventory disabled. `kind` is `hbom`, `sbom`, or `cbom`,
subject to the backend/scope restrictions above. Names must be unique within
each list and match `[a-zA-Z0-9][a-zA-Z0-9_-]*`. Application names follow the same
pattern, must be globally unique, and cannot be `host`.

```yaml
host:
  inventories:
    - name: deployed-profile
      kind: sbom
      collector:
        enabled: true
        backend: nix
        nix:
          roots: [/nix/var/nix/profiles/example]
```

Existing `host.hbom`, `host.sbom`, `applications[].sbom`, and
`applications[].cbom` remain supported alongside named inventories. They are not
replaced or implicitly enabled. Named inventories allow separate conventional
package and Nix scopes on mixed Debian/RPM plus Nix hosts. `--only` selects a
kind across inventories; `--application` selects that application and excludes
host jobs. There is no inventory-name selection flag.

### External Commands

For `command`, configure an executable followed by separate arguments. `{target}`
is substituted in arguments only: a directory path, `registry:<image>` for a
container, `dir:/` for a host SBOM, or empty for a host HBOM. The collector must
write **only CycloneDX JSON to stdout** and diagnostics to stderr. There is no
shell expansion. A wrapper can adapt collectors that require output files.
Configuration is trusted executable policy; do not accept it from untrusted users.
Bommer does not sandbox arbitrary collectors or prevent them accessing keys or
networks. Do not configure collectors that export secret material.

NixOS host software inventory refuses the Syft backend: use the native `nix`
backend or an explicitly configured Nix-aware command collector. Conventional
package discovery on Debian/RPM hosts is not a Nix closure.

### Local Nix Closures

`backend: nix` supports SBOMs only. `nix.roots` is a list of absolute local paths
and is required for host inventories. Applications require
`target.type: nix-closure` and `target.path`; when `nix.roots` is absent or empty, that path is
the default root. Explicit roots override it. A root may be a profile symlink,
but must resolve to an existing top-level `/nix/store/<hash>-name` output, not a
derivation, a subdirectory, or a custom store location.

The collector resolves roots, records configured/resolved paths and the Nix
version, and queries `nix path-info --offline --recursive --json` against an
explicitly local store connection. It never evaluates, builds, downloads, or
discovers all of `/nix/store`. It ignores remote store selection for its query.
Missing or incomplete closures fail; there is no fallback to another backend.

Nix 2.34 is the live-tested query family (fixture contract: 2.34.8). For 2.34 and
newer, the query explicitly requests `--json-format 1`. Older version queries
omit that flag; legacy array and format-1 object JSON are covered by fixtures,
not a claim of live verification across all versions. Unrecognized version
output or unsupported metadata formats fail rather than being guessed.

Each output becomes a `file` component with its full store name and reference
edges. No package version is guessed from its name. Store path, NAR hash, NAR
size, and available deriver are `bommer:nix:*` properties. **NAR hashes describe
serialized store outputs, not ordinary file hashes**, and are not emitted as
CycloneDX component `hashes`. This is store-reference evidence, not source,
runtime, or complete package-level discovery.

### Certificate Observations

`backend: certificates` supports CBOMs over explicit `certificates.paths` files
or directories. Host paths must be absolute. Application relative paths resolve
against the application target, not the config file; directory and `nix-closure`
targets are supported, not containers. An application Nix target is resolved
to its store output first. Absolute application paths are also allowed, so this
is declared scope, not a target-containment sandbox.

`certificates.max_file_bytes` defaults to 4 MiB (`4194304`); omitted or `0` uses
that default. The maximum is 64 MiB (`67108864`). Traversal is bounded to 100,000
entries and depth 128. Symlinks are refused in **all path components**, including
ancestors and discovered entries; `..` components and non-regular files are
refused. Missing/unreadable paths, refused links, malformed candidates, oversized
certificate candidates, and traversal limits produce diagnostics and `partial`
results, not silently complete inventories.

PEM certificate blocks and DER X.509 certificates are observed and deduplicated
by certificate SHA-256. Output includes fingerprints, source paths, validity
dates, expiry observations, and public-key/signature algorithms. Private-key PEM
blocks are skipped without decoding or parsing them; raw keys and certificates
are not exported. `certificates.include_identity` defaults to `false`; set it to
`true` to include subject and issuer names. Even with identity disabled, paths
and fingerprints can be sensitive. Trust chains, revocation, and application
usage are not evaluated; this is not TLS probing, source-code analysis, or proof
of all cryptography used by an application.

### Trusted CBOM Import

`backend: import` is CBOM-only. Set `import.path` to a regular file no larger
than 64 MiB. Relative import paths use the process working directory, not the
application target or config directory. Use a trusted existing CI artifact:
Bommer does not invoke its producer. The original JSON bytes are preserved,
validated against the embedded CycloneDX schema, and hashed; evidence records
`sourcePath`, `sourceSHA256`, `discovery: not-observed-locally`, and
`applicationAssociation: configuration-declared-not-verified`.

Nonempty imports must contain cryptographic assets. Duplicate JSON keys are
rejected before inspection, including differently escaped spellings of a key.
Known private-key material
markers and raw `relatedCryptoMaterialProperties.value` fields are rejected.
These checks are not a general secret sanitizer: trust and review the producer.
Imported findings do **not** prove local coverage or association with the named
application. Source-code cryptography scanner integration is a deferred proof
of concept and is **not implemented**; `command` and `import` are explicit
integration boundaries, not built-in source scanners.

### Source Scan Scope

Application Syft scans use the configured application `name` as source metadata.
An optional application `version` sets `--source-version`; it is not inferred
from Bommer's own version or Git tags.

```yaml
applications:
  - name: payments
    version: 1.0.0
    target:
      type: directory
      path: /srv/payments
    sbom:
      enabled: true
      backend: syft
      respect_gitignore: true
      exclude:
        - "./.devenv/**"
        - "./dist/**"
        - "./results/**"
```

`exclude` accepts Syft glob patterns relative to the scan root, passed literally
as separate arguments. There are no automatic build-directory exclusions.
`respect_gitignore` is opt-in and only supported for application directory scans
using Syft. Git must be installed and the target must be in a Git working tree.
Bommer asks Git for ignored paths, respecting nested `.gitignore` files,
negations, `.git/info/exclude`, and the user's global Git ignores. Tracked files
remain included even when matching an ignore rule. Git metadata is excluded too.
Explicit exclusions still take precedence over paths re-included by Git rules.

Git ignore evaluation happens before scanning; newly created ignored paths during
the scan are not guaranteed to be excluded. Use explicit directory exclusions
for concurrently changing caches and result locations. Large numbers of
individually ignored files can exceed the OS argument limit: prefer directory
ignore rules for caches. Exclusions are not a security sandbox or a secret filter.
They apply to traversal, not necessarily every dependency referenced by an
included manifest; source inventories can still include test dependencies.

## Results

Each scan creates a private unique run directory with separate `.cdx.json`
documents, stderr logs, and a `manifest.json` containing timestamps, backends,
target scopes, artifact SHA-256 hashes, and per-job status. A failed job does not
discard other jobs' valid results. Only one scan per output directory may run.
The manifest also records application versions, whether Git ignores were enabled,
and the effective exclusions (explicit patterns plus resolved ignored paths).

Manifest `version: 2` records `validation: json-schema-offline`. CycloneDX 1.6
and 1.7 documents are validated against embedded upstream schemas and their
embedded references, with no schema network fetches or document-controlled
`$schema` loading. Ambiguous duplicate keys and nesting beyond 512 levels are
rejected. Schema validity and coverage are separate: a valid document
does not prove complete discovery, trust, or application association.

Results include `scope`, optional named `inventory`, `specVersion`, `findings`,
`coverage`, and available `collectorVersion`, `diagnostics`, and `evidence`.
Native coverage is `declared-scope`, import coverage is
`producer-declared-unverified`, and external coverage remains `unknown`.
Certificate findings count unique certificates, not their additional algorithm
components; Nix findings count store outputs.

| Status | Meaning |
| --- | --- |
| `collected` | Validated nonempty evidence was produced; completeness is not guaranteed |
| `partial` | Native collector produced validated evidence with coverage diagnostics; artifact retained, scan exits `1` |
| `no-findings` | Native collector explicitly reports zero findings in a valid document; not proof of absent cryptography |
| `failed` | Preflight, execution, or validation failed; no final BOM artifact |

Only native backends can report `no-findings`, including an empty valid imported
document. Legacy/external collectors still require a positive document version
and nonempty top-level `components`; empty external output fails even if schema
valid. Invalid/failed stdout is removed; private stderr logs remain when created.
Named artifacts use `<name>.<inventory>.<kind>.cdx.json`; legacy artifacts retain
`<name>.<kind>.cdx.json`, with matching `.stderr.log` names.

Exit codes: `0` collected/no-findings/ready, `1` any partial result or
execution/preflight/validation failure, `2` usage or
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

The flake wraps Bommer with Syft, Git, and Nix. Native packages currently contain the CLI,
disabled example configuration, and systemd units, **not collector binaries**;
provision those explicitly. Native binaries use `CGO_ENABLED=0`, not a copied
Nix-linked executable. Packages do not enable or start scanning on installation.
The service uses a dynamic unprivileged user, so inaccessible scopes fail or may
yield incomplete collector evidence. Privileged hardware probes require a
deliberate administrator policy change.

For NixOS, import `inputs.bommer.nixosModules.default`, enable
`services.bommer.enable`, and set `services.bommer.settings`. Supply external
collectors through `extraPackages`. The default flake package includes the Nix executable;
native `.deb`/`.rpm` users must provision Nix separately when selecting that backend.
`schedule = "daily"` opts into the timer;
otherwise the service is manual. Settings are stored in the Nix store and must
not contain secrets. The service's writable state is `/var/lib/bommer`; retain
that output location unless explicitly adjusting service sandbox permissions.

Native systems can opt into scheduling with `systemctl enable --now bommer.timer`
after configuring and testing their collectors. Results have no automatic
retention policy. External scanner output/log sizes are not yet bounded; native
import and certificate file limits do not impose a run-wide output limit. Nix
query stdout is limited to 64 MiB and stderr capture to 16 KiB.
