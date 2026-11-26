version := env('VERSION', '0.1.0-dev')

# List available recipes.
default:
    @just --list

# Format Rust source and tests.
fmt:
    cargo fmt --all

# Check formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Run strict Rust static analysis (including tests).
vet:
    cargo clippy --locked --all-targets -- -D warnings

# Run binary-module tests and black-box CLI tests.
test:
    cargo test --locked

# Run the same suite against the portable native-package target.
portable-test:
    cargo test --locked --target x86_64-unknown-linux-musl

# Test embedded CycloneDX schemas, fixtures, and offline validation.
schema-test:
    cargo test --locked --bin bommer bom::
    cargo test --locked --bin bommer json::tests::

# Run integration fixtures with fake collectors/Nix, not live host inventory.
integration-test:
    cargo test --locked --bin bommer job::tests:: -- --nocapture
    cargo test --locked --bin bommer collectors::external::tests:: -- --nocapture
    cargo test --locked --bin bommer collectors::certificates::tests:: -- --nocapture
    cargo test --locked --bin bommer collectors::nix::tests:: -- --nocapture
    cargo test --locked --bin bommer collectors::import::tests:: -- --nocapture
    cargo test --locked --test cli
    cargo test --locked --bin bommer process::tests:: -- --nocapture
    cargo test --locked --bin bommer doctor::tests:: -- --nocapture
    cargo test --locked --bin bommer scan::tests:: -- --nocapture
    cargo test --locked --bin bommer output::tests:: -- --nocapture
    cargo test --locked --bin bommer manifest::tests:: -- --nocapture

# Check module dependency direction and the architecture checker fixtures.
architecture-test:
    cargo test --locked --test architecture

# Run all source checks and tests.
check: fmt-check vet test

# Build a static Linux executable without a Nix-store runtime dependency.
build:
    cargo build --locked --release --target x86_64-unknown-linux-musl --bin bommer
    mkdir -p dist
    install -m 0755 target/x86_64-unknown-linux-musl/release/bommer dist/bommer

# Build a Debian package. Override the version with VERSION.
deb: build
    VERSION={{quote(version)}} nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

# Build an RPM package. Override the version with VERSION.
rpm: build
    VERSION={{quote(version)}} nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
