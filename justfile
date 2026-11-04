version := env('VERSION', '0.1.0-dev')

# List available recipes.
default:
    @just --list

# Format Go source and tests.
fmt:
    gofmt -w cmd internal

# Check formatting without changing files.
fmt-check:
    @unformatted="$(gofmt -l cmd internal)"; if [ -n "$unformatted" ]; then printf '%s\n' "$unformatted"; exit 1; fi

# Run Go's static analysis.
vet:
    go vet ./...

# Run tests with the race detector.
test:
    go test -race ./...

# Test embedded CycloneDX schemas, fixtures, and offline validation.
schema-test:
    go test -race ./internal/bom

# Run integration fixtures; live Nix requires an explicit BOMMER_TEST_NIX_ROOT.
integration-test:
    go test -race -count=1 -v -run 'Test.*Integration|^TestNixLive$' ./...

# Run all source checks and tests.
check: fmt-check vet test

# Build a standalone Linux executable.
build:
    mkdir -p dist
    CGO_ENABLED=0 go build -trimpath -o dist/bommer ./cmd/bommer

# Build a Debian package. Override the version with VERSION.
deb: build
    VERSION={{quote(version)}} nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

# Build an RPM package. Override the version with VERSION.
rpm: build
    VERSION={{quote(version)}} nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
