package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/Poellebob/bommer/internal/config"
)

// The application output references itself and the library output.
const nixTestApplicationPath = "/nix/store/00000000000000000000000000000000-app-with-dashes-1.2-bin"
const nixTestLibraryPath = "/nix/store/11111111111111111111111111111111-library-2-dev"

// Nix 2.34.8 --json --json-format 1 contract, including the nullable ca,
// optional deriver, per-entry version, and full-path keys and references.
const nixTestJSON = `{
  "` + nixTestLibraryPath + `": {
    "ca": null, "narHash": "sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo=",
    "narSize": 205456, "references": [], "registrationTime": 1793796217,
    "signatures": [], "storeDir": "/nix/store", "ultimate": true, "version": 1
  },
  "` + nixTestApplicationPath + `": {
    "ca": null, "deriver": "/nix/store/22222222222222222222222222222222-app.drv",
    "narHash": "sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo=",
    "narSize": 96, "references": ["` + nixTestLibraryPath + `", "` + nixTestApplicationPath + `", "` + nixTestLibraryPath + `"],
    "signatures": [], "version": 1
  }
}`

// Legacy nix path-info --json used an array and Nix-base32 NAR hashes.
const nixTestLegacyJSON = `[{
  "path": "` + nixTestApplicationPath + `",
  "narHash": "sha256:0000000000000000000000000000000000000000000000000000",
  "narSize": 96,
  "references": [],
  "deriver": "unknown-deriver",
  "signatures": []
}]`

func nixFake(t *testing.T, body string) string {
	t.Helper()
	commandDirectory := t.TempDir()
	commandPath := filepath.Join(commandDirectory, "nix")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", commandDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NIX_TEST_JSON", nixTestJSON)
	t.Setenv("NIX_TEST_VERSION", "nix (Nix) 2.34.8")
	argumentLogPath := filepath.Join(commandDirectory, "args")
	t.Setenv("NIX_TEST_ARGS", argumentLogPath)
	return argumentLogPath
}

const nixFakeQuery = `if [ "$1" = --version ]; then
  printf '%s\n' "$NIX_TEST_VERSION"
  exit 0
fi
printf '%s\n' "$@" > "$NIX_TEST_ARGS"
printf '%s' "$NIX_TEST_JSON"
`

func nixTestJob() Job {
	return Job{
		Name:      "app",
		Kind:      "sbom",
		Target:    "/profile",
		Collector: config.Collector{Backend: "nix"},
	}
}

func TestNixCollectContract(t *testing.T) {
	argumentLogPath := nixFake(t, nixFakeQuery)
	t.Setenv("NIX_REMOTE", "ssh://must-not-be-used")
	var output bytes.Buffer
	resolveCalls := 0
	resolve := func(root string) (string, error) {
		resolveCalls++
		if root != "/profile" {
			t.Fatalf("unexpected root %q", root)
		}
		return nixTestApplicationPath, nil
	}
	result, err := nixCollect(context.Background(), nixTestJob(), &output, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if resolveCalls != 1 || result.Status != "collected" || result.Findings != 2 || result.CollectorVersion != "nix (Nix) 2.34.8" {
		t.Fatalf("calls=%d result=%+v", resolveCalls, result)
	}
	if !reflect.DeepEqual(result.Evidence["configuredRoots"], []string{"/profile"}) || !reflect.DeepEqual(result.Evidence["resolvedRoots"], []string{nixTestApplicationPath}) {
		t.Fatalf("root evidence: %#v", result.Evidence)
	}
	argumentLog, err := os.ReadFile(argumentLogPath)
	if err != nil {
		t.Fatal(err)
	}
	wantArguments := []string{
		"--extra-experimental-features", "nix-command",
		"path-info",
		"--store", result.Evidence["storeConnection"].(string),
		"--offline",
		"--recursive",
		"--json",
		"--json-format", "1",
		nixTestApplicationPath,
	}
	if !reflect.DeepEqual(strings.Split(strings.TrimSpace(string(argumentLog)), "\n"), wantArguments) {
		t.Fatalf("unsafe or unexpected CLI args: %s", argumentLog)
	}
	if wantArguments[4] != "local" && wantArguments[4] != "unix:///nix/var/nix/daemon-socket/socket" {
		t.Fatalf("not an explicitly local store: %q", wantArguments[4])
	}
	var bom struct {
		Format       string                       `json:"bomFormat"`
		Spec         string                       `json:"specVersion"`
		Version      int                          `json:"version"`
		Components   []map[string]json.RawMessage `json:"components"`
		Dependencies []nixDependency              `json:"dependencies"`
	}
	if err := json.Unmarshal(output.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Format != "CycloneDX" || bom.Spec != "1.6" || bom.Version != 1 || len(bom.Components) != 2 {
		t.Fatalf("invalid BOM: %s", output.Bytes())
	}
	var name string
	json.Unmarshal(bom.Components[0]["name"], &name)
	if name != "app-with-dashes-1.2-bin" {
		t.Fatalf("unsafe name inference: %q", name)
	}
	for _, component := range bom.Components {
		if component["version"] != nil || component["hashes"] != nil {
			t.Fatalf("inferred version or ordinary file hash: %v", component)
		}
		var properties []nixProperty
		if err := json.Unmarshal(component["properties"], &properties); err != nil {
			t.Fatal(err)
		}
		if len(properties) < 3 || properties[1].Name != "bommer:nix:nar-hash" || properties[2].Name != "bommer:nix:nar-size" {
			t.Fatalf("missing NAR semantics: %v", properties)
		}
	}
	wantGraph := []nixDependency{
		{Reference: nixTestApplicationPath, DependsOn: []string{nixTestApplicationPath, nixTestLibraryPath}},
		{Reference: nixTestLibraryPath, DependsOn: []string{}},
		{Reference: "bommer:inventory:app.sbom", DependsOn: []string{nixTestApplicationPath}},
	}
	if !reflect.DeepEqual(bom.Dependencies, wantGraph) {
		t.Fatalf("graph: %+v", bom.Dependencies)
	}
	firstOutput := append([]byte{}, output.Bytes()...)
	// Reorder entries and reference lists through the legacy array format.
	metadataByPath, err := nixDecode([]byte(nixTestJSON))
	if err != nil {
		t.Fatal(err)
	}
	applicationMetadata := metadataByPath[nixTestApplicationPath]
	libraryMetadata := metadataByPath[nixTestLibraryPath]
	applicationMetadata.Path = nixTestApplicationPath
	libraryMetadata.Path = nixTestLibraryPath
	applicationMetadata.References = &[]string{nixTestLibraryPath, nixTestApplicationPath}
	legacyJSON, _ := json.Marshal([]nixPathInfo{libraryMetadata, applicationMetadata})
	t.Setenv("NIX_TEST_JSON", string(legacyJSON))
	output.Reset()
	if _, err := nixCollect(context.Background(), nixTestJob(), &output, resolve); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstOutput, output.Bytes()) {
		t.Fatalf("nondeterministic output:\n%s\n%s", firstOutput, output.Bytes())
	}
}

func TestNixOlderVersionAndExplicitRoots(t *testing.T) {
	argumentLogPath := nixFake(t, nixFakeQuery)
	t.Setenv("NIX_TEST_VERSION", "nix (Nix) 2.18.9")
	job := nixTestJob()
	job.Name = "host"
	job.Collector.Nix = &config.NixOptions{Roots: []string{"/b", "/a", "/b"}}
	var resolvedInputs []string
	result, err := nixCollect(context.Background(), job, io.Discard, func(root string) (string, error) {
		resolvedInputs = append(resolvedInputs, root)
		if root == "/a" {
			return nixTestApplicationPath, nil
		}
		return nixTestLibraryPath, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resolvedInputs, job.Collector.Nix.Roots) || !reflect.DeepEqual(result.Evidence["configuredRoots"], resolvedInputs) {
		t.Fatalf("roots resolved incorrectly: %v %+v", resolvedInputs, result)
	}
	argumentLog, _ := os.ReadFile(argumentLogPath)
	if strings.Contains(string(argumentLog), "--json-format") || !strings.HasSuffix(string(argumentLog), nixTestApplicationPath+"\n"+nixTestLibraryPath+"\n") {
		t.Fatalf("older Nix arguments: %s", argumentLog)
	}
}

func TestNixLegacyJSON(t *testing.T) {
	metadataByPath, err := nixDecode([]byte(nixTestLegacyJSON))
	if err != nil || len(metadataByPath) != 1 || metadataByPath[nixTestApplicationPath].Deriver != "unknown-deriver" {
		t.Fatalf("legacy fixture: %+v %v", metadataByPath, err)
	}
	duplicate := strings.TrimSuffix(nixTestLegacyJSON, "]") + "," + strings.TrimPrefix(nixTestLegacyJSON, "[")
	if _, err := nixDecode([]byte(duplicate)); err == nil {
		t.Fatal("accepted duplicate legacy paths")
	}
}

func TestNixRejectRootsBeforeQuery(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("not a store output"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "profile")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{
		dir,
		regular,
		link,
		filepath.Join(dir, "missing"),
		"nixpkgs#hello",
		"https://cache.nixos.org",
		"path:/nix/store",
		nixTestApplicationPath + "/bin",
		"/nix/store/22222222222222222222222222222222-foo.drv",
	} {
		t.Run(root, func(t *testing.T) {
			job := nixTestJob()
			job.Target = root
			var output bytes.Buffer
			result, err := collectNix(context.Background(), job, &output)
			if err == nil || result.Status != "failed" || output.Len() != 0 {
				t.Fatalf("accepted arbitrary root %q: %+v %v", root, result, err)
			}
		})
	}
	job := nixTestJob()
	job.Name = "host"
	if _, err := nixCollect(context.Background(), job, io.Discard, func(string) (string, error) {
		t.Fatal("host default resolved")
		return "", nil
	}); err == nil {
		t.Fatal("accepted implicit host root")
	}
	for _, path := range []string{
		nixTestApplicationPath + "/bin",
		nixTestApplicationPath + ".drv",
		strings.Replace(nixTestApplicationPath, "000000", "eeeeee", 1),
		strings.Replace(nixTestApplicationPath, "/nix/store/", "/custom/store/", 1),
	} {
		if nixIsOutput(path) {
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestNixMalformedMetadata(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"null":            "null",
		"empty closure":   "{}",
		"trailing JSON":   nixTestJSON + "{}",
		"structured hash": strings.Replace(nixTestJSON, `"sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo="`, `{"algorithm":"sha256","hash":"abc"}`, 1),
		"invalid hash":    strings.Replace(nixTestJSON, "sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo=", "sha256-invalid", 1),
		"negative size":   strings.Replace(nixTestJSON, `"narSize": 96`, `"narSize": -1`, 1),
		"missing size":    strings.Replace(nixTestJSON, `"narSize": 96,`, "", 1),
		"null refs":       strings.Replace(nixTestJSON, `"references": []`, `"references": null`, 1),
		"absent refs":     strings.Replace(nixTestJSON, `"references": [],`, "", 1),
		"version 2":       strings.ReplaceAll(nixTestJSON, `"version": 1`, `"version": 2`),
		"bad deriver":     strings.ReplaceAll(nixTestJSON, "22222222222222222222222222222222-app.drv", "invalid"),
		"missing ref":     strings.Replace(nixTestJSON, `"references": []`, `"references": ["/nix/store/33333333333333333333333333333333-missing"]`, 1),
		"relative paths":  strings.ReplaceAll(nixTestJSON, "/nix/store/", ""),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := nixDecode([]byte(data)); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
	for _, hash := range []string{
		"sha256:" + strings.Repeat("0", 52),
		"sha256:" + strings.Repeat("a", 64),
		"sha256-7bO3fpkymZrnfW2Z6uxcYwBALxPVrZ9msGQrTG1MNZo=",
	} {
		if !nixValidNarHash(hash) {
			t.Fatalf("rejected valid NAR hash %q", hash)
		}
	}
}

func TestNixFailures(t *testing.T) {
	for _, name := range []string{"missing root", "unknown version", "bad JSON", "writer"} {
		t.Run(name, func(t *testing.T) {
			nixFake(t, nixFakeQuery)
			job := nixTestJob()
			var output io.Writer = io.Discard
			switch name {
			case "missing root":
				job.Target = nixTestLibraryPath
			case "unknown version":
				t.Setenv("NIX_TEST_VERSION", "unexpected fork")
			case "bad JSON":
				t.Setenv("NIX_TEST_JSON", "[]")
			case "writer":
				output = nixBrokenWriter{}
			}
			_, err := nixCollect(context.Background(), job, output, func(string) (string, error) {
				if name == "missing root" {
					return "/nix/store/33333333333333333333333333333333-absent", nil
				}
				return nixTestApplicationPath, nil
			})
			if err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}

type nixBrokenWriter struct{}

func (nixBrokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestNixBoundedCaptureAndSafeStderr(t *testing.T) {
	for _, truncate := range []bool{false, true} {
		capture := &nixCapture{
			limit:    4,
			truncate: truncate,
		}
		bytesWritten, err := capture.Write([]byte("123456"))
		if capture.buffer.Len() != 4 || !capture.overflow || (err == nil) != truncate || (truncate && bytesWritten != 6) {
			t.Fatalf("capture: %+v %d %v", capture, bytesWritten, err)
		}
	}
	nixFake(t, `printf '\033[31munsafe\n' >&2; exit 1`)
	_, err := nixRun(context.Background(), "--version")
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestNixStdoutLimit(t *testing.T) {
	if os.Getenv("BOMMER_NIX_TEST_LARGE_OUTPUT") == "1" {
		chunk := bytes.Repeat([]byte("x"), 1<<20)
		for chunkIndex := 0; chunkIndex < 65; chunkIndex++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				os.Exit(1)
			}
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	// Exercise the real exec pipes so io.Copy optimizations cannot bypass
	// the capture's Write method and its memory bound.
	nixFake(t, `exec "$NIX_TEST_BINARY" -test.run='^TestNixStdoutLimit$'`)
	testBinaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NIX_TEST_BINARY", testBinaryPath)
	t.Setenv("BOMMER_NIX_TEST_LARGE_OUTPUT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = nixRun(ctx, "--version")
	if err == nil || !strings.Contains(err.Error(), "stdout exceeds") {
		t.Fatalf("stdout limit not enforced: %v", err)
	}
}

func TestNixProcessGroupCancellation(t *testing.T) {
	nixFake(t, `sleep 30 &
printf '%s' "$!" > "$NIX_TEST_ARGS"
wait
`)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := nixRun(ctx, "--version")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("cancellation: %v (%s)", err, time.Since(start))
	}
	pidBytes, err := os.ReadFile(os.Getenv("NIX_TEST_ARGS"))
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscan(string(pidBytes), &pid); err != nil {
		t.Fatal(err)
	}
	// A killed child can remain a zombie until the container's init reaps it.
	if err := syscall.Kill(pid, 0); err == nil {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err == nil && !strings.Contains(string(stat), ") Z ") {
			t.Fatalf("child process %d survived cancellation: %s", pid, stat)
		}
	}
}

func TestNixLive(t *testing.T) {
	root := os.Getenv("BOMMER_TEST_NIX_ROOT")
	if root == "" {
		t.Skip("set BOMMER_TEST_NIX_ROOT to an existing local closure root for read-only live coverage")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job := nixTestJob()
	job.Target = root
	var output bytes.Buffer
	result, err := collectNix(ctx, job, &output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings < 1 || !json.Valid(output.Bytes()) {
		t.Fatalf("invalid live result: %+v", result)
	}
}
