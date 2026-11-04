package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/Poellebob/bommer/internal/collect"
	"codeberg.org/Poellebob/bommer/internal/config"
)

const validBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"example","version":"1.0.0"}]}`

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellJob(t *testing.T, name, body string, args ...string) collect.Job {
	t.Helper()
	script := writeTestFile(t, filepath.Join(t.TempDir(), "collector"), "#!/bin/sh\nset -eu\n"+body, 0700)
	return collect.Job{
		Name: name,
		Kind: "sbom",
		Collector: config.Collector{
			Enabled: true,
			Backend: "command",
			Command: append([]string{script}, args...),
		},
	}
}

func readManifest(t *testing.T, dir string) Manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestCheckBOM(t *testing.T) {
	for _, tt := range []struct {
		name, data string
		valid      bool
	}{
		{"complete minimal 1.6", validBOM, true},
		{"trailing whitespace", validBOM + "\n \t", true},
		{"empty output", "", false},
		{"malformed", "{", false},
		{"null", "null", false},
		{"wrong format", strings.Replace(validBOM, "CycloneDX", "SPDX", 1), false},
		{"unsupported version", strings.Replace(validBOM, "1.6", "0.1", 1), false},
		{"zero document version", strings.Replace(validBOM, `"version":1`, `"version":0`, 1), false},
		{"missing document version", strings.Replace(validBOM, `"version":1,`, "", 1), false},
		{"empty components", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`, false},
		{"missing components", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`, false},
		{"null components", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":null}`, false},
		{"wrong components type", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":{}}`, false},
		{"multiple documents", validBOM + "\n" + validBOM, false},
		{"trailing garbage", validBOM + "garbage", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, filepath.Join(t.TempDir(), "bom.json"), tt.data, 0600)
			if err := CheckBOM(path); (err == nil) != tt.valid {
				t.Fatalf("CheckBOM() = %v, valid = %v", err, tt.valid)
			}
		})
	}
	if err := CheckBOM(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing BOM must fail")
	}
}

func TestExecuteArtifacts(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	fixture := writeTestFile(t, filepath.Join(root, "fixture.json"), validBOM+"\n", 0600)
	// The shell only implements the fake collector; the target must arrive as one literal argument.
	target := filepath.Join(root, "source tree; $(touch INJECTED)")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	job := shellJob(t, "app", "[ \"$1\" = \"$2\" ]\nprintf 'diagnostic\\n' >&2\ncat \"$3\"\n", "{target}", target, fixture)
	job.Target = target
	job.Version = "1.2.3"
	dir, failed, err := Execute(context.Background(), []collect.Job{job}, output, time.Second, "test-version")
	if err != nil || failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	if filepath.Dir(dir) != output {
		t.Fatalf("run directory %q not under %q", dir, output)
	}
	manifest := readManifest(t, dir)
	if manifest.Version != 1 || manifest.BommerVersion != "test-version" ||
		manifest.Validation == "" || len(manifest.Results) != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	result := manifest.Results[0]
	if result.SourceVersion != "1.2.3" {
		t.Fatalf("source version = %q, want 1.2.3", result.SourceVersion)
	}
	if result.Name != "app" || result.Kind != "sbom" || result.Target != target ||
		result.Backend != "command" || result.Status != "collected" || result.Error != "" ||
		result.Artifact != "app.sbom.cdx.json" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Started.IsZero() || result.Finished.Before(result.Started) {
		t.Fatalf("invalid result times: %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(dir, result.Artifact))
	if err != nil {
		t.Fatal(err)
	}
	want := validBOM + "\n"
	hash := sha256.Sum256([]byte(want))
	if string(data) != want || result.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("artifact = %q, hash = %q", data, result.SHA256)
	}
	log, err := os.ReadFile(filepath.Join(dir, "app.sbom.stderr.log"))
	if err != nil || string(log) != "diagnostic\n" {
		t.Fatalf("stderr log = %q, %v", log, err)
	}
	for _, tt := range []struct {
		path string
		mode os.FileMode
	}{
		{output, 0700},
		{dir, 0700},
		{filepath.Join(output, ".lock"), 0600},
		{filepath.Join(dir, "manifest.json"), 0600},
		{filepath.Join(dir, result.Artifact), 0600},
		{filepath.Join(dir, "app.sbom.stderr.log"), 0600},
	} {
		info, err := os.Stat(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != tt.mode {
			t.Errorf("%s permissions = %o, want %o", tt.path, info.Mode().Perm(), tt.mode)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("run should contain only manifest, artifact and log: %v, %v", entries, err)
	}
	second, failed, err := Execute(context.Background(), []collect.Job{job}, output, time.Second, "test-version")
	if err != nil || failed || second == dir {
		t.Fatalf("second run = %q, %v, %v; lock must be released and directory unique", second, failed, err)
	}
}

func TestExecuteFailuresContinue(t *testing.T) {
	jobs := []collect.Job{
		shellJob(t, "empty", "exit 0\n"),
		shellJob(t, "malformed", "printf '{'\n"),
		shellJob(t, "empty-inventory",
			"printf '%s' '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"version\":1,\"components\":[]}'\n",
		),
		shellJob(t, "nonzero", "printf 'failure detail\\n' >&2\nexit 7\n"),
		{
			Name: "missing",
			Kind: "sbom",
			Collector: config.Collector{
				Backend: "command",
				Command: []string{filepath.Join(t.TempDir(), "missing")},
			},
		},
		shellJob(t, "good", "printf '%s' '"+validBOM+"'\n"),
	}
	dir, failed, err := Execute(context.Background(), jobs, t.TempDir(), time.Second, "test")
	if err != nil || !failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	manifest := readManifest(t, dir)
	if len(manifest.Results) != len(jobs) {
		t.Fatalf("got %d results, want %d", len(manifest.Results), len(jobs))
	}
	for i, result := range manifest.Results {
		if i == len(jobs)-1 {
			if result.Status != "collected" || result.Artifact == "" || result.SHA256 == "" {
				t.Fatalf("later successful job not collected: %+v", result)
			}
			continue
		}
		if result.Status != "failed" || result.Error == "" || result.Artifact != "" || result.SHA256 != "" {
			t.Errorf("invalid failure result: %+v", result)
		}
		if _, err := os.Stat(filepath.Join(dir, jobs[i].Name+".sbom.cdx.json")); !os.IsNotExist(err) {
			t.Errorf("failed job artifact must not exist: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".bom-") {
			t.Errorf("temporary output leaked: %s", entry.Name())
		}
	}
	log, err := os.ReadFile(filepath.Join(dir, "nonzero.sbom.stderr.log"))
	if err != nil || string(log) != "failure detail\n" {
		t.Fatalf("failure log = %q, %v", log, err)
	}
}

func TestExecuteTimeoutCleansProcessGroup(t *testing.T) {
	root := t.TempDir()
	marker, ready := filepath.Join(root, "survived"), filepath.Join(root, "ready")
	job := shellJob(t, "slow", "(sleep 1; printf survived > \"$1\") &\nprintf ready > \"$2\"\nwait\n", marker, ready)
	start := time.Now()
	dir, failed, err := Execute(
		context.Background(), []collect.Job{job}, filepath.Join(root, "output"), 250*time.Millisecond, "test",
	)
	if err != nil || !failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("collector never started: %v", err)
	}
	result := readManifest(t, dir).Results[0]
	if !strings.Contains(result.Error, "deadline exceeded") || result.Status != "failed" || result.Artifact != "" {
		t.Fatalf("unexpected timeout result: %+v", result)
	}
	// An orphaned descendant would write the marker after its sleep completes.
	time.Sleep(1100 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("collector descendant survived timeout: %v", err)
	}
}

func TestExecuteCanceledContext(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	job := shellJob(t, "canceled", "printf ran > \"$1\"\n", marker)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir, failed, err := Execute(ctx, []collect.Job{job}, t.TempDir(), time.Second, "test")
	if err != nil || !failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	result := readManifest(t, dir).Results[0]
	if result.Status != "failed" || !strings.Contains(result.Error, "context canceled") {
		t.Fatalf("unexpected cancellation result: %+v", result)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("canceled collector was started: %v", err)
	}
}

func TestExecuteLocking(t *testing.T) {
	output := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(output, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	job := shellJob(t, "app", "printf '%s' '"+validBOM+"'\n")
	dir, _, err := Execute(context.Background(), []collect.Job{job}, output, time.Second, "test")
	if err == nil || !strings.Contains(err.Error(), "lock") || dir != "" {
		t.Fatalf("locked Execute() = %q, %v", dir, err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lock" {
		t.Fatalf("contending scan created files: %v, %v", entries, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if _, failed, err := Execute(
		context.Background(), []collect.Job{job}, output, time.Second, "test",
	); err != nil || failed {
		t.Fatalf("scan after unlocking = %v, %v", failed, err)
	}
}

func TestExecuteOutputIsFile(t *testing.T) {
	path := writeTestFile(t, filepath.Join(t.TempDir(), "output"), "existing", 0600)
	if dir, _, err := Execute(context.Background(), nil, path, time.Second, "test"); err == nil || dir != "" {
		t.Fatalf("Execute() = %q, %v, want output directory error", dir, err)
	}
}
