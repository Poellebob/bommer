package collect

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"codeberg.org/Poellebob/bommer/internal/config"
)

func TestJobs(t *testing.T) {
	collector := config.Collector{
		Enabled: true,
		Backend: "command",
		Command: []string{"scanner"},
	}
	var cfg config.Config
	cfg.Host.HBOM, cfg.Host.SBOM = collector, collector
	cfg.Applications = []config.Application{
		{
			Name: "api",
			Target: config.Target{
				Type: "directory",
				Path: "/source tree",
			},
			SBOM: collector,
			CBOM: collector,
		},
		{
			Name: "image",
			Target: config.Target{
				Type:  "container",
				Image: "example/app:v1",
			},
			SBOM: collector,
		},
		{
			Name: "disabled",
			Target: config.Target{
				Type: "directory",
				Path: "/disabled",
			},
		},
	}
	for _, tt := range []struct {
		name, only, application string
		want                    []string
		wantError               string
	}{
		{
			"all", "", "",
			[]string{
				"host/hbom/",
				"host/sbom/dir:/",
				"api/sbom//source tree",
				"api/cbom//source tree",
				"image/sbom/registry:example/app:v1",
			},
			"",
		},
		{
			"kind", "sbom", "",
			[]string{"host/sbom/dir:/", "api/sbom//source tree", "image/sbom/registry:example/app:v1"},
			"",
		},
		{"application", "", "api", []string{"api/sbom//source tree", "api/cbom//source tree"}, ""},
		{"combined", "cbom", "api", []string{"api/cbom//source tree"}, ""},
		{"invalid kind", "all", "", nil, "only must be"},
		{"unknown application", "", "missing", nil, "unknown application"},
		{"disabled", "", "disabled", nil, "no enabled collectors"},
		{"no matching kind", "hbom", "api", nil, "no enabled collectors"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jobs, err := Jobs(cfg, tt.only, tt.application)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("Jobs() error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, job := range jobs {
				got = append(got, job.Name+"/"+job.Kind+"/"+job.Target)
				if !reflect.DeepEqual(job.Collector, collector) {
					t.Fatalf("collector not preserved: %+v", job)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Jobs() = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := Jobs(config.Config{}, "", ""); err == nil {
		t.Fatal("empty config must not produce a runnable selection")
	}
}

func TestSyftMetadataAndExclusions(t *testing.T) {
	var cfg config.Config
	cfg.Applications = []config.Application{{
		Name:    "api",
		Version: "1.2.3",
		Target:  config.Target{Type: "directory", Path: "/source tree"},
		SBOM:    config.Collector{Enabled: true, Backend: "syft", Exclude: []string{"./dist/**", "./cache space/**"}},
	}}
	jobs, err := Jobs(cfg, "", "api")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"syft", "scan", "dir:/source tree", "-o", "cyclonedx-json",
		"--source-name", "api", "--source-version", "1.2.3",
		"--exclude", "./dist/**", "--exclude", "./cache space/**"}
	if got := jobs[0].Command(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Command() = %q, want %q", got, want)
	}
}

func TestResolveGitignore(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	git("init", "--quiet")
	write := func(path, data string) {
		t.Helper()
		fullPath := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", "cache/\n*.log\n!keep.log\nweird*/\n")
	write("cache/module/go.mod", "ignored")
	write("drop.log", "ignored")
	write("keep.log", "included")
	write("tracked.log", "included")
	git("add", "--force", "tracked.log")
	write("nested/.gitignore", "secret.txt\n!keep.log\n")
	write("nested/secret.txt", "ignored")
	write("nested/keep.log", "included")
	write("weird[1]/module", "ignored")
	write("source.go", "included")

	job := Job{Name: "app", Target: root, Collector: config.Collector{
		Backend: "syft", RespectGitignore: true, Exclude: []string{"./manual/**"},
	}}
	resolved, err := job.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"./manual/**", "./.git", "./.git/**", "./cache/**", "./drop.log", "./nested/secret.txt", `./weird\[1\]/**`}
	if !reflect.DeepEqual(resolved.Collector.Exclude, want) {
		t.Fatalf("resolved exclusions = %q, want %q", resolved.Collector.Exclude, want)
	}
	if !reflect.DeepEqual(job.Collector.Exclude, []string{"./manual/**"}) {
		t.Fatal("Resolve mutated configuration")
	}

	t.Run("subdirectory", func(t *testing.T) {
		job := job
		job.Target = filepath.Join(root, "nested")
		resolved, err := job.Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := resolved.Collector.Exclude; !reflect.DeepEqual(got, []string{"./manual/**", "./.git", "./.git/**", "./secret.txt"}) {
			t.Fatalf("subdirectory exclusions = %q", got)
		}
	})
	t.Run("duplicate exclusions", func(t *testing.T) {
		job := job
		job.Collector.Exclude = []string{"./cache/**", "./cache/**"}
		resolved, err := job.Resolve(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, pattern := range resolved.Collector.Exclude {
			if seen[pattern] {
				t.Fatalf("duplicate resolved exclusion %q", pattern)
			}
			seen[pattern] = true
		}
	})
	t.Run("not a repository", func(t *testing.T) {
		job := job
		job.Target = t.TempDir()
		if _, err := job.Resolve(context.Background()); err == nil {
			t.Fatal("non-repository must fail")
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := job.Resolve(ctx); err == nil {
			t.Fatal("canceled resolution must fail")
		}
	})
}

func TestGitignoreSyftIntegration(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("Syft is not installed; run inside devenv for the integration test")
	}
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	files := map[string]string{
		".gitignore":                 "cache/\nlogs/*\n!logs/keep/\nweird*/\n",
		"requirements.txt":           "requests==2.32.0\n",
		"cache/requirements.txt":     "cache-leak==1.0.0\n",
		"logs/drop/requirements.txt": "logs-leak==1.0.0\n",
		"logs/keep/requirements.txt": "click==8.1.0\n",
		"weird[1]/requirements.txt":  "special-path-leak==1.0.0\n",
		"manual/requirements.txt":    "manual-leak==1.0.0\n",
	}
	for path, data := range files {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job := Job{Name: "test-app", Version: "1.2.3", Target: root, Collector: config.Collector{
		Backend: "syft", RespectGitignore: true, Exclude: []string{"./manual/**"},
	}}
	job, err := job.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	args := job.Command()
	output, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	if err != nil {
		t.Fatalf("Syft scan: %v", err)
	}
	var bom struct {
		Metadata struct {
			Component struct{ Name, Version string }
		}
		Components []struct{ Name string }
	}
	if err := json.Unmarshal(output, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Metadata.Component.Name != "test-app" || bom.Metadata.Component.Version != "1.2.3" {
		t.Fatalf("unexpected source metadata: %+v", bom.Metadata.Component)
	}
	names := map[string]bool{}
	for _, component := range bom.Components {
		names[component.Name] = true
	}
	for _, name := range []string{"requests", "click"} {
		if !names[name] {
			t.Errorf("included package %s missing: %v", name, names)
		}
	}
	for _, name := range []string{"cache-leak", "logs-leak", "special-path-leak", "manual-leak"} {
		if names[name] {
			t.Errorf("excluded package %s was scanned", name)
		}
	}
}

func TestCommand(t *testing.T) {
	for _, tt := range []struct {
		name, backend, target string
		want                  []string
	}{
		{"hardware", "hbom", "", []string{"hbom", "-p"}},
		{"directory", "syft", "/source tree", []string{"syft", "scan", "dir:/source tree", "-o", "cyclonedx-json"}},
		{"host", "syft", "dir:/", []string{"syft", "scan", "dir:/", "-o", "cyclonedx-json"}},
		{
			"registry", "syft", "registry:example/app:v1",
			[]string{"syft", "scan", "registry:example/app:v1", "-o", "cyclonedx-json"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := Job{
				Target:    tt.target,
				Collector: config.Collector{Backend: tt.backend},
			}
			if got := job.Command(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Command() = %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("literal substitution and no mutation", func(t *testing.T) {
		original := []string{"scanner-{target}", "--path={target}", "{target}/{target}", "$HOME; $(touch bad) *", ""}
		before := append([]string(nil), original...)
		target := "/source tree; $(touch bad)"
		job := Job{
			Target: target,
			Collector: config.Collector{
				Backend: "command",
				Command: original,
			},
		}
		want := []string{original[0], "--path=" + target, target + "/" + target, original[3], ""}
		got := job.Command()
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(original, before) {
			t.Fatalf("Command() = %q, original = %q", got, original)
		}
		got[1] = "mutated"
		if !reflect.DeepEqual(job.Command(), want) {
			t.Fatal("Command returned an alias of configured arguments")
		}
	})
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "collector")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, executable, target string
		valid                    bool
	}{
		{"directory", script, dir, true},
		{"registry without local path", script, "registry:example/app:v1", true},
		{"no target", script, "", true},
		{"missing executable", filepath.Join(dir, "missing-command"), dir, false},
		{"not executable", file, dir, false},
		{"missing target", script, filepath.Join(dir, "missing-target"), false},
		{"file target", script, file, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := Job{
				Name:   "app",
				Target: tt.target,
				Collector: config.Collector{
					Backend: "command",
					Command: []string{tt.executable},
				},
			}
			if err := job.Check(); (err == nil) != tt.valid {
				t.Fatalf("Check() = %v, valid = %v", err, tt.valid)
			}
		})
	}
	t.Run("Git is required when respecting ignores", func(t *testing.T) {
		t.Setenv("PATH", dir)
		job := Job{Name: "app", Target: dir, Collector: config.Collector{
			Backend: "command", Command: []string{script}, RespectGitignore: true,
		}}
		if err := job.Check(); err == nil || !strings.Contains(err.Error(), "requires Git") {
			t.Fatalf("Check() = %v, want missing Git error", err)
		}
	})
}
