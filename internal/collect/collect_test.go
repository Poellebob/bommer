package collect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
}
