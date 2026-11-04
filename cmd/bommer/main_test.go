package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/Poellebob/bommer/internal/config"
	"codeberg.org/Poellebob/bommer/internal/run"
	"gopkg.in/yaml.v3"
)

func cliConfig(t *testing.T, body string) (string, string) {
	t.Helper()
	root := t.TempDir()
	script := filepath.Join(root, "collector")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Version = 1
	cfg.Timeout = "2s"
	cfg.Output.Directory = filepath.Join(root, "output")
	collector := config.Collector{
		Enabled: true,
		Backend: "command",
		Command: []string{script, "{target}"},
	}
	cfg.Host.HBOM = collector
	cfg.Applications = []config.Application{
		{
			Name: "app",
			Target: config.Target{
				Type: "directory",
				Path: root,
			},
			SBOM: collector,
			CBOM: collector,
		},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, cfg.Output.Directory
}

func TestCLIUsage(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		code    int
		message string
	}{
		{"no command", nil, 2, "usage:"},
		{"unknown command", []string{"unknown"}, 2, "unknown command"},
		{"unknown flag", []string{"scan", "--unknown"}, 2, "flag provided but not defined"},
		{"missing flag value", []string{"scan", "--config"}, 2, "flag needs an argument"},
		{"positional argument", []string{"scan", "unexpected"}, 2, "unexpected positional arguments"},
		{"help", []string{"scan", "--help"}, 0, "Usage of scan:"},
		{"missing config", []string{"scan", "--config", filepath.Join(t.TempDir(), "missing")}, 2, "no such file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := cli(context.Background(), tt.args, &out, &errOut)
			if code != tt.code || !strings.Contains(errOut.String(), tt.message) || out.Len() != 0 {
				t.Fatalf("cli() = %d, stdout %q, stderr %q", code, out.String(), errOut.String())
			}
		})
	}
	t.Run("version", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := cli(context.Background(), []string{"version"}, &out, &errOut); code != 0 ||
			out.String() != version+"\n" || errOut.Len() != 0 {
			t.Fatalf("version: stdout %q, stderr %q, code %d", out.String(), errOut.String(), code)
		}
	})
}

func TestCLISelectionErrors(t *testing.T) {
	path, _ := cliConfig(t, "exit 0\n")
	for _, tt := range []struct {
		args    []string
		message string
	}{
		{[]string{"--only", "invalid"}, "only must be"},
		{[]string{"--application", "missing"}, "unknown application"},
		{[]string{"--application", "app", "--only", "hbom"}, "no enabled collectors"},
	} {
		var out, errOut bytes.Buffer
		args := append([]string{"scan", "--config", path}, tt.args...)
		if code := cli(context.Background(), args, &out, &errOut); code != 2 ||
			!strings.Contains(errOut.String(), tt.message) || out.Len() != 0 {
			t.Errorf("cli(%q) = %d, stdout %q, stderr %q", args, code, out.String(), errOut.String())
		}
	}
}

func TestCLIDoctor(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	path, output := cliConfig(t, "printf executed > '"+marker+"'\n")
	var out, errOut bytes.Buffer
	code := cli(context.Background(), []string{
		"doctor", "--config", path, "--application", "app", "--only", "sbom",
	}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "READY app/sbom") ||
		strings.Contains(out.String(), "host/") || errOut.Len() != 0 {
		t.Fatalf("doctor = %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	for _, path := range []string{marker, output} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("doctor must not execute collectors or create output: %s: %v", path, err)
		}
	}
	// Remove the collector, leaving the configuration intact, to exercise readiness failure.
	if err := os.Remove(filepath.Join(filepath.Dir(path), "collector")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := cli(context.Background(), []string{"doctor", "--config", path}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "FAIL host/hbom") || !strings.Contains(out.String(), "FAIL app/sbom") {
		t.Fatalf("failed doctor = %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

func TestCLIScan(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"example","version":"1.0.0"}]}`
	for _, tt := range []struct {
		name, body string
		code       int
	}{
		{"success", "printf '%s' '" + bom + "'\n", 0},
		{"empty output", "exit 0\n", 1},
		{"malformed output", "printf '{'\n", 1},
		{"collector error", "exit 4\n", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, output := cliConfig(t, tt.body)
			var out, errOut bytes.Buffer
			code := cli(context.Background(), []string{
				"scan", "--config", path, "--application", "app", "--only", "sbom",
			}, &out, &errOut)
			if code != tt.code {
				t.Fatalf("scan = %d, stdout %q, stderr %q", code, out.String(), errOut.String())
			}
			dir := strings.TrimSpace(out.String())
			if filepath.Dir(dir) != output {
				t.Fatalf("scan stdout must identify run directory: %q", out.String())
			}
			data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest run.Manifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatal(err)
			}
			if len(manifest.Results) != 1 || manifest.Results[0].Name != "app" || manifest.Results[0].Kind != "sbom" {
				t.Fatalf("selection not respected: %+v", manifest)
			}
			if tt.code == 0 {
				if manifest.Results[0].Status != "collected" || errOut.Len() != 0 {
					t.Fatalf("unexpected successful scan: %+v, stderr %q", manifest, errOut.String())
				}
			} else if manifest.Results[0].Status != "failed" ||
				!strings.Contains(errOut.String(), "one or more collectors failed") {
				t.Fatalf("unexpected failed scan: %+v, stderr %q", manifest, errOut.String())
			}
		})
	}
}
