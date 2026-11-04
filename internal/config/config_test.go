package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStrictYAML(t *testing.T) {
	const valid = "version: 1\noutput:\n  directory: /tmp/bommer\n"
	for _, tt := range []struct {
		name, data, wantError string
	}{
		{"valid defaults", valid, ""},
		{"explicit timeout", valid + "timeout: 3s\n", ""},
		{"unknown top level", valid + "unexpected: true\n", "field unexpected"},
		{"unknown nested field", "version: 1\noutput:\n  directory: /tmp/bommer\n  typo: true\n", "field typo"},
		{"unknown collector field", valid + "host:\n  hbom:\n    enable: true\n", "field enable"},
		{"duplicate key", valid + "version: 1\n", "already defined"},
		{"second document", valid + "---\nversion: 1\n", "exactly one YAML document"},
		{"empty second document", valid + "---\n", "exactly one YAML document"},
		{"malformed YAML", "version: [", "yaml:"},
		{"empty file", "", "EOF"},
		{"wrong type", "version: nope\noutput:\n  directory: /tmp/bommer\n", "cannot unmarshal"},
		{"wrong version", "version: 2\noutput:\n  directory: /tmp/bommer\n", "version must be 1"},
		{"missing output", "version: 1\n", "output.directory"},
		{"zero timeout", valid + "timeout: 0s\n", "positive duration"},
		{"negative timeout", valid + "timeout: -1s\n", "positive duration"},
		{"invalid timeout", valid + "timeout: tomorrow\n", "positive duration"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("Load() error = %v, want containing %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := "10m"
			if tt.name == "explicit timeout" {
				want = "3s"
			}
			if cfg.Timeout != want || cfg.Output.Directory != "/tmp/bommer" {
				t.Fatalf("unexpected config: %+v", cfg)
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
			t.Fatalf("Load() error = %v, want not-exist", err)
		}
	})
}

func testConfig() Config {
	var cfg Config
	cfg.Version = 1
	cfg.Output.Directory = "/tmp/bommer"
	cfg.Timeout = "1s"
	return cfg
}

func TestApplicationNames(t *testing.T) {
	for _, tt := range []struct {
		name  string
		names []string
		valid bool
	}{
		{"safe names", []string{"api", "App_2", "3-worker"}, true},
		{"duplicate", []string{"api", "api"}, false},
		{"reserved", []string{"host"}, false},
		{"empty", []string{""}, false},
		{"traversal", []string{"../api"}, false},
		{"slash", []string{"a/b"}, false},
		{"space", []string{"my app"}, false},
		{"leading dash", []string{"-api"}, false},
		{"dot", []string{"api.prod"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			for _, name := range tt.names {
				cfg.Applications = append(cfg.Applications, Application{
					Name: name,
					Target: Target{
						Type: "directory",
						Path: "/app",
					},
				})
			}
			err := cfg.Validate()
			if (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

func TestTargetValidation(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target Target
		valid  bool
	}{
		{"directory", Target{Type: "directory", Path: "/app"}, true},
		{"container", Target{Type: "container", Image: "example/app:v1"}, true},
		{"directory missing path", Target{Type: "directory"}, false},
		{"directory with image", Target{Type: "directory", Path: "/app", Image: "app"}, false},
		{"container missing image", Target{Type: "container"}, false},
		{"container with path", Target{Type: "container", Image: "app", Path: "/app"}, false},
		{"unknown", Target{Type: "file", Path: "/app"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Applications = []Application{
				{Name: "app", Target: tt.target},
			}
			if err := cfg.Validate(); (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

func TestBackendCapabilities(t *testing.T) {
	for _, slot := range []string{"host.hbom", "host.sbom", "app.sbom", "app.cbom"} {
		for _, tt := range []struct {
			name      string
			collector Collector
		}{
			{"hbom", Collector{Enabled: true, Backend: "hbom"}},
			{"syft", Collector{Enabled: true, Backend: "syft"}},
			{
				"command",
				Collector{
					Enabled: true,
					Backend: "command",
					Command: []string{"scanner", "{target}"},
				},
			},
			{"empty command", Collector{Enabled: true, Backend: "command"}},
			{
				"empty executable",
				Collector{
					Enabled: true,
					Backend: "command",
					Command: []string{"", "arg"},
				},
			},
			{
				"builtin command override",
				Collector{
					Enabled: true,
					Backend: "syft",
					Command: []string{"scanner"},
				},
			},
			{"unknown", Collector{Enabled: true, Backend: "unknown"}},
			{"missing backend", Collector{Enabled: true}},
			{"disabled", Collector{Backend: "unknown"}},
		} {
			t.Run(slot+"/"+tt.name, func(t *testing.T) {
				cfg := testConfig()
				cfg.Applications = []Application{
					{
						Name: "app",
						Target: Target{
							Type: "directory",
							Path: "/app",
						},
					},
				}
				switch slot {
				case "host.hbom":
					cfg.Host.HBOM = tt.collector
				case "host.sbom":
					cfg.Host.SBOM = tt.collector
				case "app.sbom":
					cfg.Applications[0].SBOM = tt.collector
				case "app.cbom":
					cfg.Applications[0].CBOM = tt.collector
				}
				valid := tt.name == "disabled" || tt.name == "command" ||
					(tt.name == "hbom" && slot == "host.hbom") ||
					(tt.name == "syft" && (slot == "host.sbom" || slot == "app.sbom"))
				if err := cfg.Validate(); (err == nil) != valid {
					t.Fatalf("Validate() = %v, valid = %v", err, valid)
				}
			})
		}
	}
}

func TestScanOptions(t *testing.T) {
	for _, tt := range []struct {
		name             string
		backend          string
		kind             string
		targetType       string
		exclude          []string
		respectGitignore bool
		valid            bool
	}{
		{"directory ignores", "syft", "sbom", "directory", []string{"./dist/**"}, true, true},
		{"container exclusions", "syft", "sbom", "container", []string{"/tmp/**"}, false, true},
		{"container ignores", "syft", "sbom", "container", nil, true, false},
		{"command exclusions", "command", "sbom", "directory", []string{"dist"}, false, false},
		{"command ignores", "command", "cbom", "directory", nil, true, false},
		{"empty exclusion", "syft", "sbom", "directory", []string{""}, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			app := Application{Name: "app", Version: "1.2.3", Target: Target{Type: tt.targetType}}
			if tt.targetType == "container" {
				app.Target.Image = "example/app:v1"
			} else {
				app.Target.Path = "/app"
			}
			collector := Collector{Enabled: true, Backend: tt.backend, Exclude: tt.exclude, RespectGitignore: tt.respectGitignore}
			if tt.backend == "command" {
				collector.Command = []string{"scanner"}
			}
			if tt.kind == "cbom" {
				app.CBOM = collector
			} else {
				app.SBOM = collector
			}
			cfg.Applications = []Application{app}
			if err := cfg.Validate(); (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v, valid = %v", err, tt.valid)
			}
		})
	}

	cfg := testConfig()
	cfg.Host.SBOM = Collector{Enabled: true, Backend: "syft", RespectGitignore: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("host Git ignores must be rejected")
	}
}
