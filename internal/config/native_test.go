package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"codeberg.org/Poellebob/bommer/internal/collect"
	"codeberg.org/Poellebob/bommer/internal/config"
	"gopkg.in/yaml.v3"
)

func loadNativeConfig(t *testing.T, cfg config.Config) (config.Config, error) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return config.Load(path)
}

func nativeConfig() config.Config {
	var cfg config.Config
	cfg.Version = 1
	cfg.Output.Directory = "/tmp/bommer-native-tests"
	return cfg
}

func TestNativeNamedInventoriesAndLegacySelection(t *testing.T) {
	cfg := nativeConfig()
	command := config.Collector{Enabled: true, Backend: "command", Command: []string{"scanner", "{target}"}}
	certificates := config.Collector{Enabled: true, Backend: "certificates", Certificates: &config.CertificateOptions{Paths: []string{"/etc/ssl/certs"}}}
	cfg.Host.HBOM = command
	cfg.Host.SBOM = command
	cfg.Host.Inventories = []config.Inventory{
		{Name: "hbom", Kind: "hbom", Collector: command},
		{Name: "certs", Kind: "cbom", Collector: certificates},
		{Name: "off", Kind: "cbom", Collector: config.Collector{Backend: "unknown", Import: &config.ImportOptions{}}},
	}
	cfg.Applications = []config.Application{{
		Name: "api", Version: "2.3", Target: config.Target{Type: "directory", Path: "/srv/api"}, SBOM: command, CBOM: command,
		Inventories: []config.Inventory{
			{Name: "cbom", Kind: "cbom", Collector: certificates},
			{Name: "certs", Kind: "cbom", Collector: certificates},
			{Name: "off", Kind: "sbom", Collector: config.Collector{Backend: "unknown"}},
		},
	}}
	loaded, err := loadNativeConfig(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Timeout != "10m" || loaded.Host.Inventories[1].Collector.Certificates.MaxFileBytes != 0 || loaded.Host.Inventories[1].Collector.Certificates.IncludeIdentity {
		t.Fatalf("unexpected defaults: %+v", loaded)
	}
	for _, tt := range []struct {
		name, only, app string
		stems           []string
	}{
		{"all", "", "", []string{"host.hbom", "host.sbom", "host.hbom.hbom", "host.certs.cbom", "api.sbom", "api.cbom", "api.cbom.cbom", "api.certs.cbom"}},
		{"kind", "cbom", "", []string{"host.certs.cbom", "api.cbom", "api.cbom.cbom", "api.certs.cbom"}},
		{"application", "", "api", []string{"api.sbom", "api.cbom", "api.cbom.cbom", "api.certs.cbom"}},
		{"both", "cbom", "api", []string{"api.cbom", "api.cbom.cbom", "api.certs.cbom"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			jobs, err := collect.Jobs(loaded, tt.only, tt.app)
			if err != nil {
				t.Fatal(err)
			}
			var stems []string
			seen := map[string]bool{}
			for _, job := range jobs {
				stem := job.Stem()
				if seen[stem] {
					t.Errorf("artifact collision: %s", stem)
				}
				seen[stem] = true
				stems = append(stems, stem)
				if job.Name == "host" {
					if job.Scope != "host" || !job.IsHost() {
						t.Errorf("invalid host scope: %+v", job)
					}
				} else if job.Scope != "application" || job.Target != "/srv/api" || job.Version != "2.3" || job.TargetType != "directory" {
					t.Errorf("application metadata lost: %+v", job)
				}
			}
			if !reflect.DeepEqual(stems, tt.stems) {
				t.Fatalf("stems = %v, want %v", stems, tt.stems)
			}
		})
	}
	cfg.Host.HBOM.Enabled = false
	cfg.Host.SBOM.Enabled = false
	cfg.Host.Inventories = nil
	cfg.Applications = nil
	loaded, err = loadNativeConfig(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collect.Jobs(loaded, "", ""); err == nil {
		t.Fatal("no enabled inventories must fail selection")
	}
}

func TestNativeInventoryNames(t *testing.T) {
	for _, host := range []bool{true, false} {
		for _, tt := range []struct {
			name, kind string
			duplicate  bool
		}{
			{"", "cbom", false}, {"../certs", "cbom", false}, {"a.b", "cbom", false},
			{"a/b", "cbom", false}, {"a b", "cbom", false}, {"-certs", "cbom", false},
			{"certs", "unknown", false}, {"certs", "cbom", true},
		} {
			t.Run(strings.Join([]string{map[bool]string{true: "host", false: "application"}[host], tt.name, tt.kind}, "/"), func(t *testing.T) {
				cfg := nativeConfig()
				// Disabled collectors still require valid inventory identities.
				inventories := []config.Inventory{{Name: tt.name, Kind: tt.kind}}
				if tt.duplicate {
					inventories = append(inventories, inventories[0])
				}
				if host {
					cfg.Host.Inventories = inventories
				} else {
					cfg.Applications = []config.Application{{Name: "api", Target: config.Target{Type: "directory", Path: "/srv/api"}, Inventories: inventories}}
				}
				if _, err := loadNativeConfig(t, cfg); err == nil {
					t.Fatal("invalid inventory accepted")
				}
			})
		}
	}
}

func TestNativeBackendOptionsAndScopes(t *testing.T) {
	certs := func(paths ...string) config.Collector {
		return config.Collector{Enabled: true, Backend: "certificates", Certificates: &config.CertificateOptions{Paths: paths}}
	}
	nix := func(roots ...string) config.Collector {
		return config.Collector{Enabled: true, Backend: "nix", Nix: &config.NixOptions{Roots: roots}}
	}
	imported := config.Collector{Enabled: true, Backend: "import", Import: &config.ImportOptions{Path: "/tmp/cbom.json"}}
	for _, tt := range []struct {
		name, kind, target, wantError string
		host                          bool
		collector                     config.Collector
	}{
		{"host certificates", "cbom", "", "", true, certs("/etc/ssl")},
		{"relative host certificates", "cbom", "", "must be absolute", true, certs("certs")},
		{"application relative certificates", "cbom", "directory", "", false, certs("certs")},
		{"application absolute certificates", "cbom", "directory", "", false, certs("/etc/ssl")},
		{"container certificates", "cbom", "container", "not a container", false, certs("/etc/ssl")},
		{"closure certificates", "cbom", "nix-closure", "", false, certs("certs")},
		{"missing certificates", "cbom", "directory", "certificates.paths", false, config.Collector{Enabled: true, Backend: "certificates"}},
		{"empty certificate paths", "cbom", "directory", "certificates.paths", false, certs()},
		{"empty certificate path", "cbom", "directory", "must not be empty", false, certs("")},
		{"host nix roots", "sbom", "", "", true, nix("/nix/var/nix/profiles/system")},
		{"host nix missing roots", "sbom", "", "requires nix.roots", true, nix()},
		{"relative nix root", "sbom", "nix-closure", "absolute local paths", false, nix("result")},
		{"closure target default root", "sbom", "nix-closure", "", false, config.Collector{Enabled: true, Backend: "nix"}},
		{"directory nix", "sbom", "directory", "nix-closure", false, nix("/nix/store/example")},
		{"container nix", "sbom", "container", "nix-closure", false, nix("/nix/store/example")},
		{"closure syft", "sbom", "nix-closure", "nix-closure targets require", false, config.Collector{Enabled: true, Backend: "syft"}},
		{"closure command", "cbom", "nix-closure", "nix-closure targets require", false, config.Collector{Enabled: true, Backend: "command", Command: []string{"scanner"}}},
		{"closure import", "cbom", "nix-closure", "", false, imported},
		{"container import", "cbom", "container", "", false, imported},
		{"host import", "cbom", "", "", true, imported},
		{"missing import options", "cbom", "directory", "import.path", false, config.Collector{Enabled: true, Backend: "import"}},
		{"empty import path", "cbom", "directory", "import.path", false, config.Collector{Enabled: true, Backend: "import", Import: &config.ImportOptions{}}},
		{"certificates wrong kind", "sbom", "directory", "unsupported sbom", false, certs("certs")},
		{"nix wrong kind", "cbom", "nix-closure", "unsupported cbom", false, nix()},
		{"import wrong kind", "sbom", "directory", "unsupported sbom", false, imported},
		{"application hbom", "hbom", "directory", "requires a host", false, config.Collector{Enabled: true, Backend: "hbom"}},
		{"mismatched nix options", "cbom", "directory", "options must match", false, config.Collector{Enabled: true, Backend: "import", Import: imported.Import, Nix: &config.NixOptions{}}},
		{"mismatched certificate options", "sbom", "directory", "options must match", false, config.Collector{Enabled: true, Backend: "syft", Certificates: &config.CertificateOptions{}}},
		{"mismatched import options", "sbom", "nix-closure", "options must match", false, config.Collector{Enabled: true, Backend: "nix", Import: imported.Import}},
		{"native command override", "cbom", "directory", "command is only allowed", false, config.Collector{Enabled: true, Backend: "import", Import: imported.Import, Command: []string{"scanner"}}},
		{"native excludes", "cbom", "directory", "require the syft", false, config.Collector{Enabled: true, Backend: "import", Import: imported.Import, Exclude: []string{"secret"}}},
		{"native gitignore", "sbom", "nix-closure", "require the syft", false, config.Collector{Enabled: true, Backend: "nix", RespectGitignore: true}},
		{"disabled invalid backend options", "cbom", "container", "", false, config.Collector{Backend: "unknown", Certificates: &config.CertificateOptions{Paths: []string{""}, MaxFileBytes: -1}, Nix: &config.NixOptions{}, Import: &config.ImportOptions{}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := nativeConfig()
			inventory := config.Inventory{Name: "native", Kind: tt.kind, Collector: tt.collector}
			if tt.host {
				cfg.Host.Inventories = []config.Inventory{inventory}
			} else {
				target := config.Target{Type: tt.target, Path: "/srv/api"}
				if tt.target == "container" {
					target.Path, target.Image = "", "example/api:1"
				}
				cfg.Applications = []config.Application{{Name: "api", Target: target, Inventories: []config.Inventory{inventory}}}
			}
			_, err := loadNativeConfig(t, cfg)
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want %q", err, tt.wantError)
			}
		})
	}
	for _, limit := range []int64{-1, 0, 1, 64 << 20, (64 << 20) + 1} {
		cfg := nativeConfig()
		collector := certs("/etc/ssl")
		collector.Certificates.MaxFileBytes = limit
		cfg.Host.Inventories = []config.Inventory{{Name: "certs", Kind: "cbom", Collector: collector}}
		if _, err := loadNativeConfig(t, cfg); (err == nil) != (limit >= 0 && limit <= 64<<20) {
			t.Errorf("certificate limit %d: error = %v", limit, err)
		}
	}
	for _, target := range []config.Target{{Type: "nix-closure"}, {Type: "nix-closure", Path: "/result", Image: "image"}} {
		cfg := nativeConfig()
		cfg.Applications = []config.Application{{Name: "api", Target: target}}
		if _, err := loadNativeConfig(t, cfg); err == nil {
			t.Errorf("invalid nix target accepted: %+v", target)
		}
	}
}
