package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Collector struct {
	Enabled          bool                `yaml:"enabled"`
	Backend          string              `yaml:"backend"`
	Command          []string            `yaml:"command"`
	Exclude          []string            `yaml:"exclude"`
	RespectGitignore bool                `yaml:"respect_gitignore"`
	Nix              *NixOptions         `yaml:"nix"`
	Certificates     *CertificateOptions `yaml:"certificates"`
	Import           *ImportOptions      `yaml:"import"`
}

type NixOptions struct {
	Roots []string `yaml:"roots"`
}

type CertificateOptions struct {
	Paths           []string `yaml:"paths"`
	MaxFileBytes    int64    `yaml:"max_file_bytes"`
	IncludeIdentity bool     `yaml:"include_identity"`
}

type ImportOptions struct {
	Path string `yaml:"path"`
}

type Inventory struct {
	Name      string    `yaml:"name"`
	Kind      string    `yaml:"kind"`
	Collector Collector `yaml:"collector"`
}

type Target struct {
	Type  string `yaml:"type"`
	Path  string `yaml:"path"`
	Image string `yaml:"image"`
}

type Application struct {
	Name        string      `yaml:"name"`
	Version     string      `yaml:"version"`
	Target      Target      `yaml:"target"`
	SBOM        Collector   `yaml:"sbom"`
	CBOM        Collector   `yaml:"cbom"`
	Inventories []Inventory `yaml:"inventories"`
}

type Config struct {
	Version int `yaml:"version"`
	Output  struct {
		Directory string `yaml:"directory"`
	} `yaml:"output"`
	Timeout string `yaml:"timeout"`
	Host    struct {
		HBOM        Collector   `yaml:"hbom"`
		SBOM        Collector   `yaml:"sbom"`
		Inventories []Inventory `yaml:"inventories"`
	} `yaml:"host"`
	Applications []Application `yaml:"applications"`
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func Load(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return cfg, fmt.Errorf("configuration must contain exactly one YAML document")
	}

	if cfg.Timeout == "" {
		cfg.Timeout = "10m"
	}
	return cfg, cfg.Validate()
}

func (cfg Config) Validate() error {
	if cfg.Version != 1 {
		return fmt.Errorf("version must be 1")
	}
	if cfg.Output.Directory == "" {
		return fmt.Errorf("output.directory is required")
	}

	duration, err := time.ParseDuration(cfg.Timeout)
	if err != nil || duration <= 0 {
		return fmt.Errorf("timeout must be a positive duration")
	}

	if err := validateScope(cfg.Host.HBOM, "hbom", "", true); err != nil {
		return fmt.Errorf("host.hbom: %w", err)
	}
	if err := validateScope(cfg.Host.SBOM, "sbom", "", true); err != nil {
		return fmt.Errorf("host.sbom: %w", err)
	}
	if err := validateInventories(cfg.Host.Inventories, "", true); err != nil {
		return fmt.Errorf("host.inventories: %w", err)
	}

	seenNames := map[string]bool{"host": true}
	for _, app := range cfg.Applications {
		if !namePattern.MatchString(app.Name) || seenNames[app.Name] {
			return fmt.Errorf("application name %q must be unique, filename-safe, and not 'host'", app.Name)
		}
		seenNames[app.Name] = true

		switch app.Target.Type {
		case "directory", "nix-closure":
			if app.Target.Path == "" || app.Target.Image != "" {
				return fmt.Errorf("application %s requires target.path and no target.image", app.Name)
			}
		case "container":
			if app.Target.Image == "" || app.Target.Path != "" {
				return fmt.Errorf("application %s requires target.image and no target.path", app.Name)
			}
		default:
			return fmt.Errorf("application %s: target.type must be directory, container, or nix-closure", app.Name)
		}

		if err := validateScope(app.SBOM, "sbom", app.Target.Type, false); err != nil {
			return fmt.Errorf("application %s sbom: %w", app.Name, err)
		}
		if err := validateScope(app.CBOM, "cbom", app.Target.Type, false); err != nil {
			return fmt.Errorf("application %s cbom: %w", app.Name, err)
		}
		if err := validateInventories(app.Inventories, app.Target.Type, false); err != nil {
			return fmt.Errorf("application %s inventories: %w", app.Name, err)
		}
	}
	return nil
}

func validateInventories(inventories []Inventory, targetType string, host bool) error {
	seen := map[string]bool{}
	for _, inventory := range inventories {
		if !namePattern.MatchString(inventory.Name) || seen[inventory.Name] {
			return fmt.Errorf("inventory name %q must be unique and filename-safe", inventory.Name)
		}
		seen[inventory.Name] = true
		if inventory.Kind != "hbom" && inventory.Kind != "sbom" && inventory.Kind != "cbom" {
			return fmt.Errorf("inventory %s kind must be hbom, sbom, or cbom", inventory.Name)
		}
		if err := validateScope(inventory.Collector, inventory.Kind, targetType, host); err != nil {
			return fmt.Errorf("inventory %s: %w", inventory.Name, err)
		}
	}
	return nil
}

func validateScope(collector Collector, kind, targetType string, host bool) error {
	if err := validateCollector(collector, kind); err != nil || !collector.Enabled {
		return err
	}
	if collector.RespectGitignore && (host || targetType != "directory") {
		return fmt.Errorf("respect_gitignore is only supported for application directories")
	}
	if collector.Backend == "hbom" && !host {
		return fmt.Errorf("hbom requires a host inventory")
	}
	if collector.Backend == "nix" {
		if !host && targetType != "nix-closure" {
			return fmt.Errorf("nix requires a nix-closure application target")
		}
		if host && (collector.Nix == nil || len(collector.Nix.Roots) == 0) {
			return fmt.Errorf("host nix inventory requires nix.roots")
		}
	}
	if collector.Backend == "certificates" {
		if targetType == "container" {
			return fmt.Errorf("certificates requires local paths, not a container target")
		}
		for _, path := range collector.Certificates.Paths {
			if host && !filepath.IsAbs(path) {
				return fmt.Errorf("host certificate paths must be absolute")
			}
		}
	}
	if targetType == "nix-closure" && collector.Backend != "nix" && collector.Backend != "certificates" && collector.Backend != "import" {
		return fmt.Errorf("nix-closure targets require nix, certificates, or import backends")
	}
	return nil
}

func validateCollector(collector Collector, kind string) error {
	if !collector.Enabled {
		return nil
	}
	if (collector.Nix != nil && collector.Backend != "nix") ||
		(collector.Certificates != nil && collector.Backend != "certificates") ||
		(collector.Import != nil && collector.Backend != "import") {
		return fmt.Errorf("backend-specific options must match the selected backend")
	}
	if (len(collector.Exclude) > 0 || collector.RespectGitignore) && (kind != "sbom" || collector.Backend != "syft") {
		return fmt.Errorf("exclude and respect_gitignore require the syft SBOM backend")
	}
	for _, pattern := range collector.Exclude {
		if pattern == "" {
			return fmt.Errorf("exclude patterns must not be empty")
		}
	}

	if collector.Backend == "command" {
		if len(collector.Command) == 0 || collector.Command[0] == "" {
			return fmt.Errorf("command backend requires an executable and arguments")
		}
		return nil
	}

	if len(collector.Command) > 0 {
		return fmt.Errorf("command is only allowed with backend: command")
	}
	if kind == "sbom" && collector.Backend == "nix" {
		if collector.Nix != nil {
			for _, root := range collector.Nix.Roots {
				if !filepath.IsAbs(root) {
					return fmt.Errorf("nix.roots must contain absolute local paths")
				}
			}
		}
		return nil
	}
	if kind == "cbom" && collector.Backend == "certificates" {
		options := collector.Certificates
		if options == nil || len(options.Paths) == 0 {
			return fmt.Errorf("certificates.paths is required")
		}
		for _, path := range options.Paths {
			if path == "" {
				return fmt.Errorf("certificate paths must not be empty")
			}
		}
		if options.MaxFileBytes < 0 || options.MaxFileBytes > 64<<20 {
			return fmt.Errorf("certificates.max_file_bytes must be between 0 (default) and 67108864")
		}
		return nil
	}
	if kind == "cbom" && collector.Backend == "import" {
		if collector.Import == nil || collector.Import.Path == "" {
			return fmt.Errorf("import.path is required")
		}
		return nil
	}
	if kind == "hbom" && collector.Backend == "hbom" {
		return nil
	}
	if kind == "sbom" && collector.Backend == "syft" {
		return nil
	}
	return fmt.Errorf("unsupported %s backend %q (use command for an external collector)", kind, collector.Backend)
}
