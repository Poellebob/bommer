package config

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Collector struct {
	Enabled bool     `yaml:"enabled"`
	Backend string   `yaml:"backend"`
	Command []string `yaml:"command"`
}

type Target struct {
	Type  string `yaml:"type"`
	Path  string `yaml:"path"`
	Image string `yaml:"image"`
}

type Application struct {
	Name   string    `yaml:"name"`
	Target Target    `yaml:"target"`
	SBOM   Collector `yaml:"sbom"`
	CBOM   Collector `yaml:"cbom"`
}

type Config struct {
	Version int `yaml:"version"`
	Output  struct {
		Directory string `yaml:"directory"`
	} `yaml:"output"`
	Timeout string `yaml:"timeout"`
	Host    struct {
		HBOM Collector `yaml:"hbom"`
		SBOM Collector `yaml:"sbom"`
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

	if err := validateCollector(cfg.Host.HBOM, "hbom"); err != nil {
		return fmt.Errorf("host.hbom: %w", err)
	}
	if err := validateCollector(cfg.Host.SBOM, "sbom"); err != nil {
		return fmt.Errorf("host.sbom: %w", err)
	}

	seenNames := map[string]bool{"host": true}
	for _, app := range cfg.Applications {
		if !namePattern.MatchString(app.Name) || seenNames[app.Name] {
			return fmt.Errorf("application name %q must be unique, filename-safe, and not 'host'", app.Name)
		}
		seenNames[app.Name] = true

		switch app.Target.Type {
		case "directory":
			if app.Target.Path == "" || app.Target.Image != "" {
				return fmt.Errorf("application %s requires target.path and no target.image", app.Name)
			}
		case "container":
			if app.Target.Image == "" || app.Target.Path != "" {
				return fmt.Errorf("application %s requires target.image and no target.path", app.Name)
			}
		default:
			return fmt.Errorf("application %s: target.type must be directory or container", app.Name)
		}

		if err := validateCollector(app.SBOM, "sbom"); err != nil {
			return fmt.Errorf("application %s sbom: %w", app.Name, err)
		}
		if err := validateCollector(app.CBOM, "cbom"); err != nil {
			return fmt.Errorf("application %s cbom: %w", app.Name, err)
		}
	}
	return nil
}

func validateCollector(collector Collector, kind string) error {
	if !collector.Enabled {
		return nil
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
	if kind == "hbom" && collector.Backend == "hbom" {
		return nil
	}
	if kind == "sbom" && collector.Backend == "syft" {
		return nil
	}
	return fmt.Errorf("unsupported %s backend %q (use command for an external collector)", kind, collector.Backend)
}
