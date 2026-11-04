package collect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeberg.org/Poellebob/bommer/internal/config"
)

type Job struct {
	Name       string
	Version    string
	Kind       string
	Target     string
	TargetType string
	Scope      string
	Inventory  string
	Collector  config.Collector
}

// Jobs selects enabled inventories, excluding host jobs when an application is selected.
func Jobs(cfg config.Config, only, application string) ([]Job, error) {
	if only != "" && only != "hbom" && only != "sbom" && only != "cbom" {
		return nil, fmt.Errorf("only must be hbom, sbom, or cbom")
	}

	var jobs []Job
	addJob := func(job Job) {
		if job.Collector.Enabled && (only == "" || only == job.Kind) {
			jobs = append(jobs, job)
		}
	}

	if application == "" {
		addJob(Job{Name: "host", Kind: "hbom", Scope: "host", Collector: cfg.Host.HBOM})
		addJob(Job{
			Name:       "host",
			Kind:       "sbom",
			Target:     "dir:/",
			TargetType: "directory",
			Scope:      "host",
			Collector:  cfg.Host.SBOM,
		})
		for _, inventory := range cfg.Host.Inventories {
			target := ""
			if inventory.Kind == "sbom" && inventory.Collector.Backend != "nix" {
				target = "dir:/"
			}
			addJob(Job{
				Name:      "host",
				Kind:      inventory.Kind,
				Target:    target,
				Scope:     "host",
				Inventory: inventory.Name,
				Collector: inventory.Collector,
			})
		}
	}

	foundApplication := application == ""
	for _, app := range cfg.Applications {
		if application != "" && application != app.Name {
			continue
		}
		foundApplication = true

		target := app.Target.Path
		if app.Target.Type == "container" {
			target = "registry:" + app.Target.Image
		}
		addJob(Job{
			Name:       app.Name,
			Version:    app.Version,
			Kind:       "sbom",
			Target:     target,
			TargetType: app.Target.Type,
			Scope:      "application",
			Collector:  app.SBOM,
		})
		addJob(Job{
			Name:       app.Name,
			Version:    app.Version,
			Kind:       "cbom",
			Target:     target,
			TargetType: app.Target.Type,
			Scope:      "application",
			Collector:  app.CBOM,
		})
		for _, inventory := range app.Inventories {
			addJob(Job{
				Name:       app.Name,
				Version:    app.Version,
				Kind:       inventory.Kind,
				Target:     target,
				TargetType: app.Target.Type,
				Scope:      "application",
				Inventory:  inventory.Name,
				Collector:  inventory.Collector,
			})
		}
	}

	if !foundApplication {
		return nil, fmt.Errorf("unknown application %q", application)
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("no enabled collectors match the selection")
	}
	return jobs, nil
}

func (job Job) IsHost() bool {
	return job.Scope == "host" || (job.Scope == "" && job.Name == "host")
}

// Stem retains legacy artifact names while giving named inventories their own namespace.
func (job Job) Stem() string {
	if job.Inventory != "" {
		return job.Name + "." + job.Inventory + "." + job.Kind
	}
	return job.Name + "." + job.Kind
}

// Command returns an executable and arguments without invoking a shell.
// External collectors must write only CycloneDX JSON to stdout.
func (job Job) Command() []string {
	switch job.Collector.Backend {
	case "hbom":
		return []string{"hbom", "-p"}
	case "syft":
		target := job.Target
		if !strings.HasPrefix(target, "registry:") && !strings.HasPrefix(target, "dir:") {
			target = "dir:" + target
		}
		args := []string{"syft", "scan", target, "-o", "cyclonedx-json"}
		if job.Name != "" && !job.IsHost() {
			args = append(args, "--source-name", job.Name)
			if job.Version != "" {
				args = append(args, "--source-version", job.Version)
			}
		}
		for _, pattern := range job.Collector.Exclude {
			args = append(args, "--exclude", pattern)
		}
		return args
	default:
		args := append([]string(nil), job.Collector.Command...)
		for i := 1; i < len(args); i++ {
			args[i] = strings.ReplaceAll(args[i], "{target}", job.Target)
		}
		return args
	}
}

// Resolve prepares certificate target paths and effective scan exclusions.
// Git evaluates nested ignore rules, negations, and tracked-file semantics for us.
func (job Job) Resolve(ctx context.Context) (Job, error) {
	if job.Collector.Backend == "certificates" && !job.IsHost() {
		var err error
		if job.TargetType == "nix-closure" {
			job.Target, err = nixResolveRoot(job.Target)
		} else {
			for _, part := range strings.Split(job.Target, string(os.PathSeparator)) {
				if part == ".." {
					return job, fmt.Errorf("certificate application targets must not contain parent traversal")
				}
			}
			job.Target, err = filepath.Abs(job.Target)
		}
		if err != nil {
			return job, err
		}
	}
	if !job.Collector.RespectGitignore {
		return job, nil
	}

	cmd := exec.CommandContext(ctx, "git", "-C", job.Target, "ls-files",
		"--others", "--ignored", "--exclude-standard", "--directory", "-z")
	output, err := cmd.Output()
	if err != nil {
		return job, fmt.Errorf("resolve Git ignores (target must be a Git working tree): %w", err)
	}

	patterns := append([]string(nil), job.Collector.Exclude...)
	// Git metadata is not an ignored worktree path, but is never application content.
	patterns = append(patterns, "./.git", "./.git/**")
	escapeGlob := strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`, "{", `\{`, "}", `\}`)
	for _, path := range strings.Split(string(output), "\x00") {
		if path == "" {
			continue
		}
		pattern := "./" + escapeGlob.Replace(strings.TrimSuffix(path, "/"))
		if strings.HasSuffix(path, "/") {
			pattern += "/**"
		}
		patterns = append(patterns, pattern)
	}
	job.Collector.Exclude = nil
	seen := make(map[string]bool, len(patterns))
	for _, pattern := range patterns {
		if !seen[pattern] {
			job.Collector.Exclude = append(job.Collector.Exclude, pattern)
			seen[pattern] = true
		}
	}
	return job, nil
}

// Check verifies local prerequisites without executing the collector.
func (job Job) Check() error {
	if job.IsNative() {
		switch job.Collector.Backend {
		case "nix":
			if _, err := exec.LookPath("nix"); err != nil {
				return err
			}
			var roots []string
			if job.Collector.Nix != nil {
				roots = job.Collector.Nix.Roots
			}
			if len(roots) == 0 && !job.IsHost() {
				roots = []string{job.Target}
			}
			if len(roots) == 0 {
				return fmt.Errorf("Nix inventory requires local closure roots")
			}
			for _, root := range roots {
				if _, err := nixResolveRoot(root); err != nil {
					return err
				}
			}
		case "import":
			if job.Collector.Import == nil {
				return fmt.Errorf("import.path is required")
			}
			info, err := os.Stat(job.Collector.Import.Path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() > 64<<20 {
				return fmt.Errorf("import must be a regular file no larger than 64 MiB")
			}
		case "certificates":
			if job.Collector.Certificates == nil || len(job.Collector.Certificates.Paths) == 0 {
				return fmt.Errorf("certificate paths are required")
			}
		}
		return nil
	}
	if _, err := exec.LookPath(job.Command()[0]); err != nil {
		return err
	}
	if job.Collector.RespectGitignore {
		if _, err := exec.LookPath("git"); err != nil {
			return fmt.Errorf("respect_gitignore requires Git: %w", err)
		}
	}

	if job.IsHost() && job.Kind == "sbom" && job.Collector.Backend == "syft" {
		if _, err := os.Stat("/run/current-system"); err == nil {
			return fmt.Errorf("NixOS host SBOM requires an explicit Nix-aware command backend; Syft is not a system-closure inventory")
		}
	}

	if job.Target != "" && !strings.HasPrefix(job.Target, "registry:") && !job.IsHost() {
		info, err := os.Stat(job.Target)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("target must be a directory")
		}
	}
	return nil
}
