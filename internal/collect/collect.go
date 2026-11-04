package collect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"codeberg.org/Poellebob/bommer/internal/config"
)

type Job struct {
	Name      string
	Kind      string
	Target    string
	Collector config.Collector
}

// Jobs selects enabled inventories, excluding host jobs when an application is selected.
func Jobs(cfg config.Config, only, application string) ([]Job, error) {
	if only != "" && only != "hbom" && only != "sbom" && only != "cbom" {
		return nil, fmt.Errorf("only must be hbom, sbom, or cbom")
	}

	var jobs []Job
	addJob := func(name, kind, target string, collector config.Collector) {
		if collector.Enabled && (only == "" || only == kind) {
			jobs = append(jobs, Job{
				Name:      name,
				Kind:      kind,
				Target:    target,
				Collector: collector,
			})
		}
	}

	if application == "" {
		addJob("host", "hbom", "", cfg.Host.HBOM)
		addJob("host", "sbom", "dir:/", cfg.Host.SBOM)
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
		addJob(app.Name, "sbom", target, app.SBOM)
		addJob(app.Name, "cbom", target, app.CBOM)
	}

	if !foundApplication {
		return nil, fmt.Errorf("unknown application %q", application)
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("no enabled collectors match the selection")
	}
	return jobs, nil
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
		return []string{"syft", "scan", target, "-o", "cyclonedx-json"}
	default:
		args := append([]string(nil), job.Collector.Command...)
		for i := 1; i < len(args); i++ {
			args[i] = strings.ReplaceAll(args[i], "{target}", job.Target)
		}
		return args
	}
}

// Check verifies local prerequisites without executing the collector.
func (job Job) Check() error {
	if _, err := exec.LookPath(job.Command()[0]); err != nil {
		return err
	}

	if job.Name == "host" && job.Kind == "sbom" && job.Collector.Backend == "syft" {
		if _, err := os.Stat("/run/current-system"); err == nil {
			return fmt.Errorf("NixOS host SBOM requires an explicit Nix-aware command backend; Syft is not a system-closure inventory")
		}
	}

	if job.Target != "" && !strings.HasPrefix(job.Target, "registry:") && job.Name != "host" {
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
