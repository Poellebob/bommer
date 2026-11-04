package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"codeberg.org/Poellebob/bommer/internal/bom"
	"codeberg.org/Poellebob/bommer/internal/collect"
)

type Result struct {
	Name             string               `json:"name"`
	Kind             string               `json:"kind"`
	Target           string               `json:"target,omitempty"`
	SourceVersion    string               `json:"sourceVersion,omitempty"`
	Exclude          []string             `json:"exclude,omitempty"`
	RespectGitignore bool                 `json:"respectGitignore,omitempty"`
	Backend          string               `json:"backend"`
	Status           string               `json:"status"`
	Artifact         string               `json:"artifact,omitempty"`
	SHA256           string               `json:"sha256,omitempty"`
	Error            string               `json:"error,omitempty"`
	Started          time.Time            `json:"started"`
	Finished         time.Time            `json:"finished"`
	Scope            string               `json:"scope"`
	Inventory        string               `json:"inventory,omitempty"`
	SpecVersion      string               `json:"specVersion,omitempty"`
	Findings         int                  `json:"findings"`
	CollectorVersion string               `json:"collectorVersion,omitempty"`
	Diagnostics      []collect.Diagnostic `json:"diagnostics,omitempty"`
	Evidence         map[string]any       `json:"evidence,omitempty"`
	Coverage         string               `json:"coverage"`
}

type Manifest struct {
	Version       int      `json:"version"`
	BommerVersion string   `json:"bommerVersion"`
	Validation    string   `json:"validation"`
	Results       []Result `json:"results"`
}

// CheckBOM validates the schema and preserves the nonempty external-collector contract.
func CheckBOM(path string) error {
	_, err := validateBOM(path, false)
	return err
}

func validateBOM(path string, allowEmpty bool) (bom.Info, error) {
	info, err := bom.Validate(path)
	if err != nil {
		return info, err
	}
	if allowEmpty {
		return info, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return info, err
	}
	defer file.Close()

	var document struct {
		Version    int               `json:"version"`
		Components []json.RawMessage `json:"components"`
	}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&document); err != nil {
		return info, err
	}
	if document.Version < 1 {
		return info, fmt.Errorf("external collectors must provide a positive document version")
	}
	if len(document.Components) == 0 {
		return info, fmt.Errorf("no components discovered; external collectors cannot assert no-findings")
	}
	return info, nil
}

// Execute runs jobs sequentially and records failures without discarding other results.
// It returns the run directory, whether any job failed, and any run-level error.
func Execute(ctx context.Context, jobs []collect.Job, output string, timeout time.Duration, version string) (string, bool, error) {
	if err := os.MkdirAll(output, 0700); err != nil {
		return "", false, err
	}

	lock, err := os.OpenFile(filepath.Join(output, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", false, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", false, fmt.Errorf("another scan holds the output lock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	runDirectory, err := os.MkdirTemp(output, time.Now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return "", false, err
	}

	manifest := Manifest{
		Version:       2,
		BommerVersion: version,
		Validation:    "json-schema-offline",
	}
	failed := false
	for _, job := range jobs {
		result := Result{
			Name:             job.Name,
			Kind:             job.Kind,
			Target:           job.Target,
			SourceVersion:    job.Version,
			Exclude:          job.Collector.Exclude,
			RespectGitignore: job.Collector.RespectGitignore,
			Backend:          job.Collector.Backend,
			Status:           "failed",
			Started:          time.Now().UTC(),
			Scope:            job.Scope,
			Inventory:        job.Inventory,
			Coverage:         "unknown",
		}

		err := ctx.Err()
		if err == nil {
			err = job.Check()
		}
		if err == nil {
			err = executeJob(ctx, job, runDirectory, timeout, &result)
		}
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()
			failed = true
		} else if result.Status == "partial" {
			failed = true
		}
		result.Finished = time.Now().UTC()
		manifest.Results = append(manifest.Results, result)
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return runDirectory, true, err
	}
	if err := os.WriteFile(filepath.Join(runDirectory, "manifest.json"), append(data, '\n'), 0600); err != nil {
		return runDirectory, true, err
	}
	return runDirectory, failed, nil
}

func executeJob(ctx context.Context, job collect.Job, runDirectory string, timeout time.Duration, result *Result) error {
	artifactName := job.Stem() + ".cdx.json"
	outputFile, err := os.CreateTemp(runDirectory, ".bom-*")
	if err != nil {
		return err
	}
	defer os.Remove(outputFile.Name())
	defer outputFile.Close()

	logPath := filepath.Join(runDirectory, job.Stem()+".stderr.log")
	stderrLog, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer stderrLog.Close()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	job, err = job.Resolve(ctx)
	if err != nil {
		return err
	}
	result.Exclude = job.Collector.Exclude
	result.Target = job.Target
	if job.IsNative() {
		outcome, err := collect.CollectNative(ctx, job, outputFile)
		result.Status = outcome.Status
		result.Findings = outcome.Findings
		result.Diagnostics = outcome.Diagnostics
		result.Evidence = outcome.Evidence
		result.CollectorVersion = outcome.CollectorVersion
		result.Coverage = "declared-scope"
		if job.Collector.Backend == "import" {
			result.Coverage = "producer-declared-unverified"
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if result.Status != "collected" && result.Status != "no-findings" && result.Status != "partial" {
			return fmt.Errorf("native collector returned invalid outcome")
		}
	} else {
		args := job.Command()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)

		// Kill the collector process group so timed-out child scanners cannot outlive the run.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = time.Second
		cmd.Stdout = outputFile
		cmd.Stderr = stderrLog

		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("collector failed (see stderr log): %w", err)
		}
		result.Status = "collected"
	}
	if err := outputFile.Close(); err != nil {
		return err
	}

	// Only publish validated output, leaving no final artifact for failed jobs.
	info, err := validateBOM(outputFile.Name(), job.IsNative())
	if err != nil {
		return err
	}
	result.SpecVersion = info.SpecVersion
	if err := ctx.Err(); err != nil {
		return err
	}
	if !job.IsNative() {
		result.Findings = info.ComponentCount
	}
	if info.ComponentCount == 0 && result.Status == "collected" {
		return fmt.Errorf("collector reported collected without inventory components")
	}
	artifact, err := os.Open(outputFile.Name())
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, err = io.Copy(digest, artifact)
	artifact.Close()
	if err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(outputFile.Name(), filepath.Join(runDirectory, artifactName)); err != nil {
		return err
	}
	result.Artifact = artifactName
	result.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return nil
}
