package collect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nixStdoutLimit = 64 << 20
const nixStderrLimit = 16 << 10

var nixOutputPath = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+$`)
var nixVersionPattern = regexp.MustCompile(`^nix \(Nix\) (\d+)\.(\d+)(?:\.[0-9]+)?(?:[^\r\n]*)$`)

func nixIsOutput(path string) bool {
	return nixOutputPath.MatchString(path) && !strings.HasSuffix(path, ".drv")
}

// Only the initial /nix/store layout is supported. Resolve profile links once,
// then pass the immutable output path, never the mutable profile, to Nix.
func nixResolveRoot(root string) (string, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	if !nixIsOutput(resolved) {
		return "", fmt.Errorf("root must resolve to a top-level /nix/store/<32-character-hash>-name output (not a derivation)")
	}
	fileInfo, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() && !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("store output is not a regular file or directory")
	}
	return resolved, nil
}

// nixCapture bounds captured command output. Stderr is truncated but still
// drained; stdout overflow stops the command rather than returning partial JSON.
type nixCapture struct {
	buffer     bytes.Buffer
	limit      int
	truncate   bool
	overflow   bool
	onOverflow func()
}

func (capture *nixCapture) Write(data []byte) (int, error) {
	byteCount := len(data)
	remaining := capture.limit - capture.buffer.Len()
	if byteCount > remaining {
		capture.buffer.Write(data[:remaining])
		capture.overflow = true
		if !capture.truncate {
			if capture.onOverflow != nil {
				capture.onOverflow()
			}
			return remaining, fmt.Errorf("Nix stdout exceeds %d bytes", capture.limit)
		}
		return byteCount, nil
	}
	return capture.buffer.Write(data)
}

// Kept local to this collector: no shell, bounded pipes, and group cancellation.
func nixRun(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nix", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	stdout := &nixCapture{limit: nixStdoutLimit}
	stdout.onOverflow = func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	stderr := &nixCapture{
		limit:    nixStderrLimit,
		truncate: true,
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.overflow {
		return nil, fmt.Errorf("Nix stdout exceeds %d bytes", nixStdoutLimit)
	}
	if err != nil {
		// Quote untrusted stderr so terminal controls cannot escape into logs.
		return nil, fmt.Errorf("local Nix query failed: %w; stderr=%q (truncated=%t)", err, stderr.buffer.String(), stderr.overflow)
	}
	return stdout.buffer.Bytes(), nil
}

// nixPathInfo is the subset of Nix path-info metadata used by this collector.
// Pointers distinguish missing or null fields from a zero size or empty references.
// NAR (Nix Archive) hashes and sizes describe serialized outputs, not file contents.
type nixPathInfo struct {
	Path            string    `json:"path"`
	NarHash         string    `json:"narHash"`
	NarSize         *uint64   `json:"narSize"`
	References      *[]string `json:"references"`
	Deriver         string    `json:"deriver"`
	MetadataVersion *int      `json:"version"`
}

// JSON format 1 uses full paths and string hashes. Older Nix versions emitted an
// array with a path field; newer versions emit an object keyed by full path.
func nixDecode(data []byte) (map[string]nixPathInfo, error) {
	data = bytes.TrimSpace(data)
	metadataByPath := map[string]nixPathInfo{}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty Nix JSON")
	}
	switch data[0] {
	case '{':
		if err := json.Unmarshal(data, &metadataByPath); err != nil {
			return nil, fmt.Errorf("unsupported or malformed Nix format-1 JSON: %w", err)
		}
	case '[':
		var entries []nixPathInfo
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("unsupported or malformed Nix legacy JSON: %w", err)
		}
		for _, metadata := range entries {
			if _, exists := metadataByPath[metadata.Path]; exists {
				return nil, fmt.Errorf("duplicate Nix path %q", metadata.Path)
			}
			metadataByPath[metadata.Path] = metadata
		}
	default:
		return nil, fmt.Errorf("unsupported Nix JSON format: expected format-1 object or legacy array")
	}
	if len(metadataByPath) == 0 {
		return nil, fmt.Errorf("Nix returned an empty closure")
	}
	for path, metadata := range metadataByPath {
		if !nixIsOutput(path) || (metadata.Path != "" && metadata.Path != path) {
			return nil, fmt.Errorf("invalid Nix output path %q", path)
		}
		if metadata.MetadataVersion != nil && *metadata.MetadataVersion != 1 {
			return nil, fmt.Errorf("unsupported Nix JSON metadata version %d", *metadata.MetadataVersion)
		}
		if metadata.NarSize == nil || metadata.References == nil || !nixValidNarHash(metadata.NarHash) {
			return nil, fmt.Errorf("malformed NAR metadata or missing references for %q", path)
		}
		if metadata.Deriver != "" && metadata.Deriver != "unknown-deriver" &&
			(!nixOutputPath.MatchString(metadata.Deriver) || !strings.HasSuffix(metadata.Deriver, ".drv")) {
			return nil, fmt.Errorf("malformed deriver for %q", path)
		}
		for _, referencePath := range *metadata.References {
			if _, exists := metadataByPath[referencePath]; !exists {
				return nil, fmt.Errorf("incomplete Nix closure: %q references missing output %q", path, referencePath)
			}
		}
	}
	return metadataByPath, nil
}

func nixValidNarHash(hash string) bool {
	for algorithm, digestBytes := range map[string]int{
		"md5":    16,
		"sha1":   20,
		"sha256": 32,
		"sha512": 64,
	} {
		if value, ok := strings.CutPrefix(hash, algorithm+"-"); ok {
			decoded, err := base64.StdEncoding.DecodeString(value)
			return err == nil && len(decoded) == digestBytes
		}
		if value, ok := strings.CutPrefix(hash, algorithm+":"); ok {
			alphabet := "0123456789abcdfghijklmnpqrsvwxyz"
			if len(value) == digestBytes*2 {
				alphabet = "0123456789abcdef"
			} else if len(value) != (digestBytes*8+4)/5 {
				return false
			}
			return value != "" && strings.Trim(value, alphabet) == ""
		}
	}
	return false
}

// These types encode CycloneDX output, not Nix path-info input.
type nixProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type nixComponent struct {
	Type       string        `json:"type"`
	Reference  string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Properties []nixProperty `json:"properties"`
}

type nixDependency struct {
	Reference string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func collectNix(ctx context.Context, job Job, out io.Writer) (Outcome, error) {
	return nixCollect(ctx, job, out, nixResolveRoot)
}

// The resolver argument lets portable tests exercise the CLI contract without
// creating anything in /nix/store or invoking an actual Nix installation.
func nixCollect(ctx context.Context, job Job, out io.Writer, resolve func(string) (string, error)) (Outcome, error) {
	result := Outcome{
		Status: "failed",
		Evidence: map[string]any{
			"scope":          "store-reference closure",
			"storeDirectory": "/nix/store",
		},
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var configuredRoots []string
	if job.Collector.Nix != nil {
		configuredRoots = append(configuredRoots, job.Collector.Nix.Roots...)
	}
	if len(configuredRoots) == 0 {
		if job.Name == "host" || job.Target == "" {
			return result, fmt.Errorf("Nix host collection requires explicit local closure roots")
		}
		configuredRoots = []string{job.Target}
	}
	result.Evidence["configuredRoots"] = append([]string{}, configuredRoots...)
	roots := make([]string, 0, len(configuredRoots))
	seenRoots := map[string]bool{}
	for _, root := range configuredRoots {
		resolved, err := resolve(root)
		if err != nil {
			return result, fmt.Errorf("resolve local Nix root %q: %w", root, err)
		}
		if !nixIsOutput(resolved) {
			return result, fmt.Errorf("invalid resolved Nix root %q", resolved)
		}
		if !seenRoots[resolved] {
			roots = append(roots, resolved)
			seenRoots[resolved] = true
		}
	}
	sort.Strings(roots)
	result.Evidence["resolvedRoots"] = roots
	versionBytes, err := nixRun(ctx, "--version")
	if err != nil {
		return result, err
	}
	version := strings.TrimSpace(string(versionBytes))
	versionParts := nixVersionPattern.FindStringSubmatch(version)
	if versionParts == nil {
		return result, fmt.Errorf("unsupported Nix version output %q", version)
	}
	result.CollectorVersion = version
	result.Evidence["nixVersion"] = version
	// Never inherit a potentially remote NIX_REMOTE/store setting. A Unix
	// daemon socket is local; single-user installations use the local DB.
	store := "local"
	if socketInfo, err := os.Stat("/nix/var/nix/daemon-socket/socket"); err == nil && socketInfo.Mode()&os.ModeSocket != 0 {
		store = "unix:///nix/var/nix/daemon-socket/socket"
	}
	result.Evidence["storeConnection"] = store
	args := []string{
		"--extra-experimental-features", "nix-command",
		"path-info",
		"--store", store,
		"--offline",
		"--recursive",
		"--json",
	}
	major, _ := strconv.Atoi(versionParts[1])
	minor, _ := strconv.Atoi(versionParts[2])
	if major > 2 || (major == 2 && minor >= 34) {
		args = append(args, "--json-format", "1")
	}
	args = append(args, roots...)
	data, err := nixRun(ctx, args...)
	if err != nil {
		return result, err
	}
	metadataByPath, err := nixDecode(data)
	if err != nil {
		return result, err
	}
	for _, root := range roots {
		if _, exists := metadataByPath[root]; !exists {
			return result, fmt.Errorf("Nix closure is missing requested root %q", root)
		}
	}
	paths := make([]string, 0, len(metadataByPath))
	for path := range metadataByPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	components := make([]nixComponent, 0, len(paths))
	dependencies := make([]nixDependency, 0, len(paths))
	for _, path := range paths {
		metadata := metadataByPath[path]
		properties := []nixProperty{
			{Name: "bommer:nix:store-path", Value: path},
			{Name: "bommer:nix:nar-hash", Value: metadata.NarHash},
			{Name: "bommer:nix:nar-size", Value: strconv.FormatUint(*metadata.NarSize, 10)},
		}
		if metadata.Deriver != "" && metadata.Deriver != "unknown-deriver" {
			properties = append(properties, nixProperty{
				Name:  "bommer:nix:deriver",
				Value: metadata.Deriver,
			})
		}
		// A store output is not necessarily a package. Preserve its entire name
		// and omit unknown versions; NAR hashes are not ordinary file hashes.
		_, outputName, _ := strings.Cut(filepath.Base(path), "-")
		components = append(components, nixComponent{
			Type:       "file",
			Reference:  path,
			Name:       outputName,
			Properties: properties,
		})
		referencePaths := append([]string{}, (*metadata.References)...)
		sort.Strings(referencePaths)
		uniqueReferences := referencePaths[:0]
		for _, referencePath := range referencePaths {
			if len(uniqueReferences) == 0 || uniqueReferences[len(uniqueReferences)-1] != referencePath {
				uniqueReferences = append(uniqueReferences, referencePath)
			}
		}
		dependencies = append(dependencies, nixDependency{
			Reference: path,
			DependsOn: uniqueReferences,
		})
	}
	bom := struct {
		Format   string `json:"bomFormat"`
		Spec     string `json:"specVersion"`
		Version  int    `json:"version"`
		Metadata struct {
			Properties []nixProperty  `json:"properties"`
			Component  map[string]any `json:"component"`
		} `json:"metadata"`
		Components   []nixComponent  `json:"components"`
		Dependencies []nixDependency `json:"dependencies"`
	}{
		Format:       "CycloneDX",
		Spec:         "1.6",
		Version:      1,
		Components:   components,
		Dependencies: dependencies,
	}
	bom.Metadata.Properties = []nixProperty{
		{Name: "bommer:nix:scope", Value: "store-reference closure"},
		{Name: "bommer:nix:version", Value: version},
	}
	bom.Metadata.Component = map[string]any{
		"type":    "file",
		"name":    job.Name,
		"bom-ref": "bommer:inventory:" + job.Stem(),
	}
	if job.Version != "" {
		bom.Metadata.Component["version"] = job.Version
	}
	bom.Dependencies = append(bom.Dependencies, nixDependency{
		Reference: "bommer:inventory:" + job.Stem(),
		DependsOn: append([]string{}, roots...),
	})
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := json.NewEncoder(out).Encode(bom); err != nil {
		return result, fmt.Errorf("write Nix CycloneDX document: %w", err)
	}
	result.Status, result.Findings = "collected", len(components)
	return result, nil
}
