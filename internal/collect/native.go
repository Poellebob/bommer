package collect

import (
	"context"
	"fmt"
	"io"
)

// Diagnostic records a coverage gap without embedding raw scanned content.
type Diagnostic struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Outcome describes observed coverage, independently of document validity.
type Outcome struct {
	Status           string
	Findings         int
	Diagnostics      []Diagnostic
	Evidence         map[string]any
	CollectorVersion string
}

func (job Job) IsNative() bool {
	switch job.Collector.Backend {
	case "nix", "certificates", "import":
		return true
	default:
		return false
	}
}

// CollectNative writes a BOM; validation and artifact publication stay in the runner.
func CollectNative(ctx context.Context, job Job, output io.Writer) (Outcome, error) {
	switch job.Collector.Backend {
	case "nix":
		return collectNix(ctx, job, output)
	case "certificates":
		return collectCertificates(ctx, job, output)
	case "import":
		return collectImport(ctx, job, output)
	default:
		return Outcome{}, fmt.Errorf("unsupported native backend %q", job.Collector.Backend)
	}
}
