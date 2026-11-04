package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"codeberg.org/Poellebob/bommer/internal/bom"
)

// collectImport preserves supplied evidence. It does not claim local discovery
// or verify the producer's association with the configured application.
func collectImport(ctx context.Context, job Job, out io.Writer) (Outcome, error) {
	result := Outcome{Status: "failed", CollectorVersion: "import/1"}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if job.Collector.Import == nil {
		return result, fmt.Errorf("import.path is required")
	}
	path := job.Collector.Import.Path
	// A path replaced with a FIFO must not block before its type can be checked.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return result, fmt.Errorf("import must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<20)+1))
	if err != nil {
		return result, err
	}
	if len(data) > 64<<20 {
		return result, fmt.Errorf("import exceeds 64 MiB")
	}
	decoded, err := bom.Decode(bytes.NewReader(data))
	if err != nil {
		return result, fmt.Errorf("import is not a single JSON document")
	}
	document, ok := decoded.(map[string]any)
	if !ok {
		return result, fmt.Errorf("import must be a JSON object")
	}
	var inspectCryptographicEvidence func(any) error
	inspectCryptographicEvidence = func(value any) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch value := value.(type) {
		case string:
			if strings.Contains(value, "PRIVATE KEY-----") {
				return fmt.Errorf("import contains private key material")
			}
		case map[string]any:
			if value["type"] == "cryptographic-asset" {
				result.Findings++
			}
			if material, ok := value["relatedCryptoMaterialProperties"].(map[string]any); ok {
				if _, exists := material["value"]; exists {
					return fmt.Errorf("import contains raw cryptographic material values")
				}
			}
			for _, child := range value {
				if err := inspectCryptographicEvidence(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range value {
				if err := inspectCryptographicEvidence(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := inspectCryptographicEvidence(document); err != nil {
		return result, err
	}
	if result.Findings == 0 {
		if components, ok := document["components"].([]any); ok && len(components) > 0 {
			return result, fmt.Errorf("imported CBOM contains components but no cryptographic assets")
		}
		result.Status = "no-findings"
	} else {
		result.Status = "collected"
	}
	digest := sha256.Sum256(data)
	result.Evidence = map[string]any{
		"origin":                 "imported",
		"sourcePath":             path,
		"sourceSHA256":           hex.EncodeToString(digest[:]),
		"discovery":              "not-observed-locally",
		"applicationAssociation": "configuration-declared-not-verified",
	}
	if _, err := out.Write(data); err != nil {
		return result, err
	}
	return result, nil
}
