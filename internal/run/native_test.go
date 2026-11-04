package run

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeberg.org/Poellebob/bommer/internal/bom"
	"codeberg.org/Poellebob/bommer/internal/collect"
	"codeberg.org/Poellebob/bommer/internal/config"
)

const nativeCBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "components": [{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher"}}}]
}
`

func nativeCertificate(t *testing.T, directory string) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private-identity.example"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, filepath.Join(directory, "cert.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0600)
}

func nativeCertificateJob(target string, paths ...string) collect.Job {
	return collect.Job{
		Name: "api", Kind: "cbom", Scope: "application", Target: target, TargetType: "directory", Inventory: "certs",
		Collector: config.Collector{Enabled: true, Backend: "certificates", Certificates: &config.CertificateOptions{Paths: paths}},
	}
}

func assertNativeArtifact(t *testing.T, directory string, result Result) []byte {
	t.Helper()
	if result.Artifact == "" || result.SHA256 == "" || result.SpecVersion != "1.6" {
		t.Fatalf("missing artifact metadata: %+v", result)
	}
	path := filepath.Join(directory, result.Artifact)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Errorf("artifact hash = %q, want %x", result.SHA256, digest)
	}
	if _, err := bom.Validate(path); err != nil {
		t.Fatalf("published invalid artifact: %v", err)
	}
	if result.Started.IsZero() || result.Finished.Before(result.Started) {
		t.Errorf("invalid timestamps: %+v", result)
	}
	return data
}

func TestNativeCertificateOutcomes(t *testing.T) {
	root := t.TempDir()
	certificate := nativeCertificate(t, root)
	empty := t.TempDir()
	writeTestFile(t, filepath.Join(empty, "README.txt"), "No certificates here.\n", 0600)
	for _, tt := range []struct {
		name, target, status string
		paths                []string
		findings             int
		partial              bool
	}{
		{"collected", root, "collected", []string{filepath.Base(certificate)}, 1, false},
		{"no findings", empty, "no-findings", []string{"."}, 0, false},
		{"missing root", root, "partial", []string{"missing"}, 0, true},
		{"mixed roots", root, "partial", []string{"cert.pem", "missing"}, 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := nativeCertificateJob(tt.target, tt.paths...)
			dir, failed, err := Execute(context.Background(), []collect.Job{job}, t.TempDir(), 5*time.Second, "native-test")
			if err != nil || failed != tt.partial {
				t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
			}
			manifest := readManifest(t, dir)
			if manifest.Version != 2 || manifest.Validation != "json-schema-offline" || manifest.BommerVersion != "native-test" || len(manifest.Results) != 1 {
				t.Fatalf("unexpected manifest: %+v", manifest)
			}
			result := manifest.Results[0]
			if result.Status != tt.status || result.Findings != tt.findings || result.Error != "" || result.Coverage != "declared-scope" || result.CollectorVersion != "certificates/1" || result.Scope != "application" || result.Inventory != "certs" || result.Backend != "certificates" || result.Target != tt.target || result.Artifact != "api.certs.cbom.cdx.json" {
				t.Fatalf("unexpected certificate result: %+v", result)
			}
			data := assertNativeArtifact(t, dir, result)
			if bytes.Contains(data, []byte("private-identity.example")) || result.Evidence["trust_evaluated"] != false {
				t.Errorf("identity defaults or trust evidence incorrect: %s, %+v", data, result.Evidence)
			}
			if tt.partial {
				if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "missing-path" || result.Diagnostics[0].Path != filepath.Join(tt.target, "missing") {
					t.Errorf("missing root diagnostics: %+v", result.Diagnostics)
				}
			} else if len(result.Diagnostics) != 0 {
				t.Errorf("unexpected diagnostics: %+v", result.Diagnostics)
			}
		})
	}
}

func TestNativeCertificateDefaultFileLimit(t *testing.T) {
	root := t.TempDir()
	path := nativeCertificate(t, root)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A zero configured limit means 4 MiB, not unlimited or zero bytes.
	writeTestFile(t, path, string(data)+strings.Repeat(" ", 4<<20), 0600)
	job := nativeCertificateJob(root, "cert.pem")
	dir, failed, err := Execute(context.Background(), []collect.Job{job}, t.TempDir(), 5*time.Second, "test")
	if err != nil || !failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	result := readManifest(t, dir).Results[0]
	if result.Status != "partial" || result.Findings != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "oversize" {
		t.Fatalf("default file limit not enforced: %+v", result)
	}
	assertNativeArtifact(t, dir, result)
}

func TestNativeImportValidationAndEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, data, status, wantError string
		findings                      int
	}{
		{"valid", nativeCBOM, "collected", "", 1},
		{"empty", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`, "no-findings", "", 0},
		{"invalid JSON", "{", "failed", "single JSON document", 0},
		{"multiple JSON documents", nativeCBOM + nativeCBOM, "failed", "single JSON document", 0},
		{"invalid schema", strings.Replace(nativeCBOM, `"name":"AES"`, `"name":42`, 1), "failed", "validate CycloneDX", 0},
		{"unsupported schema", strings.Replace(nativeCBOM, `"1.6"`, `"0.1"`, 1), "failed", "unsupported CycloneDX", 0},
		{"raw key value", strings.Replace(nativeCBOM, `"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher"}`, `"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"private-key","value":"c2VjcmV0"}`, 1), "failed", "raw cryptographic material", 0},
		{"PEM private key", strings.Replace(nativeCBOM, `"name":"AES"`, `"name":"-----BEGIN PRIVATE KEY-----"`, 1), "failed", "private key material", 0},
		{"escaped PEM private key", strings.Replace(nativeCBOM, `"name":"AES"`, `"name":"-----BEGIN PRIVATE\u0020KEY-----"`, 1), "failed", "private key material", 0},
		{"duplicate hides PEM key", strings.Replace(nativeCBOM, `"name":"AES"`, `"name":"-----BEGIN PRIVATE KEY-----","name":"AES"`, 1), "failed", "single JSON document", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, filepath.Join(t.TempDir(), "source.json"), tt.data, 0600)
			if tt.name == "raw key value" || tt.name == "PEM private key" {
				// These fixtures must fail the secret gate, not merely the schema gate.
				if _, err := bom.Validate(path); err != nil {
					t.Fatalf("secret fixture is not schema-valid: %v", err)
				}
			}
			job := collect.Job{Name: "api", Scope: "application", Kind: "cbom", Inventory: "imported", Target: "registry:example/api:1", TargetType: "container", Collector: config.Collector{Enabled: true, Backend: "import", Import: &config.ImportOptions{Path: path}}}
			dir, failed, err := Execute(context.Background(), []collect.Job{job}, t.TempDir(), 5*time.Second, "test")
			if err != nil || failed != (tt.wantError != "") {
				t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
			}
			manifest := readManifest(t, dir)
			if manifest.Version != 2 || manifest.Validation != "json-schema-offline" || len(manifest.Results) != 1 {
				t.Fatalf("unexpected manifest: %+v", manifest)
			}
			result := manifest.Results[0]
			if result.Status != tt.status || result.Coverage != "producer-declared-unverified" || result.CollectorVersion != "import/1" || result.Scope != job.Scope || result.Inventory != job.Inventory || result.Target != job.Target {
				t.Fatalf("unexpected import result: %+v", result)
			}
			if tt.wantError != "" {
				if !strings.Contains(result.Error, tt.wantError) || result.Artifact != "" || result.SHA256 != "" {
					t.Errorf("invalid failure result: %+v", result)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() != "manifest.json" && entry.Name() != job.Stem()+".stderr.log" {
						t.Errorf("failed import leaked output: %s", entry.Name())
					}
				}
				return
			}
			data := assertNativeArtifact(t, dir, result)
			digest := sha256.Sum256([]byte(tt.data))
			if string(data) != tt.data || result.Findings != tt.findings || result.Error != "" || result.Evidence["sourceSHA256"] != hex.EncodeToString(digest[:]) || result.Evidence["sourcePath"] != path || result.Evidence["origin"] != "imported" || result.Evidence["discovery"] != "not-observed-locally" || result.Evidence["applicationAssociation"] != "configuration-declared-not-verified" {
				t.Errorf("import bytes or evidence changed: %q, %+v", data, result)
			}
			source, err := os.ReadFile(path)
			if err != nil || string(source) != tt.data {
				t.Errorf("source modified: %q, %v", source, err)
			}
		})
	}
}

func TestNativeNamedInventoriesPublishUniqueFiles(t *testing.T) {
	root := t.TempDir()
	certificate := nativeCertificate(t, root)
	path := writeTestFile(t, filepath.Join(root, "import.json"), nativeCBOM, 0600)
	certs := nativeCertificateJob(root, certificate).Collector
	imported := config.Collector{Enabled: true, Backend: "import", Import: &config.ImportOptions{Path: path}}
	var cfg config.Config
	cfg.Version, cfg.Timeout, cfg.Output.Directory = 1, "5s", t.TempDir()
	cfg.Host.Inventories = []config.Inventory{{Name: "certs", Kind: "cbom", Collector: certs}, {Name: "imported", Kind: "cbom", Collector: imported}}
	cfg.Applications = []config.Application{{Name: "api", Version: "1.2", Target: config.Target{Type: "directory", Path: root}, CBOM: certs, Inventories: []config.Inventory{
		{Name: "certs", Kind: "cbom", Collector: certs}, {Name: "cbom", Kind: "cbom", Collector: imported}, {Name: "off", Kind: "cbom"},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	jobs, err := collect.Jobs(cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	dir, failed, err := Execute(context.Background(), jobs, cfg.Output.Directory, 5*time.Second, "test")
	if err != nil || failed {
		t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
	}
	manifest := readManifest(t, dir)
	want := []string{"host.certs.cbom.cdx.json", "host.imported.cbom.cdx.json", "api.cbom.cdx.json", "api.certs.cbom.cdx.json", "api.cbom.cbom.cdx.json"}
	if len(manifest.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(manifest.Results), len(want))
	}
	for i, result := range manifest.Results {
		if result.Artifact != want[i] || result.Status != "collected" || result.Scope != jobs[i].Scope || result.Inventory != jobs[i].Inventory || result.SourceVersion != jobs[i].Version {
			t.Errorf("unexpected result %d: %+v", i, result)
		}
		assertNativeArtifact(t, dir, result)
		if _, err := os.Stat(filepath.Join(dir, jobs[i].Stem()+".stderr.log")); err != nil {
			t.Error(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1+2*len(want) {
		t.Fatalf("unexpected output files: %v, %v", entries, err)
	}
}

func TestNativeCancellation(t *testing.T) {
	root := t.TempDir()
	certificate := nativeCertificate(t, root)
	path := writeTestFile(t, filepath.Join(root, "import.json"), nativeCBOM, 0600)
	jobs := []collect.Job{
		nativeCertificateJob(root, certificate),
		{Name: "api", Kind: "cbom", Scope: "application", Inventory: "imported", Collector: config.Collector{Enabled: true, Backend: "import", Import: &config.ImportOptions{Path: path}}},
	}
	for _, tt := range []struct {
		name, wantError string
		expired         bool
		jobTimeout      bool
	}{
		{"canceled", "context canceled", false, false},
		{"expired", "context deadline exceeded", true, false},
		{"collector timeout", "context deadline exceeded", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			timeout := time.Second
			if tt.expired {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else if tt.jobTimeout {
				timeout = 0
			} else {
				cancel()
			}
			defer cancel()
			dir, failed, err := Execute(ctx, jobs, t.TempDir(), timeout, "test")
			if err != nil || !failed {
				t.Fatalf("Execute() = %q, %v, %v", dir, failed, err)
			}
			manifest := readManifest(t, dir)
			if len(manifest.Results) != len(jobs) {
				t.Fatalf("results = %d, want %d", len(manifest.Results), len(jobs))
			}
			for _, result := range manifest.Results {
				if result.Status != "failed" || !strings.Contains(result.Error, tt.wantError) || result.Artifact != "" || result.SHA256 != "" {
					t.Errorf("unexpected canceled result: %+v", result)
				}
			}
			entries, err := os.ReadDir(dir)
			wantFiles := 1
			if tt.jobTimeout {
				wantFiles += len(jobs)
			}
			if err != nil || len(entries) != wantFiles {
				t.Errorf("canceled jobs created output: %v, %v", entries, err)
			}
			for _, entry := range entries {
				if entry.Name() != "manifest.json" && !(tt.jobTimeout && strings.HasSuffix(entry.Name(), ".stderr.log")) {
					t.Errorf("canceled job leaked output: %s", entry.Name())
				}
			}
		})
	}
}
