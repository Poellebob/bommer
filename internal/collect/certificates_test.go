package collect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/Poellebob/bommer/internal/config"
)

func certificateFixture(t *testing.T, algorithmName string, expired bool) ([]byte, crypto.Signer) {
	t.Helper()
	var privateKey crypto.Signer
	var err error
	switch algorithmName {
	case "RSA":
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "EC":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "Ed25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatal("unknown fixture algorithm")
	}
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	if expired {
		notAfter = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "IDENTITY-DO-NOT-DISCLOSE",
		},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return certificateDER, privateKey
}

func certificateWrite(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
}

func certificateJob(paths ...string) Job {
	return Job{
		Collector: config.Collector{
			Certificates: &config.CertificateOptions{
				Paths: paths,
			},
		},
	}
}

func certificateRun(t *testing.T, job Job) (Outcome, []certificateComponent, []byte) {
	t.Helper()
	var output bytes.Buffer
	result, err := collectCertificates(context.Background(), job, &output)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		BOMFormat   string                 `json:"bomFormat"`
		SpecVersion string                 `json:"specVersion"`
		Components  []certificateComponent `json:"components"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.6" {
		t.Fatal("incorrect document format")
	}
	return result, document.Components, output.Bytes()
}

func TestCertificatesAlgorithmsBundlesIdentityAndDeterminism(t *testing.T) {
	certificateDirectory := t.TempDir()
	var certificateBundle []byte
	var rsaDER []byte
	for _, algorithmName := range []string{"RSA", "EC", "Ed25519"} {
		certificateDER, _ := certificateFixture(t, algorithmName, algorithmName == "RSA")
		if algorithmName == "RSA" {
			rsaDER = certificateDER
		}
		certificateBundle = append(certificateBundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificateDER,
		})...)
	}
	certificateWrite(t, filepath.Join(certificateDirectory, "bundle.pem"), certificateBundle)
	certificateWrite(t, filepath.Join(certificateDirectory, "duplicate.der"), rsaDER)
	certificateWrite(t, filepath.Join(certificateDirectory, "ordinary.txt"), []byte("not a certificate"))
	job := certificateJob("bundle.pem", "duplicate.der", "ordinary.txt")
	job.Target = certificateDirectory
	result, components, output := certificateRun(t, job)
	if result.Status != "collected" || result.Findings != 3 || len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if bytes.Contains(output, []byte("IDENTITY-DO-NOT-DISCLOSE")) {
		t.Fatal("identity leaked")
	}
	componentReferences := []string{}
	componentsByReference := map[string]certificateComponent{}
	for _, component := range components {
		componentReferences = append(componentReferences, component.Reference)
		componentsByReference[component.Reference] = component
		if component.Type != "cryptographic-asset" {
			t.Fatal("incorrect component type")
		}
	}
	if !sort.StringsAreSorted(componentReferences) {
		t.Fatal("components not sorted")
	}
	certificateCount, algorithmCount, expiredCertificateCount := 0, 0, 0
	for _, component := range components {
		if component.CryptoProperties["assetType"] == "algorithm" {
			algorithmCount++
			continue
		}
		certificateCount++
		certificateProperties := component.CryptoProperties["certificateProperties"].(map[string]any)
		if certificateProperties["certificateFormat"] != "X.509" || certificateProperties["notValidAfter"] == nil || certificateProperties["notValidBefore"] == nil {
			t.Fatal("missing schema certificate fields")
		}
		if _, exists := certificateProperties["subjectPublicKeyRef"]; exists {
			t.Fatal("algorithm incorrectly represented as a public key")
		}
		signatureAlgorithmReference := certificateProperties["signatureAlgorithmRef"].(string)
		if componentsByReference[signatureAlgorithmReference].CryptoProperties["assetType"] != "algorithm" {
			t.Fatal("signature reference unresolved")
		}
		for _, property := range component.Properties {
			if property.Name == "bommer:certificate:expired" && property.Value == "true" {
				expiredCertificateCount++
			}
			if property.Name == "bommer:certificate:public-key-algorithm-ref" {
				if componentsByReference[property.Value].Properties[0].Value != "public-key" {
					t.Fatal("public-key algorithm role incorrect")
				}
			}
		}
	}
	if certificateCount != 3 || algorithmCount != 6 || expiredCertificateCount != 1 {
		t.Fatalf("counts: certificates=%d algorithms=%d expired=%d", certificateCount, algorithmCount, expiredCertificateCount)
	}
	digest := sha256.Sum256(rsaDER)
	sources := result.Evidence["sources"].(map[string][]string)["certificate:sha256:"+hex.EncodeToString(digest[:])]
	if len(sources) != 2 || !sort.StringsAreSorted(sources) {
		t.Fatalf("incorrect deduplicated sources: %v", sources)
	}
	job.Collector.Certificates.Paths = []string{"ordinary.txt", "duplicate.der", "bundle.pem", "bundle.pem"}
	_, _, reorderedOutput := certificateRun(t, job)
	if !bytes.Equal(output, reorderedOutput) {
		t.Fatal("output changes with root order or duplicate roots")
	}
	job.Collector.Certificates.IncludeIdentity = true
	_, _, output = certificateRun(t, job)
	if !bytes.Contains(output, []byte("IDENTITY-DO-NOT-DISCLOSE")) {
		t.Fatal("explicit identity missing")
	}
}

func TestCertificatesPrivateKeysNeverDisclosed(t *testing.T) {
	certificateDirectory := t.TempDir()
	certificateDER, privateKey := certificateFixture(t, "RSA", false)
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	mixedBundle := append(append([]byte{}, privateKeyPEM...), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})...)
	certificateWrite(t, filepath.Join(certificateDirectory, "mixed.pem"), mixedBundle)
	certificateWrite(t, filepath.Join(certificateDirectory, "key.pem"), privateKeyPEM)
	// Invalid key contents must be skipped, not sent to a key parser.
	certificateWrite(t, filepath.Join(certificateDirectory, "invalid-key.pem"), []byte("-----BEGIN PRIVATE KEY-----\nSECRET-MARKER\n-----END PRIVATE KEY-----\n"))
	result, _, output := certificateRun(t, certificateJob(certificateDirectory))
	if result.Status != "collected" || result.Findings != 1 || len(result.Diagnostics) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	resultJSON, _ := json.Marshal(result)
	combinedOutput := append(output, resultJSON...)
	for _, forbiddenContent := range []string{
		"PRIVATE KEY",
		"SECRET-MARKER",
		base64.StdEncoding.EncodeToString(privateKeyDER)[:60],
		base64.StdEncoding.EncodeToString(certificateDER)[:60],
		"encodedCertificate",
	} {
		if bytes.Contains(combinedOutput, []byte(forbiddenContent)) {
			t.Fatalf("sensitive content leaked: %q", forbiddenContent)
		}
	}
}

func TestCertificatesSeparateSubjectAndIssuerAlgorithms(t *testing.T) {
	issuerDER, issuerKey := certificateFixture(t, "RSA", false)
	issuerCertificate, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	subjectDER, subjectKey := certificateFixture(t, "EC", false)
	subjectCertificate, err := x509.ParseCertificate(subjectDER)
	if err != nil {
		t.Fatal(err)
	}
	subjectCertificate.SignatureAlgorithm = x509.SHA256WithRSA
	crossSignedDER, err := x509.CreateCertificate(rand.Reader, subjectCertificate, issuerCertificate, subjectKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cross-signed.der")
	certificateWrite(t, path, crossSignedDER)
	_, components, _ := certificateRun(t, certificateJob(path))
	algorithmNamesByReference := map[string]string{}
	for _, component := range components {
		if component.CryptoProperties["assetType"] == "algorithm" {
			algorithmNamesByReference[component.Reference] = component.Name
		}
	}
	for _, component := range components {
		if component.CryptoProperties["assetType"] != "certificate" {
			continue
		}
		certificateProperties := component.CryptoProperties["certificateProperties"].(map[string]any)
		if algorithmNamesByReference[certificateProperties["signatureAlgorithmRef"].(string)] != "SHA256-RSA" {
			t.Fatal("signature algorithm not derived from issuer signature")
		}
		for _, property := range component.Properties {
			if property.Name == "bommer:certificate:public-key-algorithm-ref" && algorithmNamesByReference[property.Value] != "ECDSA-P-256" {
				t.Fatal("subject algorithm confused with issuer algorithm")
			}
		}
	}
}

func TestCertificatesCoverageDiagnostics(t *testing.T) {
	certificateDER, _ := certificateFixture(t, "EC", false)
	for _, testCase := range []struct {
		fileName         string
		fileContents     []byte
		maxFileBytes     int64
		expectedStatus   string
		expectedFindings int
	}{
		{
			fileName:         "malformed.crt",
			fileContents:     []byte("SECRET-MALFORMED"),
			maxFileBytes:     0,
			expectedStatus:   "partial",
			expectedFindings: 0,
		},
		{
			fileName:         "malformed.pem",
			fileContents:     []byte("-----BEGIN CERTIFICATE-----\nSECRET-MALFORMED\n-----END CERTIFICATE-----"),
			maxFileBytes:     0,
			expectedStatus:   "partial",
			expectedFindings: 0,
		},
		{
			fileName:         "truncated.pem",
			fileContents:     []byte("-----BEGIN CERTIFICATE"),
			maxFileBytes:     0,
			expectedStatus:   "partial",
			expectedFindings: 0,
		},
		{
			fileName:         "default-limit.pem",
			fileContents:     bytes.Repeat([]byte("x"), (4<<20)+1),
			maxFileBytes:     0,
			expectedStatus:   "partial",
			expectedFindings: 0,
		},
		{
			fileName:         "oversize.der",
			fileContents:     certificateDER,
			maxFileBytes:     10,
			expectedStatus:   "partial",
			expectedFindings: 0,
		},
		{
			fileName:         "boundary.der",
			fileContents:     certificateDER,
			maxFileBytes:     int64(len(certificateDER)),
			expectedStatus:   "collected",
			expectedFindings: 1,
		},
		{
			fileName:         "ordinary.txt",
			fileContents:     []byte("unrelated"),
			maxFileBytes:     0,
			expectedStatus:   "no-findings",
			expectedFindings: 0,
		},
		{
			fileName:         "ordinary-big.txt",
			fileContents:     []byte("unrelated"),
			maxFileBytes:     2,
			expectedStatus:   "no-findings",
			expectedFindings: 0,
		},
		{
			fileName:         "extensionless",
			fileContents:     certificateDER,
			maxFileBytes:     0,
			expectedStatus:   "collected",
			expectedFindings: 1,
		},
	} {
		t.Run(testCase.fileName, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), testCase.fileName)
			certificateWrite(t, path, testCase.fileContents)
			job := certificateJob(path)
			job.Collector.Certificates.MaxFileBytes = testCase.maxFileBytes
			result, _, output := certificateRun(t, job)
			if result.Status != testCase.expectedStatus || result.Findings != testCase.expectedFindings {
				t.Fatalf("unexpected result: %+v", result)
			}
			resultJSON, _ := json.Marshal(result)
			if bytes.Contains(append(output, resultJSON...), []byte("SECRET-MALFORMED")) {
				t.Fatal("parser input leaked")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		result, _, _ := certificateRun(t, certificateJob(filepath.Join(t.TempDir(), "missing")))
		if result.Status != "partial" || result.Diagnostics[0].Code != "missing-path" {
			t.Fatalf("unexpected result: %+v", result)
		}
	})
	t.Run("malformed-and-valid-bundle", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bundle.pem")
		malformedCertificatePEM := []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")
		certificateWrite(t, path, append(malformedCertificatePEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificateDER,
		})...))
		result, _, _ := certificateRun(t, certificateJob(path))
		if result.Status != "partial" || result.Findings != 1 {
			t.Fatalf("unexpected result: %+v", result)
		}
	})
}

func TestCertificatesNoFollow(t *testing.T) {
	certificateDirectory, outsideDirectory := t.TempDir(), t.TempDir()
	certificateDER, _ := certificateFixture(t, "Ed25519", false)
	certificateWrite(t, filepath.Join(outsideDirectory, "cert.der"), certificateDER)
	directorySymlink := filepath.Join(certificateDirectory, "link")
	if err := os.Symlink(outsideDirectory, directorySymlink); err != nil {
		t.Fatal(err)
	}
	fileSymlink := filepath.Join(certificateDirectory, "file.der")
	if err := os.Symlink(filepath.Join(outsideDirectory, "cert.der"), fileSymlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		directorySymlink,
		fileSymlink,
		filepath.Join(directorySymlink, "cert.der"),
		certificateDirectory,
		// Keep the literal /../ so the collector must reject the symlink before any path cleaning.
		directorySymlink + "/../cert.der",
	} {
		result, _, _ := certificateRun(t, certificateJob(path))
		if result.Status != "partial" || result.Findings != 0 || len(result.Diagnostics) == 0 {
			t.Fatalf("followed symlink %q: %+v", path, result)
		}
	}
	job := certificateJob("cert.der")
	job.Target = directorySymlink
	result, _, _ := certificateRun(t, job)
	if result.Status != "partial" || result.Findings != 0 {
		t.Fatal("followed target symlink")
	}
	if err := syscall.Mkfifo(filepath.Join(certificateDirectory, "fifo.pem"), 0600); err != nil {
		t.Fatal(err)
	}
	result, _, _ = certificateRun(t, certificateJob(filepath.Join(certificateDirectory, "fifo.pem")))
	if result.Status != "partial" || result.Diagnostics[0].Code != "non-regular" {
		t.Fatalf("FIFO not skipped: %+v", result)
	}
}

func TestCertificatesPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	path := filepath.Join(t.TempDir(), "unreadable.crt")
	certificateWrite(t, path, []byte("not readable"))
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	result, _, _ := certificateRun(t, certificateJob(path))
	if result.Status != "partial" || result.Diagnostics[0].Code != "unreadable" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type certificateFailWriter struct{}

func (certificateFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("SECRET-WRITER-ERROR")
}

func TestCertificatesCancellationAndConfiguration(t *testing.T) {
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	result, err := collectCertificates(canceledContext, certificateJob(t.TempDir()), &output)
	if !errors.Is(err, context.Canceled) || result.Status != "partial" || output.Len() != 0 {
		t.Fatalf("cancellation: %+v %v", result, err)
	}
	for _, job := range []Job{{}, certificateJob()} {
		if _, err := collectCertificates(context.Background(), job, io.Discard); err == nil {
			t.Fatal("missing explicit paths accepted")
		}
	}
	job := certificateJob("relative.pem")
	result, _, _ = certificateRun(t, job)
	if result.Status != "partial" {
		t.Fatal("relative host path accepted")
	}
	job = certificateJob("")
	job.Target = t.TempDir()
	result, _, _ = certificateRun(t, job)
	if result.Status != "partial" || result.Diagnostics[0].Code != "invalid-path" {
		t.Fatal("empty path accepted")
	}
	job = certificateJob(t.TempDir())
	job.Collector.Certificates.MaxFileBytes = -1
	if _, err := collectCertificates(context.Background(), job, io.Discard); err == nil {
		t.Fatal("negative limit accepted")
	}
	_, err = collectCertificates(context.Background(), certificateJob(t.TempDir()), certificateFailWriter{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("unsafe writer error")
	}
	// An empty directory produces an explicit empty components array.
	result, components, _ := certificateRun(t, certificateJob(t.TempDir()))
	if result.Status != "no-findings" || !reflect.DeepEqual(components, []certificateComponent{}) {
		t.Fatal("incorrect empty inventory")
	}
}
