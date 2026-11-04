package collect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type certificateComponent struct {
	Type             string                `json:"type"`
	Reference        string                `json:"bom-ref"`
	Name             string                `json:"name"`
	CryptoProperties map[string]any        `json:"cryptoProperties"`
	Properties       []certificateProperty `json:"properties,omitempty"`
}

type certificateProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// collectCertificates inventories observations only; it does not evaluate trust.
func collectCertificates(ctx context.Context, job Job, out io.Writer) (Outcome, error) {
	result := Outcome{
		Status:           "no-findings",
		CollectorVersion: "certificates/1",
		Evidence:         map[string]any{},
	}
	if err := ctx.Err(); err != nil {
		result.Status = "partial"
		return result, err
	}
	options := job.Collector.Certificates
	if options == nil || len(options.Paths) == 0 {
		return result, errors.New("certificate paths are required")
	}
	maxFileBytes := options.MaxFileBytes
	if maxFileBytes == 0 {
		maxFileBytes = 4 << 20
	}
	if maxFileBytes < 0 || maxFileBytes == int64(^uint64(0)>>1) {
		return result, errors.New("invalid certificate file limit")
	}
	recordDiagnostic := func(code, path, message string) {
		result.Status = "partial"
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Code:    code,
			Path:    path,
			Message: message,
		})
	}
	type certificateObservation struct {
		certificate *x509.Certificate
		sourcePaths map[string]bool
	}
	certificatesByDigest := map[string]*certificateObservation{}
	visitedPaths := map[string]bool{}
	visitedEntryCount := 0
	var walkCertificatePath func(*os.File, string, int) error
	walkCertificatePath = func(file *os.File, path string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if visitedPaths[path] {
			return nil
		}
		visitedPaths[path] = true
		if visitedEntryCount > 100000 || depth > 128 {
			recordDiagnostic("traversal-limit", path, "Certificate traversal limit reached.")
			return nil
		}
		fileInfo, err := file.Stat()
		if err != nil {
			recordDiagnostic("unreadable", path, "Cannot inspect certificate path.")
			return nil
		}
		if fileInfo.IsDir() {
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				entryNames, readErr := file.Readdirnames(128)
				for _, entryName := range entryNames {
					if err := ctx.Err(); err != nil {
						return err
					}
					if visitedEntryCount >= 100000 {
						recordDiagnostic("traversal-limit", path, "Certificate traversal limit reached.")
						return nil
					}
					visitedEntryCount++
					childPath := filepath.Join(path, entryName)
					childFile, err := certificateOpenAt(file, entryName, false)
					if err != nil {
						recordDiagnostic(certificateOpenCode(err), childPath, "Certificate path could not be opened without following symlinks.")
						continue
					}
					err = walkCertificatePath(childFile, childPath, depth+1)
					childFile.Close()
					if err != nil {
						return err
					}
				}
				if readErr == io.EOF {
					return nil
				}
				if readErr != nil {
					recordDiagnostic("unreadable", path, "Cannot read certificate directory.")
					return nil
				}
			}
		}
		if !fileInfo.Mode().IsRegular() {
			recordDiagnostic("non-regular", path, "Non-regular certificate path skipped.")
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		isCertificateCandidate := extension == ".pem" || extension == ".crt" || extension == ".cer" || extension == ".der"
		if fileInfo.Size() > maxFileBytes {
			if isCertificateCandidate {
				recordDiagnostic("oversize", path, "Certificate candidate exceeds file size limit.")
			}
			return nil
		}
		// Read one extra byte to detect files that grow after Stat.
		fileContents, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
		if err != nil {
			recordDiagnostic("unreadable", path, "Cannot read certificate file.")
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(len(fileContents)) > maxFileBytes {
			if isCertificateCandidate {
				recordDiagnostic("oversize", path, "Certificate candidate exceeds file size limit.")
			}
			return nil
		}
		recordCertificate := func(certificateDER []byte) {
			certificate, err := x509.ParseCertificate(certificateDER)
			if err != nil {
				recordDiagnostic("malformed", path, "Malformed certificate candidate.")
				return
			}
			digest := sha256.Sum256(certificate.Raw)
			certificateDigest := hex.EncodeToString(digest[:])
			if certificatesByDigest[certificateDigest] == nil {
				certificatesByDigest[certificateDigest] = &certificateObservation{
					certificate: certificate,
					sourcePaths: map[string]bool{},
				}
			}
			certificatesByDigest[certificateDigest].sourcePaths[path] = true
		}
		// Decode certificate blocks only. Private-key blocks are never decoded or parsed.
		if bytes.Contains(fileContents, []byte("-----BEGIN ")) {
			hasMalformedCertificateBlock := false
			remainingPEM := fileContents
			for len(remainingPEM) > 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
				blockStart := bytes.Index(remainingPEM, []byte("-----BEGIN "))
				if blockStart < 0 {
					break
				}
				remainingPEM = remainingPEM[blockStart:]
				// Isolate each block before decoding so a malformed block cannot hide the next one.
				const pemBeginPrefixLength = len("-----BEGIN ")
				nextBlockStart := bytes.Index(remainingPEM[pemBeginPrefixLength:], []byte("-----BEGIN "))
				var blockContents []byte
				if nextBlockStart < 0 {
					blockContents, remainingPEM = remainingPEM, nil
				} else {
					nextBlockStart += pemBeginPrefixLength
					blockContents, remainingPEM = remainingPEM[:nextBlockStart], remainingPEM[nextBlockStart:]
				}
				if bytes.HasPrefix(blockContents, []byte("-----BEGIN CERTIFICATE REQUEST-----")) || !bytes.HasPrefix(blockContents, []byte("-----BEGIN CERTIFICATE")) {
					continue
				}
				block, _ := pem.Decode(blockContents)
				if block == nil || block.Type != "CERTIFICATE" {
					hasMalformedCertificateBlock = true
					continue
				}
				recordCertificate(block.Bytes)
			}
			if hasMalformedCertificateBlock {
				recordDiagnostic("malformed", path, "Malformed certificate candidate.")
			}
		} else if isCertificateCandidate || (len(fileContents) > 0 && fileContents[0] == 0x30) {
			// DER certificates begin with an ASN.1 SEQUENCE (0x30); ignore false positives without a certificate extension.
			if !isCertificateCandidate {
				if _, err := x509.ParseCertificate(fileContents); err != nil {
					return nil
				}
			}
			recordCertificate(fileContents)
		}
		return nil
	}
	for _, configuredPath := range options.Paths {
		if err := ctx.Err(); err != nil {
			result.Status = "partial"
			return result, err
		}
		path := configuredPath
		if path == "" {
			recordDiagnostic("invalid-path", path, "Empty certificate paths are not allowed.")
			continue
		}
		if !filepath.IsAbs(path) {
			if job.Target == "" || !filepath.IsAbs(job.Target) {
				recordDiagnostic("invalid-path", path, "Relative certificate paths require an absolute application target.")
				continue
			}
			path = job.Target + string(os.PathSeparator) + path
		}
		// Do not clean away symlink/.. components before enforcing no-follow.
		rootFile, err := certificateOpenPath(path)
		if err != nil {
			recordDiagnostic(certificateOpenCode(err), path, "Certificate root could not be opened without following symlinks.")
			continue
		}
		visitedEntryCount++
		err = walkCertificatePath(rootFile, filepath.Clean(path), 0)
		rootFile.Close()
		if err != nil {
			result.Status = "partial"
			return result, err
		}
	}
	components := []certificateComponent{}
	algorithmsByReference := map[string]certificateComponent{}
	sourcesByCertificateReference := map[string][]string{}
	now := time.Now()
	for certificateDigest, observation := range certificatesByDigest {
		if err := ctx.Err(); err != nil {
			result.Status = "partial"
			return result, err
		}
		certificate := observation.certificate
		publicKeyAlgorithmName := certificate.PublicKeyAlgorithm.String()
		publicKeyAlgorithmProperties := map[string]any{
			"primitive": "unknown",
		}
		switch publicKey := certificate.PublicKey.(type) {
		case *rsa.PublicKey:
			publicKeyAlgorithmProperties["parameterSetIdentifier"] = strconv.Itoa(publicKey.N.BitLen())
			publicKeyAlgorithmName += "-" + strconv.Itoa(publicKey.N.BitLen())
		case *ecdsa.PublicKey:
			publicKeyAlgorithmProperties["curve"] = publicKey.Curve.Params().Name
			publicKeyAlgorithmProperties["primitive"] = "signature"
			publicKeyAlgorithmName += "-" + publicKey.Curve.Params().Name
		case ed25519.PublicKey:
			publicKeyAlgorithmProperties["curve"] = "Ed25519"
			publicKeyAlgorithmProperties["primitive"] = "signature"
		}
		recordAlgorithm := func(role, name string, properties map[string]any) string {
			digest := sha256.Sum256([]byte(role + ":" + name))
			algorithmReference := "algorithm:sha256:" + hex.EncodeToString(digest[:])
			algorithmsByReference[algorithmReference] = certificateComponent{
				Type:      "cryptographic-asset",
				Reference: algorithmReference,
				Name:      name,
				CryptoProperties: map[string]any{
					"assetType":           "algorithm",
					"algorithmProperties": properties,
				},
				Properties: []certificateProperty{
					{Name: "bommer:certificate:algorithm-role", Value: role},
				},
			}
			return algorithmReference
		}
		publicKeyAlgorithmReference := recordAlgorithm("public-key", publicKeyAlgorithmName, publicKeyAlgorithmProperties)
		signatureAlgorithmReference := recordAlgorithm("signature", certificate.SignatureAlgorithm.String(), map[string]any{
			"primitive": "signature",
		})
		certificateProperties := map[string]any{
			"certificateFormat":     "X.509",
			"notValidBefore":        certificate.NotBefore.UTC().Format(time.RFC3339),
			"notValidAfter":         certificate.NotAfter.UTC().Format(time.RFC3339),
			"signatureAlgorithmRef": signatureAlgorithmReference,
		}
		if options.IncludeIdentity {
			certificateProperties["subjectName"] = certificate.Subject.String()
			certificateProperties["issuerName"] = certificate.Issuer.String()
		}
		certificateReference := "certificate:sha256:" + certificateDigest
		component := certificateComponent{
			Type:      "cryptographic-asset",
			Reference: certificateReference,
			Name:      "X.509 SHA-256 " + certificateDigest,
			CryptoProperties: map[string]any{
				"assetType":             "certificate",
				"certificateProperties": certificateProperties,
			},
			Properties: []certificateProperty{
				{Name: "bommer:certificate:sha256", Value: certificateDigest},
				{Name: "bommer:certificate:public-key-algorithm-ref", Value: publicKeyAlgorithmReference},
				{Name: "bommer:certificate:expired", Value: strconv.FormatBool(now.After(certificate.NotAfter))},
				{Name: "bommer:certificate:trust-evaluated", Value: "false"},
			},
		}
		for sourcePath := range observation.sourcePaths {
			sourcesByCertificateReference[certificateReference] = append(sourcesByCertificateReference[certificateReference], sourcePath)
		}
		sort.Strings(sourcesByCertificateReference[certificateReference])
		for _, sourcePath := range sourcesByCertificateReference[certificateReference] {
			component.Properties = append(component.Properties, certificateProperty{
				Name:  "bommer:certificate:source",
				Value: sourcePath,
			})
		}
		components = append(components, component)
	}
	for _, component := range algorithmsByReference {
		components = append(components, component)
	}
	sort.Slice(components, func(leftIndex, rightIndex int) bool {
		return components[leftIndex].Reference < components[rightIndex].Reference
	})
	sort.Slice(result.Diagnostics, func(leftIndex, rightIndex int) bool {
		leftDiagnostic, rightDiagnostic := result.Diagnostics[leftIndex], result.Diagnostics[rightIndex]
		if leftDiagnostic.Path != rightDiagnostic.Path {
			return leftDiagnostic.Path < rightDiagnostic.Path
		}
		return leftDiagnostic.Code < rightDiagnostic.Code
	})
	result.Findings = len(certificatesByDigest)
	result.Evidence["sources"] = sourcesByCertificateReference
	result.Evidence["trust_evaluated"] = false
	if result.Status != "partial" && result.Findings > 0 {
		result.Status = "collected"
	}
	if err := ctx.Err(); err != nil {
		result.Status = "partial"
		return result, err
	}
	rootComponent := map[string]any{
		"type": "file",
		"name": job.Name,
	}
	if job.Version != "" {
		rootComponent["version"] = job.Version
	}
	if err := json.NewEncoder(out).Encode(map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": map[string]any{
			"component": rootComponent,
		},
		"components": components,
	}); err != nil {
		return result, errors.New("cannot write certificate inventory")
	}
	return result, nil
}

// Open each component relative to an already-open directory. O_NONBLOCK prevents
// a substituted FIFO from blocking before fstat can reject non-regular files.
func certificateOpenAt(parentDirectory *os.File, entryName string, requireDirectory bool) (*os.File, error) {
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if requireDirectory {
		flags |= syscall.O_DIRECTORY
	}
	fileDescriptor, err := syscall.Openat(int(parentDirectory.Fd()), entryName, flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileDescriptor), entryName), nil
}

func certificateOpenPath(path string) (*os.File, error) {
	currentDirectory, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	pathComponents := strings.Split(path, string(os.PathSeparator))
	for componentIndex, pathComponent := range pathComponents {
		if pathComponent == "" || pathComponent == "." {
			continue
		}
		// Reject parent traversal rather than normalizing away a preceding symlink.
		if pathComponent == ".." {
			currentDirectory.Close()
			return nil, syscall.EINVAL
		}
		nextFile, err := certificateOpenAt(currentDirectory, pathComponent, componentIndex < len(pathComponents)-1)
		currentDirectory.Close()
		if err != nil {
			return nil, err
		}
		currentDirectory = nextFile
	}
	return currentDirectory, nil
}

func certificateOpenCode(err error) string {
	switch {
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
		return "symlink-or-not-directory"
	case errors.Is(err, os.ErrNotExist):
		return "missing-path"
	case errors.Is(err, syscall.EINVAL):
		return "invalid-path"
	default:
		return "unreadable"
	}
}
