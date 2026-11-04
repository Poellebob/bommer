package bom

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateJSON(t *testing.T, document string) (Info, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(path, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	return Validate(path)
}

func TestFixtures(t *testing.T) {
	for _, test := range []struct {
		version string
		want    Info
	}{
		{"1.6", Info{"1.6", 2, 1}},
		{"1.7", Info{"1.7", 1, 1}},
	} {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			got, err := Validate("testdata/minimal-" + test.version + ".json")
			if err != nil || got != test.want {
				t.Fatalf("Validate() = %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestEmptyDocumentsAndVersion(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		for _, fields := range []string{"", `,"components":[]`, `,"version":1`, `,"version":2.0`, `,"version":123456789012345678901234567890`, `,"metadata":{"component":{"type":"cryptographic-asset","name":"root"}}`} {
			document := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":%q%s}`, version, fields)
			got, err := validateJSON(t, document+" \n\t")
			if err != nil || got != (Info{SpecVersion: version}) {
				t.Errorf("%s: got %+v, %v", document, got, err)
			}
		}
	}
}

func TestInvalidDocuments(t *testing.T) {
	for name, document := range map[string]string{
		"empty file":      "",
		"null":            "null",
		"array":           "[]",
		"missing format":  `{"specVersion":"1.6"}`,
		"wrong format":    `{"bomFormat":"SPDX","specVersion":"1.6"}`,
		"missing spec":    `{"bomFormat":"CycloneDX"}`,
		"unsupported":     `{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		"numeric spec":    `{"bomFormat":"CycloneDX","specVersion":1.6}`,
		"trailing object": `{"bomFormat":"CycloneDX","specVersion":"1.6"} {}`,
		"trailing null":   `{"bomFormat":"CycloneDX","specVersion":"1.6"} null`,
		"trailing junk":   `{"bomFormat":"CycloneDX","specVersion":"1.6"} garbage`,
	} {
		t.Run(name, func(t *testing.T) {
			if info, err := validateJSON(t, document); err == nil || info != (Info{}) {
				t.Fatalf("got %+v, %v; want zero Info and error", info, err)
			}
		})
	}
	for _, version := range []string{"1.6", "1.7"} {
		for name, field := range map[string]string{
			"zero version":                `"version":0`,
			"negative version":            `"version":-1`,
			"fractional version":          `"version":1.5`,
			"string version":              `"version":"1"`,
			"null version":                `"version":null`,
			"unknown field":               `"surprise":true`,
			"invalid serial":              `"serialNumber":"not-a-uuid"`,
			"invalid timestamp":           `"metadata":{"timestamp":"yesterday"}`,
			"unknown component type":      `"components":[{"type":"imaginary","name":"x"}]`,
			"unknown component field":     `"components":[{"type":"library","name":"x","surprise":true}]`,
			"missing component name":      `"components":[{"type":"library"}]`,
			"component name type":         `"components":[{"type":"library","name":42}]`,
			"invalid SPDX":                `"components":[{"type":"library","name":"x","licenses":[{"license":{"id":"not-an-SPDX-license"}}]}]`,
			"invalid signature":           `"signature":{"algorithm":"invalid","value":"abc"}`,
			"missing crypto asset type":   `"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{}}]`,
			"unknown crypto asset type":   `"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"invalid"}}]`,
			"unknown crypto field":        `"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","surprise":true}}]`,
			"invalid primitive":           `"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"invalid"}}}]`,
			"invalid nested crypto field": `"components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"ae","surprise":true}}}]`,
		} {
			t.Run(version+"/"+name, func(t *testing.T) {
				document := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":%q,%s}`, version, field)
				if info, err := validateJSON(t, document); err == nil || info != (Info{}) {
					t.Fatalf("got %+v, %v; want zero Info and error", info, err)
				}
			})
		}
	}
}

func TestSchemaSelectionAndOfflineLoading(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	for _, version := range []string{"1.6", "1.7"} {
		for _, schemaURL := range []string{server.URL + "/evil.json", "https://attacker.invalid/schema.json", "file:///etc/passwd", schemaBase + "bom-1.5.schema.json"} {
			document := fmt.Sprintf(`{"$schema":%q,"bomFormat":"CycloneDX","specVersion":%q}`, schemaURL, version)
			if _, err := validateJSON(t, document); err != nil {
				t.Errorf("$schema %q must not control validation: %v", schemaURL, err)
			}
			compiler := jsonschema.NewCompiler()
			compiler.UseLoader(embeddedLoader{})
			if _, err := compiler.Compile(schemaURL); err == nil {
				t.Errorf("unexpectedly loaded unembedded schema %q", schemaURL)
			}
		}
	}
	for _, version := range []string{"1.6", "1.7"} {
		document := fmt.Sprintf(`{"$schema":%q,"bomFormat":"CycloneDX","specVersion":%q,"components":[{"type":"cryptographic-asset","name":"AES","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"algorithmFamily":"AES"}}}]}`, server.URL, version)
		_, err := validateJSON(t, document)
		if (err == nil) != (version == "1.7") {
			t.Errorf("specVersion %s did not select its own schema: %v", version, err)
		}
	}
	for _, property := range []string{"algorithmFamily", "ellipticCurve"} {
		document := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"cryptographic-asset","name":"x","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{%q:"invalid"}}}]}`, property)
		if _, err := validateJSON(t, document); err == nil {
			t.Errorf("accepted invalid external cryptography enum %s", property)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("made %d network requests", requests.Load())
	}
}

func TestNestedComponentCounts(t *testing.T) {
	for _, version := range []string{"1.6", "1.7"} {
		document := fmt.Sprintf(`{
		  "bomFormat":"CycloneDX", "specVersion":%q,
		  "metadata":{
		    "component":{"type":"cryptographic-asset","name":"root","components":[
		      {"type":"library","name":"child","components":[{"type":"cryptographic-asset","name":"grandchild"}]}
		    ]},
		    "tools":{"components":[{"type":"application","name":"tool"}]}
		  },
		  "components":[{"type":"library","name":"lib","pedigree":{
		    "ancestors":[{"type":"library","name":"ancestor"}],
		    "descendants":[{"type":"library","name":"descendant"}],
		    "variants":[{"type":"cryptographic-asset","name":"variant"}]
		  }}],
		  "formulation":[{"components":[{"type":"application","name":"builder"}]}]
		}`, version)
		got, err := validateJSON(t, document)
		if want := (Info{version, 8, 2}); err != nil || got != want {
			t.Errorf("got %+v, %v; want %+v", got, err, want)
		}
	}
}

func TestMissingFile(t *testing.T) {
	if info, err := Validate(filepath.Join(t.TempDir(), "missing.json")); err == nil || info != (Info{}) {
		t.Fatalf("got %+v, %v; want zero Info and error", info, err)
	}
}

func TestArtifactHashes(t *testing.T) {
	manifest, err := resources.ReadFile("schemas/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		fields := strings.Fields(line)
		data, err := resources.ReadFile("schemas/" + fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != fields[0] {
			t.Errorf("artifact %s hash = %s; want %s", fields[1], got, fields[0])
		}
	}
}
