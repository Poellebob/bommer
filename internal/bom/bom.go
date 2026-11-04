// Package bom validates CycloneDX JSON documents using embedded upstream schemas.
package bom

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Info describes a successfully validated BOM. Counts include nested component
// records, but exclude metadata.component itself. Crypto assets are components
// whose type is cryptographic-asset.
type Info struct {
	SpecVersion      string
	ComponentCount   int
	CryptoAssetCount int
}

//go:embed schemas
var resources embed.FS

const schemaBase = "http://cyclonedx.org/schema/"

type embeddedLoader struct{}

func (embeddedLoader) Load(url string) (any, error) {
	name := strings.TrimPrefix(url, schemaBase)
	switch name {
	case "bom-1.6.schema.json", "bom-1.7.schema.json", "spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json":
		if url != schemaBase+name {
			break
		}
		data, err := resources.ReadFile("schemas/" + name)
		if err != nil {
			return nil, err
		}
		return jsonschema.UnmarshalJSON(bytes.NewReader(data))
	}
	return nil, fmt.Errorf("schema resource is not embedded: %q", url)
}

type compiledSchema struct {
	validator *jsonschema.Schema
	document  map[string]any
}

var compiledSchemas = sync.OnceValues(func() (map[string]compiledSchema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	compiler.UseLoader(embeddedLoader{})
	schemasByVersion := make(map[string]compiledSchema)
	for _, version := range []string{"1.6", "1.7"} {
		url := schemaBase + "bom-" + version + ".schema.json"
		schemaDocument, err := (embeddedLoader{}).Load(url)
		if err != nil {
			return nil, err
		}
		validator, err := compiler.Compile(url)
		if err != nil {
			return nil, err
		}
		schemasByVersion[version] = compiledSchema{
			validator: validator,
			document:  schemaDocument.(map[string]any),
		}
	}
	return schemasByVersion, nil
})

// Validate reads exactly one JSON document from path and validates it against
// CycloneDX 1.6 or 1.7. specVersion selects the schema; the document's $schema is
// never loaded. Empty, schema-valid inventories are accepted. On error, Info is
// zero-valued. No schema references can access the network or local filesystem.
func Validate(path string) (Info, error) {
	file, err := os.Open(path)
	if err != nil {
		return Info{}, fmt.Errorf("open BOM: %w", err)
	}
	defer file.Close()

	document, err := Decode(file)
	if err != nil {
		return Info{}, fmt.Errorf("decode BOM: %w", err)
	}
	object, ok := document.(map[string]any)
	if !ok {
		return Info{}, fmt.Errorf("BOM must be a JSON object")
	}
	if object["bomFormat"] != "CycloneDX" {
		return Info{}, fmt.Errorf("bomFormat must explicitly be CycloneDX")
	}
	version, _ := object["specVersion"].(string)
	if version != "1.6" && version != "1.7" {
		return Info{}, fmt.Errorf("unsupported CycloneDX specVersion %q (expected 1.6 or 1.7)", version)
	}
	schemasByVersion, err := compiledSchemas()
	if err != nil {
		return Info{}, fmt.Errorf("compile embedded BOM schemas: %w", err)
	}
	schema := schemasByVersion[version]
	if err := schema.validator.Validate(document); err != nil {
		return Info{}, fmt.Errorf("validate CycloneDX %s: %w", version, err)
	}
	info := Info{SpecVersion: version}
	countComponents(document, schema.document, schema.document, "", &info)
	return info, nil
}

// Follow schema locations rather than guessing from instance keys. This includes
// components in tools, pedigree, formulation, annotations, and metadata children.
func countComponents(value any, schemaNode, schemaRoot map[string]any, instancePath string, info *Info) {
	if reference, ok := schemaNode["$ref"].(string); ok {
		if reference == "#/definitions/component" && instancePath != "/metadata/component" {
			info.ComponentCount++
			if value.(map[string]any)["type"] == "cryptographic-asset" {
				info.CryptoAssetCount++
			}
		}
		if definitionName, ok := strings.CutPrefix(reference, "#/definitions/"); ok {
			definition := schemaRoot["definitions"].(map[string]any)[definitionName].(map[string]any)
			countComponents(value, definition, schemaRoot, instancePath, info)
		}
		return
	}
	if object, ok := value.(map[string]any); ok {
		properties, _ := schemaNode["properties"].(map[string]any)
		for key, child := range object {
			if property, ok := properties[key].(map[string]any); ok {
				countComponents(child, property, schemaRoot, instancePath+"/"+key, info)
			}
		}
	}
	if array, ok := value.([]any); ok {
		if items, ok := schemaNode["items"].(map[string]any); ok {
			for _, child := range array {
				countComponents(child, items, schemaRoot, instancePath+"/[]", info)
			}
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		branches, _ := schemaNode[keyword].([]any)
		for _, branch := range branches {
			countComponents(value, branch.(map[string]any), schemaRoot, instancePath, info)
		}
	}
}
