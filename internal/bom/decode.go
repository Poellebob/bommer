package bom

import (
	"encoding/json"
	"fmt"
	"io"
)

// Decode accepts one unambiguous JSON value. Duplicate keys are rejected even
// when escaped differently, so preserved bytes and inspected evidence agree.
func Decode(reader io.Reader) (any, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var readValue func(int) (any, error)
	readValue = func(depth int) (any, error) {
		if depth > 512 {
			return nil, fmt.Errorf("JSON nesting exceeds 512 levels")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			object := map[string]any{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := token.(string)
				if !ok {
					return nil, fmt.Errorf("invalid JSON object key")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON object key")
				}
				value, err := readValue(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case json.Delim('['):
			array := []any{}
			for decoder.More() {
				value, err := readValue(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return array, nil
		default:
			return token, nil
		}
	}
	value, err := readValue(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one JSON document")
	}
	return value, nil
}
