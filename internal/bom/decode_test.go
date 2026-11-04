package bom

import (
	"strings"
	"testing"
)

func TestDecodeRejectsAmbiguity(t *testing.T) {
	for _, input := range []string{
		`{"name":"secret","name":"safe"}`,
		`{"outer":[{"name":"secret","na\u006de":"safe"}]}`,
		`{"name":null,"name":"safe"}`,
		`{} {}`,
		`{"x":1,}`,
		`[1,]`,
		strings.Repeat("[", 514) + strings.Repeat("]", 514),
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted ambiguous or invalid JSON: %.80s", input)
		}
	}
}
