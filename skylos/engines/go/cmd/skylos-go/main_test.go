package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"skylos/engines/go/internal/output"
	"skylos/engines/go/internal/symbols"
)

func TestEmptySymbolCollectionsAreJSONArrays(t *testing.T) {
	for _, source := range []string{
		"package main\n",
		"package main\nfunc main() { println(\"active\") }\n",
	} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "main.go")
			handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := handle.WriteString(source); err != nil {
				t.Fatal(err)
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			result, err := symbols.Extract(root)
			if err != nil {
				t.Fatal(err)
			}
			if result.Defs == nil || result.Refs == nil || result.CallPairs == nil {
				t.Fatal("extraction returned nil collections")
			}
			data, err := output.Marshal(output.EngineOutput{
				Engine:   engineID,
				Version:  "test",
				Findings: []output.Finding{},
				Symbols:  symbolDataForResult(result),
			})
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			symbolPayload := payload["symbols"].(map[string]any)
			for _, name := range []string{"defs", "refs", "call_pairs"} {
				if _, ok := symbolPayload[name].([]any); !ok {
					t.Fatalf("%s is not a JSON array: %s", name, data)
				}
			}
		})
	}
}

func TestUnavailableSymbolResultIsNotFabricatedAsEmpty(t *testing.T) {
	if symbolDataForResult(nil) != nil {
		t.Fatal("unavailable symbol extraction was fabricated as an empty result")
	}
}
