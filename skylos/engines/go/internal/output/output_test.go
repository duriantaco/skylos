package output

import (
	"encoding/json"
	"testing"
)

func TestMarshalEmptySymbolArraysKeepTheEngineContract(t *testing.T) {
	for name, marshal := range map[string]func(EngineOutput) ([]byte, error){
		"compact": Marshal,
		"pretty":  MarshalPretty,
	} {
		t.Run(name, func(t *testing.T) {
			original := &SymbolData{}
			data, err := marshal(EngineOutput{Engine: "skylos-go", Version: "test", Findings: []Finding{}, Symbols: original})
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				Symbols map[string]any `json:"symbols"`
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"defs", "refs", "call_pairs"} {
				array, ok := decoded.Symbols[field].([]any)
				if !ok || len(array) != 0 {
					t.Errorf("%s must encode an empty JSON array, got %#v", field, decoded.Symbols[field])
				}
			}
			if original.Defs != nil || original.Refs != nil || original.CallPairs != nil {
				t.Fatal("serialization must not mutate the extraction result")
			}
		})
	}
}
