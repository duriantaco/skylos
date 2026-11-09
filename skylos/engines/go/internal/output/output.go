package output

import "encoding/json"

type Finding struct {
	RuleID     string  `json:"rule_id,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Message    string  `json:"message,omitempty"`
	File       string  `json:"file,omitempty"`
	Line       int     `json:"line,omitempty"`
	Col        int     `json:"col,omitempty"`
	Symbol     string  `json:"symbol,omitempty"`
}

type SymbolDef struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	IsExported   bool   `json:"is_exported"`
	Receiver     string `json:"receiver,omitempty"`
	Reachability string `json:"reachability,omitempty"`
}

type SymbolRef struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type SymbolCallPair struct {
	Caller string `json:"caller"`
	Callee string `json:"callee"`
}

type SymbolData struct {
	Defs      []SymbolDef      `json:"defs"`
	Refs      []SymbolRef      `json:"refs"`
	CallPairs []SymbolCallPair `json:"call_pairs"`
}

type EngineOutput struct {
	Engine   string      `json:"engine"`
	Version  string      `json:"version"`
	Findings []Finding   `json:"findings"`
	Symbols  *SymbolData `json:"symbols,omitempty"`
}

func Marshal(out EngineOutput) ([]byte, error) {
	return json.Marshal(withSymbolArrays(out))
}

func MarshalPretty(out EngineOutput) ([]byte, error) {
	return json.MarshalIndent(withSymbolArrays(out), "", "  ")
}

// Symbol arrays are required by the Python engine contract even when a valid
// package has no declarations or no references to project declarations.
func withSymbolArrays(out EngineOutput) EngineOutput {
	if out.Symbols == nil {
		return out
	}
	symbols := *out.Symbols
	if symbols.Defs == nil {
		symbols.Defs = []SymbolDef{}
	}
	if symbols.Refs == nil {
		symbols.Refs = []SymbolRef{}
	}
	if symbols.CallPairs == nil {
		symbols.CallPairs = []SymbolCallPair{}
	}
	out.Symbols = &symbols
	return out
}
