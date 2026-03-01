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
	Name       string `json:"name"`
	Type       string `json:"type"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	IsExported bool   `json:"is_exported"`
	Receiver   string `json:"receiver,omitempty"`
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
	return json.Marshal(out)
}

func MarshalPretty(out EngineOutput) ([]byte, error) {
	return json.MarshalIndent(out, "", "  ")
}
