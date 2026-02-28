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

type EngineOutput struct {
	Engine   string    `json:"engine"`
	Version  string    `json:"version"`
	Findings []Finding `json:"findings"`
}

func Marshal(out EngineOutput) ([]byte, error) {
	return json.Marshal(out)
}

func MarshalPretty(out EngineOutput) ([]byte, error) {
	return json.MarshalIndent(out, "", "  ")
}
