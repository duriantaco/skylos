package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"skylos/engines/go/internal/analyzer"
	"skylos/engines/go/internal/output"
	"skylos/engines/go/internal/symbols"
)

const engineID = "skylos-go"
const standaloneVersion = "dev"

func main() {
	if len(os.Args) >= 2 {
		a := os.Args[1]
		if a == "--version" || a == "-v" || a == "version" {
			fmt.Printf("%s %s (standalone engine; normally invoked by skylos CLI)\n", engineID, standaloneVersion)
			return
		}
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "analyze":
		analyze(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  skylos-go analyze --root <path> --format json --skylos-version <ver>
  skylos-go --version
`)
}

func analyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var root string
	var format string
	var skylosVersion string
	var pretty bool

	fs.StringVar(&root, "root", ".", "Root directory to analyze (Go module root)")
	fs.StringVar(&format, "format", "json", "Output format: json")
	fs.StringVar(&skylosVersion, "skylos-version", "", "Skylos version passed from Python orchestrator")
	fs.BoolVar(&pretty, "pretty", false, "Pretty-print JSON output")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format != "json" {
		fmt.Fprintf(os.Stderr, "Unsupported format: %q\n", format)
		os.Exit(2)
	}

	if strings.TrimSpace(skylosVersion) == "" {
		fmt.Fprintf(os.Stderr, "Missing required flag: --skylos-version\n")
		os.Exit(2)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve root: %v\n", err)
		os.Exit(2)
	}
	info, err := os.Stat(absRoot)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "Invalid --root directory: %s\n", absRoot)
		os.Exit(2)
	}

	a := analyzer.New()
	findings, analysisErr := a.AnalyzeDir(absRoot)
	if analysisErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: analysis encountered errors: %v\n", analysisErr)
	}
	if findings == nil {
		findings = []output.Finding{}
	}

	// Extract symbols for dead code detection.
	symResult, symErr := symbols.Extract(absRoot)
	if symErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: symbol extraction encountered errors: %v\n", symErr)
	}

	var symData *output.SymbolData
	if symResult != nil {
		symData = &output.SymbolData{}
		for _, d := range symResult.Defs {
			symData.Defs = append(symData.Defs, output.SymbolDef{
				Name:       d.Name,
				Type:       d.Type,
				File:       d.File,
				Line:       d.Line,
				IsExported: d.IsExported,
				Receiver:   d.Receiver,
			})
		}
		for _, r := range symResult.Refs {
			symData.Refs = append(symData.Refs, output.SymbolRef{
				Name: r.Name,
				File: r.File,
			})
		}
		for _, c := range symResult.CallPairs {
			symData.CallPairs = append(symData.CallPairs, output.SymbolCallPair{
				Caller: c.Caller,
				Callee: c.Callee,
			})
		}
	}

	out := output.EngineOutput{
		Engine:   engineID,
		Version:  skylosVersion,
		Findings: findings,
		Symbols:  symData,
	}

	var b []byte
	if pretty {
		b, err = output.MarshalPretty(out)
	} else {
		b, err = output.Marshal(out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode JSON: %v\n", err)
		os.Exit(2)
	}

	fmt.Println(string(b))
}
