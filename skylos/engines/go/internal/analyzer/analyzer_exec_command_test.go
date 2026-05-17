package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecCommandShellCommandInjectionDetection(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		wantRule bool
	}{
		{
			name: "literal shell flag with variable command",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	userInput := os.Args[1]
	exec.Command("sh", "-c", userInput).Run()
}
`,
			wantRule: true,
		},
		{
			name: "variable shell flag with variable command",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	flag := "-c"
	userInput := os.Args[1]
	exec.Command("sh", flag, userInput).Run()
}
`,
			wantRule: true,
		},
		{
			name: "command context variable shell flag with variable command",
			source: `package main

import (
	"context"
	"os"
	"os/exec"
)

func main() {
	flag := "-c"
	userInput := os.Args[1]
	exec.CommandContext(context.Background(), "sh", flag, userInput).Run()
}
`,
			wantRule: true,
		},
		{
			name: "variable option before literal shell flag with variable command",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	option := "-x"
	userInput := os.Args[1]
	exec.Command("sh", option, "-c", userInput).Run()
}
`,
			wantRule: true,
		},
		{
			name: "variable shell flag with literal command",
			source: `package main

import "os/exec"

func main() {
	flag := "-c"
	exec.Command("sh", flag, "echo ok").Run()
}
`,
			wantRule: false,
		},
		{
			name: "non shell command with variable argument",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	branch := os.Args[1]
	exec.Command("git", "checkout", branch).Run()
}
`,
			wantRule: false,
		},
		{
			name: "literal shell script with variable argument",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	userInput := os.Args[1]
	exec.Command("sh", "script.sh", userInput).Run()
}
`,
			wantRule: false,
		},
		{
			name: "powershell file mode with variable arguments",
			source: `package main

import (
	"os"
	"os/exec"
)

func main() {
	script := os.Args[1]
	arg := os.Args[2]
	exec.Command("powershell", "-File", script, arg).Run()
}
`,
			wantRule: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := analyzeGoSource(t, tc.source)
			gotRule := hasRule(findings, "SKY-G212")
			if gotRule != tc.wantRule {
				t.Fatalf("SKY-G212 presence = %v, want %v; findings: %#v", gotRule, tc.wantRule, findings)
			}
		})
	}
}

func analyzeGoSource(t *testing.T, source string) []string {
	t.Helper()

	root := t.TempDir()
	path := filepath.Join(root, "main.go")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}

	rules := make([]string, 0, len(findings))
	for _, finding := range findings {
		rules = append(rules, finding.RuleID)
	}
	return rules
}

func hasRule(rules []string, ruleID string) bool {
	for _, rule := range rules {
		if rule == ruleID {
			return true
		}
	}
	return false
}
