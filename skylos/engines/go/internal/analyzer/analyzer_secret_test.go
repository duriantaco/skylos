package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func secretFindings(t *testing.T, body string) []string {
	t.Helper()
	root := t.TempDir()
	source := "package main\n\nimport (\n\t\"flag\"\n\t\"fmt\"\n\t\"os\"\n)\n\n" +
		"type Config struct {\n\tPassword string\n\tSecret   string\n\tUsage    string\n}\n\n" +
		"var _ = flag.String\nvar _ = fmt.Errorf\nvar _ = os.Getenv\n\n" + body
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var severities []string
	for _, finding := range findings {
		if finding.RuleID == "SKY-S101" {
			severities = append(severities, finding.Severity)
		}
	}
	return severities
}

// A keyword in a message, flag, case label or env-var name is not a secret
// (caddy: 15 HIGH "secrets" such as "loading password hasher module: %v").
func TestCredentialKeywordInProseIsNotASecret(t *testing.T) {
	cases := map[string]string{
		"error message":               "func main() { _ = fmt.Errorf(\"loading password hasher module: %v\", nil) }\n",
		"case label":                  "func main() {\n\tswitch os.Args[0] {\n\tcase \"insecure_secrets_log\":\n\t}\n}\n",
		"flag help":                   "func main() { _ = flag.String(\"password\", \"\", \"The plaintext password\") }\n",
		"env lookup":                  "func main() { _ = os.Getenv(\"DB_PASSWORD\") }\n",
		"env name":                    "func main() { passwordEnv := \"DB_PASSWORD\"; _ = passwordEnv }\n",
		"env name in credential var":  "func main() { password := \"DB_PASSWORD_FILE2\"; _ = password }\n",
		"empty field":                 "func main() { _ = Config{Password: \"\"} }\n",
		"placeholder":                 "func main() { _ = Config{Password: \"changeme\"} }\n",
		"format string":               "func main() { secret := \"secret=%s;x=%d\"; _ = secret }\n",
		"usage text":                  "func main() { _ = Config{Usage: \"[--plaintext <password>] [--algorithm <argon2id|bcrypt>]\"} }\n",
		"message in credential field": "func main() { _ = Config{Password: \"password is required here\"} }\n",
		"path":                        "func main() { _ = Config{Secret: \"/run/secrets/db-password\"} }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := secretFindings(t, body); len(got) != 0 {
				t.Fatalf("unexpected SKY-S101 %v", got)
			}
		})
	}
}

func TestLiteralCredentialAssignmentsAreSecrets(t *testing.T) {
	cases := map[string]struct {
		body     string
		severity string
	}{
		"short var":      {"func main() { password := \"hunter2-Xq8Zt4mN7bJc\"; _ = password }\n", "HIGH"},
		"struct literal": {"func main() { _ = Config{Password: \"Xq8Zt4mN7bJc5HsY\"} }\n", "HIGH"},
		"map key":        {"func main() { _ = map[string]string{\"api_key\": \"Xq8Zt4mN7bJc5HsY1aGd\"} }\n", "HIGH"},
		"field assign":   {"func main() { var cfg Config; cfg.Secret = \"Xq8Zt4mN7bJc5HsY1aGd\"; _ = cfg }\n", "HIGH"},
		"var spec":       {"var dbPassword = \"Xq8Zt4mN7bJc5HsY1aGd\"\n\nfunc main() {}\n", "HIGH"},
		// Split so no token-shaped literal is committed (as the Python tests do); Go folds the constant.
		"provider token": {"func main() { token := \"ghp_" + "Xq8Zt4mN7bJc5HsY1aGd3FeU6Wn0Pq2Lk9Rv\"; _ = token }\n", "CRITICAL"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := secretFindings(t, tc.body)
			if len(got) != 1 || got[0] != tc.severity {
				t.Fatalf("want one %s SKY-S101, got %v", tc.severity, got)
			}
		})
	}
}
