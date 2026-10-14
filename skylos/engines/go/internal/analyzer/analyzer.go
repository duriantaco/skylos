package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"skylos/engines/go/internal/output"
)

var sqlSinks = map[string][]string{
	"database/sql": {"Query", "QueryRow", "Exec", "QueryContext", "ExecContext"},
}

var cmdSinks = map[string][]string{
	"os/exec": {"Command", "CommandContext"},
	"os":      {"StartProcess"},
}

var pathSinks = map[string][]string{
	"os":        {"Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "Mkdir", "MkdirAll"},
	"io/ioutil": {"ReadFile", "WriteFile"},
}

var httpSinks = map[string][]string{
	"net/http": {"Get", "Post", "Head", "PostForm"},
}

var cryptoWeakFuncs = map[string][]string{
	"crypto/md5":  {"New", "Sum"},
	"crypto/sha1": {"New", "Sum"},
}

var openFuncs = map[string]map[string]bool{
	"os":           {"Open": true, "OpenFile": true},
	"database/sql": {"Open": true},
}

var defaultSkipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true,
	"testdata": true, ".github": true,
}

type Analyzer struct {
	fset      *token.FileSet
	findings  []output.Finding
	imports   map[string]string
	seen      map[string]bool
	callTaint map[*ast.CallExpr]*funcTaint
	// the current file is test-support code (see isTestSupportFile)
	testSupport bool
}

func New() *Analyzer {
	return &Analyzer{
		fset:    token.NewFileSet(),
		imports: make(map[string]string),
		seen:    make(map[string]bool),
	}
}

func (a *Analyzer) AnalyzeDir(root string) ([]output.Finding, error) {
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return nil, rootErr
	}
	root = resolvedRoot

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			if defaultSkipDirs[name] || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		resolvedPath, err := filepath.EvalSymlinks(path)
		if err != nil || !isPathWithinRoot(resolvedRoot, resolvedPath) {
			return nil
		}

		a.analyzeFile(resolvedPath)
		return nil
	})

	return a.findings, err
}

func isPathWithinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func (a *Analyzer) analyzeFile(path string) {
	file, err := parser.ParseFile(a.fset, path, nil, parser.ParseComments)
	if err != nil {
		return
	}

	a.imports = make(map[string]string)

	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			parts := strings.Split(importPath, "/")
			alias = parts[len(parts)-1]
		}
		a.imports[alias] = importPath
	}

	a.computeTaint(file)
	a.testSupport = a.isTestSupportFile(file)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Body != nil {
				a.checkDeferInLoop(node.Body, path)
				a.checkUnclosedResource(node.Body, path)
				a.checkArchiveExtraction(node.Body, path)
			}
		case *ast.FuncLit:
			if node.Body != nil {
				a.checkDeferInLoop(node.Body, path)
				a.checkUnclosedResource(node.Body, path)
				a.checkArchiveExtraction(node.Body, path)
			}
		case *ast.CallExpr:
			a.checkCallExpr(node, path)
		case *ast.CompositeLit:
			a.checkCompositeLit(node, path)
		case *ast.Field:
			if node.Tag != nil {
				return false
			}
		case *ast.BasicLit:
			a.checkHardcodedSecret(node, path)
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					a.checkCredentialAssignment(credentialName(lhs), node.Rhs[i], path)
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					a.checkCredentialAssignment(name.Name, node.Values[i], path)
				}
			}
		case *ast.KeyValueExpr:
			a.checkCredentialAssignment(credentialName(node.Key), node.Value, path)
		}
		return true
	})
}

func (a *Analyzer) checkCallExpr(call *ast.CallExpr, path string) {
	pkg, funcName := a.getFuncInfo(call.Fun)
	ft := a.taintFor(call)

	sqlMatched := false
	if funcs, ok := sqlSinks[pkg]; ok && contains(funcs, funcName) {
		sqlMatched = true
		_ = funcs
	}
	if !sqlMatched {
		if isSQLMethodName(funcName) && a.isSQLReceiver(call.Fun) {
			sqlMatched = true
		}
	}
	if sqlMatched {
		queryArg := 0
		if strings.HasSuffix(funcName, "Context") {
			queryArg = 1 // QueryContext(ctx, query, args...)
		}
		if len(call.Args) > queryArg {
			if severity, detail := a.sqlQuerySeverity(call.Args[queryArg], ft); severity != "" {
				a.addFinding(call, path, "SKY-G211", severity, "SQL Injection", detail)
			}
		}
	}

	if funcs, ok := cmdSinks[pkg]; ok && contains(funcs, funcName) {
		severity, detail := "", ""
		if pkg == "os/exec" && (funcName == "Command" || funcName == "CommandContext") {
			severity, detail = a.execCommandSeverity(call, funcName, ft)
		} else if len(call.Args) > 0 && a.isTainted(call.Args[0], ft.tainted) {
			severity = "CRITICAL"
			detail = "The program path comes from request or network input. Run a fixed program and validate its arguments."
		}
		if severity != "" {
			a.addFinding(call, path, "SKY-G212", severity, "Command Injection", detail)
		}
	}

	pathArg := -1
	if funcs, ok := pathSinks[pkg]; ok && contains(funcs, funcName) {
		pathArg = 0
	} else if pkg == "net/http" && funcName == "ServeFile" {
		pathArg = 2
	}
	if pathArg >= 0 && len(call.Args) > pathArg && a.isUntrustedPath(call.Args[pathArg], ft) {
		a.addFinding(call, path, "SKY-G215", "HIGH", "Potential Path Traversal",
			"File path comes from request or network input without a containment check. "+
				"Use filepath.Base, or clean it and verify it stays under a fixed base (filepath.Rel or a prefix check).")
	}

	if funcs, ok := httpSinks[pkg]; ok && contains(funcs, funcName) {
		if len(call.Args) > 0 && a.isSSRFURL(call.Args[0], ft) {
			a.addFinding(call, path, "SKY-G216", "CRITICAL", "Potential SSRF",
				"HTTP request URL comes from request or network input and can choose the host. Validate it against an allowlist.")
		}
	}

	if pkg == "net/http" {
		urlArg := -1
		switch funcName {
		case "NewRequest":
			urlArg = 1
		case "NewRequestWithContext":
			urlArg = 2
		}
		if urlArg >= 0 && len(call.Args) > urlArg && a.isSSRFURL(call.Args[urlArg], ft) {
			a.addFinding(call, path, "SKY-G216", "CRITICAL", "Potential SSRF",
				"HTTP request URL comes from request or network input and can choose the host. Validate it against an allowlist.")
		}
	}

	if funcs, ok := cryptoWeakFuncs[pkg]; ok && contains(funcs, funcName) {
		rule := "SKY-G207"
		msg := "Weak hash algorithm MD5"
		if strings.Contains(pkg, "sha1") {
			rule = "SKY-G208"
			msg = "Weak hash algorithm SHA1"
		}
		a.addFinding(call, path, rule, "MEDIUM", msg,
			"MD5/SHA1 are cryptographically broken. Use SHA-256 or better for security purposes.")
	}

	// SKY-G209: Weak random number generator
	if pkg == "math/rand" || pkg == "math/rand/v2" {
		a.addFinding(call, path, "SKY-G209", "MEDIUM", "Weak Random Number Generator",
			"math/rand is not cryptographically secure. Use crypto/rand for security-sensitive operations.")
	}

	// SKY-G206: Unsafe package usage. LOW, like gosec's G103 ("use of unsafe
	// calls should be audited"): a review prompt, not a vulnerability.
	if pkg == "unsafe" {
		a.addFinding(call, path, "SKY-G206", "LOW", "Unsafe Package Usage",
			"The unsafe package bypasses Go's type safety. Avoid unless absolutely necessary.")
	}

	// SKY-G220: Open redirect
	if pkg == "net/http" && funcName == "Redirect" {
		if len(call.Args) >= 3 && a.isOpenRedirectTarget(call.Args[2], ft) {
			a.addFinding(call, path, "SKY-G220", "HIGH", "Open Redirect",
				"Redirect target comes from request or network input and can choose where the redirect goes. "+
					"Allow only same-origin paths (one leading \"/\", not \"//\") or an allowlist.")
		}
	}
}

func (a *Analyzer) checkCompositeLit(lit *ast.CompositeLit, path string) {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}

	importPath := a.imports[id.Name]
	typeName := sel.Sel.Name

	// crypto/tls.Config checks
	if importPath == "crypto/tls" && typeName == "Config" {
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					if key.Name == "InsecureSkipVerify" {
						// Not in test-support code, like Python's D346 (debug
						// mode) in test modules: a deployment-only hazard.
						if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" && !a.testSupport {
							a.addFinding(lit, path, "SKY-G210", "HIGH", "TLS Verification Disabled",
								"InsecureSkipVerify disables certificate validation, enabling MITM attacks.")
						}
					}
					// SKY-G280: Weak TLS version
					if key.Name == "MinVersion" {
						if valSel, ok := kv.Value.(*ast.SelectorExpr); ok {
							if valSel.Sel.Name == "VersionTLS10" || valSel.Sel.Name == "VersionTLS11" {
								a.addFinding(lit, path, "SKY-G280", "HIGH", "Weak TLS Version",
									"TLS 1.0/1.1 are deprecated. Use tls.VersionTLS12 or tls.VersionTLS13.")
							}
						}
					}
				}
			}
		}
	}

	// SKY-G221: Insecure Cookie
	if importPath == "net/http" && typeName == "Cookie" {
		hasHttpOnly := false
		hasSecure := false
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok {
					if key.Name == "HttpOnly" {
						if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
							hasHttpOnly = true
						}
					}
					if key.Name == "Secure" {
						if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
							hasSecure = true
						}
					}
				}
			}
		}
		if !hasHttpOnly || !hasSecure {
			a.addFinding(lit, path, "SKY-G221", "MEDIUM", "Insecure Cookie",
				"http.Cookie missing HttpOnly or Secure flag. Set both to true to prevent XSS and MITM.")
		}
	}
}

func (a *Analyzer) checkHardcodedSecret(lit *ast.BasicLit, path string) {
	if lit.Kind != token.STRING {
		return
	}

	val := strings.Trim(lit.Value, `"'`+"`")
	valLower := strings.ToLower(val)

	if len(val) < 16 {
		return
	}

	if hasProviderSecretPrefix(val, valLower) {
		a.addFinding(lit, path, "SKY-S101", "CRITICAL", "Hardcoded Secret",
			"Potential secret or API key found in source code. Use environment variables instead.")
	}
}

var providerSecretPrefixes = append([]string{
	"sk-",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"xoxb-", "xoxp-", "xoxa-",
	"AKIA",
	"eyJ",
}, stripeStylePrefixes()...)

// stripeStylePrefixes joins "sk_live_" and "sk_test_" at run time. As string
// constants the linker can pack them against other text, and secret scanners
// (GitHub push protection) then read the engine binary as holding a key.
func stripeStylePrefixes() []string {
	modes := []string{"live", "test"}
	prefixes := make([]string, 0, len(modes))
	for _, mode := range modes {
		prefixes = append(prefixes, "sk_"+mode+"_")
	}
	return prefixes
}

func hasProviderSecretPrefix(val, valLower string) bool {
	if len(val) < 16 {
		return false
	}
	for _, p := range providerSecretPrefixes {
		if strings.HasPrefix(val, p) || strings.HasPrefix(valLower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// A keyword in a string ("loading password hasher module", "insecure_secrets_log",
// CLI usage text) is not a secret. A credential is a literal value assigned to a
// credential-named variable, struct field or map key, judged by the same rules as
// the Python secrets scanner (skylos/rules/secrets.py: _is_credential_key,
// _is_placeholder_credential, _looks_like_config_credential).
var credentialKeySuffixes = []string{
	"password", "passwd", "passphrase", "pwd", "secret", "secretkey",
	"clientsecret", "token", "apikey", "accesskey", "privatekey", "authkey",
}

// Names that end with a credential word but name, point to or describe it.
var credentialKeyExcludedPrefixes = []string{
	"existing", "use", "enable", "require", "min", "max", "no", "skip",
	"generate", "auto", "random", "has", "is",
}

var credentialPlaceholderValues = map[string]bool{
	"": true, "password": true, "passwd": true, "pass": true, "pwd": true,
	"secret": true, "token": true, "changeme": true, "change_me": true,
	"change-me": true, "changeit": true, "example": true, "placeholder": true,
	"redacted": true, "hidden": true, "masked": true, "dummy": true, "none": true,
	"null": true, "nil": true, "undefined": true, "true": true, "false": true,
	"yes": true, "no": true, "on": true, "off": true, "todo": true, "tbd": true,
	"fixme": true, "default": true, "user": true, "username": true, "pw": true,
	"xxx": true, "test": true, "testing": true, "foo": true, "bar": true,
	"baz": true, "qux": true, "foobar": true, "hunter2": true, "secret123": true,
	"password123": true, "password1": true,
}

var credentialPlaceholderHints = []string{
	"example", "changeme", "change_me", "change-me", "placeholder", "your_",
	"your-", "yourpass", "yoursecret", "yourtoken", "replace", "dummy", "sample",
	"redacted", "fake", "insert", "not_a_real", "notreal", "do_not_use", "xxxx",
	"****", "....",
}

var credentialReferenceMarkers = []string{
	"${", "{{", "}}", "$(", "%(", "<%", "#{", "enc[", "vault:", "secretref",
	"secretkeyref", "valuefrom", "arn:aws:secretsmanager", "projects/",
}

var (
	envVarNameRE      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	formatVerbRE      = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
	numericValueRE    = regexp.MustCompile(`^[+-]?\d+(?:\.\d+)?$`)
	tokenValueShapeRE = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

// credentialName is the name a value is bound to: a variable, a selector's
// field (cfg.Password), a struct-literal key (Password:) or a string map key.
func credentialName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return credentialName(e.Index)
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			if unquoted, err := strconv.Unquote(e.Value); err == nil {
				return unquoted
			}
		}
	}
	return ""
}

func normalizedCredentialKey(name string) string {
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isCredentialKey(name string) bool {
	key := normalizedCredentialKey(name)
	matched := false
	for _, suffix := range credentialKeySuffixes {
		if strings.HasSuffix(key, suffix) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, prefix := range credentialKeyExcludedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return false
		}
	}
	return true
}

func isPlaceholderCredential(value string) bool {
	stripped := strings.TrimSpace(value)
	lowered := strings.ToLower(stripped)
	if credentialPlaceholderValues[lowered] {
		return true
	}
	if stripped != "" && strings.ContainsAny(stripped[:1], "$%<{!@&-") {
		return true
	}
	for _, prefix := range []string{"/", "./", "../", "~/", "file:"} {
		if strings.HasPrefix(stripped, prefix) {
			return true
		}
	}
	distinct := map[rune]bool{}
	for _, r := range stripped {
		distinct[r] = true
	}
	if len(distinct) <= 2 {
		return true
	}
	for _, marker := range credentialReferenceMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	for _, hint := range credentialPlaceholderHints {
		if strings.Contains(lowered, hint) {
			return true
		}
	}
	return false
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func looksLikeCredentialValue(value, key string) bool {
	if len(value) < 8 || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return false
	}
	if envVarNameRE.MatchString(value) || formatVerbRE.MatchString(value) {
		return false // an environment variable's name, or a format string
	}
	if strings.HasSuffix(normalizedCredentialKey(key), "token") {
		// "token" is also a lexer/parser term: require a long random value.
		return len(value) >= 16 && shannonEntropy(value) >= 3.5 &&
			tokenValueShapeRE.MatchString(value)
	}
	if numericValueRE.MatchString(value) || strings.Contains(value, "://") {
		return false
	}
	hasLower, hasUpper, hasDigit, hasOther := false, false, false, false
	for _, r := range value {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	classes := 0
	for _, has := range []bool{hasLower, hasUpper, hasDigit, hasOther} {
		if has {
			classes++
		}
	}
	hasLetter := hasLower || hasUpper
	if classes >= 3 && hasLetter {
		return true
	}
	return hasLetter && hasDigit && len(value) >= 12 && shannonEntropy(value) >= 3.3
}

func (a *Analyzer) checkCredentialAssignment(name string, value ast.Expr, path string) {
	lit, ok := value.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING || name == "" || !isCredentialKey(name) {
		return
	}
	unquoted, err := strconv.Unquote(lit.Value)
	if err != nil || hasProviderSecretPrefix(unquoted, strings.ToLower(unquoted)) {
		return // reported as CRITICAL by checkHardcodedSecret
	}
	if isPlaceholderCredential(unquoted) ||
		strings.EqualFold(normalizedCredentialKey(unquoted), normalizedCredentialKey(name)) ||
		!looksLikeCredentialValue(unquoted, name) {
		return
	}
	a.addFinding(lit, path, "SKY-S101", "HIGH", "Potential Hardcoded Secret",
		"Literal credential assigned to '"+name+"'. Use environment variables or a secrets manager instead.")
}

func (a *Analyzer) getFuncInfo(expr ast.Expr) (pkg, funcName string) {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		funcName = e.Sel.Name
		if id, ok := e.X.(*ast.Ident); ok {
			if importPath, ok := a.imports[id.Name]; ok {
				pkg = importPath
			} else {
				pkg = id.Name
			}
		}
	case *ast.Ident:
		funcName = e.Name
	}
	return
}

func (a *Analyzer) isStringConcat(expr ast.Expr) bool {
	binExpr, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	return binExpr.Op == token.ADD && (a.hasStringLit(binExpr.X) || a.hasStringLit(binExpr.Y))
}

func (a *Analyzer) isFormatString(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			if id.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Sprint") {
				return true
			}
		}
	}
	return false
}

func (a *Analyzer) hasStringLit(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

func (a *Analyzer) isVariable(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name != "nil" && e.Name != "true" && e.Name != "false"
	case *ast.SelectorExpr:
		return true
	case *ast.IndexExpr:
		return true
	case *ast.CallExpr:
		return true
	case *ast.BinaryExpr:
		return a.isVariable(e.X) || a.isVariable(e.Y)
	}
	return false
}

func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func shellBaseName(name string) string {
	normalized := strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(normalized, "/")
	base := strings.ToLower(parts[len(parts)-1])
	return strings.TrimSuffix(base, ".exe")
}

func isShellCommandName(name string) bool {
	base := shellBaseName(name)
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func posixShellOptionTakesOperand(value string) bool {
	lower := strings.ToLower(value)
	switch lower {
	case "-o", "-O", "--init-file", "--rcfile":
		return true
	default:
		return false
	}
}

func shellCommandArgIndex(shellName string, args []ast.Expr) (int, bool) {
	base := shellBaseName(shellName)
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				return 0, false
			}
			if value == "--" {
				return 0, false
			}
			if posixShellOptionTakesOperand(value) {
				if i+1 >= len(args) {
					return 0, false
				}
				i++
				continue
			}
			if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value[1:], "c") {
				if i+1 < len(args) {
					return i + 1, true
				}
				return 0, false
			}
			if !strings.HasPrefix(value, "-") {
				return 0, false
			}
		}
	case "cmd":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				return 0, false
			}
			if strings.EqualFold(value, "/c") || strings.EqualFold(value, "/k") {
				if i+1 < len(args) {
					return i + 1, true
				}
				return 0, false
			}
			if !strings.HasPrefix(value, "/") {
				return 0, false
			}
		}
	case "powershell", "pwsh":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				continue
			}
			normalized := strings.ToLower(value)
			switch normalized {
			case "-file", "/file", "-f", "/f":
				return 0, false
			case "-command", "-c", "/command", "/c", "-encodedcommand", "-enc", "/encodedcommand", "/enc":
				if i+1 < len(args) {
					return i + 1, true
				}
				return 0, false
			}
		}
	}
	return 0, false
}

func (a *Analyzer) hasVariablePotentialShellCommandArg(shellName string, args []ast.Expr) bool {
	// A non-literal shell option can still be "-c", "/c", or "-Command";
	// treat the following variable argument as a possible command string.
	switch shellBaseName(shellName) {
	case "sh", "bash", "dash", "zsh", "ksh":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				if i+1 < len(args) && a.isVariable(args[i+1]) {
					return true
				}
				continue
			}
			if value == "--" {
				return false
			}
			if posixShellOptionTakesOperand(value) {
				if i+1 >= len(args) {
					return false
				}
				i++
				continue
			}
			if strings.HasPrefix(value, "-") {
				if !strings.HasPrefix(value, "--") && strings.Contains(value[1:], "c") {
					return i+1 < len(args) && a.isVariable(args[i+1])
				}
				continue
			}
			return false
		}
	case "cmd":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				if i+1 < len(args) && a.isVariable(args[i+1]) {
					return true
				}
				continue
			}
			if strings.EqualFold(value, "/c") || strings.EqualFold(value, "/k") {
				return i+1 < len(args) && a.isVariable(args[i+1])
			}
			if strings.HasPrefix(value, "/") {
				continue
			}
			return false
		}
	case "powershell", "pwsh":
		for i := 1; i < len(args); i++ {
			value, ok := stringLiteralValue(args[i])
			if !ok {
				if i+1 < len(args) && a.isVariable(args[i+1]) {
					return true
				}
				continue
			}
			normalized := strings.ToLower(value)
			switch normalized {
			case "-file", "/file", "-f", "/f":
				return false
			case "-command", "-c", "/command", "/c", "-encodedcommand", "-enc", "/encodedcommand", "/enc":
				return i+1 < len(args) && a.isVariable(args[i+1])
			}
			if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") {
				continue
			}
			return false
		}
	}
	return false
}

func (a *Analyzer) addFinding(node ast.Node, path, ruleID, severity, message, detail string) {
	pos := a.fset.Position(node.Pos())
	fullMessage := message + " " + detail
	key := ruleID + "\x00" + path + "\x00" + strconv.Itoa(pos.Line) + "\x00" + fullMessage
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	a.findings = append(a.findings, output.Finding{
		RuleID:   ruleID,
		Severity: severity,
		Message:  fullMessage,
		File:     path,
		Line:     pos.Line,
		Col:      pos.Column,
	})
}

var sqlMethodNames = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true,
	"QueryContext": true, "ExecContext": true, "QueryRowContext": true,
	"Prepare": true, "PrepareContext": true,
}

func isSQLMethodName(name string) bool {
	return sqlMethodNames[name]
}

func (a *Analyzer) isSQLReceiver(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	name := strings.ToLower(id.Name)
	switch name {
	case "db", "tx", "conn", "sqldb", "database", "stmt", "row", "rows":
		return true
	}
	return false
}

// checkDeferInLoop (SKY-G203, MEDIUM like Python's SKY-L008 missing resource
// cleanup): a defer inside a loop delays every iteration's cleanup to the end
// of the function. Not reported when, after the defer, the loop body ends with
// an unconditional return (or break, in a loop no other loop encloses), since
// the defer then runs at most once per call.
func (a *Analyzer) checkDeferInLoop(body *ast.BlockStmt, path string) {
	a.walkDefersInLoops(body.List, nil, path)
}

func loopBody(node ast.Node) *ast.BlockStmt {
	switch loop := node.(type) {
	case *ast.ForStmt:
		return loop.Body
	case *ast.RangeStmt:
		return loop.Body
	}
	return nil
}

func (a *Analyzer) walkDefersInLoops(stmts []ast.Stmt, loops []ast.Node, path string) {
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				return false // a closure has its own defers
			case *ast.ForStmt, *ast.RangeStmt:
				a.walkDefersInLoops(loopBody(node).List, append(loops, node), path)
				return false
			case *ast.DeferStmt:
				if len(loops) > 0 && !deferRunsOnce(node, loops) {
					a.addFinding(node, path, "SKY-G203", "MEDIUM", "Defer in Loop",
						"defer inside a loop delays every iteration's cleanup to the end of the function. Execute cleanup explicitly per iteration.")
				}
			}
			return true
		})
	}
}

func deferRunsOnce(d *ast.DeferStmt, loops []ast.Node) bool {
	body := loopBody(loops[len(loops)-1])
	seen := false
	for _, stmt := range body.List {
		if stmt == d {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		switch exit := stmt.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.BranchStmt:
			if exit.Tok == token.BREAK && exit.Label == nil && len(loops) == 1 {
				return true
			}
		}
	}
	return false
}

// checkUnclosedResource (SKY-G260, MEDIUM like Python's SKY-L008): a file or
// database handle opened in the function with no cleanup and no hand-off. A
// Close() call anywhere (deferred, explicit or in a deferred closure),
// returning the handle (directly or wrapped) or storing it in a field counts.
func (a *Analyzer) checkUnclosedResource(body *ast.BlockStmt, path string) {
	openVars := make(map[string]ast.Node)
	handled := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok {
					pkg, fn := a.getFuncInfo(call.Fun)
					if funcs, ok := openFuncs[pkg]; ok && funcs[fn] {
						if len(assign.Lhs) > 0 {
							if id, ok := assign.Lhs[0].(*ast.Ident); ok {
								openVars[id.Name] = call
							}
						}
					}
				}
			}
		}
		return true
	})
	if len(openVars) == 0 {
		return
	}

	mark := func(expr ast.Expr) {
		for _, name := range identNames(expr) {
			if _, ok := openVars[name]; ok {
				handled[name] = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
				mark(sel.X)
			}
		case *ast.ReturnStmt:
			for _, result := range node.Results {
				mark(result)
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if _, isField := lhs.(*ast.SelectorExpr); isField && i < len(node.Rhs) {
					mark(node.Rhs[i])
				}
				if _, isIndex := lhs.(*ast.IndexExpr); isIndex && i < len(node.Rhs) {
					mark(node.Rhs[i])
				}
			}
		}
		return true
	})

	for varName, node := range openVars {
		if !handled[varName] {
			a.addFinding(node, path, "SKY-G260", "MEDIUM", "Unclosed Resource",
				"Resource opened but never closed, returned or stored. This may leak file or connection handles.")
		}
	}
}

func (a *Analyzer) checkArchiveExtraction(body *ast.BlockStmt, path string) {
	if !a.hasImportPath("archive/zip") && !a.hasImportPath("archive/tar") {
		return
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch loop := n.(type) {
		case *ast.RangeStmt:
			entryVars := a.archiveEntryVarsFromRange(loop)
			if len(entryVars) > 0 {
				a.checkArchiveLoopBody(loop.Body, entryVars, path)
				return false
			}
		case *ast.ForStmt:
			entryVars := a.archiveEntryVarsFromFor(loop)
			if len(entryVars) > 0 {
				a.checkArchiveLoopBody(loop.Body, entryVars, path)
				return false
			}
		}
		return true
	})
}

func (a *Analyzer) archiveEntryVarsFromRange(loop *ast.RangeStmt) map[string]bool {
	sel, ok := loop.X.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "File" || !a.hasImportPath("archive/zip") {
		return nil
	}

	ident, ok := loop.Value.(*ast.Ident)
	if !ok || ident.Name == "" || ident.Name == "_" {
		return nil
	}

	return map[string]bool{ident.Name: true}
}

func (a *Analyzer) archiveEntryVarsFromFor(loop *ast.ForStmt) map[string]bool {
	if !a.hasImportPath("archive/tar") {
		return nil
	}

	entryVars := make(map[string]bool)
	ast.Inspect(loop, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for idx, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			pkg, fn := a.getFuncInfo(call.Fun)
			if pkg != "archive/tar" && fn != "Next" {
				continue
			}
			if idx >= len(assign.Lhs) {
				continue
			}
			if ident, ok := assign.Lhs[idx].(*ast.Ident); ok && ident.Name != "_" {
				entryVars[ident.Name] = true
			}
		}
		return true
	})
	if len(entryVars) == 0 {
		return nil
	}
	return entryVars
}

func (a *Analyzer) checkArchiveLoopBody(body *ast.BlockStmt, entryVars map[string]bool, path string) {
	if body == nil {
		return
	}

	taintedPaths := make(map[string]bool)
	cleanedPaths := make(map[string]bool)
	resolvedPaths := make(map[string]bool)
	relativeSources := make(map[string]string)
	guardVars := make(map[string]archiveGuardMode)
	guardedPaths := make(map[string]bool)
	a.scanArchiveStatements(body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, false, path)
}

type archiveGuardMode int

const (
	archiveGuardNone archiveGuardMode = iota
	archiveGuardRejectBad
	archiveGuardAllowGood
)

func (a *Analyzer) scanArchiveStatements(stmts []ast.Stmt, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, resolvedPaths map[string]bool, relativeSources map[string]string, guardVars map[string]archiveGuardMode, guardedPaths map[string]bool, guarded bool, path string) bool {
	currentGuarded := guarded

	for _, stmt := range stmts {
		switch node := stmt.(type) {
		case *ast.AssignStmt:
			a.recordArchiveTaintedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths)
			a.recordArchiveCleanedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths, cleanedPaths)
			a.recordArchiveResolvedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths, resolvedPaths)
			a.recordArchiveRelativeSources(node.Lhs, node.Rhs, resolvedPaths, relativeSources)
			a.recordArchiveGuardVars(node.Lhs, node.Rhs, entryVars, taintedPaths, cleanedPaths, guardVars)
			a.recordArchiveGuardedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths, cleanedPaths, guardedPaths, currentGuarded)
			if sink := a.archiveSinkInExprs(node.Rhs, entryVars, taintedPaths, cleanedPaths, guardedPaths, currentGuarded); sink != nil {
				a.addFinding(sink, path, "SKY-G305", "HIGH", "Archive Extraction Path Traversal",
					"Archive entry path is written to disk without validating traversal segments. Reject '..' paths or ensure the cleaned output path stays under the extraction root.")
				return true
			}
		case *ast.DeclStmt:
			gen, ok := node.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				lhs := make([]ast.Expr, 0, len(valueSpec.Names))
				for _, name := range valueSpec.Names {
					lhs = append(lhs, name)
				}
				a.recordArchiveTaintedPaths(lhs, valueSpec.Values, entryVars, taintedPaths)
				a.recordArchiveCleanedPaths(lhs, valueSpec.Values, entryVars, taintedPaths, cleanedPaths)
				a.recordArchiveResolvedPaths(lhs, valueSpec.Values, entryVars, taintedPaths, resolvedPaths)
				a.recordArchiveRelativeSources(lhs, valueSpec.Values, resolvedPaths, relativeSources)
				a.recordArchiveGuardVars(lhs, valueSpec.Values, entryVars, taintedPaths, cleanedPaths, guardVars)
				a.recordArchiveGuardedPaths(lhs, valueSpec.Values, entryVars, taintedPaths, cleanedPaths, guardedPaths, currentGuarded)
				if sink := a.archiveSinkInExprs(valueSpec.Values, entryVars, taintedPaths, cleanedPaths, guardedPaths, currentGuarded); sink != nil {
					a.addFinding(sink, path, "SKY-G305", "HIGH", "Archive Extraction Path Traversal",
						"Archive entry path is written to disk without validating traversal segments. Reject '..' paths or ensure the cleaned output path stays under the extraction root.")
					return true
				}
			}
		case *ast.ExprStmt:
			call, ok := node.X.(*ast.CallExpr)
			if ok && a.isArchiveSink(call, entryVars, taintedPaths, cleanedPaths, guardedPaths, currentGuarded) {
				a.addFinding(call, path, "SKY-G305", "HIGH", "Archive Extraction Path Traversal",
					"Archive entry path is written to disk without validating traversal segments. Reject '..' paths or ensure the cleaned output path stays under the extraction root.")
				return true
			}
		case *ast.IfStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}

			mode := a.archiveGuardModeForExpr(node.Cond, entryVars, taintedPaths, cleanedPaths, guardVars)
			if mode == archiveGuardRejectBad && a.archiveBlockTerminates(node.Body) {
				a.markArchiveGuardedPathsFromExpr(node.Cond, cleanedPaths, relativeSources, guardedPaths)
				if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, true, path) {
					return true
				}
				currentGuarded = true
				continue
			}

			if mode == archiveGuardAllowGood {
				if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, true, path) {
					return true
				}
				if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
				continue
			}

			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
			if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.BlockStmt:
			if a.scanArchiveStatements(node.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.ForStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
			if node.Post != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Post}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
		case *ast.RangeStmt:
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.SwitchStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.TypeSwitchStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.SelectStmt:
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.CaseClause:
			if a.scanArchiveStatements(node.Body, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.CommClause:
			if a.scanArchiveStatements(node.Body, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		}
	}

	return false
}

func (a *Analyzer) scanArchiveElse(stmt ast.Stmt, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, resolvedPaths map[string]bool, relativeSources map[string]string, guardVars map[string]archiveGuardMode, guardedPaths map[string]bool, guarded bool, path string) bool {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return a.scanArchiveStatements(node.List, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, guarded, path)
	case *ast.IfStmt:
		return a.scanArchiveStatements([]ast.Stmt{node}, entryVars, taintedPaths, cleanedPaths, resolvedPaths, relativeSources, guardVars, guardedPaths, guarded, path)
	default:
		return false
	}
}

func (a *Analyzer) recordArchiveTaintedPaths(lhs []ast.Expr, rhs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool) {
	if len(rhs) == 1 {
		if call, ok := rhs[0].(*ast.CallExpr); ok {
			if resultIdxs, handled := a.archiveTaintedResultIndices(call, entryVars, taintedPaths); handled {
				for idx, expr := range lhs {
					ident, ok := expr.(*ast.Ident)
					if !ok || ident.Name == "_" {
						continue
					}
					if resultIdxs[idx] {
						taintedPaths[ident.Name] = true
						continue
					}
					delete(taintedPaths, ident.Name)
				}
				return
			}
		}
	}

	for idx := 0; idx < len(lhs); idx++ {
		if idx >= len(lhs) {
			break
		}
		ident, ok := lhs[idx].(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if idx < len(rhs) && a.exprUsesArchiveEntry(rhs[idx], entryVars, taintedPaths) {
			taintedPaths[ident.Name] = true
			continue
		}
		delete(taintedPaths, ident.Name)
	}
}

func (a *Analyzer) recordArchiveCleanedPaths(lhs []ast.Expr, rhs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool) {
	for idx, expr := range rhs {
		if idx >= len(lhs) {
			continue
		}
		ident, ok := lhs[idx].(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			delete(cleanedPaths, ident.Name)
			continue
		}
		pkg, fn := a.getFuncInfo(call.Fun)
		if (pkg == "path/filepath" || pkg == "path") && fn == "Clean" && len(call.Args) >= 1 && a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) {
			cleanedPaths[ident.Name] = true
			continue
		}
		delete(cleanedPaths, ident.Name)
	}
}

func (a *Analyzer) recordArchiveResolvedPaths(lhs []ast.Expr, rhs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, resolvedPaths map[string]bool) {
	if len(rhs) == 1 {
		if call, ok := rhs[0].(*ast.CallExpr); ok {
			pkg, fn := a.getFuncInfo(call.Fun)
			if pkg == "path/filepath" && fn == "EvalSymlinks" && len(call.Args) >= 1 && a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) {
				for idx, expr := range lhs {
					ident, ok := expr.(*ast.Ident)
					if !ok || ident.Name == "_" {
						continue
					}
					if idx == 0 {
						resolvedPaths[ident.Name] = true
						continue
					}
					delete(resolvedPaths, ident.Name)
				}
				return
			}
		}
	}

	for _, expr := range lhs {
		ident, ok := expr.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		delete(resolvedPaths, ident.Name)
	}
}

func (a *Analyzer) recordArchiveRelativeSources(lhs []ast.Expr, rhs []ast.Expr, resolvedPaths map[string]bool, relativeSources map[string]string) {
	if len(rhs) == 1 {
		if call, ok := rhs[0].(*ast.CallExpr); ok {
			pkg, fn := a.getFuncInfo(call.Fun)
			if pkg == "path/filepath" && fn == "Rel" && len(call.Args) >= 2 {
				if ident, ok := call.Args[1].(*ast.Ident); ok && resolvedPaths[ident.Name] {
					for idx, expr := range lhs {
						name, ok := expr.(*ast.Ident)
						if !ok || name.Name == "_" {
							continue
						}
						if idx == 0 {
							relativeSources[name.Name] = ident.Name
							continue
						}
						delete(relativeSources, name.Name)
					}
					return
				}
			}
		}
	}

	for _, expr := range lhs {
		ident, ok := expr.(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		delete(relativeSources, ident.Name)
	}
}

func (a *Analyzer) recordArchiveGuardVars(lhs []ast.Expr, rhs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardVars map[string]archiveGuardMode) {
	for idx, expr := range rhs {
		if idx >= len(lhs) {
			continue
		}
		ident, ok := lhs[idx].(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		mode := a.archiveGuardModeForExpr(expr, entryVars, taintedPaths, cleanedPaths, guardVars)
		if mode == archiveGuardNone {
			delete(guardVars, ident.Name)
			continue
		}
		guardVars[ident.Name] = mode
	}
}

func (a *Analyzer) recordArchiveGuardedPaths(lhs []ast.Expr, rhs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardedPaths map[string]bool, guarded bool) {
	if len(rhs) == 1 {
		if call, ok := rhs[0].(*ast.CallExpr); ok {
			if resultIdxs, handled := a.archiveGuardedResultIndices(call, entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded); handled {
				for idx, expr := range lhs {
					ident, ok := expr.(*ast.Ident)
					if !ok || ident.Name == "_" {
						continue
					}
					if resultIdxs[idx] {
						guardedPaths[ident.Name] = true
						continue
					}
					delete(guardedPaths, ident.Name)
				}
				return
			}
		}
	}

	for idx := 0; idx < len(lhs); idx++ {
		ident, ok := lhs[idx].(*ast.Ident)
		if !ok || ident.Name == "_" {
			continue
		}
		if idx >= len(rhs) || !a.exprUsesArchiveEntry(rhs[idx], entryVars, taintedPaths) {
			delete(guardedPaths, ident.Name)
			continue
		}
		if a.archiveExprPreservesGuard(rhs[idx], entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded) {
			guardedPaths[ident.Name] = true
			continue
		}
		delete(guardedPaths, ident.Name)
	}
}

func (a *Analyzer) archiveTaintedResultIndices(call *ast.CallExpr, entryVars map[string]bool, taintedPaths map[string]bool) (map[int]bool, bool) {
	pkg, fn := a.getFuncInfo(call.Fun)
	switch {
	case pkg == "strings" && fn == "Cut":
		if len(call.Args) >= 1 && a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) {
			return map[int]bool{0: true, 1: true}, true
		}
	case pkg == "path/filepath" && fn == "EvalSymlinks":
		if len(call.Args) >= 1 && a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) {
			return map[int]bool{0: true}, true
		}
	case pkg == "path/filepath" && fn == "Rel":
		if len(call.Args) >= 2 && a.exprUsesArchiveEntry(call.Args[1], entryVars, taintedPaths) {
			return map[int]bool{0: true}, true
		}
	}
	return nil, false
}

func (a *Analyzer) archiveGuardedResultIndices(call *ast.CallExpr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardedPaths map[string]bool, guarded bool) (map[int]bool, bool) {
	pkg, fn := a.getFuncInfo(call.Fun)
	switch {
	case pkg == "strings" && fn == "Cut":
		if len(call.Args) >= 1 && a.archiveExprPreservesGuard(call.Args[0], entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded) {
			return map[int]bool{0: true, 1: true}, true
		}
	}
	return nil, false
}

func (a *Analyzer) exprUsesArchiveEntry(expr ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return entryVars[e.Name] || taintedPaths[e.Name]
	case *ast.SelectorExpr:
		if e.Sel != nil && (e.Sel.Name == "Name" || e.Sel.Name == "Linkname") {
			if id, ok := e.X.(*ast.Ident); ok && entryVars[id.Name] {
				return true
			}
			if inner, ok := e.X.(*ast.SelectorExpr); ok {
				if id, ok := inner.X.(*ast.Ident); ok && entryVars[id.Name] {
					return true
				}
			}
		}
		return a.exprUsesArchiveEntry(e.X, entryVars, taintedPaths)
	case *ast.BinaryExpr:
		return a.exprUsesArchiveEntry(e.X, entryVars, taintedPaths) || a.exprUsesArchiveEntry(e.Y, entryVars, taintedPaths)
	case *ast.CallExpr:
		for _, arg := range e.Args {
			if a.exprUsesArchiveEntry(arg, entryVars, taintedPaths) {
				return true
			}
		}
	case *ast.IndexExpr:
		return a.exprUsesArchiveEntry(e.X, entryVars, taintedPaths) || a.exprUsesArchiveEntry(e.Index, entryVars, taintedPaths)
	case *ast.ParenExpr:
		return a.exprUsesArchiveEntry(e.X, entryVars, taintedPaths)
	}
	return false
}

func (a *Analyzer) archiveGuardModeForExpr(expr ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardVars map[string]archiveGuardMode) archiveGuardMode {
	switch e := expr.(type) {
	case *ast.Ident:
		return guardVars[e.Name]
	case *ast.ParenExpr:
		return a.archiveGuardModeForExpr(e.X, entryVars, taintedPaths, cleanedPaths, guardVars)
	case *ast.UnaryExpr:
		if e.Op != token.NOT {
			return archiveGuardNone
		}
		switch a.archiveGuardModeForExpr(e.X, entryVars, taintedPaths, cleanedPaths, guardVars) {
		case archiveGuardRejectBad:
			return archiveGuardAllowGood
		case archiveGuardAllowGood:
			return archiveGuardRejectBad
		default:
			return archiveGuardNone
		}
	case *ast.BinaryExpr:
		left := a.archiveGuardModeForExpr(e.X, entryVars, taintedPaths, cleanedPaths, guardVars)
		right := a.archiveGuardModeForExpr(e.Y, entryVars, taintedPaths, cleanedPaths, guardVars)
		switch e.Op {
		case token.LOR:
			if left == archiveGuardRejectBad && right == archiveGuardRejectBad {
				return archiveGuardRejectBad
			}
		case token.LAND:
			if left == archiveGuardAllowGood && right == archiveGuardAllowGood {
				return archiveGuardAllowGood
			}
		}
		return archiveGuardNone
	case *ast.CallExpr:
		pkg, fn := a.getFuncInfo(e.Fun)
		switch {
		case pkg == "strings" && fn == "Contains":
			if len(e.Args) >= 2 && a.exprUsesArchiveEntry(e.Args[0], entryVars, taintedPaths) {
				if lit, ok := e.Args[1].(*ast.BasicLit); ok && strings.Contains(lit.Value, "..") {
					return archiveGuardRejectBad
				}
			}
		case pkg == "strings" && fn == "HasPrefix":
			if len(e.Args) >= 2 {
				if lit, ok := e.Args[1].(*ast.BasicLit); ok && strings.Contains(lit.Value, "..") {
					if ident, ok := e.Args[0].(*ast.Ident); ok && (cleanedPaths[ident.Name] || taintedPaths[ident.Name]) {
						return archiveGuardRejectBad
					}
				}
				if ident, ok := e.Args[0].(*ast.Ident); ok && cleanedPaths[ident.Name] {
					return archiveGuardAllowGood
				}
			}
		case pkg == "path/filepath" && fn == "IsLocal":
			if len(e.Args) >= 1 && a.exprUsesArchiveEntry(e.Args[0], entryVars, taintedPaths) {
				return archiveGuardAllowGood
			}
		}
	}

	return archiveGuardNone
}

func (a *Analyzer) archiveExprPreservesGuard(expr ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardedPaths map[string]bool, guarded bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		if entryVars[e.Name] {
			return guarded
		}
		if guarded && cleanedPaths[e.Name] {
			return true
		}
		return guardedPaths[e.Name]
	case *ast.SelectorExpr:
		if e.Sel != nil && e.Sel.Name == "Name" {
			if id, ok := e.X.(*ast.Ident); ok && entryVars[id.Name] {
				return guarded
			}
			if inner, ok := e.X.(*ast.SelectorExpr); ok {
				if id, ok := inner.X.(*ast.Ident); ok && entryVars[id.Name] {
					return guarded
				}
			}
		}
		return false
	case *ast.ParenExpr:
		return a.archiveExprPreservesGuard(e.X, entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded)
	case *ast.CallExpr:
		pkg, fn := a.getFuncInfo(e.Fun)
		if (pkg != "path/filepath" && pkg != "path") || (fn != "Join" && fn != "Clean") {
			return false
		}
		usesArchive := false
		for _, arg := range e.Args {
			if !a.exprUsesArchiveEntry(arg, entryVars, taintedPaths) {
				continue
			}
			usesArchive = true
			if !a.archiveExprPreservesGuard(arg, entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded) {
				return false
			}
		}
		return usesArchive
	default:
		return false
	}
}

func (a *Analyzer) markArchiveGuardedPathsFromExpr(expr ast.Expr, cleanedPaths map[string]bool, relativeSources map[string]string, guardedPaths map[string]bool) {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		a.markArchiveGuardedPathsFromExpr(e.X, cleanedPaths, relativeSources, guardedPaths)
	case *ast.BinaryExpr:
		a.markArchiveGuardedPathsFromExpr(e.X, cleanedPaths, relativeSources, guardedPaths)
		a.markArchiveGuardedPathsFromExpr(e.Y, cleanedPaths, relativeSources, guardedPaths)
	case *ast.CallExpr:
		pkg, fn := a.getFuncInfo(e.Fun)
		if pkg != "strings" || fn != "HasPrefix" || len(e.Args) < 2 {
			return
		}
		lit, ok := e.Args[1].(*ast.BasicLit)
		if !ok || !strings.Contains(lit.Value, "..") {
			return
		}
		ident, ok := e.Args[0].(*ast.Ident)
		if !ok {
			return
		}
		if !cleanedPaths[ident.Name] && relativeSources[ident.Name] == "" {
			return
		}
		if source := relativeSources[ident.Name]; source != "" {
			guardedPaths[source] = true
		}
	}
}

func (a *Analyzer) archiveBlockTerminates(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}

	last := body.List[len(body.List)-1]
	switch stmt := last.(type) {
	case *ast.BranchStmt:
		return stmt.Tok == token.CONTINUE || stmt.Tok == token.BREAK
	case *ast.ReturnStmt:
		return true
	}

	return false
}

func (a *Analyzer) archiveSinkInExprs(exprs []ast.Expr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardedPaths map[string]bool, guarded bool) *ast.CallExpr {
	for _, expr := range exprs {
		var sink *ast.CallExpr
		ast.Inspect(expr, func(n ast.Node) bool {
			if sink != nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if a.isArchiveSink(call, entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded) {
				sink = call
				return false
			}
			return true
		})
		if sink != nil {
			return sink
		}
	}
	return nil
}

func (a *Analyzer) isArchiveSink(call *ast.CallExpr, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardedPaths map[string]bool, guarded bool) bool {
	pkg, fn := a.getFuncInfo(call.Fun)
	if pkg == "os" && fn == "Symlink" && len(call.Args) >= 2 {
		linkTargetUnsafe := a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) &&
			!a.archiveExprPreservesGuard(call.Args[0], entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded)
		linkPathUnsafe := a.exprUsesArchiveEntry(call.Args[1], entryVars, taintedPaths) &&
			!a.archiveExprPreservesGuard(call.Args[1], entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded)
		return linkTargetUnsafe || linkPathUnsafe
	}

	if !contains([]string{"os", "io/ioutil"}, pkg) {
		return false
	}

	sinkFns := map[string]bool{
		"Create":    true,
		"OpenFile":  true,
		"WriteFile": true,
		"MkdirAll":  true,
	}
	if !sinkFns[fn] || len(call.Args) == 0 {
		return false
	}

	return a.exprUsesArchiveEntry(call.Args[0], entryVars, taintedPaths) &&
		!a.archiveExprPreservesGuard(call.Args[0], entryVars, taintedPaths, cleanedPaths, guardedPaths, guarded)
}

func (a *Analyzer) hasImportPath(path string) bool {
	for _, importPath := range a.imports {
		if importPath == path {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
