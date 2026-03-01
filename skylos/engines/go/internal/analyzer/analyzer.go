package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

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
	"os":        {"Open", "OpenFile", "ReadFile", "WriteFile", "Remove", "RemoveAll", "Mkdir", "MkdirAll"},
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
	fset     *token.FileSet
	findings []output.Finding
	imports  map[string]string
}

func New() *Analyzer {
	return &Analyzer{
		fset:    token.NewFileSet(),
		imports: make(map[string]string),
	}
}

func (a *Analyzer) AnalyzeDir(root string) ([]output.Finding, error) {
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

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		a.analyzeFile(path)
		return nil
	})

	return a.findings, err
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

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Body != nil {
				a.checkDeferInLoop(node.Body, path)
				a.checkUnclosedResource(node.Body, path)
			}
		case *ast.FuncLit:
			if node.Body != nil {
				a.checkDeferInLoop(node.Body, path)
				a.checkUnclosedResource(node.Body, path)
			}
		case *ast.CallExpr:
			a.checkCallExpr(node, path)
		case *ast.CompositeLit:
			a.checkCompositeLit(node, path)
		case *ast.BasicLit:
			a.checkHardcodedSecret(node, path)
		}
		return true
	})
}

func (a *Analyzer) checkCallExpr(call *ast.CallExpr, path string) {
	pkg, funcName := a.getFuncInfo(call.Fun)

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
		if len(call.Args) > 0 {
			if a.isStringConcat(call.Args[0]) || a.isFormatString(call.Args[0]) {
				a.addFinding(call, path, "SKY-G211", "CRITICAL", "SQL Injection",
					"SQL query built with string concatenation or formatting. Use parameterized queries instead.")
			}
		}
	}

	if funcs, ok := cmdSinks[pkg]; ok && contains(funcs, funcName) {
		if a.hasVariableArgs(call) {
			a.addFinding(call, path, "SKY-G212", "CRITICAL", "Command Injection",
				"Command executed with variable arguments. Validate and sanitize all inputs.")
		}
	}

	if funcs, ok := pathSinks[pkg]; ok && contains(funcs, funcName) {
		if len(call.Args) > 0 && a.isVariable(call.Args[0]) {
			a.addFinding(call, path, "SKY-G215", "HIGH", "Potential Path Traversal",
				"File path includes variable input. Validate path does not escape intended directory.")
		}
	}

	if funcs, ok := httpSinks[pkg]; ok && contains(funcs, funcName) {
		if len(call.Args) > 0 && a.isVariable(call.Args[0]) {
			a.addFinding(call, path, "SKY-G216", "CRITICAL", "Potential SSRF",
				"HTTP request URL includes variable input. Validate against allowlist.")
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

	// SKY-G206: Unsafe package usage
	if pkg == "unsafe" {
		a.addFinding(call, path, "SKY-G206", "HIGH", "Unsafe Package Usage",
			"The unsafe package bypasses Go's type safety. Avoid unless absolutely necessary.")
	}

	// SKY-G220: Open redirect
	if pkg == "net/http" && funcName == "Redirect" {
		if len(call.Args) >= 3 && a.isVariable(call.Args[2]) {
			a.addFinding(call, path, "SKY-G220", "HIGH", "Open Redirect",
				"http.Redirect with variable URL. Validate redirect target against allowlist.")
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
						if val, ok := kv.Value.(*ast.Ident); ok && val.Name == "true" {
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

	patterns := []string{
		"sk-", "sk_live_", "sk_test_",
		"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		"xoxb-", "xoxp-", "xoxa-",
		"AKIA",
		"eyJ",
	}

	for _, p := range patterns {
		if strings.HasPrefix(val, p) || strings.HasPrefix(valLower, strings.ToLower(p)) {
			a.addFinding(lit, path, "SKY-S101", "CRITICAL", "Hardcoded Secret",
				"Potential secret or API key found in source code. Use environment variables instead.")
			return
		}
	}

	if strings.Contains(valLower, "password") || strings.Contains(valLower, "secret") ||
		strings.Contains(valLower, "apikey") || strings.Contains(valLower, "api_key") {
		a.addFinding(lit, path, "SKY-S101", "HIGH", "Potential Hardcoded Secret",
			"String appears to contain sensitive data. Use environment variables instead.")
	}
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

func (a *Analyzer) hasVariableArgs(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if a.isVariable(arg) {
			return true
		}
	}
	return false
}

func (a *Analyzer) addFinding(node ast.Node, path, ruleID, severity, message, detail string) {
	pos := a.fset.Position(node.Pos())
	a.findings = append(a.findings, output.Finding{
		RuleID:   ruleID,
		Severity: severity,
		Message:  message + " " + detail,
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

func (a *Analyzer) checkDeferInLoop(body *ast.BlockStmt, path string) {
	ast.Inspect(body, func(n ast.Node) bool {
		isLoop := false
		switch n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			isLoop = true
		case *ast.FuncLit:
			return false // don't cross closure boundaries
		}
		if !isLoop {
			return true
		}
		ast.Inspect(n, func(inner ast.Node) bool {
			if inner == n {
				return true
			}
			if d, ok := inner.(*ast.DeferStmt); ok {
				a.addFinding(d, path, "SKY-G203", "HIGH", "Defer in Loop",
					"defer inside a loop may cause resource leak. Execute cleanup explicitly per iteration.")
			}
			if _, ok := inner.(*ast.FuncLit); ok {
				return false
			}
			return true
		})
		return false
	})
}

func (a *Analyzer) checkUnclosedResource(body *ast.BlockStmt, path string) {
	openVars := make(map[string]ast.Node)
	closedVars := make(map[string]bool)

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
		if d, ok := n.(*ast.DeferStmt); ok {
			if sel, ok := d.Call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "Close" {
					if id, ok := sel.X.(*ast.Ident); ok {
						closedVars[id.Name] = true
					}
				}
			}
		}
		return true
	})

	for varName, node := range openVars {
		if !closedVars[varName] {
			a.addFinding(node, path, "SKY-G260", "HIGH", "Unclosed Resource",
				"Resource opened but no defer .Close() found. This may cause resource leaks.")
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
