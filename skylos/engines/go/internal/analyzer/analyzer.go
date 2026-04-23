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
	guardVars := make(map[string]archiveGuardMode)
	guardedPaths := make(map[string]bool)
	a.scanArchiveStatements(body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, false, path)
}

type archiveGuardMode int

const (
	archiveGuardNone archiveGuardMode = iota
	archiveGuardRejectBad
	archiveGuardAllowGood
)

func (a *Analyzer) scanArchiveStatements(stmts []ast.Stmt, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardVars map[string]archiveGuardMode, guardedPaths map[string]bool, guarded bool, path string) bool {
	currentGuarded := guarded

	for _, stmt := range stmts {
		switch node := stmt.(type) {
		case *ast.AssignStmt:
			a.recordArchiveTaintedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths)
			a.recordArchiveCleanedPaths(node.Lhs, node.Rhs, entryVars, taintedPaths, cleanedPaths)
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
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}

			mode := a.archiveGuardModeForExpr(node.Cond, entryVars, taintedPaths, cleanedPaths, guardVars)
			if mode == archiveGuardRejectBad && a.archiveBlockTerminates(node.Body) {
				if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, true, path) {
					return true
				}
				currentGuarded = true
				continue
			}

			if mode == archiveGuardAllowGood {
				if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, true, path) {
					return true
				}
				if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
				continue
			}

			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
			if node.Else != nil && a.scanArchiveElse(node.Else, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.BlockStmt:
			if a.scanArchiveStatements(node.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.ForStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
			if node.Post != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Post}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
		case *ast.RangeStmt:
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.SwitchStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.TypeSwitchStmt:
			if node.Init != nil {
				if a.scanArchiveStatements([]ast.Stmt{node.Init}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
					return true
				}
			}
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.SelectStmt:
			if a.scanArchiveStatements(node.Body.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.CaseClause:
			if a.scanArchiveStatements(node.Body, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		case *ast.CommClause:
			if a.scanArchiveStatements(node.Body, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, currentGuarded, path) {
				return true
			}
		}
	}

	return false
}

func (a *Analyzer) scanArchiveElse(stmt ast.Stmt, entryVars map[string]bool, taintedPaths map[string]bool, cleanedPaths map[string]bool, guardVars map[string]archiveGuardMode, guardedPaths map[string]bool, guarded bool, path string) bool {
	switch node := stmt.(type) {
	case *ast.BlockStmt:
		return a.scanArchiveStatements(node.List, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, guarded, path)
	case *ast.IfStmt:
		return a.scanArchiveStatements([]ast.Stmt{node}, entryVars, taintedPaths, cleanedPaths, guardVars, guardedPaths, guarded, path)
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
		if e.Sel != nil && e.Sel.Name == "Name" {
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
			if len(e.Args) >= 1 {
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
