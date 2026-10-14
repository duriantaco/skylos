package analyzer

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
)

// Untrusted input for the SSRF (SKY-G216) and command-injection (SKY-G212)
// rules, mirroring the Python and TypeScript rules: data an outside party
// controls, i.e. an incoming HTTP request or other network input. Literals
// (loopback included), os.Args, flags, environment variables, config structs
// and os.Executable() are the program's own inputs and are not sources.
//
// Taint is tracked per top-level function, flow-insensitively: a name is
// tainted if any assignment in the function gives it a tainted value. Same-
// file functions called with a tainted argument get that parameter tainted,
// iterated to a fixpoint.

type funcTaint struct {
	tainted map[string]bool
	// values assigned to each local name, to resolve one hop when checking
	// whether a URL's host is fixed
	defs map[string][]ast.Expr
	// names a containment check proves stay under a fixed base (G215)
	guarded map[string]bool
	// parameters tainted on entry (source type or a tainted caller)
	paramTainted map[string]bool
	// names a same-origin check covers (G220)
	redirectGuarded map[string]bool
}

const maxTaintRounds = 12

// Calls that fill their buffer or &target argument from a tainted reader.
var taintFillingCalls = map[string]bool{
	"Read": true, "ReadFull": true, "ReadAtLeast": true, "ReadAt": true,
	"Decode": true, "Unmarshal": true, "Scan": true, "ReadJSON": true,
	"Bind": true, "BindJSON": true, "ShouldBind": true, "ShouldBindJSON": true,
	"BodyParser": true,
}

// Request methods that do not return request data.
var nonDataRequestMethods = map[string]bool{
	"Context": true, "Done": true, "Deadline": true, "Err": true,
}

// "scheme://host" followed by a path, query or fragment delimiter: once a
// literal prefix reaches this point, the rest cannot change the host.
var fixedHostPrefixRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/?#{}%\s]+[/?#]`)

func (a *Analyzer) isSourceParamType(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	importPath := a.imports[pkgIdent.Name]
	name := sel.Sel.Name
	switch {
	case importPath == "net/http":
		return name == "Request"
	case importPath == "net":
		return name == "Conn" || name == "TCPConn" || name == "UDPConn" || name == "UnixConn"
	case strings.HasPrefix(importPath, "github.com/gin-gonic/gin"):
		return name == "Context"
	case strings.HasPrefix(importPath, "github.com/labstack/echo"):
		return name == "Context"
	case strings.HasPrefix(importPath, "github.com/gofiber/fiber"):
		return name == "Ctx"
	}
	return false
}

func (a *Analyzer) fieldListHasSource(fields *ast.FieldList, name string) bool {
	for _, field := range fields.List {
		for _, ident := range field.Names {
			if ident.Name == name && a.isSourceParamType(field.Type) {
				return true
			}
		}
	}
	return false
}

func paramNames(fields *ast.FieldList) []string {
	var names []string
	if fields == nil {
		return names
	}
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

func (a *Analyzer) seedSourceParams(fields *ast.FieldList, tainted map[string]bool) bool {
	changed := false
	if fields == nil {
		return false
	}
	for _, field := range fields.List {
		if !a.isSourceParamType(field.Type) {
			continue
		}
		for _, name := range field.Names {
			if name.Name != "_" && !tainted[name.Name] {
				tainted[name.Name] = true
				changed = true
			}
		}
	}
	return changed
}

func (a *Analyzer) isPackageIdent(expr ast.Expr, tainted map[string]bool) bool {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	_, isPkg := a.imports[id.Name]
	return isPkg && !tainted[id.Name]
}

// isTainted reports whether expr may carry untrusted data.
func (a *Analyzer) isTainted(expr ast.Expr, tainted map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return tainted[e.Name]
	case *ast.SelectorExpr:
		if a.isPackageIdent(e.X, tainted) {
			return false
		}
		return a.isTainted(e.X, tainted)
	case *ast.IndexExpr:
		// m[key] with an attacker key still returns the program's value.
		return a.isTainted(e.X, tainted)
	case *ast.IndexListExpr:
		return a.isTainted(e.X, tainted)
	case *ast.SliceExpr:
		return a.isTainted(e.X, tainted)
	case *ast.StarExpr:
		return a.isTainted(e.X, tainted)
	case *ast.ParenExpr:
		return a.isTainted(e.X, tainted)
	case *ast.UnaryExpr:
		return a.isTainted(e.X, tainted)
	case *ast.TypeAssertExpr:
		return a.isTainted(e.X, tainted)
	case *ast.BinaryExpr:
		return a.isTainted(e.X, tainted) || a.isTainted(e.Y, tainted)
	case *ast.KeyValueExpr:
		return a.isTainted(e.Value, tainted)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if a.isTainted(elt, tainted) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && a.isPackageIdent(sel.X, tainted) && a.pathSanitizer(sel) {
			return false
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, tainted) {
			if nonDataRequestMethods[sel.Sel.Name] && len(e.Args) == 0 {
				return false
			}
			if sel.Sel.Name == "Accept" && len(e.Args) == 0 {
				return true // net.Listener.Accept: an incoming connection
			}
			if a.isTainted(sel.X, tainted) {
				return true
			}
		}
		for _, arg := range e.Args {
			if a.isTainted(arg, tainted) {
				return true
			}
		}
	}
	return false
}

// rootName is the variable an assignment target writes into.
func rootName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return rootName(e.X)
	case *ast.IndexExpr:
		return rootName(e.X)
	case *ast.SliceExpr:
		return rootName(e.X)
	case *ast.StarExpr:
		return rootName(e.X)
	case *ast.ParenExpr:
		return rootName(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return rootName(e.X)
		}
	}
	return ""
}

func markTainted(tainted map[string]bool, expr ast.Expr) bool {
	name := rootName(expr)
	if name == "" || name == "_" || tainted[name] {
		return false
	}
	tainted[name] = true
	return true
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// propagate runs one pass over body and reports whether taint grew.
func (a *Analyzer) propagate(body ast.Node, ft *funcTaint) bool {
	changed := false
	t := ft.tainted
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if a.seedSourceParams(node.Type.Params, t) {
				changed = true
			}
			if ft.paramTainted != nil {
				for _, name := range paramNames(node.Type.Params) {
					if t[name] && a.fieldListHasSource(node.Type.Params, name) {
						ft.paramTainted[name] = true
					}
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if a.isTainted(node.Rhs[i], t) && markTainted(t, lhs) {
						changed = true
					}
				}
			} else if len(node.Rhs) == 1 && a.isTainted(node.Rhs[0], t) {
				for _, lhs := range node.Lhs {
					if markTainted(t, lhs) {
						changed = true
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					if a.isTainted(node.Values[i], t) && markTainted(t, name) {
						changed = true
					}
				}
			} else if len(node.Values) == 1 && a.isTainted(node.Values[0], t) {
				for _, name := range node.Names {
					if markTainted(t, name) {
						changed = true
					}
				}
			}
		case *ast.RangeStmt:
			if a.isTainted(node.X, t) {
				if node.Key != nil && markTainted(t, node.Key) {
					changed = true
				}
				if node.Value != nil && markTainted(t, node.Value) {
					changed = true
				}
			}
		case *ast.CallExpr:
			if !taintFillingCalls[calleeName(node.Fun)] {
				return true
			}
			from := false
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, t) {
				from = a.isTainted(sel.X, t)
			}
			for _, arg := range node.Args {
				if a.isTainted(arg, t) {
					from = true
				}
			}
			if from {
				for _, arg := range node.Args {
					if markTainted(t, arg) {
						changed = true
					}
				}
			}
		}
		return true
	})
	return changed
}

func collectDefs(body ast.Node) map[string][]ast.Expr {
	defs := map[string][]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					var value ast.Expr
					if len(node.Lhs) == len(node.Rhs) {
						value = node.Rhs[i]
					}
					defs[id.Name] = append(defs[id.Name], value)
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				var value ast.Expr
				if len(node.Names) == len(node.Values) {
					value = node.Values[i]
				}
				defs[name.Name] = append(defs[name.Name], value)
			}
		}
		return true
	})
	return defs
}

// computeTaint records, for every call in the file, the taint of the
// top-level function it appears in.
func (a *Analyzer) computeTaint(file *ast.File) {
	a.callTaint = make(map[*ast.CallExpr]*funcTaint)
	var funcs []*ast.FuncDecl
	byName := map[string][]*ast.FuncDecl{}
	scopes := map[*ast.FuncDecl]*funcTaint{}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		funcs = append(funcs, fd)
		byName[fd.Name.Name] = append(byName[fd.Name.Name], fd)
		ft := &funcTaint{tainted: map[string]bool{}, defs: collectDefs(fd.Body), paramTainted: map[string]bool{}}
		a.seedSourceParams(fd.Type.Params, ft.tainted)
		for name := range ft.tainted {
			ft.paramTainted[name] = true
		}
		scopes[fd] = ft
	}

	for round := 0; round < maxTaintRounds; round++ {
		changed := false
		for _, fd := range funcs {
			if a.propagate(fd.Body, scopes[fd]) {
				changed = true
			}
		}
		for _, fd := range funcs {
			t := scopes[fd].tainted
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && a.isPackageIdent(sel.X, t) {
					return true // a call into another package
				}
				for _, callee := range byName[calleeName(call.Fun)] {
					params := paramNames(callee.Type.Params)
					for i, arg := range call.Args {
						idx := i
						if idx >= len(params) {
							if callee.Type.Params == nil || len(params) == 0 {
								break
							}
							idx = len(params) - 1 // variadic tail
						}
						name := params[idx]
						if name == "" || name == "_" || scopes[callee].tainted[name] {
							continue
						}
						if a.isTainted(arg, t) {
							scopes[callee].tainted[name] = true
							scopes[callee].paramTainted[name] = true
							changed = true
						}
					}
				}
				return true
			})
		}
		if !changed {
			break
		}
	}

	for _, fd := range funcs {
		ft := scopes[fd]
		a.collectPathGuards(fd.Body, ft)
		a.collectRedirectGuards(fd.Body, ft)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				a.callTaint[call] = ft
			}
			return true
		})
	}
}

func (a *Analyzer) taintFor(call *ast.CallExpr) *funcTaint {
	if ft, ok := a.callTaint[call]; ok {
		return ft
	}
	return &funcTaint{
		tainted: map[string]bool{}, defs: map[string][]ast.Expr{}, guarded: map[string]bool{},
		paramTainted: map[string]bool{}, redirectGuarded: map[string]bool{},
	}
}

// leadingLiteral is the constant text a URL expression starts with.
func (a *Analyzer) leadingLiteral(expr ast.Expr, ft *funcTaint, depth int) (string, bool) {
	if depth > 3 {
		return "", false
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		return stringLiteralValue(e)
	case *ast.ParenExpr:
		return a.leadingLiteral(e.X, ft, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return a.leadingLiteral(e.X, ft, depth+1)
		}
	case *ast.CallExpr:
		if a.isFormatString(e) && len(e.Args) > 0 {
			return a.leadingLiteral(e.Args[0], ft, depth+1)
		}
	case *ast.Ident:
		values := ft.defs[e.Name]
		if len(values) == 1 && values[0] != nil {
			return a.leadingLiteral(values[0], ft, depth+1)
		}
	}
	return "", false
}

// hasFixedHost: the URL starts with a literal "scheme://host/" (or ? or #),
// so untrusted data later in it cannot choose the host.
func (a *Analyzer) hasFixedHost(expr ast.Expr, ft *funcTaint) bool {
	prefix, ok := a.leadingLiteral(expr, ft, 0)
	return ok && fixedHostPrefixRE.MatchString(prefix)
}

// isSSRFURL: the URL is untrusted and can choose the host.
func (a *Analyzer) isSSRFURL(expr ast.Expr, ft *funcTaint) bool {
	return a.isTainted(expr, ft.tainted) && !a.hasFixedHost(expr, ft)
}

// execCommandSeverity returns "" (no finding), "HIGH" (a shell runs a
// command string built from a non-constant value) or "CRITICAL" (the program
// path or the shell command string comes from untrusted input).
func (a *Analyzer) execCommandSeverity(call *ast.CallExpr, funcName string, ft *funcTaint) (string, string) {
	args := call.Args
	if funcName == "CommandContext" {
		if len(args) < 2 {
			return "", ""
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return "", ""
	}
	t := ft.tainted
	commandName, ok := stringLiteralValue(args[0])
	if !ok {
		if a.isTainted(args[0], t) {
			return "CRITICAL", "The program path comes from request or network input. Run a fixed program and validate its arguments."
		}
		return "", "" // the program's own binary, config or a flag: argv, no shell
	}
	if !isShellCommandName(commandName) {
		return "", ""
	}
	commandIndex, ok := shellCommandArgIndex(commandName, args)
	var candidates []ast.Expr
	if ok {
		if !a.isVariable(args[commandIndex]) {
			return "", ""
		}
		candidates = []ast.Expr{args[commandIndex]}
	} else {
		if !a.hasVariablePotentialShellCommandArg(commandName, args) {
			return "", ""
		}
		candidates = args[1:]
	}
	for _, candidate := range candidates {
		if a.isTainted(candidate, t) {
			return "CRITICAL", "Shell command built from request or network input. Pass arguments to a fixed program without a shell."
		}
	}
	return "HIGH", "Shell command built from a non-constant value. If any part comes from outside the program this is command injection; pass arguments to a fixed program without a shell."
}

// Path traversal (SKY-G215): a file path is a finding only when untrusted
// input reaches it without a containment proof, like the Python D215 rule
// (os.path.basename/safe_join sanitisers; is_relative_to/commonpath guards).

// pathSanitizer: calls whose result cannot leave the directory it is joined
// to, so it is not untrusted path data.
func (a *Analyzer) pathSanitizer(sel *ast.SelectorExpr) bool {
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch a.imports[pkgIdent.Name] {
	case "path/filepath", "path":
		return sel.Sel.Name == "Base"
	case "github.com/cyphar/filepath-securejoin":
		return sel.Sel.Name == "SecureJoin"
	}
	return false
}

// cleaningCall: filepath.Clean/Join/Abs/EvalSymlinks, which resolve "..", so
// a prefix check on their result is a real containment check.
func (a *Analyzer) cleaningCall(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkgIdent, ok := sel.X.(*ast.Ident); ok && a.imports[pkgIdent.Name] == "path/filepath" {
				switch sel.Sel.Name {
				case "Clean", "Join", "Abs", "EvalSymlinks":
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func (a *Analyzer) isPkgCall(call *ast.CallExpr, importPath, name string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	return ok && a.imports[pkgIdent.Name] == importPath
}

func identNames(expr ast.Expr) []string {
	var names []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			names = append(names, id.Name)
		}
		return true
	})
	return names
}

func mentionsDotDot(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "..") {
			found = true
		}
		return !found
	})
	return found
}

// collectPathGuards records the names a containment check in the function
// proves stay under a fixed base:
//   - strings.HasPrefix(v, base) in an if condition, v cleaned (Clean/Join/
//     Abs/EvalSymlinks, directly or in v's definition);
//   - rel, _ := filepath.Rel(base, v) with a ".." check on rel;
//   - filepath.IsLocal(v).
func (a *Analyzer) collectPathGuards(body ast.Node, ft *funcTaint) {
	ft.guarded = map[string]bool{}
	relOf := map[string][]string{} // rel variable -> names in the checked path
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if ok && a.isPkgCall(call, "path/filepath", "Rel") && len(call.Args) == 2 {
			if id, ok := assign.Lhs[0].(*ast.Ident); ok {
				relOf[id.Name] = identNames(call.Args[1])
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(ifStmt.Cond, func(c ast.Node) bool {
			if id, ok := c.(*ast.Ident); ok && relOf[id.Name] != nil && mentionsDotDot(ifStmt.Cond) {
				for _, name := range relOf[id.Name] {
					ft.guarded[name] = true
				}
			}
			call, ok := c.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			switch {
			case a.isPkgCall(call, "path/filepath", "IsLocal"):
				for _, name := range identNames(call.Args[0]) {
					ft.guarded[name] = true
				}
			case a.isPkgCall(call, "strings", "HasPrefix") && len(call.Args) == 2:
				checked := call.Args[0]
				if a.cleaningCall(checked) {
					for _, name := range identNames(checked) {
						ft.guarded[name] = true
					}
				} else if name := rootName(checked); name != "" {
					for _, value := range ft.defs[name] {
						if value != nil && a.cleaningCall(value) {
							ft.guarded[name] = true
						}
					}
				}
			}
			return true
		})
		return true
	})
}

// isUntrustedPath: untrusted input reaches the path and no guard covers every
// untrusted name it uses.
func (a *Analyzer) isUntrustedPath(expr ast.Expr, ft *funcTaint) bool {
	if !a.isTainted(expr, ft.tainted) {
		return false
	}
	for _, name := range identNames(expr) {
		if ft.tainted[name] && !ft.guarded[name] {
			return true
		}
	}
	return false
}

// Open redirect (SKY-G220): untrusted input must be able to choose where the
// redirect goes. Data after a literal "?" or "#" (query or fragment) cannot,
// like the fixed-host rule for SSRF. originTainted follows the same sources
// as isTainted but stops at such a delimiter; a name is origin-tainted only by
// an untrusted parameter or an assignment whose value is origin-tainted.
func (a *Analyzer) originTainted(expr ast.Expr, ft *funcTaint) bool {
	return a.originTaintedVisit(expr, ft, map[string]bool{})
}

func flattenAdd(expr ast.Expr) []ast.Expr {
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		return append(flattenAdd(bin.X), flattenAdd(bin.Y)...)
	}
	if paren, ok := expr.(*ast.ParenExpr); ok {
		return flattenAdd(paren.X)
	}
	return []ast.Expr{expr}
}

var formatVerbPositionRE = regexp.MustCompile(`%[-+# 0-9.*]*[a-zA-Z%]`)

func (a *Analyzer) originTaintedVisit(expr ast.Expr, ft *funcTaint, visiting map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return a.originTaintedVisit(e.X, ft, visiting)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return a.isTainted(e, ft.tainted)
		}
		for _, operand := range flattenAdd(e) {
			if text, ok := stringLiteralValue(operand); ok {
				if strings.ContainsAny(text, "?#") {
					return false // the rest is query or fragment
				}
				continue
			}
			if a.originTaintedVisit(operand, ft, visiting) {
				return true
			}
		}
		return false
	case *ast.Ident:
		if !ft.tainted[e.Name] || visiting[e.Name] {
			return false
		}
		if ft.paramTainted[e.Name] {
			return true
		}
		values := ft.defs[e.Name]
		if len(values) == 0 {
			return true // tainted by range, Read/Decode or a closure: be conservative
		}
		visiting[e.Name] = true
		defer delete(visiting, e.Name)
		for _, value := range values {
			if value == nil || a.originTaintedVisit(value, ft, visiting) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if a.isFormatString(e) && len(e.Args) > 0 {
			if format, ok := stringLiteralValue(e.Args[0]); ok {
				cut := strings.IndexAny(format, "?#")
				arg := 1
				for _, loc := range formatVerbPositionRE.FindAllStringIndex(format, -1) {
					if format[loc[1]-1] == '%' {
						continue // "%%"
					}
					if cut >= 0 && loc[0] > cut {
						break
					}
					if arg < len(e.Args) && a.originTaintedVisit(e.Args[arg], ft, visiting) {
						return true
					}
					arg++
				}
				return false
			}
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, ft.tainted) {
			if nonDataRequestMethods[sel.Sel.Name] && len(e.Args) == 0 {
				return false
			}
			if _, isIdent := sel.X.(*ast.Ident); isIdent {
				if a.originTaintedVisit(sel.X, ft, visiting) {
					return true
				}
			} else if a.isTainted(sel.X, ft.tainted) {
				return true
			}
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && a.isPackageIdent(sel.X, ft.tainted) && a.pathSanitizer(sel) {
			return false
		}
		for _, arg := range e.Args {
			if a.originTaintedVisit(arg, ft, visiting) {
				return true
			}
		}
		return false
	}
	return a.isTainted(expr, ft.tainted)
}

// collectRedirectGuards records names a same-origin check covers:
//   - strings.HasPrefix(v, "/") and a "//" check on v (single leading slash);
//   - u, _ := url.Parse(v) with a check on u.Host, u.Scheme or u.IsAbs();
//   - an allowlist: allowed[v], slices.Contains(list, v) or v == "literal" in
//     a condition.
func (a *Analyzer) collectRedirectGuards(body ast.Node, ft *funcTaint) {
	ft.redirectGuarded = map[string]bool{}
	parsedFrom := map[string][]string{}
	slashChecked := map[string]bool{}
	doubleSlashChecked := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && len(call.Args) == 1 &&
			(a.isPkgCall(call, "net/url", "Parse") || a.isPkgCall(call, "net/url", "ParseRequestURI")) {
			if id, ok := assign.Lhs[0].(*ast.Ident); ok {
				parsedFrom[id.Name] = identNames(call.Args[0])
			}
		}
		return true
	})
	conditions := []ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			conditions = append(conditions, node.Cond)
		case *ast.ForStmt:
			if node.Cond != nil {
				conditions = append(conditions, node.Cond)
			}
		}
		return true
	})
	for _, cond := range conditions {
		ast.Inspect(cond, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if a.isPkgCall(node, "strings", "HasPrefix") && len(node.Args) == 2 {
					if prefix, ok := stringLiteralValue(node.Args[1]); ok {
						if name := rootName(node.Args[0]); name != "" {
							switch prefix {
							case "/":
								slashChecked[name] = true
							case "//":
								doubleSlashChecked[name] = true
							}
						}
					}
				}
				if a.isPkgCall(node, "slices", "Contains") && len(node.Args) == 2 {
					for _, name := range identNames(node.Args[1]) {
						ft.redirectGuarded[name] = true
					}
				}
				if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "IsAbs" {
					for _, name := range parsedFrom[rootName(sel.X)] {
						ft.redirectGuarded[name] = true
					}
				}
			case *ast.SelectorExpr:
				if node.Sel.Name == "Host" || node.Sel.Name == "Scheme" {
					for _, name := range parsedFrom[rootName(node.X)] {
						ft.redirectGuarded[name] = true
					}
				}
			case *ast.IndexExpr:
				for _, name := range identNames(node.Index) {
					ft.redirectGuarded[name] = true
				}
			case *ast.BinaryExpr:
				if node.Op == token.EQL || node.Op == token.NEQ {
					_, leftLit := stringLiteralValue(node.X)
					_, rightLit := stringLiteralValue(node.Y)
					if rightLit {
						if name := rootName(node.X); name != "" {
							ft.redirectGuarded[name] = true
						}
					} else if leftLit {
						if name := rootName(node.Y); name != "" {
							ft.redirectGuarded[name] = true
						}
					}
				}
			}
			return true
		})
	}
	for name := range slashChecked {
		if doubleSlashChecked[name] {
			ft.redirectGuarded[name] = true
		}
	}
}

// isOpenRedirectTarget: untrusted input chooses where the redirect goes and
// no same-origin check covers it.
func (a *Analyzer) isOpenRedirectTarget(expr ast.Expr, ft *funcTaint) bool {
	if !a.originTainted(expr, ft) {
		return false
	}
	for _, name := range identNames(expr) {
		if ft.tainted[name] && !ft.redirectGuarded[name] {
			return true
		}
	}
	return false
}

// sqlQuerySeverity (SKY-G211): CRITICAL when request or network input reaches
// the query text; HIGH when the query is string-built from a non-constant
// value with no proven source (Python D211 reports that case too); none for
// placeholders or constants.
func (a *Analyzer) sqlQuerySeverity(query ast.Expr, ft *funcTaint) (string, string) {
	if a.isTainted(query, ft.tainted) {
		return "CRITICAL", "SQL query text comes from request or network input. Use parameterized queries instead."
	}
	stringBuilt := false
	if a.isStringConcat(query) {
		for _, operand := range flattenAdd(query) {
			if _, ok := stringLiteralValue(operand); !ok {
				stringBuilt = true
			}
		}
	} else if call, ok := query.(*ast.CallExpr); ok && a.isFormatString(call) {
		for _, arg := range call.Args[1:] {
			if _, ok := stringLiteralValue(arg); !ok {
				stringBuilt = true
			}
		}
	}
	if stringBuilt {
		return "HIGH", "SQL query built with string concatenation or formatting from a non-constant value. Use parameterized queries instead."
	}
	return "", ""
}

// isTestSupportFile: a non-_test.go file that imports "testing" and takes a
// test handle (testing.TB, *testing.T/B/F/M) as a parameter or struct field:
// a test helper package (httptest-style). Importing "testing" alone (for
// testing.Testing()) does not make production code a test.
func (a *Analyzer) isTestSupportFile(file *ast.File) bool {
	alias := ""
	for name, importPath := range a.imports {
		if importPath == "testing" {
			alias = name
		}
	}
	if alias == "" {
		return false
	}
	isHandle := func(expr ast.Expr) bool {
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != alias {
			return false
		}
		switch sel.Sel.Name {
		case "TB", "T", "B", "F", "M":
			return true
		}
		return false
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		if field, ok := n.(*ast.Field); ok && isHandle(field.Type) {
			found = true
		}
		return !found
	})
	return found
}
