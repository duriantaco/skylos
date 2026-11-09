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
	// Path-only barriers must not erase command, SQL or destination evidence.
	pathTainted map[string]bool
	// values assigned to each local name, to resolve one hop when checking
	// whether a URL's host is fixed
	defs map[string][]ast.Expr
	// names a containment check proves stay under a fixed base (G215)
	guarded map[token.Pos]map[string]bool
	// parameters tainted on entry (source type or a tainted caller)
	paramTainted map[string]bool
	// names a same-origin check covers (G220)
	redirectGuarded map[token.Pos]map[string]bool
	// names carrying untrusted data that is not HTML-escaped (G226/G228)
	xss map[string]bool
	// declared types of parameters, receivers and typed vars
	declTypes map[string]ast.Expr
	// the call defining the first name of `a, b := f()`
	multiDefs map[string][]ast.Expr
	// Content-Type writes and body writes per response (G228)
	contentTypes   []ctWrite
	responseWrites map[string][]respWrite
	// requests whose URL or host is set from untrusted input (G216 via Do)
	urlAssigned map[string]bool
}

type taintKind int

const (
	taintGeneral taintKind = iota
	taintXSS
	taintPath
)

const maxTaintRounds = 12

// Calls that fill their buffer or &target argument from a tainted reader.
// gin ShouldBind*/Bind*, echo Bind and DefaultBinder, fiber *Parser (CodeQL's
// gin, echo and fiber source models).
var taintFillingCalls = map[string]bool{
	"Read": true, "ReadFull": true, "ReadAtLeast": true, "ReadAt": true,
	"Decode": true, "Unmarshal": true, "Scan": true, "ReadJSON": true,
	"Bind": true, "BindJSON": true, "ShouldBind": true, "ShouldBindJSON": true,
	"BodyParser": true, "ShouldBindQuery": true, "ShouldBindUri": true, "ShouldBindHeader": true, "ShouldBindXML": true,
	"ShouldBindYAML": true, "ShouldBindTOML": true, "ShouldBindWith": true, "ShouldBindBodyWith": true,
	"ShouldBindBodyWithJSON": true, "ShouldBindBodyWithXML": true, "ShouldBindBodyWithYAML": true,
	"ShouldBindBodyWithTOML": true, "ShouldBindForm": true, "BindQuery": true, "BindUri": true,
	"BindHeader": true, "BindXML": true, "BindYAML": true, "BindTOML": true, "BindWith": true,
	"MustBindWith": true, "BindForm": true, "BindQueryParams": true, "BindPathParams": true,
	"BindHeaders": true, "BindBody": true, "QueryParser": true, "ParamsParser": true,
	"ReqHeaderParser": true, "CookieParser": true,
}

// fiber v3 binds through c.Bind().Body(&v), c.Bind().Query(&v)...
var fiberBindTargets = map[string]bool{
	"Body": true, "Query": true, "URI": true, "Header": true, "Cookie": true, "JSON": true,
	"XML": true, "Form": true, "MultipartForm": true, "All": true,
}

// Results that cannot carry injected text: numeric parsing (CodeQL treats
// numeric and boolean types as taint barriers) and UUID parsing.
var numericBarriers = map[string]map[string]bool{
	"strconv":                   {"Atoi": true, "ParseInt": true, "ParseUint": true, "ParseFloat": true, "ParseBool": true, "ParseComplex": true},
	"github.com/google/uuid":    {"Parse": true, "MustParse": true, "ParseBytes": true, "FromBytes": true},
	"github.com/gofrs/uuid":     {"FromString": true, "FromStringOrNil": true, "FromBytes": true, "FromBytesOrNil": true},
	"github.com/gofrs/uuid/v5":  {"FromString": true, "FromStringOrNil": true, "FromBytes": true, "FromBytesOrNil": true},
	"github.com/satori/go.uuid": {"FromString": true, "FromStringOrNil": true, "FromBytes": true, "FromBytesOrNil": true},
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
	return isPkg && id.Obj == nil && !tainted[id.Name]
}

// isTainted reports whether expr may carry untrusted data.
func (a *Analyzer) isTainted(expr ast.Expr, tainted map[string]bool) bool {
	return a.taintedIn(expr, tainted, taintGeneral)
}

// taintedIn: expr may carry untrusted data of the given kind. A value whose
// type resolves to a number or boolean never does.
func (a *Analyzer) taintedIn(expr ast.Expr, tainted map[string]bool, kind taintKind) bool {
	if !a.taintedExpr(expr, tainted, kind) {
		return false
	}
	switch expr.(type) {
	case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
		if a.scope != nil && a.isScalarTyped(expr, a.scope) {
			return false
		}
	}
	return true
}

func (a *Analyzer) taintedExpr(expr ast.Expr, tainted map[string]bool, kind taintKind) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return tainted[e.Name]
	case *ast.SelectorExpr:
		if a.isPackageIdent(e.X, tainted) {
			return false
		}
		return a.taintedIn(e.X, tainted, kind)
	case *ast.IndexExpr:
		// m[key] with an attacker key still returns the program's value.
		return a.taintedIn(e.X, tainted, kind)
	case *ast.IndexListExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.SliceExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.StarExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.ParenExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.UnaryExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.TypeAssertExpr:
		return a.taintedIn(e.X, tainted, kind)
	case *ast.BinaryExpr:
		return a.taintedIn(e.X, tainted, kind) || a.taintedIn(e.Y, tainted, kind)
	case *ast.KeyValueExpr:
		return a.taintedIn(e.Value, tainted, kind)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if a.taintedIn(elt, tainted, kind) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if a.isTaintBarrier(e, tainted, kind) {
			return false
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, tainted) {
			if nonDataRequestMethods[sel.Sel.Name] && len(e.Args) == 0 {
				return false
			}
			if sel.Sel.Name == "Accept" && len(e.Args) == 0 {
				return true // net.Listener.Accept: an incoming connection
			}
			if a.taintedIn(sel.X, tainted, kind) {
				return true
			}
		}
		for _, arg := range e.Args {
			if a.taintedIn(arg, tainted, kind) {
				return true
			}
		}
	}
	return false
}

// isTaintBarrier: the call's result carries no untrusted data of this kind:
// numeric parsing, len/cap and numeric conversions for every kind,
// filepath.Base/SecureJoin for the general kind (as before), escapers for XSS.
func (a *Analyzer) isTaintBarrier(call *ast.CallExpr, tainted map[string]bool, kind taintKind) bool {
	if id, ok := call.Fun.(*ast.Ident); ok && len(call.Args) == 1 && !tainted[id.Name] {
		if id.Name == "len" || id.Name == "cap" || scalarTypes[id.Name] {
			return true
		}
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if a.isPackageIdent(sel.X, tainted) {
		if numericBarriers[a.imports[sel.X.(*ast.Ident).Name]][sel.Sel.Name] {
			return true
		}
		if kind == taintPath && a.pathSanitizer(sel) {
			return true
		}
	}
	if kind == taintXSS && sel.Sel.Name == "Error" && len(call.Args) == 0 && !a.isPackageIdent(sel.X, tainted) {
		return true // err.Error(): text the failing code wrote, e.g. a decoder's syntax error
	}
	return kind == taintXSS && a.isXSSSanitizerCall(call, tainted)
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
	a.scope = ft
	defer func() { a.scope = nil }()
	general := a.propagateKind(body, ft, ft.tainted, taintGeneral)
	xss := a.propagateKind(body, ft, ft.xss, taintXSS)
	paths := a.propagateKind(body, ft, ft.pathTainted, taintPath)
	return general || xss || paths
}

func (a *Analyzer) propagateKind(body ast.Node, ft *funcTaint, t map[string]bool, kind taintKind) bool {
	changed := false
	tainted := func(expr ast.Expr) bool { return a.taintedIn(expr, t, kind) }
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if a.seedSourceParams(node.Type.Params, t) {
				changed = true
			}
			if ft.paramTainted != nil && kind == taintGeneral {
				for _, name := range paramNames(node.Type.Params) {
					if t[name] && a.fieldListHasSource(node.Type.Params, name) {
						ft.paramTainted[name] = true
					}
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if tainted(node.Rhs[i]) && markTainted(t, lhs) {
						changed = true
					}
				}
			} else if len(node.Rhs) == 1 && tainted(node.Rhs[0]) {
				for _, lhs := range node.Lhs {
					if markTainted(t, lhs) {
						changed = true
					}
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == len(node.Values) {
				for i, name := range node.Names {
					if tainted(node.Values[i]) && markTainted(t, name) {
						changed = true
					}
				}
			} else if len(node.Values) == 1 && tainted(node.Values[0]) {
				for _, name := range node.Names {
					if markTainted(t, name) {
						changed = true
					}
				}
			}
		case *ast.RangeStmt:
			if tainted(node.X) {
				if node.Key != nil && markTainted(t, node.Key) {
					changed = true
				}
				if node.Value != nil && markTainted(t, node.Value) {
					changed = true
				}
			}
		case *ast.CallExpr:
			if target, data := a.bufferWrite(node, ft); target != nil {
				for _, arg := range data {
					if tainted(arg) && markTainted(t, target) {
						changed = true
					}
				}
				return true
			}
			if !taintFillingCalls[calleeName(node.Fun)] && !isFiberBindCall(node) {
				return true
			}
			from := false
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, t) {
				from = tainted(sel.X)
			}
			for _, arg := range node.Args {
				if tainted(arg) {
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

// isFiberBindCall: c.Bind().Body(&v) and the other fiber v3 binders.
func isFiberBindCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !fiberBindTargets[sel.Sel.Name] {
		return false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok || len(inner.Args) != 0 {
		return false
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	return ok && innerSel.Sel.Name == "Bind"
}

func isBufferType(ref typeRef) bool {
	return ref.is("bytes", "Buffer") || ref.is("strings", "Builder") || ref.is("bufio", "Writer")
}

// bufferWrite: a write into an in-memory buffer (bytes.Buffer,
// strings.Builder, bufio.Writer) taints the buffer, so HTML assembled in a
// builder and then written to the response is followed.
func (a *Analyzer) bufferWrite(call *ast.CallExpr, ft *funcTaint) (ast.Expr, []ast.Expr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}
	if importPath, ok := a.packageOf(sel.X, ft); ok {
		isFmt := importPath == "fmt" && strings.HasPrefix(sel.Sel.Name, "Fprint")
		isIO := importPath == "io" && sel.Sel.Name == "WriteString"
		if (isFmt || isIO) && len(call.Args) >= 2 && isBufferType(a.resolveType(call.Args[0], ft, 0)) {
			return call.Args[0], call.Args[1:]
		}
		return nil, nil
	}
	switch sel.Sel.Name {
	case "Write", "WriteString", "WriteByte", "WriteRune":
		if isBufferType(a.resolveType(sel.X, ft, 0)) {
			return sel.X, call.Args
		}
	}
	return nil, nil
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
		ft := emptyFuncTaint()
		ft.defs = collectDefs(fd.Body)
		ft.multiDefs = collectMultiDefs(fd.Body)
		ft.declTypes = collectDeclTypes(fd, a.imports)
		a.seedSourceParams(fd.Type.Params, ft.tainted)
		a.seedSourceParams(fd.Type.Params, ft.xss)
		a.seedSourceParams(fd.Type.Params, ft.pathTainted)
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
			caller := scopes[fd]
			a.scope = caller
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && a.isPackageIdent(sel.X, caller.tainted) {
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
						if name == "" || name == "_" {
							continue
						}
						if !scopes[callee].tainted[name] && a.isTainted(arg, caller.tainted) {
							scopes[callee].tainted[name] = true
							scopes[callee].paramTainted[name] = true
							changed = true
						}
						if !scopes[callee].xss[name] && a.isXSSTainted(arg, caller) {
							scopes[callee].xss[name] = true
							changed = true
						}
						if !scopes[callee].pathTainted[name] && a.taintedIn(arg, caller.pathTainted, taintPath) {
							scopes[callee].pathTainted[name] = true
							changed = true
						}
					}
				}
				return true
			})
			a.scope = nil
		}
		if !changed {
			break
		}
	}

	guardMetadata := a.guardFileMetadata(file)
	for _, fd := range funcs {
		ft := scopes[fd]
		a.scope = ft
		a.collectValueGuards(guardMetadata, fd, ft)
		a.collectResponseFacts(fd.Body, ft)
		a.collectURLAssignments(fd.Body, ft)
		a.scope = nil
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				a.callTaint[call] = ft
			}
			return true
		})
	}
}

func emptyFuncTaint() *funcTaint {
	return &funcTaint{
		tainted: map[string]bool{}, pathTainted: map[string]bool{}, defs: map[string][]ast.Expr{}, guarded: map[token.Pos]map[string]bool{},
		paramTainted: map[string]bool{}, redirectGuarded: map[token.Pos]map[string]bool{}, xss: map[string]bool{},
		declTypes: map[string]ast.Expr{}, multiDefs: map[string][]ast.Expr{},
		responseWrites: map[string][]respWrite{}, urlAssigned: map[string]bool{},
	}
}

func (a *Analyzer) taintFor(call *ast.CallExpr) *funcTaint {
	if ft, ok := a.callTaint[call]; ok {
		return ft
	}
	return emptyFuncTaint()
}

// collectURLAssignments records requests whose destination is set from
// untrusted input after creation: req.URL = u, req.URL.Host = h.
func (a *Analyzer) collectURLAssignments(body ast.Node, ft *funcTaint) {
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			switch {
			case sel.Sel.Name == "URL":
				if a.isSSRFURL(assign.Rhs[i], ft) {
					ft.urlAssigned[rootName(sel.X)] = true
				}
			case sel.Sel.Name == "Host":
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "URL" && a.isTainted(assign.Rhs[i], ft.tainted) {
					ft.urlAssigned[rootName(inner.X)] = true
				}
			}
		}
		return true
	})
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
		if len(e.Args) == 1 && (a.isPkgCall(e, "net/url", "Parse") || a.isPkgCall(e, "net/url", "ParseRequestURI")) {
			return a.leadingLiteral(e.Args[0], ft, depth+1)
		}
	case *ast.Ident:
		values := ft.defs[e.Name]
		if len(values) == 1 && values[0] != nil {
			return a.leadingLiteral(values[0], ft, depth+1)
		}
		if len(values) == 1 && values[0] == nil && len(ft.multiDefs[e.Name]) == 1 {
			return a.leadingLiteral(ft.multiDefs[e.Name][0], ft, depth+1)
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
	return ok && pkgIdent.Obj == nil && a.imports[pkgIdent.Name] == importPath
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

// isUntrustedPath: untrusted input reaches the path and no guard covers every
// untrusted name it uses.
func (a *Analyzer) isUntrustedPath(expr ast.Expr, ft *funcTaint) bool {
	if !a.taintedIn(expr, ft.pathTainted, taintPath) {
		return false
	}
	return !ft.guarded[expr.Pos()]["value"]
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
		for _, arg := range e.Args {
			if a.originTaintedVisit(arg, ft, visiting) {
				return true
			}
		}
		return false
	}
	return a.isTainted(expr, ft.tainted)
}

// isOpenRedirectTarget: untrusted input chooses where the redirect goes and
// no same-origin check covers it.
func (a *Analyzer) isOpenRedirectTarget(expr ast.Expr, ft *funcTaint) bool {
	if !a.originTainted(expr, ft) {
		return false
	}
	return !ft.redirectGuarded[expr.Pos()]["value"]
}

// sqlQuerySeverity (SKY-G211): CRITICAL when request or network input reaches
// the query text; HIGH when the query is string-built from a non-constant
// value with no proven source (Python D211 reports that case too); none for
// placeholders or constants.
//
// stringOnly is set for ORMs (GORM) that bind a struct, map, slice or pointer
// argument as parameters: an argument resolved to such a type is not query
// text. An argument of unknown type is still checked.
func (a *Analyzer) sqlQuerySeverity(query ast.Expr, ft *funcTaint, stringOnly bool) (string, string) {
	if stringOnly && a.isNonStringTyped(query, ft) {
		return "", ""
	}
	if a.isTainted(query, ft.tainted) {
		return "CRITICAL", "SQL query text comes from request or network input. Use parameterized queries instead."
	}
	stringBuilt := a.isStringBuiltSQL(query)
	if id, ok := query.(*ast.Ident); ok && !stringBuilt {
		// q := fmt.Sprintf(...); db.Query(q), like gosec G201/G202's
		// variable case: moving the formatting out of the call hides nothing.
		for _, value := range ft.defs[id.Name] {
			if value != nil && a.isStringBuiltSQL(value) {
				stringBuilt = true
			}
		}
	}
	if stringBuilt {
		return "HIGH", "SQL query built with string concatenation or formatting from a non-constant value. Use parameterized queries instead."
	}
	return "", ""
}

// isStringBuiltSQL: concatenation or fmt formatting that inserts a
// non-constant, non-numeric value.
func (a *Analyzer) isStringBuiltSQL(expr ast.Expr) bool {
	if a.isStringConcat(expr) {
		for _, operand := range flattenAdd(expr) {
			if _, ok := stringLiteralValue(operand); !ok && !a.isNumericText(operand) {
				return true
			}
		}
		return false
	}
	if call, ok := expr.(*ast.CallExpr); ok && a.isFormatString(call) {
		return a.formatsTextArgument(call)
	}
	return false
}

// isNumericText: strconv.Itoa/Format* of a number, or a value of numeric,
// boolean, UUID or time type.
func (a *Analyzer) isNumericText(expr ast.Expr) bool {
	if a.scope != nil && (a.isScalarTyped(expr, a.scope) || isFixedFormatType(a.resolveType(expr, a.scope, 0))) {
		return true
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, name := range []string{"Itoa", "FormatInt", "FormatUint", "FormatFloat", "FormatBool"} {
		if a.isPkgCall(call, "strconv", name) {
			return true
		}
	}
	return false
}

// Verbs that print a number, boolean or hex digits, never text an attacker can
// shape into SQL (gosec G201 skips them too).
const numericVerbs = "bdoOxXeEfFgGtUp"

// formatsTextArgument: fmt.Sprintf places a non-constant value through a
// text verb (%s, %v, %q...). fmt.Sprint and formats with explicit argument
// indexes fall back to "any non-constant argument".
func (a *Analyzer) formatsTextArgument(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	nonConstant := func(arg ast.Expr) bool {
		_, isLit := stringLiteralValue(arg)
		return !isLit && !a.isNumericText(arg)
	}
	format, ok := stringLiteralValue(call.Args[0])
	sel, _ := call.Fun.(*ast.SelectorExpr)
	if !ok || sel == nil || sel.Sel.Name != "Sprintf" || strings.Contains(format, "[") {
		for _, arg := range call.Args[1:] {
			if nonConstant(arg) {
				return true
			}
		}
		return false
	}
	arg := 1
	for _, loc := range formatVerbPositionRE.FindAllStringIndex(format, -1) {
		spec := format[loc[0]:loc[1]]
		verb := spec[len(spec)-1]
		if verb == '%' {
			continue
		}
		arg += strings.Count(spec, "*")
		if arg >= len(call.Args) {
			return false
		}
		if !strings.ContainsRune(numericVerbs, rune(verb)) && nonConstant(call.Args[arg]) {
			return true
		}
		arg++
	}
	for _, extra := range call.Args[arg:] {
		if nonConstant(extra) {
			return true
		}
	}
	return false
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
