package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
)

// Cross-site scripting, modelled on CodeQL's go/reflected-xss:
//   - SKY-G226: request input converted to an html/template "safe" type
//     (template.HTML, JS, URL, HTMLAttr, CSS, JSStr, Srcset), which the
//     template then writes unescaped (gosec G203, restricted to request data);
//   - SKY-G228: request input written to an HTTP response that is HTML.
//
// A net/http response is HTML unless a non-HTML Content-Type was set on the
// same writer before the write, or the first write to it starts with constant
// text whose first character is not "<" (net/http then sniffs text/plain).
// gin c.String/c.JSON, echo c.String/c.JSON and fiber writes default to
// non-HTML types and are sinks only after an HTML Content-Type was set; gin
// c.Data and echo c.Blob are sinks with an HTML content-type argument, echo
// c.HTML/c.HTMLBlob always. The XSS taint set treats html.EscapeString, the
// html/template escapers, url.QueryEscape/PathEscape, json.Marshal and
// bluemonday policies as sanitisers, and request cookies as not reflected
// input (CodeQL CookieSanitizer).

type ctWrite struct {
	key  string
	pos  token.Pos
	html bool
}

type respWrite struct {
	pos       token.Pos
	lead      string
	leadKnown bool
}

var templateSafeTypes = map[string]bool{
	"HTML": true, "JS": true, "URL": true, "HTMLAttr": true, "CSS": true, "JSStr": true, "Srcset": true,
}

var templateEscapers = map[string]bool{
	"HTMLEscapeString": true, "JSEscapeString": true, "HTMLEscaper": true, "JSEscaper": true, "URLQueryEscaper": true,
}

var xssSanitizers = map[string]map[string]bool{
	"html":          {"EscapeString": true},
	"html/template": templateEscapers,
	"text/template": templateEscapers,
	"net/url":       {"QueryEscape": true, "PathEscape": true},
	"encoding/json": {"Marshal": true, "MarshalIndent": true},
}

const bluemondayPath = "github.com/microcosm-cc/bluemonday"

// isXSSSanitizerCall: the call's result is safe to place in HTML.
func (a *Analyzer) isXSSSanitizerCall(call *ast.CallExpr, set map[string]bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if a.isPackageIdent(sel.X, set) {
		pkgIdent := sel.X.(*ast.Ident)
		return xssSanitizers[a.imports[pkgIdent.Name]][sel.Sel.Name]
	}
	if a.scope == nil {
		return false
	}
	recv := a.resolveType(sel.X, a.scope, 0)
	switch sel.Sel.Name {
	case "Sanitize", "SanitizeBytes", "SanitizeReader":
		return recv.is(bluemondayPath, "Policy")
	case "Cookie", "Cookies":
		return recv.is("net/http", "Request") || a.frameworkOf(sel.X, a.scope) != ""
	}
	return false
}

func (a *Analyzer) isXSSTainted(expr ast.Expr, ft *funcTaint) bool {
	return a.taintedIn(expr, ft.xss, taintXSS)
}

func isContentTypeKey(expr ast.Expr) bool {
	if text, ok := stringLiteralValue(expr); ok {
		return strings.EqualFold(text, "content-type")
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "HeaderContentType"
	}
	return false
}

// valueIsHTML: a content-type value that names HTML.
func valueIsHTML(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		text, _ := stringLiteralValue(e)
		return strings.Contains(strings.ToLower(text), "html")
	case *ast.SelectorExpr:
		return strings.Contains(e.Sel.Name, "HTML")
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if valueIsHTML(elt) {
				return true
			}
		}
	case *ast.BinaryExpr:
		return valueIsHTML(e.X) || valueIsHTML(e.Y)
	}
	return false
}

// writerKey names the response an expression writes to: a net/http
// ResponseWriter, gin c.Writer, or echo c.Response() / c.Response().Writer
// (both keyed by the context).
func (a *Analyzer) writerKey(expr ast.Expr, ft *funcTaint) (string, bool) {
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 0 {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Response" && a.frameworkOf(sel.X, ft) == "echo" {
			return exprKey(sel.X), exprKey(sel.X) != ""
		}
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok && sel.Sel.Name == "Writer" {
		if a.frameworkOf(sel.X, ft) == "gin" {
			return exprKey(sel.X), exprKey(sel.X) != ""
		}
		if key, ok := a.writerKey(sel.X, ft); ok {
			return key, true
		}
	}
	if a.resolveType(expr, ft, 0).is("net/http", "ResponseWriter") {
		key := exprKey(expr)
		return key, key != ""
	}
	return "", false
}

// headerOwner: the writer key of W in W.Header().
func (a *Analyzer) headerOwner(expr ast.Expr, ft *funcTaint) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Header" {
		return "", false
	}
	if key, ok := a.writerKey(sel.X, ft); ok {
		return key, true
	}
	key := exprKey(sel.X)
	return key, key != ""
}

func unwrapConversion(expr ast.Expr) ast.Expr {
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return expr
		}
		switch fun := call.Fun.(type) {
		case *ast.ArrayType:
			expr = call.Args[0]
			continue
		case *ast.Ident:
			if fun.Name == "string" {
				expr = call.Args[0]
				continue
			}
		}
		return expr
	}
}

// leadText: the constant text a written value starts with.
func (a *Analyzer) leadText(expr ast.Expr, ft *funcTaint) (string, bool) {
	text, ok := a.leadingLiteral(unwrapConversion(expr), ft, 0)
	if !ok || strings.HasPrefix(strings.TrimLeft(text, " \t\r\n\f"), "%") {
		return "", false
	}
	return text, true
}

// sniffsAsText: net/http's content sniffing cannot choose HTML for a body
// that starts with this text.
func sniffsAsText(lead string) bool {
	trimmed := strings.TrimLeft(lead, " \t\r\n\f")
	return trimmed != "" && trimmed[0] != '<'
}

// responseWrite recognises a net/http-style write: fmt.Fprint*(W, ...),
// io.WriteString(W, s), W.Write(b), W.WriteString(s).
func (a *Analyzer) responseWrite(call *ast.CallExpr, ft *funcTaint) (string, []ast.Expr, string, bool, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", nil, "", false, false
	}
	if importPath, ok := a.packageOf(sel.X, ft); ok {
		if len(call.Args) < 2 {
			return "", nil, "", false, false
		}
		key, isWriter := a.writerKey(call.Args[0], ft)
		if !isWriter {
			return "", nil, "", false, false
		}
		switch {
		case importPath == "fmt" && sel.Sel.Name == "Fprintf":
			lead, known := "", false
			if text, ok := stringLiteralValue(call.Args[1]); ok && !strings.HasPrefix(strings.TrimLeft(text, " \t\r\n\f"), "%") {
				lead, known = text, true
			}
			return key, call.Args[1:], lead, known, true
		case importPath == "fmt" && (sel.Sel.Name == "Fprint" || sel.Sel.Name == "Fprintln"):
			lead, known := a.leadText(call.Args[1], ft)
			return key, call.Args[1:], lead, known, true
		case importPath == "io" && sel.Sel.Name == "WriteString":
			lead, known := a.leadText(call.Args[1], ft)
			return key, call.Args[1:2], lead, known, true
		}
		return "", nil, "", false, false
	}
	if (sel.Sel.Name == "Write" || sel.Sel.Name == "WriteString") && len(call.Args) == 1 {
		if key, isWriter := a.writerKey(sel.X, ft); isWriter {
			lead, known := a.leadText(call.Args[0], ft)
			return key, call.Args, lead, known, true
		}
	}
	return "", nil, "", false, false
}

// collectResponseFacts records, per function, Content-Type writes and the
// first write to each response.
func (a *Analyzer) collectResponseFacts(body ast.Node, ft *funcTaint) {
	ft.contentTypes = nil
	ft.responseWrites = map[string][]respWrite{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				index, ok := lhs.(*ast.IndexExpr)
				if !ok || i >= len(node.Rhs) || !isContentTypeKey(index.Index) {
					continue
				}
				if key, ok := a.headerOwner(index.X, ft); ok {
					html := valueIsHTML(node.Rhs[i]) || a.isTainted(node.Rhs[i], ft.tainted)
					ft.contentTypes = append(ft.contentTypes, ctWrite{key: key, pos: node.Pos(), html: html})
				}
			}
		case *ast.CallExpr:
			a.recordContentType(node, ft)
			if key, _, lead, known, ok := a.responseWrite(node, ft); ok {
				ft.responseWrites[key] = append(ft.responseWrites[key], respWrite{pos: node.Pos(), lead: lead, leadKnown: known})
			}
		}
		return true
	})
}

func (a *Analyzer) recordContentType(call *ast.CallExpr, ft *funcTaint) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	// A content type the request chooses can be text/html.
	htmlValue := func(value ast.Expr) bool {
		return valueIsHTML(value) || a.isTainted(value, ft.tainted)
	}
	switch sel.Sel.Name {
	case "Set", "Add":
		if len(call.Args) == 2 && isContentTypeKey(call.Args[0]) {
			if key, ok := a.headerOwner(sel.X, ft); ok {
				ft.contentTypes = append(ft.contentTypes, ctWrite{key: key, pos: call.Pos(), html: htmlValue(call.Args[1])})
				return
			}
			if a.frameworkOf(sel.X, ft) == "fiber" {
				ft.contentTypes = append(ft.contentTypes, ctWrite{key: exprKey(sel.X), pos: call.Pos(), html: htmlValue(call.Args[1])})
			}
		}
	case "Header":
		if len(call.Args) == 2 && isContentTypeKey(call.Args[0]) && a.frameworkOf(sel.X, ft) == "gin" {
			ft.contentTypes = append(ft.contentTypes, ctWrite{key: exprKey(sel.X), pos: call.Pos(), html: htmlValue(call.Args[1])})
		}
	case "Type":
		if len(call.Args) >= 1 && a.frameworkOf(sel.X, ft) == "fiber" {
			ft.contentTypes = append(ft.contentTypes, ctWrite{key: exprKey(sel.X), pos: call.Pos(), html: htmlValue(call.Args[0])})
		}
	}
}

// contentTypeBefore: whether a Content-Type was set on the response before
// pos, and whether any such value names HTML.
func (ft *funcTaint) contentTypeBefore(key string, pos token.Pos) (bool, bool) {
	set, html := false, false
	for _, write := range ft.contentTypes {
		if write.key == key && write.pos < pos {
			set = true
			if write.html {
				html = true
			}
		}
	}
	return set, html
}

// startsAsText: every write to the response up to and including pos starts
// with constant text that net/http sniffs as text/plain, so whichever of them
// runs first, the response is not HTML.
func (ft *funcTaint) startsAsText(key string, pos token.Pos) bool {
	found := false
	for _, write := range ft.responseWrites[key] {
		if write.pos > pos {
			continue
		}
		if !write.leadKnown || !sniffsAsText(write.lead) {
			return false
		}
		found = true
	}
	return found
}

func (a *Analyzer) anyXSSTainted(exprs []ast.Expr, ft *funcTaint) bool {
	for _, expr := range exprs {
		if a.isXSSTainted(expr, ft) {
			return true
		}
	}
	return false
}

const xssResponseDetail = "Request or network input is written into an HTML response without escaping. " +
	"Render it with html/template, escape it (html.EscapeString), or send it as JSON or text/plain."

func (a *Analyzer) checkXSS(call *ast.CallExpr, ft *funcTaint, path string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if importPath, ok := a.packageOf(sel.X, ft); ok && importPath == "html/template" {
		if templateSafeTypes[sel.Sel.Name] && len(call.Args) == 1 && a.isXSSTainted(call.Args[0], ft) {
			a.addFinding(call, path, "SKY-G226", "CRITICAL", "Cross-Site Scripting",
				"Request or network input is converted to template."+sel.Sel.Name+", which html/template writes without escaping. "+
					"Pass the plain string so the template escapes it, or sanitize it first (bluemonday).")
		}
		return
	}
	if key, data, _, _, ok := a.responseWrite(call, ft); ok {
		if !a.anyXSSTainted(data, ft) {
			return
		}
		set, html := ft.contentTypeBefore(key, call.Pos())
		if set && !html {
			return
		}
		if !html && ft.startsAsText(key, call.Pos()) {
			return
		}
		a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
		return
	}
	args := call.Args
	switch a.frameworkOf(sel.X, ft) {
	case "gin":
		switch {
		case sel.Sel.Name == "Data" && len(args) == 3:
			if valueIsHTML(args[1]) && a.isXSSTainted(args[2], ft) {
				a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
			}
		case sel.Sel.Name == "String" && len(args) >= 2:
			_, html := ft.contentTypeBefore(exprKey(sel.X), call.Pos())
			if html && a.anyXSSTainted(args[1:], ft) {
				a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
			}
		}
	case "echo":
		switch {
		case (sel.Sel.Name == "HTML" || sel.Sel.Name == "HTMLBlob") && len(args) == 2:
			if a.isXSSTainted(args[1], ft) {
				a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
			}
		case sel.Sel.Name == "Blob" && len(args) == 3:
			if valueIsHTML(args[1]) && a.isXSSTainted(args[2], ft) {
				a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
			}
		}
	case "fiber":
		switch sel.Sel.Name {
		case "SendString", "Send", "Write", "WriteString":
			if len(args) != 1 {
				return
			}
			_, html := ft.contentTypeBefore(exprKey(sel.X), call.Pos())
			if html && a.isXSSTainted(args[0], ft) {
				a.addFinding(call, path, "SKY-G228", "HIGH", "Cross-Site Scripting", xssResponseDetail)
			}
		}
	}
}
