package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractResolvesReceiverMethodRefsFromTypedSelectors(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

type Context struct {
	writermem responseWriter
}

type Pool struct{}
type responseWriter struct{}

func (*Pool) Get() any { return &Context{} }
func (c *Context) reset() {}
func (w *responseWriter) reset(_ any) {}

func serve(pool *Pool, writer any) {
	c := pool.Get().(*Context)
	c.reset()
	c.writermem.reset(writer)
}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectRef(t, result, "Context.reset")
	expectRef(t, result, "responseWriter.reset")
	expectCall(t, result, "serve", "Context.reset")
	expectCall(t, result, "serve", "responseWriter.reset")
}

func TestExtractResolvesPromotedEmbeddedMethodRef(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

type inner struct{}
type outer struct {
	inner
}

func (i inner) run() {}

func serve(o outer) {
	o.run()
}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectRef(t, result, "inner.run")
	expectCall(t, result, "serve", "inner.run")
}

func TestExtractResolvesMethodExpressionRef(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

type Context struct{}

func (c *Context) reset() {}

func serve() {
	reset := (*Context).reset
	reset(&Context{})
}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectRef(t, result, "Context.reset")
}

func TestExtractResolvesGenericReceiverMethodRef(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

type Box[T any] struct{}

func (b *Box[T]) reset() {}

func serve() {
	var b Box[int]
	b.reset()
}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectRef(t, result, "Box.reset")
	expectCall(t, result, "serve", "Box.reset")
}

func TestExtractDoesNotEmitPhantomInterfaceMethodRefs(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

type runner interface {
	run()
}

type worker struct{}

func (w worker) run() {}

func serve(r runner) {
	r.run()
}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectNoRef(t, result, "runner.run")
	expectNoCall(t, result, "serve", "runner.run")
}

func TestHasMethodDefsOnlyMatchesMethods(t *testing.T) {
	defs := []Def{
		{Name: "main", Type: "function"},
		{Name: "unused", Type: "function"},
	}
	if hasMethodDefs(defs) {
		t.Fatal("function-only package should not require typed selector resolution")
	}

	defs = append(defs, Def{Name: "worker.run", Type: "method"})
	if !hasMethodDefs(defs) {
		t.Fatal("method package should use typed selector resolution")
	}
}

func TestExtractRespectsImportedSelectorWhenLocalNameIsNotTyped(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "demo.go", `package demo

import "example.com/demo/helper"

func serve() {
	helper.Run()
}
`)
	if err := os.Mkdir(filepath.Join(root, "helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, filepath.Join("helper", "helper.go"), `package helper

func Run() {}
`)

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	expectRef(t, result, "helper.Run")
	expectCall(t, result, "serve", "helper.Run")
}

func writeTestFile(t *testing.T, root string, relPath string, content string) {
	t.Helper()

	path := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expectRef(t *testing.T, result *Result, name string) {
	t.Helper()

	for _, ref := range result.Refs {
		if ref.Name == name {
			return
		}
	}
	t.Fatalf("expected ref %q in %#v", name, result.Refs)
}

func expectCall(t *testing.T, result *Result, caller string, callee string) {
	t.Helper()

	for _, call := range result.CallPairs {
		if call.Caller == caller && call.Callee == callee {
			return
		}
	}
	t.Fatalf("expected call %q -> %q in %#v", caller, callee, result.CallPairs)
}

func expectNoRef(t *testing.T, result *Result, name string) {
	t.Helper()

	for _, ref := range result.Refs {
		if ref.Name == name {
			t.Fatalf("did not expect ref %q in %#v", name, result.Refs)
		}
	}
}

func expectNoCall(t *testing.T, result *Result, caller string, callee string) {
	t.Helper()

	for _, call := range result.CallPairs {
		if call.Caller == caller && call.Callee == callee {
			t.Fatalf("did not expect call %q -> %q in %#v", caller, callee, result.CallPairs)
		}
	}
}
