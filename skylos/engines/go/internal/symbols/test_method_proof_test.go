package symbols

import (
	"path/filepath"
	"testing"
)

func TestOnlyUnobtainablePrivateTestReceiversBecomeCandidates(t *testing.T) {
	cases := []struct {
		name, extra string
		want        bool
	}{
		{"uninstantiated", "", true},
		{"constructor", `func makeWorker() worker {return worker{}}`, false},
		{"test framework value", `var registered = worker{}`, false},
		{"interface conversion", `var registered interface{} = worker{}`, false},
		{"type alias", `type retained = worker`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestFile(t, root, "go.mod", "module example.com/testmethods\ngo 1.22\n")
			writeTestFile(t, root, "api.go", "package demo\n")
			writeTestFile(t, root, "api_test.go", "package demo\ntype worker struct{}\nfunc(worker) Match(){}\n"+tc.extra)
			r, err := Extract(root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, d := range r.Defs {
				if d.Name == "worker.Match" {
					found = true
					if d.Reachability != "unreachable" || d.IsExported {
						t.Fatalf("unproven method %+v", d)
					}
				}
			}
			if found != tc.want {
				t.Fatalf("method emitted=%v want=%v", found, tc.want)
			}
		})
	}
}
func TestUnadmittedPackageSourcePreventsTestReceiverProof(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "api_test.go", "package demo\ntype worker struct{}\nfunc(worker) Match(){}\n")
	writeTestFile(t, root, "consumer_test.go", "package demo\nvar registered=worker{}\n")
	r, err := ExtractScoped(root, map[string]bool{filepath.Join(root, "api_test.go"): true})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Defs {
		if d.Name == "worker.Match" {
			t.Fatal("partial package proved receiver unused")
		}
	}
}
func TestPartialTypesExposeOnlyObjectBoundLiveTestHelpers(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "api.go", "package demo\n")
	writeTestFile(t, root, "api_test.go", `package demo
import("testing";"example.invalid/unavailable")
func TestValue(t *testing.T){live()}
func live(){leaf();unavailable.Touch()}
func leaf(){}
func stale(){}
`)
	r, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, d := range r.Defs {
		states[d.Name] = d.Reachability
	}
	for _, name := range []string{"live", "leaf"} {
		if states[name] != "reachable" {
			t.Errorf("lost live helper %s: %+v", name, states)
		}
	}
	if _, ok := states["stale"]; ok {
		t.Fatal("partial type check proved unused helper")
	}
}
