package symbols

import "testing"

func TestPluginLookupKeepsNamedMainPackageSymbols(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "host/host.go", `package host

import "plugin"

func Load(path string) (plugin.Symbol, error) {
	loaded, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := loaded.Lookup("Settings"); err != nil {
		return nil, err
	}
	if _, err := loaded.Lookup("describe"); err != nil {
		return nil, err
	}
	return loaded.Lookup("Describe")
}
`)
	writeTestFile(t, root, "registry/registry.go", `package registry

type Table struct{ entries map[string]string }

func (t Table) Lookup(name string) string { return t.entries[name] }

func Default(t Table) string { return t.Lookup("Orphan") }
`)
	writeTestFile(t, root, "plugins/greeter/main.go", `package main

var Settings = map[string]string{}

var Unlisted = 1

type Greeter struct{}

func (Greeter) Describe() string { return "method" }

func Describe() string { return "greeter" }

func describe() string { return "lowercase is never a plugin symbol" }

func Orphan() string { return "named only by an unrelated Lookup" }

func Unnamed() string { return "no lookup names it" }

func main() {}
`)
	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"plugins/greeter.Describe":         true,
		"plugins/greeter.Settings":         true,
		"plugins/greeter.describe":         false,
		"plugins/greeter.Orphan":           false,
		"plugins/greeter.Unnamed":          false,
		"plugins/greeter.Unlisted":         false,
		"plugins/greeter.Greeter.Describe": false,
	}
	for name, exported := range want {
		found := false
		for _, def := range result.Defs {
			if def.Name != name {
				continue
			}
			found = true
			if def.IsExported != exported {
				t.Errorf("%s exported = %v, want %v", name, def.IsExported, exported)
			}
		}
		if !found {
			t.Errorf("missing definition %s", name)
		}
	}
}
