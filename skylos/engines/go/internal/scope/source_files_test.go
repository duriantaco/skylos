package scope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceInventoryLoadAndBoundaries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(realRoot, "main.go")
	inventory := filepath.Join(root, "sources.json")
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"one source", `["` + filepath.ToSlash(source) + `"]`, true},
		{"empty scope", `[]`, true},
		{"null", `null`, false},
		{"non-array", `{}`, false},
		{"bad type", `[1]`, false},
		{"relative source", `["main.go"]`, false},
		{"outside source", `["` + filepath.ToSlash(filepath.Join(t.TempDir(), "outside.go")) + `"]`, false},
		{"missing source", `["` + filepath.ToSlash(filepath.Join(realRoot, "missing.go")) + `"]`, false},
		{"directory source", `["` + filepath.ToSlash(realRoot) + `"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(inventory, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			files, err := Load(realRoot, inventory)
			if (err == nil) != tc.valid {
				t.Fatalf("Load error=%v, valid=%v", err, tc.valid)
			}
			if tc.valid && len(files) == 1 && !files[source] {
				t.Fatal(files)
			}
		})
	}
	if files, err := Load(realRoot, ""); err != nil || files != nil {
		t.Fatalf("legacy files=%v error=%v", files, err)
	}
}

func TestSourceInventoryRejectsSymlinkedInventoryAndParents(t *testing.T) {
	root := t.TempDir()
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	source := filepath.Join(outside, "outside.go")
	if err := os.WriteFile(source, []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "nested")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := FromPaths(realRoot, []string{filepath.Join(realRoot, "nested/outside.go")}); err == nil {
		t.Fatal("symlink parent admitted")
	}
	inventory := filepath.Join(outside, "inventory.json")
	body, _ := json.Marshal([]string{})
	if err := os.WriteFile(inventory, body, 0600); err != nil {
		t.Fatal(err)
	}
	inventoryLink := filepath.Join(root, "sources.json")
	if err := os.Symlink(inventory, inventoryLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(realRoot, inventoryLink); err == nil {
		t.Fatal("symlink inventory admitted")
	}
}
