package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSkipsSymlinkedGoFilesOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/demo\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(`package main

const InsideToken = "safe"

func main() { println(InsideToken) }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(outside, "secret.go")
	if err := os.WriteFile(outsideFile, []byte(`package main

const OutsideSecret = "password=supersecretvalue"

func useOutside() { println(OutsideSecret) }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	linkFile := filepath.Join(root, "leak.go")
	if err := os.Symlink(outsideFile, linkFile); err != nil {
		t.Skipf("filesystem does not allow symlink creation: %v", err)
	}

	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}

	resolvedOutsideFile, err := filepath.EvalSymlinks(outsideFile)
	if err != nil {
		t.Fatal(err)
	}

	foundInside := false
	for _, def := range result.Defs {
		if def.Name == "OutsideSecret" || def.File == resolvedOutsideFile || def.File == linkFile {
			t.Fatalf("outside-root symlink target was included in defs: %#v", def)
		}
		if def.Name == "InsideToken" {
			foundInside = true
		}
	}
	if !foundInside {
		t.Fatalf("expected in-root definitions to still be extracted: %#v", result.Defs)
	}

	for _, ref := range result.Refs {
		if ref.Name == "OutsideSecret" || ref.File == resolvedOutsideFile || ref.File == linkFile {
			t.Fatalf("outside-root symlink target was included in refs: %#v", ref)
		}
	}
}
