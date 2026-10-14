package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeDirSkipsSymlinkedGoFilesOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	insideFile := filepath.Join(root, "secret.go")
	if err := os.WriteFile(insideFile, []byte(`package main

const dbPassword = "Xq8Zt4mN7bJc5HsY1aGd"

func main() { println(dbPassword) }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(outside, "secret.go")
	if err := os.WriteFile(outsideFile, []byte(`package main

const dbPassword = "Zq8vR2kLp9XwT4mN7bJc"

func main() { println(dbPassword) }
`), 0o600); err != nil {
		t.Fatal(err)
	}

	linkFile := filepath.Join(root, "leak.go")
	if err := os.Symlink(outsideFile, linkFile); err != nil {
		t.Skipf("filesystem does not allow symlink creation: %v", err)
	}

	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}

	resolvedInsideFile, err := filepath.EvalSymlinks(insideFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected only the in-root finding, got %d findings: %#v", len(findings), findings)
	}
	if findings[0].File != resolvedInsideFile {
		t.Fatalf("expected finding for %s, got %s", resolvedInsideFile, findings[0].File)
	}
}
