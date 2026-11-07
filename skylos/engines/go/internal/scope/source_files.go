// Package scope validates the orchestrator's explicit source-file inventory.
package scope

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load returns nil for the legacy directory scan. A supplied inventory is
// bounded, regular JSON and contains only ordinary files inside the root.
func Load(root, inventory string) (map[string]bool, error) {
	if inventory == "" {
		return nil, nil
	}
	info, err := os.Lstat(inventory)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return nil, fmt.Errorf("invalid source inventory")
	}
	data, err := os.ReadFile(inventory)
	if err != nil {
		return nil, err
	}
	var paths []string
	if err := json.Unmarshal(data, &paths); err != nil || paths == nil || len(paths) > 32768 {
		return nil, fmt.Errorf("invalid source inventory JSON")
	}
	return FromPaths(root, paths)
}

func FromPaths(root string, paths []string) (map[string]bool, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	files := map[string]bool{}
	for _, name := range paths {
		if !filepath.IsAbs(name) || !strings.HasSuffix(name, ".go") {
			return nil, fmt.Errorf("invalid admitted Go file")
		}
		name = filepath.Clean(name)
		rel, err := filepath.Rel(resolvedRoot, name)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("admitted Go file leaves source root")
		}
		current := resolvedRoot
		for _, part := range strings.Split(rel, string(os.PathSeparator)) {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("admitted Go source is missing or symlinked")
			}
		}
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("admitted Go source is not regular")
		}
		files[name] = true
	}
	return files, nil
}
