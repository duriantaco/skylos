package symbols

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// localReplacementModules admits a small, source-only module context: a direct
// required module with an unversioned replacement inside the scanned root. It
// never discovers dependency files, follows a workspace, or downloads anything.
func localReplacementModules(root, modulePath string) map[string]string {
	modules := map[string]string{root: modulePath}
	if modulePath == "" || hasWorkspaceContext(root) {
		return modules
	}
	data, ok := regularModuleFile(filepath.Join(root, "go.mod"))
	if !ok {
		return modules
	}
	required := map[string]bool{}
	replacements := map[string]string{}
	blocked := map[string]bool{}
	seen := map[string]bool{}
	moduleCount := 0
	block := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields, valid := moduleLineFields(line)
		if !valid {
			return modules
		}
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 && fields[0] == ")" {
			if block == "" {
				return modules
			}
			block = ""
			continue
		}
		kind := block
		if kind == "" {
			kind, fields = fields[0], fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				if kind != "require" && kind != "replace" {
					return modules
				}
				block = kind
				continue
			}
		}
		switch kind {
		case "module":
			moduleCount++
			if len(fields) != 1 || fields[0] != modulePath || moduleCount != 1 {
				return modules
			}
		case "require":
			if len(fields) != 2 || !canonicalModulePath(fields[0]) || !strings.HasPrefix(fields[1], "v") || required[fields[0]] {
				return modules
			}
			required[fields[0]] = true
		case "replace":
			if len(fields) == 0 || !canonicalModulePath(fields[0]) {
				return modules
			}
			prefix := fields[0]
			if seen[prefix] || len(fields) != 3 || fields[1] != "=>" {
				blocked[prefix] = true
			} else {
				replacements[prefix] = fields[2]
			}
			seen[prefix] = true
		case "go", "toolchain":
			if len(fields) != 1 {
				return modules
			}
		default:
			// Unmodeled metadata cannot supply replacement-context proof,
			// even if a future Go release accepts the directive.
			return modules
		}
	}
	if block != "" || moduleCount != 1 || len(replacements) > 64 {
		return modules
	}
	for prefix, replacement := range replacements {
		if blocked[prefix] || !required[prefix] || prefix == modulePath || (!strings.HasPrefix(replacement, "./") && !strings.HasPrefix(replacement, "../")) || strings.Contains(replacement, "\\") {
			continue
		}
		dir := filepath.Clean(filepath.Join(root, filepath.FromSlash(replacement)))
		if dir == root || !safeProjectDirectory(root, dir) {
			continue
		}
		if readModulePath(dir) != prefix {
			continue
		}
		modules[dir] = prefix
	}
	return modules
}

func canonicalModulePath(value string) bool {
	return value != "" && value != "." && value != ".." && !path.IsAbs(value) && path.Clean(value) == value && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\" \t\r\n")
}

func regularModuleFile(name string) ([]byte, bool) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, false
	}
	data, err := os.ReadFile(name)
	return data, err == nil
}

// Go workspace replacements can override go.mod replacements. This bounded
// proof declines them instead of guessing the active workspace or reading one
// outside the scanned root. GOWORK=off explicitly selects module mode.
func hasWorkspaceContext(root string) bool {
	workspace := os.Getenv("GOWORK")
	if workspace == "off" {
		return false
	}
	if workspace != "" {
		return true
	}
	for current := root; ; current = filepath.Dir(current) {
		if _, err := os.Lstat(filepath.Join(current, "go.work")); err == nil || !os.IsNotExist(err) {
			return true
		}
		if parent := filepath.Dir(current); parent == current {
			return false
		}
	}
}

func safeProjectDirectory(root, dir string) bool {
	if !isPathWithinRoot(root, dir) {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return false
	}
	current := root
	for _, component := range strings.Split(rel, string(os.PathSeparator)) {
		if defaultSkipDirs[component] || strings.HasPrefix(component, ".") {
			return false
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

// go.mod strings may contain spaces or // inside quotes. Comments are removed
// only outside strings; malformed or unsupported quoting declines the proof.
func moduleLineFields(line string) ([]string, bool) {
	fields := []string{}
	for line = strings.TrimSpace(line); line != ""; line = strings.TrimSpace(line) {
		if strings.HasPrefix(line, "//") {
			break
		}
		if line[0] == '"' {
			end := 1
			for end < len(line) {
				if line[end] == '\\' {
					end += 2
					continue
				}
				if line[end] == '"' {
					break
				}
				end++
			}
			if end >= len(line) {
				return nil, false
			}
			value, err := strconv.Unquote(line[:end+1])
			if err != nil {
				return nil, false
			}
			fields = append(fields, value)
			line = line[end+1:]
			if line != "" && !strings.ContainsRune(" \t\r", rune(line[0])) && !strings.HasPrefix(line, "//") {
				return nil, false
			}
			continue
		}
		end := 0
		for end < len(line) && !strings.ContainsRune(" \t\r", rune(line[end])) && !strings.HasPrefix(line[end:], "//") {
			if line[end] == '"' || line[end] == '`' {
				return nil, false
			}
			end++
		}
		fields = append(fields, line[:end])
		line = line[end:]
	}
	return fields, true
}
