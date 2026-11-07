package symbols

import (
	"go/version"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// workspaceSourceModules recognizes only an active, fully contained workspace
// whose use directives name unambiguous source modules. The caller still has to
// index the package files; this metadata never discovers dependency source.
// Unsupported replacements and directives decline the additional type proof.
func workspaceSourceModules(root string) (map[string]string, map[string]string, bool) {
	workspace, active := activeWorkspaceFile(root)
	if !active || workspace == "" || filepath.Dir(workspace) != root {
		return nil, nil, active
	}
	data, ok := regularModuleFile(workspace)
	if !ok {
		return nil, nil, true
	}
	uses := []string{}
	block, goVersion, goCount, toolchainCount := "", "", 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		fields, valid := moduleLineFields(line)
		if !valid {
			return nil, nil, true
		}
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 && fields[0] == ")" {
			if block == "" {
				return nil, nil, true
			}
			block = ""
			continue
		}
		kind := block
		if kind == "" {
			kind, fields = fields[0], fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				if kind != "use" {
					return nil, nil, true
				}
				block = kind
				continue
			}
		}
		switch kind {
		case "go":
			goCount++
			if goCount != 1 || len(fields) != 1 || !validGoVersion(fields[0]) {
				return nil, nil, true
			}
			goVersion = fields[0]
		case "toolchain":
			toolchainCount++
			if toolchainCount != 1 || len(fields) != 1 || !strings.HasPrefix(fields[0], "go") || !validGoVersion(strings.TrimPrefix(fields[0], "go")) {
				return nil, nil, true
			}
		case "use":
			if len(fields) != 1 || len(uses) >= 64 {
				return nil, nil, true
			}
			uses = append(uses, fields[0])
		default:
			return nil, nil, true
		}
	}
	if block != "" || goCount != 1 || len(uses) == 0 {
		return nil, nil, true
	}
	modules, prefixes, versions := map[string]string{}, map[string]bool{}, map[string]string{}
	for _, use := range uses {
		if use == "" || strings.ContainsAny(use, "\\\x00\r\n") {
			return nil, nil, true
		}
		dir := use
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, filepath.FromSlash(dir))
		}
		dir = filepath.Clean(dir)
		if (dir != root && !safeProjectDirectory(root, dir)) || modules[dir] != "" {
			return nil, nil, true
		}
		prefix, languageVersion := workspaceModuleMetadata(dir, goVersion)
		if prefix == "" || prefixes[prefix] {
			return nil, nil, true
		}
		modules[dir], prefixes[prefix], versions[dir] = prefix, true, languageVersion
	}
	return modules, versions, true
}

func activeWorkspaceFile(root string) (string, bool) {
	workspace := os.Getenv("GOWORK")
	if workspace == "off" {
		return "", false
	}
	if workspace != "" {
		if !filepath.IsAbs(workspace) {
			return "", true
		}
		// A system temporary-directory alias may occur before the admitted
		// physical root. Metadata itself must still be an ordinary file.
		if info, err := os.Lstat(workspace); err != nil || !info.Mode().IsRegular() {
			return "", true
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(workspace))
		if err != nil {
			return "", true
		}
		return filepath.Join(parent, filepath.Base(workspace)), true
	}
	for current := root; ; current = filepath.Dir(current) {
		name := filepath.Join(current, "go.work")
		if _, err := os.Lstat(name); err == nil || !os.IsNotExist(err) {
			return name, true
		}
		if parent := filepath.Dir(current); parent == current {
			return "", false
		}
	}
}

func validGoVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "1" || !version.IsValid(runtime.Version()) || version.Compare("go"+value, runtime.Version()) > 0 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// Main modules in this bounded workspace must have simple, valid metadata.
// Requirements do not fetch anything: only an independently indexed workspace
// or standard-library package can satisfy an import. Replacement/version graph
// semantics remain unknown instead of silently choosing a provider.
func workspaceModuleMetadata(dir, workspaceGo string) (string, string) {
	data, ok := regularModuleFile(filepath.Join(dir, "go.mod"))
	if !ok {
		return "", ""
	}
	prefix, block := "", ""
	goCount, toolchainCount, languageVersion := 0, 0, "go1.16"
	required := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields, valid := moduleLineFields(line)
		if !valid {
			return "", ""
		}
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 && fields[0] == ")" {
			if block == "" {
				return "", ""
			}
			block = ""
			continue
		}
		kind := block
		if kind == "" {
			kind, fields = fields[0], fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				if kind != "require" {
					return "", ""
				}
				block = kind
				continue
			}
		}
		switch kind {
		case "module":
			if prefix != "" || len(fields) != 1 || !canonicalModulePath(fields[0]) {
				return "", ""
			}
			prefix = fields[0]
			// Standard packages retain the host toolchain's identity. A
			// source module with the same prefix cannot replace that proof.
			if info, err := os.Stat(filepath.Join(buildDefaultGOROOT(), "src", filepath.FromSlash(strings.Split(prefix, "/")[0]))); err == nil && info.IsDir() {
				return "", ""
			}
		case "go":
			goCount++
			if goCount != 1 || len(fields) != 1 || !validGoVersion(fields[0]) || newerGoVersion(fields[0], workspaceGo) {
				return "", ""
			}
			languageVersion = "go" + fields[0]
		case "toolchain":
			toolchainCount++
			if toolchainCount != 1 || len(fields) != 1 || !strings.HasPrefix(fields[0], "go") || !validGoVersion(strings.TrimPrefix(fields[0], "go")) {
				return "", ""
			}
		case "require":
			if len(fields) != 2 || !canonicalModulePath(fields[0]) || !canonicalRequiredVersion(fields[0], fields[1]) || required[fields[0]] {
				return "", ""
			}
			required[fields[0]] = true
		default:
			return "", ""
		}
	}
	if block != "" {
		return "", ""
	}
	return prefix, languageVersion
}

func buildDefaultGOROOT() string {
	ensureHostBuildContext()
	return targetBuildContext.GOROOT
}

func newerGoVersion(left, right string) bool {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < 3; index++ {
		a, b := 0, 0
		if index < len(leftParts) {
			a, _ = strconv.Atoi(leftParts[index])
		}
		if index < len(rightParts) {
			b, _ = strconv.Atoi(rightParts[index])
		}
		if a != b {
			return a > b
		}
	}
	return false
}

// Canonical module requirements are bounded semver identifiers. Invalid version
// text must not turn an otherwise invalid workspace into a negative proof.
func canonicalRequiredVersion(modulePath, value string) bool {
	if len(value) > 128 || !strings.HasPrefix(value, "v") {
		return false
	}
	value = strings.TrimPrefix(value, "v")
	build := strings.Split(value, "+")
	if len(build) > 2 || (len(build) == 2 && build[1] != "incompatible") {
		return false
	}
	core, pre, hasPre := strings.Cut(build[0], "-")
	numbers := strings.Split(core, ".")
	if len(numbers) != 3 {
		return false
	}
	for _, number := range numbers {
		if number == "" || (len(number) > 1 && number[0] == '0') {
			return false
		}
		for _, digit := range number {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	if hasPre {
		for _, identifier := range strings.Split(pre, ".") {
			if identifier == "" {
				return false
			}
			numeric := true
			for _, letter := range identifier {
				if !((letter >= '0' && letter <= '9') || (letter >= 'a' && letter <= 'z') || (letter >= 'A' && letter <= 'Z') || letter == '-') {
					return false
				}
				if letter < '0' || letter > '9' {
					numeric = false
				}
			}
			if numeric && len(identifier) > 1 && identifier[0] == '0' {
				return false
			}
		}
	}
	last := modulePath[strings.LastIndex(modulePath, "/")+1:]
	if strings.HasPrefix(modulePath, "gopkg.in/") {
		marker := strings.LastIndex(last, ".v")
		return marker >= 0 && last[marker+2:] == numbers[0]
	}
	if strings.HasPrefix(last, "v") && len(last) > 1 && last[1] >= '0' && last[1] <= '9' {
		return last[1:] == numbers[0] && numbers[0] != "0" && numbers[0] != "1"
	}
	return numbers[0] == "0" || numbers[0] == "1" || len(build) == 2
}
