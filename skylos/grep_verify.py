from __future__ import annotations

import concurrent.futures
import io
import logging
import re
import shutil
import subprocess
import threading
import time
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class GrepVerdict:
    alive: bool
    suppression_code: str | None = None
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class GrepStrategy:
    name: str
    build_pattern: Callable[..., str | list[str]]
    include_globs: list[str] = field(default_factory=list)
    is_strong: bool = False
    languages: list[str] = field(default_factory=lambda: ["python"])
    use_regex: bool = True
    fixed_string: bool = False
    filter_definitions: bool = True
    result_key: str = ""

    @property
    def key(self) -> str:
        return self.result_key or self.name


_PYTHON_EXTS = {".py", ".pyi"}
_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_GO_EXTS = {".go"}
_JAVA_EXTS = {".java"}
_PHP_EXTS = {".php"}
_RUST_EXTS = {".rs"}
_DART_EXTS = {".dart"}

_ALL_SOURCE_GLOBS = [
    "*.py",
    "*.pyi",
    "*.ts",
    "*.tsx",
    "*.js",
    "*.jsx",
    "*.mjs",
    "*.cjs",
    "*.go",
    "*.java",
    "*.php",
    "*.rs",
    "*.dart",
    "*.rst",
    "*.md",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.cfg",
    "*.ini",
    "*.txt",
]

_LANG_GLOBS: dict[str, list[str]] = {
    "python": ["*.py", "*.pyi"],
    "typescript": ["*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs"],
    "go": ["*.go"],
    "java": ["*.java"],
    "php": ["*.php"],
    "rust": ["*.rs"],
    "dart": ["*.dart"],
}

_IGNORED_GREP_PATH_PARTS = (
    "/.git/",
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/.ruff_cache/",
    "/.skylos/",
    "/.venv/",
    "/venv/",
    "/__pycache__/",
    "/node_modules/",
    ".egg-info",
)
_GREP_EXCLUDE_DIRS = (
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".skylos",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "*.egg-info",
)



def detect_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _TS_EXTS:
        return "typescript"
    if ext in _GO_EXTS:
        return "go"
    if ext in _JAVA_EXTS:
        return "java"
    if ext in _PHP_EXTS:
        return "php"
    if ext in _RUST_EXTS:
        return "rust"
    if ext in _DART_EXTS:
        return "dart"
    return "python"


def _cached_group_results(
    cache: Any,
    group_name: str,
    finding: dict,
    search_fn: Callable[[], dict[str, list[str]]],
) -> dict[str, list[str]]:
    if cache is None or not group_name:
        return search_fn()

    from skylos.grep_cache import file_content_hash as _fch
    import json as _json

    simple_name = finding.get("simple_name", finding.get("name", ""))
    finding_file = finding.get("file", "")
    content_hash = _fch(finding_file) if finding_file else ""
    cache_key = (
        f"{_GREP_VERIFY_CACHE_VERSION}:group:{group_name}:"
        f"{simple_name}:{finding.get('full_name', '')}:"
        f"{finding.get('type', '')}:{content_hash}"
    )
    cached = cache.get(cache_key)
    if cached is not None:
        try:
            return _json.loads(cached[0]) if cached else {}
        except Exception:
            pass

    results = search_fn()
    try:
        cache.put(cache_key, [_json.dumps(results)])
    except Exception:
        pass
    return results


def source_globs_for_language(lang: str) -> list[str]:
    return _LANG_GLOBS.get(lang, _LANG_GLOBS["python"])


def _run_grep(
    pattern: str,
    project_root: str,
    use_regex: bool = False,
    include_globs: list[str] | None = None,
    fixed_string: bool = False,
    max_results: int = 20,
) -> list[str]:
    if include_globs is None:
        include_globs = [
            "*.py",
            "*.rst",
            "*.md",
            "*.yaml",
            "*.yml",
            "*.toml",
            "*.cfg",
            "*.ini",
            "*.txt",
        ]

    try:
        rg = shutil.which("rg")
        if rg:
            cmd = [
                rg,
                "-n",
                "--no-heading",
                "--color",
                "never",
                "--hidden",
                "--no-ignore",
            ]
            if fixed_string:
                cmd.append("-F")
            for g in include_globs:
                cmd.extend(["-g", g])
            for d in _GREP_EXCLUDE_DIRS:
                if any(ch in d for ch in "*?["):
                    cmd.extend(["-g", f"!**/{d}/**"])
                else:
                    cmd.extend(["-g", f"!**/{d}/**"])
            cmd.extend(["--", pattern, project_root])
        else:
            grep_flags = ["-rn"]
            if fixed_string:
                grep_flags.append("-F")
            elif use_regex:
                grep_flags.append("-E")

            includes = []
            for g in include_globs:
                includes.extend(["--include", g])
            excludes = []
            for d in _GREP_EXCLUDE_DIRS:
                excludes.extend(["--exclude-dir", d])

            cmd = ["grep", *grep_flags, *includes, *excludes, pattern, project_root]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().splitlines()
        filtered = []
        for line in lines:
            normalized = line.replace("\\", "/")
            if any(part in normalized for part in _IGNORED_GREP_PATH_PARTS):
                continue
            filtered.append(line)
        return filtered[:max_results]
    except Exception as e:
        logger.debug("grep failed for pattern %r: %s", pattern, e)
        return []


def repo_relative_path(file_path: str, project_root: str | Path) -> str:
    try:
        rel = Path(file_path).resolve().relative_to(Path(project_root).resolve())
        return rel.as_posix()
    except Exception:
        return Path(file_path).as_posix()


def module_candidates(file_path: str, project_root: str | Path) -> list[str]:
    rel = repo_relative_path(file_path, project_root)
    lang = detect_language(file_path)

    if lang == "python":
        if not rel.endswith(".py"):
            return []
        stem = rel[:-3]
        parts = [p for p in stem.split("/") if p]
        if not parts:
            return []
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return []
        candidates = [".".join(parts)]
        if parts[0] == "src" and len(parts) > 1:
            candidates.append(".".join(parts[1:]))
        return list(dict.fromkeys(candidates))

    elif lang == "typescript":
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
            if rel.endswith(ext):
                stem = rel[: -len(ext)]
                break
        else:
            return []
        parts = [p for p in stem.split("/") if p]
        if not parts:
            return []
        if parts[-1] == "index":
            parts = parts[:-1]
        if not parts:
            return []
        candidates = ["/".join(parts)]
        if parts[0] == "src" and len(parts) > 1:
            candidates.append("/".join(parts[1:]))
        candidates.append(".".join(parts))
        return list(dict.fromkeys(candidates))

    elif lang == "go":
        parts = [p for p in rel.split("/") if p]
        if parts:
            pkg_parts = parts[:-1] if len(parts) > 1 else parts
            return ["/".join(pkg_parts)]
        return []

    elif lang == "java":
        if not rel.endswith(".java"):
            return []
        stem = rel[:-5]
        parts = [p for p in stem.split("/") if p]
        if not parts:
            return []
        for prefix in ("src/main/java", "src/test/java", "src"):
            prefix_parts = prefix.split("/")
            if parts[: len(prefix_parts)] == prefix_parts:
                parts = parts[len(prefix_parts) :]
                break
        return [".".join(parts)] if parts else []

    elif lang == "php":
        if not rel.endswith(".php"):
            return []
        stem = rel[:-4]
        parts = [p for p in stem.split("/") if p]
        if not parts:
            return []
        if parts[0] in {"src", "app", "lib"} and len(parts) > 1:
            parts = parts[1:]
        return list(dict.fromkeys(["/".join(parts), ".".join(parts)]))

    elif lang == "rust":
        if not rel.endswith(".rs"):
            return []
        stem = rel[:-3]
        parts = [p for p in stem.split("/") if p]
        if not parts:
            return []
        if parts[-1] in ("mod", "lib", "main"):
            parts = parts[:-1]
        if parts and parts[0] == "src":
            parts = parts[1:]
        return ["::".join(parts)] if parts else []

    return []


def parameter_owner_name(finding: dict) -> str:
    if str(finding.get("type", "")).lower() != "parameter":
        return ""
    full_name = str(finding.get("full_name", finding.get("name", "")))
    if "." not in full_name:
        return ""
    return full_name.rsplit(".", 1)[0]


def is_definition_line(grep_line: str, finding: dict) -> bool:
    file_path = finding.get("file", "")
    line_num = finding.get("line", 0)

    if file_path and file_path in grep_line:
        try:
            parts = grep_line.split(":")
            if len(parts) >= 2 and parts[1].strip().isdigit():
                match_line = int(parts[1].strip())
                if abs(match_line - line_num) <= 2:
                    return True
        except (ValueError, IndexError):
            pass

    if ":" in grep_line:
        content = grep_line.split(":", 2)[-1]
    else:
        content = grep_line

    simple_name = finding.get("simple_name", "")
    definition_patterns = [
        # Python
        f"def {simple_name}",
        f"class {simple_name}",
        f"{simple_name} =",
        f'TypeVar("{simple_name}"',
        f"TypeVar('{simple_name}'",
        # TypeScript/JS
        f"function {simple_name}",
        f"const {simple_name}",
        f"let {simple_name}",
        f"var {simple_name}",
        f"interface {simple_name}",
        f"type {simple_name}",
        f"enum {simple_name}",
        f"export default function {simple_name}",
        f"export function {simple_name}",
        f"export const {simple_name}",
        f"export class {simple_name}",
        f"export interface {simple_name}",
        f"export type {simple_name}",
        # Go
        f"func {simple_name}",
        f"type {simple_name} struct",
        f"type {simple_name} interface",
        # Java
        f"public class {simple_name}",
        f"public interface {simple_name}",
        f"private void {simple_name}",
        f"public void {simple_name}",
        f"protected void {simple_name}",
        # PHP
        f"function {simple_name}",
        f"class {simple_name}",
        f"interface {simple_name}",
        f"trait {simple_name}",
        f"private function {simple_name}",
        f"public function {simple_name}",
        f"protected function {simple_name}",
        f"private ${simple_name}",
        f"public ${simple_name}",
        f"protected ${simple_name}",
        # Rust
        f"fn {simple_name}",
        f"pub fn {simple_name}",
        f"pub(crate) fn {simple_name}",
        f"struct {simple_name}",
        f"pub struct {simple_name}",
        f"trait {simple_name}",
        f"pub trait {simple_name}",
        f"impl {simple_name}",
    ]
    for pattern in definition_patterns:
        if pattern in content:
            return True

    return False


def filter_grep_results(
    lines: list[str],
    finding: dict,
) -> tuple[list[str], list[str]]:
    """Separate grep results into definitions and usages."""
    definitions = []
    usages = []
    for line in lines:
        if is_definition_line(line, finding):
            definitions.append(line)
        else:
            usages.append(line)
    return definitions, usages


def is_substring_match(grep_line: str, simple_name: str) -> bool:
    """Check if the match is a false positive due to substring matching."""
    if ":" in grep_line:
        content = grep_line.split(":", 2)[-1]
    else:
        content = grep_line

    for match in re.finditer(re.escape(simple_name), content):
        start, end = match.start(), match.end()
        before_ok = start == 0 or not content[start - 1].isalnum()
        after_ok = end == len(content) or not content[end].isalnum()
        if before_ok and after_ok:
            return False
    return True


def _grep_line_path(grep_line: str) -> str:
    parts = grep_line.split(":", 2)
    if len(parts) >= 2 and parts[1].strip().isdigit():
        return parts[0]
    return ""


def _grep_line_content(grep_line: str) -> str:
    parts = grep_line.split(":", 2)
    if len(parts) >= 3 and parts[1].strip().isdigit():
        return parts[2]
    return grep_line


def _python_line_has_name_token(grep_line: str, simple_name: str) -> bool:
    content = _grep_line_content(grep_line)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        return any(
            token.type == tokenize.NAME and token.string == simple_name
            for token in tokens
        )
    except tokenize.TokenError:
        return bool(re.search(rf"\b{re.escape(simple_name)}\b", content))


def _is_python_source_reference(grep_line: str, simple_name: str) -> bool:
    path = _grep_line_path(grep_line)
    if path and Path(path).suffix.lower() not in _PYTHON_EXTS:
        return False
    return _python_line_has_name_token(grep_line, simple_name)


def _deduplicate_grep_results(
    results: dict[str, list[str]],
) -> dict[str, list[str]]:
    deduped: dict[str, list[str]] = {}

    for strategy, lines in results.items():
        seen_in_strategy: set[str] = set()
        unique = []
        for line in lines:
            parts = line.split(":", 2)
            if len(parts) >= 2 and parts[1].strip().isdigit():
                key = f"{parts[0]}:{parts[1]}"
            else:
                key = line
            if key not in seen_in_strategy:
                seen_in_strategy.add(key)
                unique.append(line)
        if unique:
            deduped[strategy] = unique
        elif strategy in results and not lines:
            deduped[strategy] = lines
    return deduped


_STRONG_ALIVE_STRATEGIES = {
    "references",
    "method_calls",
    "imports",
    "qualified_references",
    "string_dispatch",
    "ts_imports",
    "ts_jsx_usage",
    "go_calls",
    "java_imports",
    "rust_use",
}

_MAX_RESULTS_PER_STRATEGY = 5
_DEFAULT_GREP_WORKERS = 4
_GREP_VERIFY_CACHE_VERSION = "v3"


def _deterministic_suppress_ts(finding: dict) -> bool:
    file_path = finding.get("file", "")
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")

    if any(marker in file_path for marker in (".test.", ".spec.", "__tests__/")):
        if kind in ("function", "class") and simple_name.startswith("test"):
            return True

    if file_path.endswith("index.ts") or file_path.endswith("index.js"):
        if kind == "import":
            return True

    return False


def _deterministic_suppress_go(finding: dict) -> bool:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    file_path = finding.get("file", "")

    if simple_name.startswith("Test") and file_path.endswith("_test.go"):
        return True

    return False


def _deterministic_suppress_java(finding: dict) -> bool:
    decorators = finding.get("decorators", [])
    if isinstance(decorators, list):
        for dec in decorators:
            if str(dec).strip() in (
                "@Test",
                "@Override",
                "@Bean",
                "@Autowired",
                "@Component",
            ):
                return True
    return False


def _deterministic_suppress_php(finding: dict) -> bool:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    file_path = str(finding.get("file", "")).lower()

    if simple_name in {"__construct", "__destruct", "__invoke", "__toString"}:
        return True

    if "/tests/" in file_path or file_path.endswith("test.php"):
        if simple_name.startswith("test") or simple_name in {"setUp", "tearDown"}:
            return True

    return False


def _deterministic_suppress_rust(finding: dict) -> bool:
    decorators = finding.get("decorators", [])

    if isinstance(decorators, list):
        for dec in decorators:
            dec_str = str(dec).strip()
            if dec_str in ("#[test]", "#[cfg(test)]", "#[derive"):
                return True

    if finding.get("type") == "method":
        full_name = finding.get("full_name", "")
        if "::impl::" in full_name or "::Impl::" in full_name:
            return True

    return False


def _deterministic_suppress_multilang(finding: dict) -> bool:
    lang = detect_language(finding.get("file", ""))
    if lang == "typescript":
        return _deterministic_suppress_ts(finding)
    elif lang == "go":
        return _deterministic_suppress_go(finding)
    elif lang == "java":
        return _deterministic_suppress_java(finding)
    elif lang == "php":
        return _deterministic_suppress_php(finding)
    elif lang == "rust":
        return _deterministic_suppress_rust(finding)
    return False


def _run_ts_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    ts_globs = _LANG_GLOBS["typescript"]

    if not simple_name or len(simple_name) <= 1:
        return results

    import_pattern = rf"import\s+.*\b{re.escape(simple_name)}\b"
    import_refs = _run_grep(
        import_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if import_refs:
        _defs, usages = filter_grep_results(import_refs, finding)
        if usages:
            results["ts_imports"] = usages[:max_per_strategy]

    require_pattern = rf'require\s*\(["\x27].*{re.escape(simple_name)}["\x27]\)'
    require_refs = _run_grep(
        require_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if require_refs:
        _defs, usages = filter_grep_results(require_refs, finding)
        if usages:
            results["ts_require"] = usages[:max_per_strategy]

    if kind in ("class", "function", "variable") and simple_name[0].isupper():
        jsx_pattern = rf"<{re.escape(simple_name)}[\s/>]"
        jsx_refs = _run_grep(
            jsx_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.tsx", "*.jsx"],
            max_results=max_per_strategy,
        )
        if jsx_refs:
            _defs, usages = filter_grep_results(jsx_refs, finding)
            if usages:
                results["ts_jsx_usage"] = usages[:max_per_strategy]

    # Barrel exports: export { X }
    export_pattern = rf"export\s*\{{[^}}]*\b{re.escape(simple_name)}\b"
    export_refs = _run_grep(
        export_pattern,
        project_root,
        use_regex=True,
        include_globs=ts_globs,
        max_results=max_per_strategy,
    )
    if export_refs:
        _defs, usages = filter_grep_results(export_refs, finding)
        if usages:
            results["ts_barrel_export"] = usages[:max_per_strategy]

    # Decorator usage: @Decorator
    if kind in ("class", "function"):
        dec_pattern = rf"@{re.escape(simple_name)}"
        dec_refs = _run_grep(
            dec_pattern,
            project_root,
            use_regex=True,
            include_globs=ts_globs,
            max_results=max_per_strategy,
        )
        if dec_refs:
            _defs, usages = filter_grep_results(dec_refs, finding)
            if usages:
                results["ts_decorator"] = usages[:max_per_strategy]

    if kind in ("class", "interface"):
        impl_pattern = rf"implements\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=ts_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["ts_implements"] = usages[:max_per_strategy]

    return results


def _run_go_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    go_globs = _LANG_GLOBS["go"]

    if not simple_name or len(simple_name) <= 1:
        return results

    call_pattern = rf"\b\w+\.{re.escape(simple_name)}\s*\("
    call_refs = _run_grep(
        call_pattern,
        project_root,
        use_regex=True,
        include_globs=go_globs,
        max_results=max_per_strategy,
    )
    if call_refs:
        _defs, usages = filter_grep_results(call_refs, finding)
        if usages:
            results["go_calls"] = usages[:max_per_strategy]

    if kind == "method":
        iface_pattern = rf"\b{re.escape(simple_name)}\s*\("
        iface_refs = _run_grep(
            iface_pattern,
            project_root,
            use_regex=True,
            include_globs=go_globs,
            max_results=max_per_strategy,
        )
        if iface_refs:
            _defs, usages = filter_grep_results(iface_refs, finding)
            if usages:
                results["go_interface_method"] = usages[:max_per_strategy]

    # Struct field references
    if kind in ("variable", "field"):
        field_pattern = rf"\.{re.escape(simple_name)}\b"
        field_refs = _run_grep(
            field_pattern,
            project_root,
            use_regex=True,
            include_globs=go_globs,
            max_results=max_per_strategy,
        )
        if field_refs:
            _defs, usages = filter_grep_results(field_refs, finding)
            if usages:
                results["go_field_refs"] = usages[:max_per_strategy]

    return results


def _run_java_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    java_globs = _LANG_GLOBS["java"]

    if not simple_name or len(simple_name) <= 1:
        return results

    import_pattern = rf"import\s+.*\b{re.escape(simple_name)}\b"
    import_refs = _run_grep(
        import_pattern,
        project_root,
        use_regex=True,
        include_globs=java_globs,
        max_results=max_per_strategy,
    )
    if import_refs:
        _defs, usages = filter_grep_results(import_refs, finding)
        if usages:
            results["java_imports"] = usages[:max_per_strategy]

    if kind == "method":
        override_pattern = rf"@Override.*\b{re.escape(simple_name)}\b"
        override_refs = _run_grep(
            override_pattern,
            project_root,
            use_regex=True,
            include_globs=java_globs,
            max_results=max_per_strategy,
        )
        if override_refs:
            results["java_override"] = override_refs[:max_per_strategy]

    # implements/extends
    if kind == "class":
        impl_pattern = rf"(?:implements|extends)\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=java_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["java_implements"] = usages[:max_per_strategy]

    spring_pattern = rf"@\w+.*\b{re.escape(simple_name)}\b"
    spring_refs = _run_grep(
        spring_pattern,
        project_root,
        use_regex=True,
        include_globs=java_globs,
        max_results=max_per_strategy,
    )
    if spring_refs:
        _defs, usages = filter_grep_results(spring_refs, finding)
        if usages:
            results["java_annotations"] = usages[:max_per_strategy]

    return results


def _run_rust_strategies(
    finding: dict,
    project_root: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    kind = finding.get("type", "")
    results: dict[str, list[str]] = {}
    rust_globs = _LANG_GLOBS["rust"]

    if not simple_name or len(simple_name) <= 1:
        return results

    use_pattern = rf"use\s+.*\b{re.escape(simple_name)}\b"
    use_refs = _run_grep(
        use_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if use_refs:
        _defs, usages = filter_grep_results(use_refs, finding)
        if usages:
            results["rust_use"] = usages[:max_per_strategy]

    if kind in ("class", "trait"):
        impl_pattern = rf"impl\s+.*\b{re.escape(simple_name)}\b"
        impl_refs = _run_grep(
            impl_pattern,
            project_root,
            use_regex=True,
            include_globs=rust_globs,
            max_results=max_per_strategy,
        )
        if impl_refs:
            _defs, usages = filter_grep_results(impl_refs, finding)
            if usages:
                results["rust_impl"] = usages[:max_per_strategy]

    derive_pattern = rf"#\[derive\([^)]*\b{re.escape(simple_name)}\b"
    derive_refs = _run_grep(
        derive_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if derive_refs:
        results["rust_derive"] = derive_refs[:max_per_strategy]

    pub_pattern = rf"\b{re.escape(simple_name)}\s*\("
    pub_refs = _run_grep(
        pub_pattern,
        project_root,
        use_regex=True,
        include_globs=rust_globs,
        max_results=max_per_strategy,
    )
    if pub_refs:
        _defs, usages = filter_grep_results(pub_refs, finding)
        if usages:
            results["rust_calls"] = usages[:max_per_strategy]

    return results


def parallel_multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> dict[str, list[str]]:
    simple_name = _finding_simple_name(finding)
    if not simple_name or len(simple_name) <= 1:
        return {}

    lang = _finding_language(finding)
    results: dict[str, list[str]] = {}
    results_lock = threading.Lock()
    early_exit_event = threading.Event()

    def _check_early_exit() -> bool:
        with results_lock:
            for strategy in _STRONG_ALIVE_STRATEGIES:
                if len(results.get(strategy, [])) >= early_exit_threshold:
                    return True
        return False

    def _run_strategy_group(
        run_fn: Callable[..., dict[str, list[str]]],
        group_name: str = "",
        *args: Any,
    ) -> None:
        if early_exit_event.is_set():
            return
        partial_results = _cached_group_results(
            cache,
            group_name,
            finding,
            lambda: run_fn(*args),
        )
        with results_lock:
            results.update(partial_results)
        if _check_early_exit():
            early_exit_event.set()

    tasks = _build_parallel_strategy_tasks(
        finding,
        project_root,
        simple_name=simple_name,
        lang=lang,
        max_per_strategy=max_per_strategy,
        early_exit_threshold=early_exit_threshold,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for run_fn, group_name in tasks:
            if early_exit_event.is_set():
                break
            futures.append(executor.submit(_run_strategy_group, run_fn, group_name))

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result(timeout=30)
            except Exception as e:
                logger.debug("Strategy group failed: %s", e)
            if early_exit_event.is_set():
                for f in futures:
                    f.cancel()
                break

    return _deduplicate_grep_results(results)


def multi_strategy_search(
    finding: dict,
    project_root: str,
    *,
    max_per_strategy: int = _MAX_RESULTS_PER_STRATEGY,
    early_exit_threshold: int = 5,
) -> dict[str, list[str]]:
    simple_name = finding.get("simple_name", finding.get("name", ""))
    full_name = finding.get("full_name", "")
    kind = finding.get("type", "")
    file_path = finding.get("file", "")

    if file_path:
        rel_file = repo_relative_path(file_path, project_root)
    else:
        rel_file = ""

    if file_path:
        module_names = module_candidates(file_path, project_root)
    else:
        module_names = []

    if kind == "parameter":
        owner_full_name = parameter_owner_name(finding)
    else:
        owner_full_name = ""

    if owner_full_name:
        owner_simple_name = owner_full_name.rsplit(".", 1)[-1]
    else:
        owner_simple_name = ""

    results: dict[str, list[str]] = {}

    if not simple_name or len(simple_name) <= 1:
        return results

    def _should_early_exit() -> bool:
        for strategy in _STRONG_ALIVE_STRATEGIES:
            hits = results.get(strategy, [])
            if len(hits) >= early_exit_threshold:
                return True
        return False

    boundary_pattern = rf"\b{simple_name}\b"
    if kind != "import":
        refs = _run_grep(
            boundary_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py", "*.pyi"],
            max_results=max_per_strategy * 2,
        )
        if refs:
            refs = [
                r
                for r in refs
                if not is_substring_match(r, simple_name)
                and _is_python_source_reference(r, simple_name)
            ]
            _defs, usages = filter_grep_results(refs, finding)
            if usages:
                results["references"] = usages[:max_per_strategy]
            elif _defs:
                results["references_definition_only"] = [
                    "(only the definition itself found, no usages)"
                ]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if full_name and full_name != simple_name:
        qualified_refs = _run_grep(
            rf"\b{re.escape(full_name)}\b",
            project_root,
            use_regex=True,
            max_results=max_per_strategy,
        )
        if qualified_refs:
            _defs, usages = filter_grep_results(qualified_refs, finding)
            if usages:
                results["qualified_references"] = usages[:max_per_strategy]

    if kind in ("method", "function"):
        call_pattern = rf"\.{re.escape(simple_name)}[[:space:]]*\("
        call_refs = _run_grep(
            call_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if call_refs:
            _defs, usages = filter_grep_results(call_refs, finding)
            if usages:
                results["method_calls"] = usages[:max_per_strategy]

    if kind != "import":
        import_pattern = rf"import.*\b{simple_name}\b"
        import_refs = _run_grep(
            import_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if import_refs:
            _defs, usages = filter_grep_results(import_refs, finding)
            if usages:
                results["imports"] = usages[:max_per_strategy]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    quote_chars = "\"'"
    dispatch_patterns = [
        rf"(getattr|setattr|hasattr|delattr)[[:space:]]*\([^,]+,[[:space:]]*[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]",
        rf"\[[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]\]",
        rf"\.[[:alnum:]_]+[[:space:]]*\([[:space:]]*[{quote_chars}]{re.escape(simple_name)}[{quote_chars}]",
        rf"[{quote_chars}]{re.escape(simple_name)}[{quote_chars}][[:space:]]*:[[:space:]]*[[:alnum:]_]+[[:space:]]*\(",
    ]
    for dp in dispatch_patterns:
        dp_refs = _run_grep(
            dp,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if dp_refs:
            dp_refs = [
                r
                for r in dp_refs
                if not any(pat in r for pat in ["TypeVar(", "TypeAlias", "Literal["])
            ]
            _defs, usages = filter_grep_results(dp_refs, finding)
            if usages:
                results["string_dispatch"] = usages[:max_per_strategy]
                break

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    all_refs = _run_grep(
        rf"__all__.*\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["*.py"],
        max_results=max_per_strategy,
    )
    if all_refs:
        results["exported_in_all"] = all_refs[:max_per_strategy]

    if kind in ("import", "variable", "class"):
        cast_pattern = rf'cast\(\s*["\x27]{simple_name}["\x27]'
        cast_refs = _run_grep(
            cast_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if cast_refs:
            _defs, usages = filter_grep_results(cast_refs, finding)
            if usages:
                results["cast_usage"] = usages[:max_per_strategy]

        bound_pattern = rf'bound\s*=\s*["\x27]{simple_name}["\x27]'
        bound_refs = _run_grep(
            bound_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if bound_refs:
            _defs, usages = filter_grep_results(bound_refs, finding)
            if usages:
                results["typevar_bound"] = usages[:max_per_strategy]

    elif kind == "method":
        method_parts = full_name.split(".")
        if len(method_parts) >= 2:
            parent_class = method_parts[-2]
            if len(parent_class) > 2:
                cast_pattern = rf"cast\([^,]+,\s*[^)]*\b{parent_class}\b"
                cast_refs = _run_grep(
                    cast_pattern,
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if cast_refs:
                    _defs, usages = filter_grep_results(cast_refs, finding)
                    if usages:
                        results["cast_protocol"] = usages[:max_per_strategy]

    test_refs = _run_grep(
        rf"\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["test_*.py", "*_test.py", "conftest.py"],
        max_results=max_per_strategy,
    )
    if test_refs:
        test_refs = [r for r in test_refs if not is_substring_match(r, simple_name)]
        _defs, test_usages = filter_grep_results(test_refs, finding)
        if test_usages:
            results["test_references"] = test_usages[:max_per_strategy]

    if _should_early_exit():
        return _deduplicate_grep_results(results)

    if rel_file and rel_file.endswith(".py"):
        file_refs = _run_grep(
            rel_file, project_root, fixed_string=True, max_results=max_per_strategy
        )
        if file_refs:
            _defs, usages = filter_grep_results(file_refs, finding)
            if usages:
                results["file_path_references"] = usages[:max_per_strategy]

        config_refs = _run_grep(
            rel_file,
            project_root,
            fixed_string=True,
            include_globs=["*.toml", "*.cfg", "*.ini", "*.yaml", "*.yml"],
            max_results=max_per_strategy,
        )
        if config_refs:
            _defs, usages = filter_grep_results(config_refs, finding)
            if usages:
                results["config_references"] = usages[:max_per_strategy]

    for module_name in module_names:
        module_refs = _run_grep(
            module_name, project_root, fixed_string=True, max_results=max_per_strategy
        )
        if module_refs:
            _defs, usages = filter_grep_results(module_refs, finding)
            if usages:
                results["module_references"] = usages[:max_per_strategy]
                break

    if kind == "parameter" and owner_simple_name:
        callback_pattern = (
            rf"callback\s*=\s*(?:[\w\.]+\.)*{re.escape(owner_simple_name)}\b"
        )
        callback_refs = _run_grep(
            callback_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy,
        )
        if callback_refs:
            results["callback_registrations"] = callback_refs[:max_per_strategy]

        def _parse_int(value):
            return int(value) if isinstance(value, (int, float)) else 0

        signature_pattern = rf"def\s+{re.escape(owner_simple_name)}\s*\([^)]*\b{re.escape(simple_name)}\b"
        signature_refs = _run_grep(
            signature_pattern,
            project_root,
            use_regex=True,
            include_globs=["*.py"],
            max_results=max_per_strategy * 2,
        )
        if signature_refs:
            override_refs = []
            line_num = _parse_int(finding.get("line", 0))
            for ref in signature_refs:
                parts = ref.split(":", 2)
                if len(parts) < 2 or not parts[1].isdigit():
                    continue
                match_file = parts[0]
                match_line = int(parts[1])
                if match_file == file_path and abs(match_line - line_num) <= 3:
                    continue
                override_refs.append(ref)
            if override_refs:
                results["signature_overrides"] = override_refs[:max_per_strategy]

    doc_refs = _run_grep(
        rf"\b{simple_name}\b",
        project_root,
        use_regex=True,
        include_globs=["*.rst", "*.md"],
        max_results=max_per_strategy * 2,
    )
    if doc_refs:
        doc_refs = [r for r in doc_refs if not is_substring_match(r, simple_name)]
        if doc_refs:
            compatibility_refs = [
                r
                for r in doc_refs
                if any(
                    keyword in r.lower()
                    for keyword in (
                        "reintroduced",
                        "restored",
                        "backward compatibility",
                        "backwards compatibility",
                        "compatibility",
                        "synonym",
                        "alias",
                        "shim",
                        "shortcut",
                    )
                )
            ]
            if compatibility_refs:
                results["compatibility_references"] = compatibility_refs[
                    :max_per_strategy
                ]
            sphinx_refs = [
                r
                for r in doc_refs
                if any(
                    pat in r
                    for pat in [
                        ":func:",
                        ":meth:",
                        ":class:",
                        ":attr:",
                        "autofunction",
                        "autoclass",
                        "automethod",
                        "automodule",
                        ".. function::",
                        ".. method::",
                    ]
                )
            ]
            if sphinx_refs:
                results["sphinx_directive"] = sphinx_refs[:max_per_strategy]
            else:
                results["doc_references"] = doc_refs[:max_per_strategy]

            if not simple_name.startswith("_"):
                changelog_patterns = [
                    "changelog",
                    "changes",
                    "history",
                    "news",
                    "release",
                ]
                api_refs = []
                for ref in doc_refs:
                    ref_path = ref.split(":", 1)[0].replace("\\", "/").lower()
                    in_docs_dir = (
                        ref_path.startswith("docs/")
                        or ref_path.startswith("doc/")
                        or "/docs/" in ref_path
                        or "/doc/" in ref_path
                    )
                    if not in_docs_dir:
                        continue
                    if any(pattern in ref_path for pattern in changelog_patterns):
                        continue
                    api_refs.append(ref)
                if api_refs:
                    results["public_api_docs"] = api_refs[:max_per_strategy]

    if kind == "method":
        parts = full_name.split(".")
        if len(parts) >= 2:
            class_name = parts[-2]
            if len(class_name) > 2:
                class_refs = _run_grep(
                    rf"\b{class_name}\b",
                    project_root,
                    use_regex=True,
                    include_globs=["*.py"],
                    max_results=max_per_strategy,
                )
                if class_refs:
                    usage_lines = []
                    for cr in class_refs:
                        if ":" in cr:
                            line_text = cr.split(":", 2)[-1]
                        else:
                            line_text = cr
                        if re.search(
                            rf"^\s*class\s+{re.escape(class_name)}", line_text
                        ):
                            continue
                        usage_lines.append(cr)
                    if usage_lines:
                        results["class_usage"] = usage_lines[:max_per_strategy]

    return _deduplicate_grep_results(results)


_DETERMINISTIC_RULES: list[tuple[str, str, str]] = [
    ("method_calls", "real_method_call", "Direct method-call usage found via grep"),
    ("imports", "imported_elsewhere", "Symbol is imported elsewhere in the project"),
    ("string_dispatch", "dynamic_dispatch", "Dynamic dispatch references this symbol"),
    ("qualified_references", "qualified_reference", "Qualified reference found"),
    ("test_references", "test_reference", "Tests reference this symbol"),
    ("config_references", "config_reference", "Referenced in config files"),
    ("cast_protocol", "protocol_required", "Cast to protocol type requires this"),
]


def _finding_simple_name(finding: dict) -> str:
    return finding.get("simple_name", finding.get("name", ""))


def _finding_full_name(finding: dict) -> str:
    return finding.get("full_name", finding.get("name", ""))


def _finding_language(finding: dict) -> str:
    return detect_language(finding.get("file", ""))


def _run_general_reference_strategies(
    finding: dict,
    project_root: str,
    *,
    simple_name: str,
    max_per_strategy: int,
) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    boundary = rf"\b{re.escape(simple_name)}\b"
    refs = _run_grep(
        boundary,
        project_root,
        use_regex=True,
        include_globs=_ALL_SOURCE_GLOBS,
        max_results=max_per_strategy * 2,
    )
    if refs:
        refs = [ref for ref in refs if not is_substring_match(ref, simple_name)]
        defs, usages = filter_grep_results(refs, finding)
        if usages:
            results["references"] = usages[:max_per_strategy]
        elif defs:
            results["references_definition_only"] = [
                "(only the definition itself found, no usages)"
            ]
    return results


def _build_parallel_strategy_tasks(
    finding: dict,
    project_root: str,
    *,
    simple_name: str,
    lang: str,
    max_per_strategy: int,
    early_exit_threshold: int,
) -> list[tuple[Callable[[], dict[str, list[str]]], str]]:
    tasks: list[tuple[Callable[[], dict[str, list[str]]], str]] = []

    if lang == "python":
        tasks.append(
            (
                lambda: multi_strategy_search(
                    finding,
                    project_root,
                    max_per_strategy=max_per_strategy,
                    early_exit_threshold=early_exit_threshold,
                ),
                "python_core",
            )
        )
    else:
        tasks.append(
            (
                lambda: _run_general_reference_strategies(
                    finding,
                    project_root,
                    simple_name=simple_name,
                    max_per_strategy=max_per_strategy,
                ),
                "general_refs",
            )
        )

    if lang == "typescript":
        tasks.append(
            (
                lambda: _run_ts_strategies(finding, project_root, max_per_strategy),
                "typescript",
            )
        )
    elif lang == "go":
        tasks.append(
            (
                lambda: _run_go_strategies(finding, project_root, max_per_strategy),
                "go",
            )
        )
    elif lang == "java":
        tasks.append(
            (
                lambda: _run_java_strategies(finding, project_root, max_per_strategy),
                "java",
            )
        )
    elif lang == "rust":
        tasks.append(
            (
                lambda: _run_rust_strategies(finding, project_root, max_per_strategy),
                "rust",
            )
        )

    return tasks


def _apply_deterministic_rules(
    search_results: dict[str, list[str]],
    finding: dict,
) -> GrepVerdict | None:
    refs = search_results.get("references", [])
    if refs:
        simple_name = finding.get("simple_name", "")
        filtered = (
            [r for r in refs if not is_substring_match(r, simple_name)]
            if simple_name
            else refs
        )
        if filtered:
            return GrepVerdict(
                alive=True,
                suppression_code="grep_reference",
                rationale="Grep found usage references in the project",
                evidence=filtered[:3],
            )

    if search_results.get("exported_in_all") and search_results.get("imports"):
        return GrepVerdict(
            alive=True,
            suppression_code="exported_in_all",
            rationale="Exported in __all__ and imported elsewhere",
            evidence=(
                search_results["exported_in_all"][:2] + search_results["imports"][:1]
            ),
        )

    for strategy_key, code, rationale in _DETERMINISTIC_RULES:
        if search_results.get(strategy_key):
            return GrepVerdict(
                alive=True,
                suppression_code=code,
                rationale=rationale,
                evidence=search_results[strategy_key][:3],
            )

    return None


def grep_verify_findings(
    findings: list[dict],
    project_root: str,
    time_budget: float = 30.0,
    *,
    parallel: bool = False,
    max_workers: int = _DEFAULT_GREP_WORKERS,
    cache: Any = None,
) -> dict[str, GrepVerdict]:
    verdicts: dict[str, GrepVerdict] = {}
    start_time = time.monotonic()
    search_fn = _build_grep_search_fn(
        project_root,
        parallel=False,
        max_workers=max_workers,
        cache=cache,
    )

    def process_finding(finding: dict) -> tuple[str, GrepVerdict | None]:
        full_name = _finding_full_name(finding)
        if not full_name:
            return "", None

        deterministic_verdict = _deterministic_suppression_verdict(finding)
        if deterministic_verdict:
            return full_name, deterministic_verdict

        search_results = search_fn(finding)
        return full_name, _apply_deterministic_rules(search_results, finding)

    verified_names = set(verdicts)
    remaining_findings = [
        finding
        for finding in findings
        if _finding_full_name(finding)
        and _finding_full_name(finding) not in verified_names
    ]

    if parallel:
        max_workers = max(1, int(max_workers or _DEFAULT_GREP_WORKERS))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        pending: set[concurrent.futures.Future] = set()
        findings_iter = iter(remaining_findings)

        def submit_next() -> bool:
            if time.monotonic() - start_time > time_budget:
                return False
            for finding in findings_iter:
                if not _finding_full_name(finding):
                    continue
                pending.add(executor.submit(process_finding, finding))
                return True
            return False

        try:
            for _ in range(max_workers):
                if not submit_next():
                    break

            while pending and time.monotonic() - start_time <= time_budget:
                remaining = max(0.0, time_budget - (time.monotonic() - start_time))
                done, pending = concurrent.futures.wait(
                    pending,
                    timeout=remaining,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                if not done:
                    break
                for future in done:
                    try:
                        full_name, verdict = future.result()
                    except Exception as e:
                        logger.debug("grep verification failed: %s", e)
                        continue
                    if full_name and verdict:
                        verdicts[full_name] = verdict
                    submit_next()
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

        return verdicts

    for finding in remaining_findings:
        if time.monotonic() - start_time > time_budget:
            break

        full_name, verdict = process_finding(finding)
        if verdict:
            verdicts[full_name] = verdict

    return verdicts


def _build_grep_search_fn(
    project_root: str,
    *,
    parallel: bool,
    max_workers: int,
    cache: Any,
) -> Callable[[dict], dict[str, list[str]]]:
    if parallel:

        def search_fn(finding: dict) -> dict[str, list[str]]:
            return parallel_multi_strategy_search(
                finding, project_root, max_workers=max_workers, cache=cache
            )

        return search_fn

    def search_fn(finding: dict) -> dict[str, list[str]]:
        if cache is None:
            return multi_strategy_search(finding, project_root)
        return _cached_serial_search_results(finding, project_root, cache)

    return search_fn


def _cached_serial_search_results(
    finding: dict, project_root: str, cache: Any
) -> dict[str, list[str]]:
    lang = _finding_language(finding)
    group_name = "python_core" if lang == "python" else f"serial_{lang}"
    return _cached_group_results(
        cache,
        group_name,
        finding,
        lambda: multi_strategy_search(finding, project_root),
    )


def _deterministic_suppression_verdict(finding: dict) -> GrepVerdict | None:
    if not _deterministic_suppress_multilang(finding):
        return None
    return GrepVerdict(
        alive=True,
        suppression_code="lang_deterministic",
        rationale=(
            "Language-specific deterministic suppression "
            f"({_finding_language(finding)})"
        ),
        evidence=[finding.get("file", "")],
    )
