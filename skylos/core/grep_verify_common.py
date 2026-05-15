from __future__ import annotations

import io
import logging
import re
import shutil
import subprocess
import tokenize
from pathlib import Path

logger = logging.getLogger(__name__)


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


def _method_owner_simple(finding: dict) -> str:
    full_name = str(finding.get("full_name", finding.get("name", "")))
    parts = full_name.split(".")
    if len(parts) < 3:
        return ""
    return parts[-2]


def _called_owner_method_names(finding: dict) -> set[tuple[str, str]]:
    calls = finding.get("calls", []) or []
    if not isinstance(calls, list):
        return set()

    out: set[tuple[str, str]] = set()
    for call in calls:
        parts = str(call).split(".")
        if len(parts) >= 2:
            out.add((parts[-2], parts[-1]))
    return out


def _is_other_owner_same_method_call(grep_line: str, finding: dict) -> bool:
    if str(finding.get("type", "")).lower() != "method":
        return False

    simple_name = str(finding.get("simple_name", finding.get("name", "")))
    owner = _method_owner_simple(finding)
    if not simple_name or not owner:
        return False

    content = _grep_line_content(grep_line)
    for call_owner, call_name in _called_owner_method_names(finding):
        if call_name != simple_name or call_owner == owner:
            continue
        pattern = rf"\b{re.escape(call_owner)}\.{re.escape(simple_name)}\s*\("
        if re.search(pattern, content):
            return True
    return False


def _filter_other_owner_same_method_calls(lines: list[str], finding: dict) -> list[str]:
    return [
        line for line in lines if not _is_other_owner_same_method_call(line, finding)
    ]


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
