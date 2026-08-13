from __future__ import annotations

import io
import logging
import re
import shutil
import subprocess
import time
import tokenize
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


_PYTHON_EXTS = {".py", ".pyi"}
_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_GO_EXTS = {".go"}
_JAVA_EXTS = {".java"}
_PHP_EXTS = {".php"}
_RUST_EXTS = {".rs"}
_DART_EXTS = {".dart"}
_KOTLIN_EXTS = {".kt", ".kts"}

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
    "*.kt",
    "*.kts",
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
    "kotlin": ["*.kt", "*.kts"],
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

_GREP_BATCH_SIZE = 128
# Python's classifier must preserve the same leftmost-first semantics as each
# original ripgrep pattern. Keep this translation deliberately narrow: an
# unsupported POSIX class falls back to the legacy one-pattern subprocess.
_PYTHON_REGEX_TRANSLATIONS = {
    "[[:space:]]": r"\s",
    "[[:alnum:]_]": r"[A-Za-z0-9_]",
}
_POSIX_CLASS = re.compile(r"\[\[:[^]]+:\]\]")


@dataclass(frozen=True, slots=True)
class GrepRequest:
    """One repository grep request."""

    pattern: str
    project_root: str
    use_regex: bool
    include_globs: tuple[str, ...]
    fixed_string: bool
    max_results: int


_GREP_REQUEST_RECORDER: ContextVar[list[GrepRequest] | None] = ContextVar(
    "grep_request_recorder", default=None
)
_GREP_RESULT_REPLAY: ContextVar[Mapping[GrepRequest, tuple[str, ...]] | None] = (
    ContextVar("grep_result_replay", default=None)
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
    if ext in _KOTLIN_EXTS:
        return "kotlin"
    return "python"


def source_globs_for_language(lang: str) -> list[str]:
    return _LANG_GLOBS.get(lang, _LANG_GLOBS["python"])


@contextmanager
def record_grep_requests() -> Iterator[list[GrepRequest]]:
    """Record grep requests without executing them."""
    requests: list[GrepRequest] = []
    token = _GREP_REQUEST_RECORDER.set(requests)
    try:
        yield requests
    finally:
        _GREP_REQUEST_RECORDER.reset(token)


@contextmanager
def replay_grep_results(
    results: Mapping[GrepRequest, tuple[str, ...]],
) -> Iterator[None]:
    """Replay previously collected grep results."""
    token = _GREP_RESULT_REPLAY.set(results)
    try:
        yield
    finally:
        _GREP_RESULT_REPLAY.reset(token)


def _default_grep_globs() -> tuple[str, ...]:
    return (
        "*.py",
        "*.rst",
        "*.md",
        "*.yaml",
        "*.yml",
        "*.toml",
        "*.cfg",
        "*.ini",
        "*.txt",
    )


def _make_grep_request(
    pattern: str,
    project_root: str,
    *,
    use_regex: bool,
    include_globs: list[str] | None,
    fixed_string: bool,
    max_results: int,
) -> GrepRequest:
    return GrepRequest(
        pattern=pattern,
        project_root=project_root,
        use_regex=use_regex,
        include_globs=(
            tuple(include_globs) if include_globs is not None else _default_grep_globs()
        ),
        fixed_string=fixed_string,
        max_results=max_results,
    )


def _ripgrep_command(request: GrepRequest, rg: str) -> list[str]:
    cmd = [
        rg,
        "-n",
        "--no-heading",
        "--color",
        "never",
        "--hidden",
        "--no-ignore",
    ]
    if request.fixed_string:
        cmd.append("-F")
    for glob in request.include_globs:
        cmd.extend(["-g", glob])
    for directory in _GREP_EXCLUDE_DIRS:
        cmd.extend(["-g", f"!**/{directory}/**"])
    return cmd


def _filter_grep_output(stdout: str) -> list[str]:
    filtered: list[str] = []
    for line in stdout.strip().splitlines():
        normalized = line.replace("\\", "/")
        if any(part in normalized for part in _IGNORED_GREP_PATH_PARTS):
            continue
        filtered.append(line)
    return filtered


def _run_grep_request(request: GrepRequest) -> list[str]:
    try:
        rg = shutil.which("rg")
        if rg:
            cmd = _ripgrep_command(request, rg)
            cmd.extend(["--", request.pattern, request.project_root])
        else:
            grep_flags = ["-rn"]
            if request.fixed_string:
                grep_flags.append("-F")
            elif request.use_regex:
                grep_flags.append("-E")

            includes: list[str] = []
            for glob in request.include_globs:
                includes.extend(["--include", glob])
            excludes: list[str] = []
            for directory in _GREP_EXCLUDE_DIRS:
                excludes.extend(["--exclude-dir", directory])

            cmd = [
                "grep",
                *grep_flags,
                *includes,
                *excludes,
                request.pattern,
                request.project_root,
            ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False
        )
        return _filter_grep_output(result.stdout)[: request.max_results]
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        logger.debug("grep failed for pattern %r: %s", request.pattern, exc)
        return []


def _python_regex(pattern: str) -> re.Pattern[str] | None:
    translated = pattern
    for source, replacement in _PYTHON_REGEX_TRANSLATIONS.items():
        translated = translated.replace(source, replacement)
    if _POSIX_CLASS.search(translated):
        return None
    try:
        return re.compile(translated)
    except re.error:
        return None


def _grep_line_sort_key(line: str) -> tuple[str, int, str]:
    parts = line.split(":", 2)
    if len(parts) >= 3 and parts[1].strip().isdigit():
        return parts[0].replace("\\", "/"), int(parts[1]), parts[2]
    return line.replace("\\", "/"), 0, ""


def _batch_group_key(request: GrepRequest) -> tuple[str, tuple[str, ...], bool]:
    return request.project_root, request.include_globs, request.fixed_string


def _run_ripgrep_batch(
    requests: Sequence[GrepRequest],
    rg: str,
    timeout: float,
) -> tuple[dict[GrepRequest, tuple[str, ...]], set[GrepRequest]]:
    representative = requests[0]
    cmd = _ripgrep_command(representative, rg)
    cmd.extend(["-f", "-", "--", representative.project_root])
    patterns = "\n".join(dict.fromkeys(request.pattern for request in requests))
    result = subprocess.run(
        cmd,
        input=f"{patterns}\n",
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode not in (0, 1):
        msg = result.stderr.strip() or f"exit status {result.returncode}"
        raise RuntimeError(msg)

    lines = sorted(_filter_grep_output(result.stdout), key=_grep_line_sort_key)
    line_contents = [(line, _grep_line_content(line)) for line in lines]
    compiled: dict[GrepRequest, re.Pattern[str]] = {}
    direct_requests: set[GrepRequest] = set()
    for request in requests:
        if request.fixed_string:
            continue
        pattern = _python_regex(request.pattern)
        if pattern is None:
            direct_requests.add(request)
        else:
            compiled[request] = pattern

    batch_results: dict[GrepRequest, tuple[str, ...]] = {}
    completed: set[GrepRequest] = set()
    for request in requests:
        if request in direct_requests:
            continue
        matches: list[str] = []
        if request.max_results <= 0:
            batch_results[request] = ()
            completed.add(request)
            continue
        regex = compiled.get(request)
        for line, content in line_contents:
            is_match = (
                request.pattern in content
                if request.fixed_string
                else regex is not None and regex.search(content) is not None
            )
            if not is_match:
                continue
            matches.append(line)
            if len(matches) >= request.max_results:
                break
        batch_results[request] = tuple(matches)
        completed.add(request)

    for request in direct_requests:
        batch_results[request] = tuple(_run_grep_request(request))
        completed.add(request)
    return batch_results, completed


def execute_grep_batch(
    requests: Sequence[GrepRequest],
    *,
    deadline: float,
) -> tuple[dict[GrepRequest, tuple[str, ...]], set[GrepRequest]]:
    """Execute compatible grep requests in fixed-size batches."""
    unique_requests = list(dict.fromkeys(requests))
    if not unique_requests:
        return {}, set()

    rg = shutil.which("rg")
    if not rg:
        results: dict[GrepRequest, tuple[str, ...]] = {}
        completed: set[GrepRequest] = set()
        for request in unique_requests:
            if time.monotonic() >= deadline:
                break
            results[request] = tuple(_run_grep_request(request))
            completed.add(request)
        return results, completed

    groups: dict[tuple[str, tuple[str, ...], bool], list[GrepRequest]] = {}
    for request in unique_requests:
        groups.setdefault(_batch_group_key(request), []).append(request)

    results: dict[GrepRequest, tuple[str, ...]] = {}
    completed: set[GrepRequest] = set()
    for group_requests in groups.values():
        for start in range(0, len(group_requests), _GREP_BATCH_SIZE):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return results, completed
            chunk = group_requests[start : start + _GREP_BATCH_SIZE]
            try:
                chunk_results, chunk_completed = _run_ripgrep_batch(
                    chunk, rg, min(30.0, remaining)
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                logger.debug("batched grep failed; using serial fallback: %s", exc)
                for request in chunk:
                    if time.monotonic() >= deadline:
                        return results, completed
                    results[request] = tuple(_run_grep_request(request))
                    completed.add(request)
            else:
                results.update(chunk_results)
                completed.update(chunk_completed)
    return results, completed


def _run_grep(
    pattern: str,
    project_root: str,
    use_regex: bool = False,
    include_globs: list[str] | None = None,
    fixed_string: bool = False,
    max_results: int = 20,
) -> list[str]:
    request = _make_grep_request(
        pattern,
        project_root,
        use_regex=use_regex,
        include_globs=include_globs,
        fixed_string=fixed_string,
        max_results=max_results,
    )
    recorder = _GREP_REQUEST_RECORDER.get()
    if recorder is not None:
        recorder.append(request)
        return []

    replay = _GREP_RESULT_REPLAY.get()
    if replay is not None:
        return list(replay.get(request, ()))[:max_results]

    return _run_grep_request(request)


def repo_relative_path(file_path: str, project_root: str | Path) -> str:
    try:
        rel = Path(file_path).resolve().relative_to(Path(project_root).resolve())
        return rel.as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        logger.debug(
            "Failed to compute repo-relative path for %s under %s: %s",
            file_path,
            project_root,
            exc,
        )
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

    elif lang == "kotlin":
        if rel.endswith(".kts"):
            stem = rel[:-4]
        elif rel.endswith(".kt"):
            stem = rel[:-3]
        else:
            return []
        parts = [p for p in stem.split("/") if p]
        for prefix in ("src/main/kotlin", "src/test/kotlin", "src"):
            prefix_parts = prefix.split("/")
            if parts[: len(prefix_parts)] == prefix_parts:
                parts = parts[len(prefix_parts) :]
                break
        return [".".join(parts)] if parts else []

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
        # Kotlin
        f"fun {simple_name}",
        f"private fun {simple_name}",
        f"class {simple_name}",
        f"object {simple_name}",
        f"interface {simple_name}",
        f"enum class {simple_name}",
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
