from __future__ import annotations

import io
import json
import logging
import ntpath
import os
import re
import shutil
import subprocess
import threading
import time
import tokenize
import unicodedata
from bisect import bisect_right
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
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
_GREP_BATCH_TIMEOUT_SECONDS = 30.0
_GREP_REQUEST_TIMEOUT_SECONDS = 10.0
_GREP_BATCH_MAX_PATTERN_BYTES = 64 * 1024
_GREP_BATCH_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_GREP_BATCH_MAX_STDERR_BYTES = 128 * 1024
_GREP_BATCH_MAX_MATCHES = _GREP_BATCH_SIZE * 256
_GREP_STREAM_MAX_RETAINED_BYTES = _GREP_BATCH_MAX_OUTPUT_BYTES
_GREP_UNICODE_MAX_INPUT_BYTES = 512 * 1024
# Every request in a bounded batch must receive the same Unicode-boundary
# adjudication. Skipping later requests makes a successful batch partial and
# forces the analyzer to abstain from all grep-verified dead-code candidates.
_GREP_UNICODE_MAX_ADJUDICATIONS = _GREP_BATCH_SIZE
_GREP_PIPE_READ_BYTES = 64 * 1024
_GREP_PROCESS_CLEANUP_SECONDS = 0.25
# Classification precedes strategy-specific definition filtering. Keep a
# wider deterministic window so early definitions do not crowd out usages.
_GREP_BATCH_RESULT_FLOOR = 256
_DEFAULT_GREP_GLOBS = (
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
_GREP_EVIDENCE_SUFFIXES = frozenset(
    {glob[1:].lower() for glob in _ALL_SOURCE_GLOBS if glob.startswith("*.")}
    | {".go", ".java", ".php", ".rs", ".dart", ".kt", ".kts"}
)
# Python's classifier must preserve the same leftmost-first semantics as each
# original ripgrep pattern. Keep this translation deliberately narrow: an
# unsupported POSIX class falls back to the legacy one-pattern subprocess.
_PYTHON_REGEX_TRANSLATIONS = {
    "[[:space:]]": r"[ \t\n\r\f\v]",
    "[[:alnum:]_]": r"[A-Za-z0-9_]",
}
_POSIX_CLASS = re.compile(r"\[\[:[^]]+:\]\]")
_UNICODE_WORD_PATTERN = re.compile(r"\\[bBwW]")
_UNICODE_CASE_INSENSITIVE_PATTERN = re.compile(r"\(\?[a-z-]*i")
_ENGINE_SENSITIVE_SPACE_PATTERN = re.compile(r"\\[sS]")
_UNESCAPED_ALTERNATION_PATTERN = re.compile(r"(?<!\\)(?:\\\\)*\|")
# Python's re \s matches U+001C-U+001F; ripgrep's Unicode White_Space \s does
# not. Those four characters are the complete divergence in both directions.
_ENGINE_DIVERGENT_SPACE_CHARS = ("\x1c", "\x1d", "\x1e", "\x1f")
_MAX_GREP_LINE_NUMBER = 999_999_999
_MAX_GREP_LINE_CANDIDATES = 256
_GREP_LINE_NUMBER = re.compile(r":([1-9][0-9]{0,8}):")
_HOST_PATH_CASE_INSENSITIVE = os.name == "nt"


@dataclass(frozen=True, slots=True)
class GrepRequest:
    """One repository grep request."""

    pattern: str
    project_root: str
    use_regex: bool
    include_globs: tuple[str, ...]
    fixed_string: bool
    max_results: int
    project_root_is_file: bool = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Remember single-file roots before a later filesystem race."""
        try:
            is_file = Path(self.project_root).is_file()
        except OSError:
            is_file = False
        object.__setattr__(self, "project_root_is_file", is_file)


class _GrepEvidence(str):
    """Legacy evidence text carrying unambiguous structured match fields."""

    __slots__ = ("path", "line_number", "content")

    def __new__(
        cls, path: str, line_number: int, content: str
    ) -> _GrepEvidence:
        value = super().__new__(cls, f"{path}:{line_number}:{content}")
        value.path = path
        value.line_number = line_number
        value.content = content
        return value

    def __reduce__(self) -> tuple[object, tuple[str, int, str]]:
        return (
            _GrepEvidence,
            (self.path, self.line_number, self.content),
        )


@dataclass(frozen=True, slots=True)
class _GrepMatch:
    path: str
    line_number: int
    content: str
    evidence: _GrepEvidence = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence",
            _GrepEvidence(self.path, self.line_number, self.content),
        )

    def legacy_line(self) -> _GrepEvidence:
        return self.evidence


@dataclass(frozen=True, slots=True)
class _BoundedProcessResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(slots=True)
class _BoundedProcessState:
    overflow: threading.Event = field(default_factory=threading.Event)
    stderr_overflow: threading.Event = field(default_factory=threading.Event)
    captured: dict[str, list[bytes]] = field(
        default_factory=lambda: {"stdout": [], "stderr": []}
    )
    thread_errors: list[BaseException] = field(default_factory=list)
    readers: list[threading.Thread] = field(default_factory=list)
    writer: threading.Thread | None = None
    started_threads: list[threading.Thread] = field(default_factory=list)
    timed_out: bool = False


@dataclass(slots=True)
class _StreamedGrepState:
    requests: tuple[GrepRequest, ...]
    matches: dict[GrepRequest, list[_GrepMatch]]
    regexes: dict[GrepRequest, re.Pattern[str] | None]
    deadline: float | None
    trust_ripgrep_attribution: bool = False
    requests_requiring_exact_search: set[GrepRequest] = field(default_factory=set)
    incomplete_requests: set[GrepRequest] = field(default_factory=set)
    retained_counts: dict[int, int] = field(default_factory=dict)
    retained_bytes: int = 0


class _GrepExecutionIncomplete(RuntimeError):
    """A bounded grep operation did not produce a complete result."""


class _GrepDeadlineExceeded(_GrepExecutionIncomplete):
    """The shared grep verification deadline was exhausted."""


class _GrepOutputLimitExceeded(_GrepExecutionIncomplete):
    """A grep operation exceeded its bounded output allowance."""


class _GrepInputLimitExceeded(_GrepExecutionIncomplete):
    """A grep operation exceeded its bounded input allowance."""


class _GrepBatchRejected(RuntimeError):
    """Ripgrep rejected a combined pattern batch."""


class _GrepBatchResults(dict[GrepRequest, tuple[str, ...]]):
    """Completed and conservative partial results from one grep execution."""

    def __init__(self) -> None:
        super().__init__()
        self.incomplete_requests: set[GrepRequest] = set()

    def merge(self, other: Mapping[GrepRequest, tuple[str, ...]]) -> None:
        self.update(other)
        self.incomplete_requests.update(
            getattr(other, "incomplete_requests", ())
        )


_GREP_REQUEST_RECORDER: ContextVar[list[GrepRequest] | None] = ContextVar(
    "grep_request_recorder", default=None
)
_GREP_RESULT_REPLAY: ContextVar[Mapping[GrepRequest, tuple[str, ...]] | None] = (
    ContextVar("grep_result_replay", default=None)
)
_GREP_REPLAY_DEADLINE: ContextVar[float | None] = ContextVar(
    "grep_replay_deadline", default=None
)
_GREP_EXECUTION_DEADLINE: ContextVar[float | None] = ContextVar(
    "grep_execution_deadline", default=None
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
    *,
    deadline: float | None = None,
) -> Iterator[None]:
    """Replay previously collected grep results."""
    replay_token = _GREP_RESULT_REPLAY.set(results)
    deadline_token = _GREP_REPLAY_DEADLINE.set(deadline)
    try:
        yield
    finally:
        _GREP_REPLAY_DEADLINE.reset(deadline_token)
        _GREP_RESULT_REPLAY.reset(replay_token)


@contextmanager
def grep_execution_deadline(deadline: float | None) -> Iterator[None]:
    """Apply one absolute deadline to direct grep calls in this context."""
    token = _GREP_EXECUTION_DEADLINE.set(deadline)
    try:
        yield
    finally:
        _GREP_EXECUTION_DEADLINE.reset(token)


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
            tuple(include_globs) if include_globs is not None else _DEFAULT_GREP_GLOBS
        ),
        fixed_string=fixed_string,
        max_results=max_results,
    )


def _ripgrep_command(request: GrepRequest, rg: str) -> list[str]:
    cmd = [
        rg,
        "--no-config",
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


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _trusted_which(
    executable: str,
    project_roots: Sequence[str] = (),
) -> str | None:
    """Resolve a backend without ever executing one supplied by target code."""
    candidate = shutil.which(executable)
    if not candidate:
        return None
    try:
        candidate_path = Path(candidate)
        absolute_candidate = (
            candidate_path
            if candidate_path.is_absolute()
            else Path.cwd() / candidate_path
        )
        resolved_candidate = candidate_path.resolve()
        current_directory = Path.cwd().resolve()
        untrusted_roots = []
        if not project_roots:
            untrusted_roots.append(current_directory)
        for root in project_roots:
            resolved_root = Path(root).resolve()
            untrusted_roots.append(
                resolved_root.parent if resolved_root.is_file() else resolved_root
            )
    except (OSError, RuntimeError):
        return None
    directly_from_cwd = (
        not candidate_path.is_absolute()
        or absolute_candidate.parent == current_directory
    )
    if directly_from_cwd or any(
        _path_is_within(candidate, root)
        for root in untrusted_roots
        for candidate in (absolute_candidate, resolved_candidate)
    ):
        logger.warning(
            "Ignoring %s executable resolved inside an untrusted directory: %s",
            executable,
            resolved_candidate,
        )
        return None
    return str(resolved_candidate)


def _request_trust_root(request: GrepRequest) -> str:
    """Return the directory whose contents may control backend resolution."""
    if request.project_root_is_file:
        return os.path.dirname(os.path.abspath(request.project_root))
    return request.project_root


def _deadline_expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _remaining_timeout(deadline: float | None, maximum: float) -> float:
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _GrepDeadlineExceeded("grep verification deadline exceeded")
    return min(maximum, remaining)


def _looks_like_source_path(path: str) -> bool:
    filename = path.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    return suffix in _GREP_EVIDENCE_SUFFIXES


def _split_grep_evidence(line: str) -> tuple[str, int | None, str]:
    if isinstance(line, _GrepEvidence):
        return line.path, line.line_number, line.content

    selected = None
    fallback = None
    for index, candidate in enumerate(_GREP_LINE_NUMBER.finditer(line)):
        if fallback is None:
            fallback = candidate
        if _looks_like_source_path(line[: candidate.start()]):
            selected = candidate
            break
        if index + 1 >= _MAX_GREP_LINE_CANDIDATES:
            break
    selected = selected or fallback
    if selected is None:
        return "", None, line
    return (
        line[: selected.start()],
        int(selected.group(1)),
        line[selected.end() :],
    )


def _is_ignored_grep_path(path: str) -> bool:
    components = [
        component
        for component in path.replace("\\", "/").split("/")
        if component
    ]
    ignored_names = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".skylos",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
    }
    return any(
        component in ignored_names or component.endswith(".egg-info")
        for component in components
    )


def _filter_null_grep_output(stdout: str) -> list[str]:
    filtered: list[str] = []
    output = stdout.strip("\r\n")
    if not output:
        return filtered
    for raw_line in output.split("\n"):
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        path, separator, remainder = line.partition("\0")
        line_text, number_separator, content = remainder.partition(":")
        if (
            not separator
            or not number_separator
            or not line_text.isdigit()
            or len(line_text) > 9
        ):
            raise _GrepExecutionIncomplete("grep emitted malformed null output")
        evidence = _GrepEvidence(path, int(line_text), content)
        if not _is_ignored_grep_path(path):
            filtered.append(evidence)
    return filtered


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    cleanup_deadline = time.monotonic() + _GREP_PROCESS_CLEANUP_SECONDS
    try:
        process.terminate()
        process.wait(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            remaining = max(0.0, cleanup_deadline - time.monotonic())
            if remaining:
                process.wait(timeout=remaining)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _open_grep_process(cmd: Sequence[str]) -> subprocess.Popen[bytes]:
    executable = Path(cmd[0])
    if not executable.is_absolute():
        raise _GrepExecutionIncomplete(
            "grep subprocess executable was not fully qualified"
        )
    return subprocess.Popen(
        list(cmd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(executable.parent),
    )


def _read_bounded_process_pipe(
    process: subprocess.Popen[bytes],
    name: str,
    limit: int,
    state: _BoundedProcessState,
) -> None:
    pipe = process.stdout if name == "stdout" else process.stderr
    assert pipe is not None
    total = 0
    try:
        while chunk := pipe.read(_GREP_PIPE_READ_BYTES):
            total += len(chunk)
            if total > limit:
                state.overflow.set()
                if name == "stderr":
                    state.stderr_overflow.set()
                _terminate_process(process)
                return
            state.captured[name].append(chunk)
    except (OSError, ValueError) as exc:
        state.thread_errors.append(exc)


def _write_bounded_process_input(
    process: subprocess.Popen[bytes],
    encoded_input: bytes,
    state: _BoundedProcessState,
) -> None:
    pipe = process.stdin
    assert pipe is not None
    try:
        pipe.write(encoded_input)
        pipe.flush()
    except (BrokenPipeError, OSError, ValueError) as exc:
        if process.poll() is None:
            state.thread_errors.append(exc)
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def _bounded_process_threads(
    process: subprocess.Popen[bytes],
    encoded_input: bytes,
    state: _BoundedProcessState,
) -> None:
    state.readers = [
        threading.Thread(
            target=_read_bounded_process_pipe,
            args=(
                process,
                "stdout",
                _GREP_BATCH_MAX_OUTPUT_BYTES,
                state,
            ),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_process_pipe,
            args=(
                process,
                "stderr",
                _GREP_BATCH_MAX_STDERR_BYTES,
                state,
            ),
            daemon=True,
        ),
    ]
    state.writer = threading.Thread(
        target=_write_bounded_process_input,
        args=(process, encoded_input, state),
        daemon=True,
    )


def _cleanup_bounded_process(
    process: subprocess.Popen[bytes],
    started_threads: Sequence[threading.Thread],
) -> None:
    cleanup_deadline = time.monotonic() + _GREP_PROCESS_CLEANUP_SECONDS
    if process.poll() is None:
        _terminate_process(process)
    for thread in started_threads:
        thread.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is None:
            continue
        try:
            pipe.close()
        except (OSError, ValueError):
            pass
    for thread in started_threads:
        if thread.is_alive():
            thread.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))


def _run_bounded_process_workers(
    process: subprocess.Popen[bytes],
    state: _BoundedProcessState,
    timeout: float,
) -> None:
    writer = state.writer
    assert writer is not None
    try:
        for thread in state.readers:
            thread.start()
            state.started_threads.append(thread)
        writer.start()
        state.started_threads.append(writer)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            state.timed_out = True
    except RuntimeError as exc:
        raise _GrepExecutionIncomplete(
            "grep subprocess worker could not start"
        ) from exc
    finally:
        _cleanup_bounded_process(process, state.started_threads)


def _raise_for_bounded_process_failure(
    cmd: Sequence[str],
    timeout: float,
    state: _BoundedProcessState,
) -> None:
    writer = state.writer
    assert writer is not None
    if writer.is_alive() or any(thread.is_alive() for thread in state.readers):
        raise _GrepExecutionIncomplete("ripgrep pipe did not close cleanly")
    if state.timed_out:
        raise subprocess.TimeoutExpired(list(cmd), timeout)
    if state.stderr_overflow.is_set():
        raise _GrepExecutionIncomplete(
            "ripgrep stderr exceeded its size limit"
        )
    if state.overflow.is_set():
        raise _GrepOutputLimitExceeded("ripgrep output exceeded its size limit")
    if state.thread_errors:
        raise OSError(str(state.thread_errors[0]))


def _run_bounded_subprocess(
    cmd: Sequence[str],
    *,
    input_text: str,
    timeout: float,
    input_limit: int = _GREP_BATCH_MAX_PATTERN_BYTES,
) -> _BoundedProcessResult:
    """Run ripgrep with bounded stdin/stdout/stderr memory and wall time."""
    encoded_input = input_text.encode("utf-8")
    if len(encoded_input) > input_limit:
        raise _GrepInputLimitExceeded("grep subprocess input is too large")

    process = _open_grep_process(cmd)
    state = _BoundedProcessState()
    _bounded_process_threads(process, encoded_input, state)
    _run_bounded_process_workers(process, state, timeout)
    _raise_for_bounded_process_failure(cmd, timeout, state)

    return _BoundedProcessResult(
        returncode=process.returncode,
        stdout=b"".join(state.captured["stdout"]).decode("utf-8"),
        stderr=b"".join(state.captured["stderr"]).decode("utf-8"),
    )


def _grep_fallback_command(
    request: GrepRequest,
    grep: str,
    target: str,
) -> list[str]:
    grep_flags = ["-rn", "--null"]
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
    return [
        grep,
        *grep_flags,
        *includes,
        *excludes,
        "-e",
        request.pattern,
        "--",
        target,
    ]


def _direct_grep_command(request: GrepRequest) -> tuple[list[str], bool]:
    trust_root = _request_trust_root(request)
    target = os.path.abspath(request.project_root)
    rg = _trusted_which("rg", (trust_root,))
    if rg:
        command = _ripgrep_command(request, rg)
        command.extend(["--json", "--", request.pattern, target])
        return command, True

    grep = _trusted_which("grep", (trust_root,))
    if not grep:
        raise _GrepExecutionIncomplete("no grep executable is available")
    return _grep_fallback_command(request, grep, target), False


def _direct_grep_results(
    request: GrepRequest,
    result: _BoundedProcessResult,
    *,
    used_ripgrep: bool,
    deadline: float | None,
) -> list[str]:
    if result.returncode not in (0, 1):
        message = result.stderr.strip() or f"exit status {result.returncode}"
        raise _GrepExecutionIncomplete(message)
    if used_ripgrep:
        matches = _parse_ripgrep_json_matches(result.stdout, deadline=deadline)
        return [match.legacy_line() for match in matches[: request.max_results]]
    return _filter_null_grep_output(result.stdout)[: request.max_results]


def _run_grep_request(
    request: GrepRequest,
    *,
    deadline: float | None = None,
    require_complete: bool = False,
) -> list[str]:
    try:
        cmd, used_ripgrep = _direct_grep_command(request)
        result = _run_bounded_subprocess(
            cmd,
            input_text="",
            timeout=_remaining_timeout(deadline, _GREP_REQUEST_TIMEOUT_SECONDS),
        )
        return _direct_grep_results(
            request,
            result,
            used_ripgrep=used_ripgrep,
            deadline=deadline,
        )
    except subprocess.TimeoutExpired as exc:
        logger.debug("grep timed out for pattern %r: %s", request.pattern, exc)
        if deadline is not None or require_complete:
            raise _GrepExecutionIncomplete("direct grep request timed out") from exc
        return []
    except _GrepExecutionIncomplete as exc:
        logger.debug("grep was incomplete for pattern %r: %s", request.pattern, exc)
        if deadline is not None or require_complete:
            raise
        return []
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
        logger.debug("grep failed for pattern %r: %s", request.pattern, exc)
        if deadline is not None or require_complete:
            raise _GrepExecutionIncomplete("direct grep request failed") from exc
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


def _grep_match_sort_key(match: _GrepMatch) -> tuple[str, int, str]:
    return match.path.replace("\\", "/"), match.line_number, match.content


def _remove_one_line_ending(content: str) -> str:
    if content.endswith("\r\n"):
        return content[:-2]
    if content.endswith(("\n", "\r")):
        return content[:-1]
    return content


def _ripgrep_json_text(value: object, field_name: str) -> str:
    if not isinstance(value, dict) or not isinstance(value.get("text"), str):
        raise ValueError(f"ripgrep match has non-text {field_name}")
    return value["text"]


def _load_ripgrep_json_event(raw_line: str) -> dict[str, object]:
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise ValueError("ripgrep emitted malformed JSON") from exc
    if not isinstance(event, dict):
        raise ValueError("ripgrep emitted a non-object JSON event")
    return event


def _ripgrep_line_number(data: Mapping[str, object]) -> int:
    line_number = data.get("line_number")
    if (
        not isinstance(line_number, int)
        or isinstance(line_number, bool)
        or line_number <= 0
        or line_number > _MAX_GREP_LINE_NUMBER
    ):
        raise ValueError("ripgrep match has an invalid line number")
    return line_number


def _ripgrep_match_from_event(event: Mapping[str, object]) -> _GrepMatch | None:
    if event.get("type") != "match":
        return None
    data = event.get("data")
    if not isinstance(data, dict):
        raise ValueError("ripgrep match has no data object")
    path = _ripgrep_json_text(data.get("path"), "path")
    content = _remove_one_line_ending(
        _ripgrep_json_text(data.get("lines"), "lines")
    )
    return _GrepMatch(
        path=path,
        line_number=_ripgrep_line_number(data),
        content=content,
    )


def _parse_ripgrep_json_matches(
    stdout: str,
    *,
    deadline: float | None,
) -> list[_GrepMatch]:
    matches: list[_GrepMatch] = []
    for index, raw_line in enumerate(stdout.split("\n")):
        if index % 256 == 0 and _deadline_expired(deadline):
            raise _GrepDeadlineExceeded("deadline exceeded while parsing ripgrep")
        if not raw_line:
            continue
        match = _ripgrep_match_from_event(_load_ripgrep_json_event(raw_line))
        if match is None or _is_ignored_grep_path(match.path):
            continue
        matches.append(match)
        if len(matches) > _GREP_BATCH_MAX_MATCHES:
            raise _GrepOutputLimitExceeded("ripgrep emitted too many matches")
    return sorted(matches, key=_grep_match_sort_key)


def _ripgrep_pattern_file_command(
    request: GrepRequest,
    rg: str,
) -> list[str]:
    cmd = _ripgrep_command(request, rg)
    cmd.extend(
        [
            "--json",
            "-f",
            "-",
            "--",
            os.path.abspath(request.project_root),
        ]
    )
    return cmd


def _grep_pattern_input(requests: Sequence[GrepRequest]) -> str:
    patterns = "\n".join(dict.fromkeys(request.pattern for request in requests))
    return f"{patterns}\n"


def _release_streamed_match(
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> None:
    match_id = id(match)
    count = state.retained_counts[match_id]
    if count > 1:
        state.retained_counts[match_id] = count - 1
        return
    del state.retained_counts[match_id]
    state.retained_bytes -= len(match.evidence.encode("utf-8"))


def _retain_streamed_match(
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> None:
    match_id = id(match)
    count = state.retained_counts.get(match_id, 0)
    if count == 0:
        match_bytes = len(match.evidence.encode("utf-8"))
        if state.retained_bytes + match_bytes > _GREP_STREAM_MAX_RETAINED_BYTES:
            raise _GrepOutputLimitExceeded(
                "streamed ripgrep evidence exceeded its retained-data limit"
            )
        state.retained_bytes += match_bytes
    state.retained_counts[match_id] = count + 1


def _insert_streamed_match(
    request: GrepRequest,
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> None:
    limit = max(request.max_results, _GREP_BATCH_RESULT_FLOOR)
    if limit <= 0:
        return

    retained = state.matches[request]
    match_key = _grep_match_sort_key(match)
    if len(retained) >= limit:
        if match_key >= _grep_match_sort_key(retained[-1]):
            return
        removed = retained.pop()
        _release_streamed_match(removed, state)

    _retain_streamed_match(match, state)
    retained.insert(
        bisect_right(retained, match_key, key=_grep_match_sort_key),
        match,
    )


def _literal_regex_fragment(body: str) -> str | None:
    literal: list[str] = []
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\":
            index += 1
            if index >= len(body) or body[index].isalnum():
                return None
            literal.append(body[index])
        elif character.isalnum() or character == "_":
            literal.append(character)
        else:
            return None
        index += 1
    return "".join(literal) or None


def _required_trailing_boundary_literal(pattern: str) -> str | None:
    if (
        not pattern.endswith(r"\b")
        or _UNICODE_CASE_INSENSITIVE_PATTERN.search(pattern)
        or _UNESCAPED_ALTERNATION_PATTERN.search(pattern)
    ):
        return None
    boundary_start = pattern.rfind(r"\b", 0, len(pattern) - 2)
    if boundary_start < 0:
        return None
    return _literal_regex_fragment(pattern[boundary_start + 2 : -2])


def _streamed_match_can_improve(
    request: GrepRequest,
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> bool:
    if request in state.requests_requiring_exact_search:
        return False
    retained = state.matches[request]
    limit = max(request.max_results, _GREP_BATCH_RESULT_FLOOR)
    return len(retained) < limit or (
        _grep_match_sort_key(match) < _grep_match_sort_key(retained[-1])
    )


def _contains_engine_divergent_space(content: str) -> bool:
    return any(char in content for char in _ENGINE_DIVERGENT_SPACE_CHARS)


def _streamed_request_matches(
    request: GrepRequest,
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> bool:
    if state.trust_ripgrep_attribution:
        return True
    if request.fixed_string:
        return request.pattern in match.content

    regex = state.regexes[request]
    assert regex is not None
    python_matches = regex.search(match.content) is not None
    if (
        _ENGINE_SENSITIVE_SPACE_PATTERN.search(request.pattern)
        and _contains_engine_divergent_space(match.content)
    ):
        state.requests_requiring_exact_search.add(request)
        return False
    if not match.content.isascii():
        needs_adjudication = bool(
            _UNICODE_CASE_INSENSITIVE_PATTERN.search(request.pattern)
        )
        if (
            not needs_adjudication
            and _UNICODE_WORD_PATTERN.search(request.pattern)
        ):
            needs_adjudication = _rust_and_python_word_classes_can_differ(
                match.content,
                deadline=state.deadline,
            )
        if needs_adjudication:
            required_literal = _required_trailing_boundary_literal(
                request.pattern
            )
            if required_literal is None or required_literal in match.content:
                state.requests_requiring_exact_search.add(request)
                python_matches = False
    return python_matches


def _record_streamed_grep_match(
    match: _GrepMatch,
    state: _StreamedGrepState,
) -> None:
    for request in state.requests:
        if (
            request.max_results > 0
            and _streamed_match_can_improve(request, match, state)
            and _streamed_request_matches(request, match, state)
        ):
            _insert_streamed_match(request, match, state)


def _read_streamed_grep_output(
    process: subprocess.Popen[bytes],
    process_state: _BoundedProcessState,
    search_state: _StreamedGrepState,
) -> None:
    pipe = process.stdout
    assert pipe is not None
    try:
        while raw_line := pipe.readline(_GREP_BATCH_MAX_OUTPUT_BYTES + 1):
            if len(raw_line) > _GREP_BATCH_MAX_OUTPUT_BYTES:
                raise _GrepOutputLimitExceeded(
                    "ripgrep emitted an oversized JSON event"
                )
            if not raw_line.endswith(b"\n"):
                raise _GrepExecutionIncomplete(
                    "ripgrep emitted an unterminated JSON event"
                )
            event = _load_ripgrep_json_event(raw_line.decode("utf-8"))
            match = _ripgrep_match_from_event(event)
            if match is None or _is_ignored_grep_path(match.path):
                continue
            _record_streamed_grep_match(match, search_state)
    except _GrepOutputLimitExceeded:
        process_state.overflow.set()
        _terminate_process(process)
    except (
        AssertionError,
        _GrepExecutionIncomplete,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        process_state.thread_errors.append(exc)
        _terminate_process(process)


def _streamed_grep_process_threads(
    process: subprocess.Popen[bytes],
    encoded_input: bytes,
    process_state: _BoundedProcessState,
    search_state: _StreamedGrepState,
) -> None:
    process_state.readers = [
        threading.Thread(
            target=_read_streamed_grep_output,
            args=(process, process_state, search_state),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_process_pipe,
            args=(
                process,
                "stderr",
                _GREP_BATCH_MAX_STDERR_BYTES,
                process_state,
            ),
            daemon=True,
        ),
    ]
    process_state.writer = threading.Thread(
        target=_write_bounded_process_input,
        args=(process, encoded_input, process_state),
        daemon=True,
    )


def _run_streamed_process_workers(
    process: subprocess.Popen[bytes],
    state: _BoundedProcessState,
    timeout: float,
) -> None:
    """Run workers while allowing the parsing reader to drain to EOF."""
    writer = state.writer
    assert writer is not None
    worker_deadline = time.monotonic() + timeout
    try:
        for thread in state.readers:
            thread.start()
            state.started_threads.append(thread)
        writer.start()
        state.started_threads.append(writer)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            state.timed_out = True

        if not state.timed_out:
            for thread in state.started_threads:
                thread.join(timeout=max(0.0, worker_deadline - time.monotonic()))
    except RuntimeError as exc:
        raise _GrepExecutionIncomplete(
            "grep subprocess worker could not start"
        ) from exc
    finally:
        _cleanup_bounded_process(process, state.started_threads)


def _prepare_streamed_grep(
    requests: Sequence[GrepRequest],
    *,
    deadline: float | None,
    trust_ripgrep_attribution: bool,
) -> tuple[bytes, _StreamedGrepState]:
    retained_slots = sum(
        max(request.max_results, _GREP_BATCH_RESULT_FLOOR)
        for request in requests
    )
    if retained_slots > _GREP_BATCH_MAX_MATCHES:
        raise _GrepOutputLimitExceeded(
            "streamed grep requested too many retained matches"
        )

    encoded_input = _grep_pattern_input(requests).encode("utf-8")
    if len(encoded_input) > _GREP_BATCH_MAX_PATTERN_BYTES:
        raise _GrepInputLimitExceeded("grep subprocess input is too large")

    regexes = {
        request: None if request.fixed_string else _python_regex(request.pattern)
        for request in requests
    }
    if any(
        regex is None and not request.fixed_string
        for request, regex in regexes.items()
    ):
        raise _GrepExecutionIncomplete(
            "streamed grep received an unsupported regex"
        )
    return encoded_input, _StreamedGrepState(
        requests=tuple(requests),
        matches={request: [] for request in requests},
        regexes=regexes,
        deadline=deadline,
        trust_ripgrep_attribution=trust_ripgrep_attribution,
    )


def _raise_for_streamed_grep_exit(
    cmd: Sequence[str],
    process: subprocess.Popen[bytes],
    process_state: _BoundedProcessState,
    timeout: float,
) -> None:
    _raise_for_bounded_process_failure(cmd, timeout, process_state)
    if process.returncode in (0, 1):
        return
    stderr = b"".join(process_state.captured["stderr"]).decode("utf-8").strip()
    raise _GrepBatchRejected(stderr or f"exit status {process.returncode}")


def _execute_streamed_grep(
    requests: Sequence[GrepRequest],
    rg: str,
    *,
    deadline: float | None,
    trust_ripgrep_attribution: bool = False,
) -> _StreamedGrepState:
    encoded_input, search_state = _prepare_streamed_grep(
        requests,
        deadline=deadline,
        trust_ripgrep_attribution=trust_ripgrep_attribution,
    )
    cmd = _ripgrep_pattern_file_command(requests[0], rg)
    timeout = _remaining_timeout(deadline, _GREP_BATCH_TIMEOUT_SECONDS)
    process = _open_grep_process(cmd)
    process_state = _BoundedProcessState()
    _streamed_grep_process_threads(
        process,
        encoded_input,
        process_state,
        search_state,
    )
    _run_streamed_process_workers(process, process_state, timeout)
    _raise_for_streamed_grep_exit(cmd, process, process_state, timeout)
    return search_state


def _replace_streamed_request_matches(
    request: GrepRequest,
    replacements: Sequence[_GrepMatch],
    state: _StreamedGrepState,
) -> None:
    for match in state.matches[request]:
        _release_streamed_match(match, state)
    state.matches[request] = []
    for match in replacements:
        _retain_streamed_match(match, state)
        state.matches[request].append(match)


def _resolve_streamed_exact_searches(
    state: _StreamedGrepState,
    rg: str,
) -> None:
    pending = tuple(
        request
        for request in state.requests
        if request in state.requests_requiring_exact_search
    )
    for index, request in enumerate(pending):
        if _deadline_expired(state.deadline):
            state.incomplete_requests.update(pending[index:])
            return
        try:
            exact_state = _execute_streamed_grep(
                (request,),
                rg,
                deadline=state.deadline,
                trust_ripgrep_attribution=True,
            )
            _replace_streamed_request_matches(
                request,
                exact_state.matches[request],
                state,
            )
        except (
            _GrepExecutionIncomplete,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            UnicodeError,
            ValueError,
        ) as exc:
            logger.debug(
                "Exact streamed grep was unavailable for %r: %s",
                request.pattern,
                exc,
            )
            state.incomplete_requests.add(request)


def _merge_streamed_grep_results(
    results: _GrepBatchResults,
    search_state: _StreamedGrepState,
) -> None:
    for request, matches in search_state.matches.items():
        results[request] = tuple(match.legacy_line() for match in matches)
    results.incomplete_requests.update(search_state.incomplete_requests)


def _run_streamed_grep_batch(
    requests: Sequence[GrepRequest],
    rg: str,
    *,
    deadline: float | None,
) -> _GrepBatchResults:
    if not requests:
        raise _GrepExecutionIncomplete("streamed grep retry requires requests")

    batched, direct = _partition_grep_requests(requests)
    results = _GrepBatchResults()
    for request in batched:
        results[request] = ()

    searchable = [request for request in batched if request.max_results > 0]
    if searchable:
        search_state = _execute_streamed_grep(
            searchable,
            rg,
            deadline=deadline,
        )
        _resolve_streamed_exact_searches(search_state, rg)
        _merge_streamed_grep_results(results, search_state)

    results.merge(_run_serial_grep_requests(direct, deadline=deadline))
    return results


def _batch_group_key(request: GrepRequest) -> tuple[str, tuple[str, ...], bool]:
    return request.project_root, request.include_globs, request.fixed_string


def _requires_direct_grep(request: GrepRequest) -> bool:
    if "\n" in request.pattern or "\r" in request.pattern:
        return True
    if not request.pattern.isascii():
        return True
    return not request.fixed_string and _python_regex(request.pattern) is None


def _partition_grep_requests(
    requests: Sequence[GrepRequest],
) -> tuple[list[GrepRequest], list[GrepRequest]]:
    batched: list[GrepRequest] = []
    direct: list[GrepRequest] = []
    for request in requests:
        target = direct if _requires_direct_grep(request) else batched
        target.append(request)
    return batched, direct


def _run_ripgrep_pattern_file(
    requests: Sequence[GrepRequest],
    rg: str,
    timeout: float = _GREP_BATCH_TIMEOUT_SECONDS,
    *,
    deadline: float | None = None,
) -> list[_GrepMatch]:
    representative = requests[0]
    cmd = _ripgrep_pattern_file_command(representative, rg)
    result = _run_bounded_subprocess(
        cmd,
        input_text=_grep_pattern_input(requests),
        timeout=_remaining_timeout(deadline, timeout),
    )
    if result.returncode not in (0, 1):
        msg = result.stderr.strip() or f"exit status {result.returncode}"
        raise _GrepBatchRejected(msg)
    return _parse_ripgrep_json_matches(result.stdout, deadline=deadline)


def _grep_stdin_chunks(
    contents: Sequence[str],
    limit: int,
) -> Iterator[tuple[int, list[str]]]:
    """Yield ``(offset, lines)`` groups whose encoded stdin fits in ``limit``.

    A single line wider than the cap cannot be sent at all, so it keeps the
    fail-closed behavior rather than being silently dropped from adjudication.
    """
    chunk: list[str] = []
    chunk_bytes = 0
    offset = 0
    for index, content in enumerate(contents):
        line_bytes = len(content.encode("utf-8")) + 1
        if line_bytes > limit:
            raise _GrepInputLimitExceeded("grep adjudication line is too large")
        if chunk and chunk_bytes + line_bytes > limit:
            yield offset, chunk
            chunk = []
            chunk_bytes = 0
            offset = index
        chunk.append(content)
        chunk_bytes += line_bytes
    if chunk:
        yield offset, chunk


def _ripgrep_stdin_match_positions(
    pattern: str,
    contents: Sequence[str],
    rg: str,
    *,
    deadline: float | None = None,
) -> set[int]:
    """Return the 0-based positions of the given lines that ripgrep matches.

    The candidate lines are adjudicated in stdin-sized chunks. A repository
    can hold more divergent lines than one bounded stdin write allows, and a
    direct per-pattern search would have resolved all of them, so refusing the
    whole request there would drop real evidence.
    """
    positions: set[int] = set()
    for offset, chunk in _grep_stdin_chunks(
        contents, _GREP_UNICODE_MAX_INPUT_BYTES
    ):
        if _deadline_expired(deadline):
            raise _GrepDeadlineExceeded("deadline exceeded while adjudicating grep")
        result = _run_bounded_subprocess(
            [
                rg,
                "--no-config",
                "-n",
                "--no-heading",
                "--color",
                "never",
                "--",
                pattern,
                "-",
            ],
            input_text="\n".join(chunk) + "\n",
            timeout=_remaining_timeout(deadline, _GREP_REQUEST_TIMEOUT_SECONDS),
            input_limit=_GREP_UNICODE_MAX_INPUT_BYTES,
        )
        if result.returncode not in (0, 1):
            msg = result.stderr.strip() or f"exit status {result.returncode}"
            raise RuntimeError(msg)
        for line in result.stdout.split("\n"):
            prefix = line.split(":", 1)[0]
            if prefix.isdigit():
                positions.add(offset + int(prefix) - 1)
    return positions


def _rust_and_python_word_classes_can_differ(
    content: str,
    *,
    deadline: float | None = None,
) -> bool:
    for index, character in enumerate(content):
        if index % 4096 == 0 and _deadline_expired(deadline):
            raise _GrepDeadlineExceeded(
                "deadline exceeded while checking Unicode classes"
            )
        if character.isascii():
            continue
        category = unicodedata.category(character)
        python_word = character.isalnum() or character == "_"
        rust_word = (
            category[0] in {"L", "M"}
            or category == "Nd"
            or category == "Pc"
            or character in {"\u200c", "\u200d"}
        )
        if python_word != rust_word:
            return True
    return False


def _word_divergent_lines(
    non_ascii_lines: Sequence[tuple[int, str]],
    *,
    deadline: float | None,
) -> list[tuple[int, str]]:
    divergent: list[tuple[int, str]] = []
    for index, line in enumerate(non_ascii_lines):
        if index % 64 == 0 and _deadline_expired(deadline):
            raise _GrepDeadlineExceeded(
                "deadline exceeded while checking non-ASCII lines"
            )
        if _rust_and_python_word_classes_can_differ(
            line[1], deadline=deadline
        ):
            divergent.append(line)
    return divergent


def _space_divergent_lines(
    grep_matches: Sequence[_GrepMatch],
) -> list[tuple[int, str]]:
    return [
        (index, match.content)
        for index, match in enumerate(grep_matches)
        if _contains_engine_divergent_space(match.content)
    ]


def _unicode_sensitive_lines(
    request: GrepRequest,
    non_ascii_lines: Sequence[tuple[int, str]],
    word_divergent_lines: Sequence[tuple[int, str]],
    space_divergent_lines: Sequence[tuple[int, str]] = (),
) -> list[tuple[int, str]]:
    if request.fixed_string:
        return []
    sensitive: dict[int, str] = {}
    if _ENGINE_SENSITIVE_SPACE_PATTERN.search(request.pattern):
        sensitive.update(space_divergent_lines)
    if non_ascii_lines:
        if _UNICODE_CASE_INSENSITIVE_PATTERN.search(request.pattern):
            sensitive.update(non_ascii_lines)
        elif _UNICODE_WORD_PATTERN.search(request.pattern):
            sensitive.update(word_divergent_lines)
    return sorted(sensitive.items())


def _non_ascii_line_overrides(
    request: GrepRequest,
    non_ascii_lines: Sequence[tuple[int, str]],
    word_divergent_lines: Sequence[tuple[int, str]],
    rg: str,
    *,
    space_divergent_lines: Sequence[tuple[int, str]] = (),
    deadline: float | None = None,
) -> dict[int, bool] | None:
    # After POSIX-class translation two engine-sensitive constructs remain in
    # classifier patterns. \b: ripgrep's UTS#18 word class includes combining
    # marks, join controls, and non-decimal numerics that Python's re does not
    # (and vice versa). \s: Python's re matches U+001C-U+001F, which ripgrep's
    # Unicode White_Space class excludes. Let ripgrep itself adjudicate the
    # affected lines so batched attribution matches what a per-pattern search
    # returns. Fixed strings are byte-exact substring checks and never diverge.
    sensitive_lines = _unicode_sensitive_lines(
        request, non_ascii_lines, word_divergent_lines, space_divergent_lines
    )
    if not sensitive_lines:
        return None
    matched = _ripgrep_stdin_match_positions(
        request.pattern,
        [content for _, content in sensitive_lines],
        rg,
        deadline=deadline,
    )
    return {
        index: position in matched
        for position, (index, _) in enumerate(sensitive_lines)
    }


def _request_matches_line(
    request: GrepRequest,
    regex: re.Pattern[str] | None,
    content: str,
) -> bool:
    if request.fixed_string:
        return request.pattern in content
    return regex is not None and regex.search(content) is not None


def _classify_grep_request(
    request: GrepRequest,
    grep_matches: Sequence[_GrepMatch],
    overrides: dict[int, bool] | None = None,
    *,
    deadline: float | None = None,
) -> tuple[str, ...]:
    if request.max_results <= 0:
        return ()
    regex = None if request.fixed_string else _python_regex(request.pattern)
    limit = max(request.max_results, _GREP_BATCH_RESULT_FLOOR)
    matches: list[str] = []
    for index, grep_match in enumerate(grep_matches):
        if index % 256 == 0 and _deadline_expired(deadline):
            raise _GrepDeadlineExceeded("deadline exceeded while classifying grep")
        override = overrides.get(index) if overrides is not None else None
        is_match = (
            override
            if override is not None
            else _request_matches_line(request, regex, grep_match.content)
        )
        if not is_match:
            continue
        matches.append(grep_match.legacy_line())
        if len(matches) >= limit:
            break
    return tuple(matches)


def _run_serial_grep_requests(
    requests: Sequence[GrepRequest],
    *,
    deadline: float | None = None,
) -> _GrepBatchResults:
    results = _GrepBatchResults()
    for request in requests:
        if _deadline_expired(deadline):
            break
        try:
            direct_results = _run_grep_request(
                request,
                deadline=deadline,
                require_complete=True,
            )
        except _GrepExecutionIncomplete:
            continue
        results[request] = tuple(direct_results)
    return results


def _run_ripgrep_batch(
    requests: Sequence[GrepRequest],
    rg: str,
    timeout: float = _GREP_BATCH_TIMEOUT_SECONDS,
    *,
    deadline: float | None = None,
) -> _GrepBatchResults:
    batched, direct = _partition_grep_requests(requests)
    batch_results = _GrepBatchResults()
    if not batched:
        return _run_serial_grep_requests(direct, deadline=deadline)

    grep_matches = _run_ripgrep_pattern_file(
        batched, rg, timeout, deadline=deadline
    )
    non_ascii_lines = [
        (index, match.content)
        for index, match in enumerate(grep_matches)
        if not match.content.isascii()
    ]
    word_divergent_lines = _word_divergent_lines(
        non_ascii_lines, deadline=deadline
    )
    has_space_pattern = any(
        not request.fixed_string
        and _ENGINE_SENSITIVE_SPACE_PATTERN.search(request.pattern)
        for request in batched
    )
    space_divergent_lines = (
        _space_divergent_lines(grep_matches) if has_space_pattern else []
    )
    unicode_adjudications = 0
    for request in batched:
        if _deadline_expired(deadline):
            break
        sensitive_lines = _unicode_sensitive_lines(
            request, non_ascii_lines, word_divergent_lines, space_divergent_lines
        )
        overrides: dict[int, bool] | None = None
        request_incomplete = False
        if sensitive_lines:
            unresolved = {index: False for index, _ in sensitive_lines}
            if unicode_adjudications < _GREP_UNICODE_MAX_ADJUDICATIONS:
                unicode_adjudications += 1
                try:
                    overrides = _non_ascii_line_overrides(
                        request,
                        non_ascii_lines,
                        word_divergent_lines,
                        rg,
                        space_divergent_lines=space_divergent_lines,
                        deadline=deadline,
                    )
                except (
                    _GrepExecutionIncomplete,
                    OSError,
                    RuntimeError,
                    subprocess.SubprocessError,
                    UnicodeError,
                    ValueError,
                ) as exc:
                    if _deadline_expired(deadline):
                        break
                    logger.debug(
                        "Treating unresolved engine-sensitive matches as non-matches "
                        "for %r: %s",
                        request.pattern,
                        exc,
                    )
                    overrides = unresolved
                    request_incomplete = True
            else:
                logger.debug(
                    "Unicode adjudication cap reached for %r; retaining only "
                    "unambiguous matches",
                    request.pattern,
                )
                overrides = unresolved
                request_incomplete = True
        try:
            batch_results[request] = _classify_grep_request(
                request,
                grep_matches,
                overrides,
                deadline=deadline,
            )
            if request_incomplete:
                batch_results.incomplete_requests.add(request)
        except (
            _GrepExecutionIncomplete,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            UnicodeError,
            ValueError,
        ) as exc:
            logger.debug(
                "Grep attribution was incomplete for %r: %s",
                request.pattern,
                exc,
            )
    batch_results.merge(
        _run_serial_grep_requests(direct, deadline=deadline)
    )
    return batch_results


def _group_grep_requests(
    requests: Sequence[GrepRequest],
) -> dict[tuple[str, tuple[str, ...], bool], list[GrepRequest]]:
    groups: dict[tuple[str, tuple[str, ...], bool], list[GrepRequest]] = {}
    for request in requests:
        groups.setdefault(_batch_group_key(request), []).append(request)
    return groups


def _try_streamed_grep_retry(
    requests: Sequence[GrepRequest],
    rg: str,
    *,
    deadline: float | None,
) -> _GrepBatchResults | None:
    if _deadline_expired(deadline):
        return None
    try:
        return _run_streamed_grep_batch(requests, rg, deadline=deadline)
    except (
        _GrepExecutionIncomplete,
        _GrepBatchRejected,
        OSError,
        subprocess.TimeoutExpired,
        UnicodeError,
        ValueError,
    ) as exc:
        logger.debug("streamed grep was unavailable: %s", exc)
        return None


def _recover_from_grep_resource_limit(
    requests: Sequence[GrepRequest],
    rg: str,
    exc: _GrepExecutionIncomplete,
    *,
    deadline: float | None,
) -> _GrepBatchResults:
    if isinstance(exc, _GrepOutputLimitExceeded):
        streamed = _try_streamed_grep_retry(
            requests,
            rg,
            deadline=deadline,
        )
        if streamed is not None:
            return streamed
    if len(requests) <= 1 or _deadline_expired(deadline):
        logger.debug("grep request exceeded a resource limit: %s", exc)
        return _GrepBatchResults()

    midpoint = len(requests) // 2
    logger.debug("splitting oversized grep batch of %d requests", len(requests))
    results = _GrepBatchResults()
    results.merge(
        _execute_grep_chunk(requests[:midpoint], rg, deadline=deadline)
    )
    if not _deadline_expired(deadline):
        results.merge(
            _execute_grep_chunk(requests[midpoint:], rg, deadline=deadline)
        )
    return results


def _execute_grep_chunk(
    requests: Sequence[GrepRequest],
    rg: str,
    *,
    deadline: float | None = None,
) -> _GrepBatchResults:
    try:
        return _run_ripgrep_batch(requests, rg, deadline=deadline)
    except (_GrepOutputLimitExceeded, _GrepInputLimitExceeded) as exc:
        return _recover_from_grep_resource_limit(
            requests,
            rg,
            exc,
            deadline=deadline,
        )
    except (
        _GrepExecutionIncomplete,
        subprocess.TimeoutExpired,
    ) as exc:
        logger.debug("batched grep was incomplete; not retrying: %s", exc)
        return _GrepBatchResults()
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
    ) as exc:
        logger.debug("batched grep failed; using serial fallback: %s", exc)
        return _run_serial_grep_requests(requests, deadline=deadline)


def _grep_request_chunks(
    requests: Sequence[GrepRequest],
) -> Iterator[list[GrepRequest]]:
    chunk: list[GrepRequest] = []
    pattern_bytes = 0
    for request in requests:
        request_bytes = len(request.pattern.encode("utf-8")) + 1
        if chunk and (
            len(chunk) >= _GREP_BATCH_SIZE
            or pattern_bytes + request_bytes > _GREP_BATCH_MAX_PATTERN_BYTES
        ):
            yield chunk
            chunk = []
            pattern_bytes = 0
        chunk.append(request)
        pattern_bytes += request_bytes
    if chunk:
        yield chunk


def execute_grep_batch(
    requests: Sequence[GrepRequest],
    *,
    deadline: float | None = None,
) -> _GrepBatchResults:
    """Execute compatible grep requests within one optional absolute deadline.

    A present empty tuple means a completed search with no matches. A missing
    request means bounded verification could not complete and must not be
    cached as a negative result.
    """
    unique_requests = list(dict.fromkeys(requests))
    if not unique_requests:
        return _GrepBatchResults()

    rg = _trusted_which(
        "rg", tuple(_request_trust_root(request) for request in unique_requests)
    )
    if not rg:
        return _run_serial_grep_requests(unique_requests, deadline=deadline)

    results = _GrepBatchResults()
    for group_requests in _group_grep_requests(unique_requests).values():
        for chunk in _grep_request_chunks(group_requests):
            if _deadline_expired(deadline):
                return results
            results.merge(_execute_grep_chunk(chunk, rg, deadline=deadline))
    return results


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
        replayed = replay.get(request)
        if replayed is not None:
            return list(replayed)
        logger.warning("grep replay miss for pattern %r; executing directly", pattern)
        deadline = _GREP_REPLAY_DEADLINE.get()
        return (
            _run_grep_request(request)
            if deadline is None
            else _run_grep_request(request, deadline=deadline)
        )

    deadline = _GREP_EXECUTION_DEADLINE.get()
    return (
        _run_grep_request(request)
        if deadline is None
        else _run_grep_request(request, deadline=deadline)
    )


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


def _grep_paths_equal(first: str, second: str) -> bool:
    normalized_first = first.replace("\\", "/")
    normalized_second = second.replace("\\", "/")
    if _HOST_PATH_CASE_INSENSITIVE:
        return ntpath.normcase(normalized_first) == ntpath.normcase(
            normalized_second
        )
    return normalized_first == normalized_second


def is_definition_line(grep_line: str, finding: dict) -> bool:
    file_path = finding.get("file", "")
    line_num = finding.get("line", 0)
    path, match_line, content = _split_grep_evidence(grep_line)

    if (
        file_path
        and match_line is not None
        and _grep_paths_equal(str(file_path), path)
        and abs(match_line - line_num) <= 2
    ):
        return True

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
    content = _grep_line_content(grep_line)

    for match in re.finditer(re.escape(simple_name), content):
        start, end = match.start(), match.end()
        before_ok = start == 0 or not content[start - 1].isalnum()
        after_ok = end == len(content) or not content[end].isalnum()
        if before_ok and after_ok:
            return False
    return True


def _grep_line_path(grep_line: str) -> str:
    return _split_grep_evidence(grep_line)[0]


def _grep_line_number(grep_line: str) -> int | None:
    return _split_grep_evidence(grep_line)[1]


def _grep_line_content(grep_line: str) -> str:
    return _split_grep_evidence(grep_line)[2]


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
            path, line_number, _ = _split_grep_evidence(line)
            key = (
                f"{path}\0{line_number}"
                if line_number is not None
                else str(line)
            )
            if key not in seen_in_strategy:
                seen_in_strategy.add(key)
                unique.append(line)
        if unique:
            deduped[strategy] = unique
        elif strategy in results and not lines:
            deduped[strategy] = lines
    return deduped
