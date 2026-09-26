"""``skylos hook <event>``: agent-loop hooks for Claude Code, Codex and Cursor.

The agent runs this command with the hook event JSON on stdin. Contracts:

* Claude Code: https://code.claude.com/docs/en/hooks
* Codex:       https://developers.openai.com/codex/hooks
* Cursor:      https://cursor.com/docs/agent/hooks

Every hook exits 0 and signals through JSON on stdout. Any internal error
fails open: the agent is never blocked because Skylos broke.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from skylos.commands.hook_policy import dedupe_by_line

EVENTS = ("post-edit", "pre-read", "pre-bash", "stop")
CLIENTS = ("claude", "codex", "cursor")

SESSION_PATH = Path(".skylos") / "agent-session.json"
SESSION_LOCK_PATH = Path(".skylos") / "agent-session.lock"
LOG_PATH = Path(".skylos") / "hook.log"
DISABLE_ENV = "SKYLOS_HOOKS_DISABLE"

MAX_STDIN_BYTES = 8_000_000
MAX_SCAN_BYTES = 2_000_000
MAX_LOG_BYTES = 512_000
MAX_ITEMS = 10
MAX_NOTES = 5
MAX_HINT_FILES = 5
MAX_NOTE_CHARS = 100
MAX_MESSAGE_CHARS = 180
MAX_FIX_CHARS = 140
MAX_SESSIONS = 20
SESSION_TTL_SECONDS = 7 * 24 * 3600
MAX_OCCURRENCES = 20

CODE_SUFFIXES = frozenset(
    {
        ".py", ".pyi", ".pyw",
        ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs",
        ".java", ".go", ".php", ".rs", ".dart", ".cs", ".kt", ".kts",
        ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx",
        ".sh", ".bash", ".zsh",
    }
)  # fmt: skip
CURSOR_EVENTS = frozenset(
    {"afterFileEdit", "beforeReadFile", "beforeShellExecution", "stop"}
)
EDIT_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "apply_patch"})
_REDACTED_RE = re.compile(r"\s*\(redacted:[^)]*\)")
# Same pre-filter as skylos.rules.ai_defect.install_command (kept here so the
# common "not an install" path costs no heavy imports).
_INSTALL_HINT_RE = re.compile(
    r"\b(?:pip3?|pipx|uv|poetry|npm|pnpm|yarn|bun|go)\b[^\n]*?\b(?:install|add|get|i)\b"
)
_WS_RE = re.compile(r"\s+")

VerifyFunc = Callable[..., dict[str, Any]]
PARSE_INCOMPLETE_RULE = "SKY-ANALYSIS-INCOMPLETE"
InstallChecker = Callable[[str, Path], dict[str, Any]]


@dataclass
class HookDeps:
    verify: VerifyFunc | None = None
    install_checker: InstallChecker | None = None
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))


@dataclass
class EditedFile:
    path: Path
    # None = whole file is agent-written; [] = nothing added (pure deletion).
    ranges: list[tuple[int, int]] | None


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def run_hook_command(
    argv: Sequence[str],
    *,
    stdin=None,
    stdout=None,
    deps: HookDeps | None = None,
) -> int:
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout
    deps = deps or HookDeps()
    started = time.monotonic()
    event, client_arg = _parse_argv(argv)
    if event == "recheck":
        return run_recheck(list(argv)[1:], stdout=stdout, deps=deps)
    interactive = bool(getattr(stdin, "isatty", lambda: False)())
    if event in {"-h", "--help", "help", ""} or interactive:
        stdout.write(_usage())
        return 0

    record: dict[str, Any] = {"event": event, "outcome": "allow"}
    client = client_arg or "claude"
    root: Path | None = None
    output: dict[str, Any] | None = None
    try:
        payload = _read_payload(stdin)
        client = client_arg or _detect_client(payload)
        root = _project_root(payload, deps.env)
        record["client"] = client
        if event not in EVENTS:
            record["outcome"] = "unknown-event"
            output = _allow_output(event, client)
        elif _disabled(event, deps.env):
            record["outcome"] = "disabled"
            output = _allow_output(event, client)
        else:
            handler = _HANDLERS[event]
            with _quiet():
                output = handler(payload, root, client, deps, record)
    except (Exception, SystemExit) as exc:  # fail open, always
        record["outcome"] = "error"
        record["error"] = type(exc).__name__
        output = _allow_output(event, client)
        if root is None:
            with contextlib.suppress(Exception):
                root = _project_root({}, deps.env)

    if output is not None:
        stdout.write(json.dumps(output) + "\n")
        stdout.flush()
    record["ms"] = int((time.monotonic() - started) * 1000)
    _log(root, record)
    return 0


# --------------------------------------------------------------------------
# recheck: the command the block message tells the agent to run
# --------------------------------------------------------------------------


def run_recheck(argv: list[str], *, stdout=None, deps: HookDeps | None = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    deps = deps or HookDeps()
    files: list[str] = []
    line_range: tuple[int, int] | None = None
    session_mode = False
    args = iter(argv)
    try:
        for arg in args:
            if arg in {"-h", "--help"}:
                stdout.write(_usage())
                return 0
            if arg == "--client":
                next(args, None)
            elif arg.startswith("--client="):
                continue
            elif arg == "--session":
                session_mode = True
            elif arg == "--range" or arg.startswith("--range="):
                value = arg.split("=", 1)[1] if "=" in arg else next(args, "")
                line_range = _parse_range(value)
            elif arg.startswith("-"):
                raise ValueError(f"unknown option {arg}")
            else:
                files.append(arg)
        if session_mode and (files or line_range is not None):
            raise ValueError("--session takes no files or --range")
        if not files and not session_mode:
            raise ValueError("give at least one file, or --session")
    except ValueError as exc:
        stdout.write(f"skylos hook recheck: {exc}\n")
        return 2

    root = _project_root({"cwd": os.getcwd()}, deps.env)
    state = _load_session_state(_state_root(root))
    if session_mode:
        files = [
            str(root / rel)
            for rel in _files_with_introduced(state)
            if (root / rel).is_file()
        ]
    blocking: list[dict[str, Any]] = []
    notes = 0
    checked = 0
    with _quiet():
        for raw in files:
            path = _abs_path(raw, Path.cwd())
            if path is None or not path.is_file():
                stdout.write(f"skylos hook recheck: no such file: {raw}\n")
                return 2
            result = _check_file(path, root, deps)
            if result is None:
                continue
            checked += 1
            findings, lines, _stat = result
            notes += sum(1 for f in findings if not f.get("blocking", True))
            if line_range is not None:
                findings = [
                    f for f in findings if line_range[0] <= f["line"] <= line_range[1]
                ]
            else:
                introduced = _introduced_keys(state, _rel(path, root))
                if introduced is not None:
                    findings = [
                        f for f in findings if _finding_key(f, lines) in introduced
                    ]
            blocking.extend(f for f in findings if f.get("blocking", True))
    blocking = dedupe_by_line(blocking)
    note_text = f" ({notes} non-blocking note(s) in these files)" if notes else ""
    if not blocking:
        stdout.write(
            f"Skylos: no blocking issues in {checked} file(s){note_text}. "
            "The hook will not block on these files.\n"
        )
        return 0
    stdout.write(
        _format_problems(
            blocking,
            root,
            header=f"Skylos: {len(blocking)} blocking issue(s) still open{note_text}:",
            footer="",
        )
        + "\n"
    )
    return 1


def _parse_range(value: str) -> tuple[int, int]:
    raw = value.replace("-", ":")
    left, _, right = raw.partition(":")
    try:
        start = int(left)
        end = int(right) if right else start
    except ValueError:
        raise ValueError(f"bad --range {value!r}; use L1:L2") from None
    if start < 1 or end < start:
        raise ValueError(f"bad --range {value!r}; use L1:L2")
    return start, end


def _files_with_introduced(state: dict[str, Any]) -> list[str]:
    """Project-relative files where agent edits introduced issues (any session)."""
    found: set[str] = set()
    for session in (state.get("sessions") or {}).values():
        files = session.get("files") if isinstance(session, dict) else None
        for rel, info in (files or {}).items():
            if isinstance(info, dict) and info.get("introduced"):
                found.add(rel)
    return sorted(found)


def _introduced_keys(state: dict[str, Any], rel: str) -> set[str] | None:
    """Issue keys agent edits introduced in ``rel`` (any session), if recorded."""
    keys: set[str] = set()
    seen = False
    for session in (state.get("sessions") or {}).values():
        info = session.get("files", {}).get(rel) if isinstance(session, dict) else None
        if isinstance(info, dict):
            seen = True
            keys.update(info.get("introduced") or [])
    return keys if seen else None


def _parse_argv(argv: Sequence[str]) -> tuple[str, str | None]:
    args = list(argv)
    event = args[0] if args else ""
    client = None
    for idx, arg in enumerate(args[1:], start=1):
        if arg == "--client" and idx + 1 < len(args):
            client = args[idx + 1]
        elif arg.startswith("--client="):
            client = arg.split("=", 1)[1]
    if client not in CLIENTS:
        client = None
    return event, client


def _usage() -> str:
    return (
        "usage: skylos hook {post-edit,pre-read,pre-bash,stop} "
        "[--client claude|codex|cursor]\n"
        "       skylos hook recheck FILE... [--range L1:L2]\n"
        "       skylos hook recheck --session\n\n"
        "Agent-loop hook. Reads the hook event JSON on stdin and answers with\n"
        "the agent's hook JSON contract. Install with `skylos agent install-hooks`.\n"
        "`recheck` applies the same blocking policy to files on disk and prints a\n"
        "short verdict (exit 0 clean, 1 blocking issues, 2 usage error).\n"
        "`recheck --session` rechecks every file where agent edits introduced\n"
        "issues (the files the stop hook re-verifies).\n"
        f"Disable one hook with {DISABLE_ENV}=pre-read (comma list, or 'all').\n"
    )


def _read_payload(stdin) -> dict[str, Any]:
    raw = stdin.read(MAX_STDIN_BYTES + 1)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) > MAX_STDIN_BYTES or not raw.strip():
        return {}
    payload = json.loads(raw)
    return payload if isinstance(payload, dict) else {}


def _detect_client(payload: dict[str, Any]) -> str:
    if "cursor_version" in payload or payload.get("hook_event_name") in CURSOR_EVENTS:
        return "cursor"
    if payload.get("tool_name") == "apply_patch" or "turn_id" in payload:
        return "codex"
    return "claude"


def _project_root(payload: dict[str, Any], env: dict[str, str]) -> Path:
    # The agent's declared project dir is authoritative; a bare cwd (Codex,
    # or a session started in a subdirectory) is widened to its Git root.
    declared: list[Any] = [env.get("CLAUDE_PROJECT_DIR"), env.get("CURSOR_PROJECT_DIR")]
    roots = payload.get("workspace_roots")
    if isinstance(roots, list) and roots:
        declared.append(roots[0])
    for candidate in declared:
        if isinstance(candidate, str) and candidate:
            path = Path(candidate).expanduser()
            if path.is_dir():
                return path.resolve()
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd and Path(cwd).expanduser().is_dir():
        return _git_root(Path(cwd).expanduser().resolve())
    return _git_root(Path.cwd().resolve())


def _git_root(start: Path) -> Path:
    for parent in (start, *start.parents):
        if (parent / ".git").exists():
            return parent
    return start


def _disabled(event: str, env: dict[str, str]) -> bool:
    raw = env.get(DISABLE_ENV, "")
    names = {part.strip().lower() for part in raw.split(",") if part.strip()}
    return bool(names & {"all", "1", "true", event})


@contextlib.contextmanager
def _quiet():
    """Keep analyzer logging/prints off the hook's stdout/stderr."""
    import logging

    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            yield
    finally:
        logging.disable(previous)


# --------------------------------------------------------------------------
# Client-specific output shapes
# --------------------------------------------------------------------------


def _allow_output(event: str, client: str) -> dict[str, Any] | None:
    if client == "cursor":
        if event in {"pre-read", "pre-bash"}:
            # Cursor treats empty/invalid output of permission hooks as deny.
            return {"permission": "allow"}
        if event == "stop":
            return {}
        return None
    if event == "stop":
        return {}  # Codex requires JSON from Stop; Claude accepts {}.
    # No output = normal permission flow. Never emit "allow": in Claude Code
    # that would skip the user's permission prompt.
    return None


def _deny_output(client: str, reason: str) -> dict[str, Any]:
    if client == "cursor":
        return {"permission": "deny", "user_message": reason, "agent_message": reason}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _cursor_read_deny(reason: str) -> dict[str, Any]:
    return {"permission": "deny", "user_message": reason}


def _note_output(client: str, text: str) -> dict[str, Any] | None:
    """Non-blocking context for the agent (Claude Code PostToolUse only)."""
    if client != "claude":
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": text,
        }
    }


def _block_output(client: str, reason: str) -> dict[str, Any] | None:
    if client == "cursor":
        return None  # afterFileEdit has no feedback channel; Stop reports.
    return {"decision": "block", "reason": reason}


def _stop_block_output(client: str, reason: str) -> dict[str, Any]:
    if client == "cursor":
        return {"followup_message": reason}
    return {"decision": "block", "reason": reason}


# --------------------------------------------------------------------------
# post-edit
# --------------------------------------------------------------------------


def _handle_post_edit(payload, root, client, deps, record):
    edited = _edited_files(payload, root, client)
    record["files"] = len(edited)
    if not edited:
        record["outcome"] = "skip"
        return _allow_output("post-edit", client)

    problems: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []
    session_updates: dict[str, dict[str, Any]] = {}
    for item in edited:
        checked = _check_file(item.path, root, deps)
        if checked is None:
            continue
        findings, lines, stat_key = checked
        in_range = [
            f
            for f in findings
            if f.get("file_level") or _in_ranges(f["line"], item.ranges)
        ]
        blocking = [f for f in in_range if f.get("blocking", True)]
        rel = _rel(item.path, root)
        session_updates[rel] = {
            "introduced": sorted({_finding_key(f, lines) for f in blocking}),
            "stat": stat_key,
            "findings": [_session_finding(f, lines) for f in findings],
        }
        problems.extend(blocking)
        notes.extend(f for f in in_range if not f.get("blocking", True))

    _update_session(_state_root(root), _session_id(payload), session_updates)
    problems = dedupe_by_line(problems)
    notes = [n for n in dedupe_by_line(notes) if not _same_line(n, problems)]
    record["findings"] = len(problems)
    record["notes"] = len(notes)
    if not problems:
        if any(n.get("rule_id") == PARSE_INCOMPLETE_RULE for n in notes):
            # A file Skylos could not parse was not checked: never "pass".
            record["outcome"] = "incomplete"
        else:
            record["outcome"] = "note" if notes else "pass"
        if notes:
            return _note_output(client, _format_notes(notes, root))
        return _allow_output("post-edit", client)
    record["outcome"] = "block"
    reason = _format_problems(
        problems,
        root,
        header=(
            f"Skylos found {len(problems)} issue(s) in the lines you just "
            "changed. Fix them before moving on:"
        ),
        footer=_rerun_hint(problems, root),
    )
    if notes:
        reason += "\n" + _format_notes(notes, root)
    return _block_output(client, reason)


def _same_line(finding: dict[str, Any], others: list[dict[str, Any]]) -> bool:
    return any(
        o.get("path") == finding.get("path") and o.get("line") == finding.get("line")
        for o in others
    )


def _edited_files(payload, root: Path, client: str) -> list[EditedFile]:
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    base = _cwd(payload, root)

    if client == "cursor" and "file_path" in payload:
        path = _abs_path(payload.get("file_path"), base)
        if path is None:
            return []
        edits = payload.get("edits") if isinstance(payload.get("edits"), list) else []
        texts = [e.get("new_string") for e in edits if isinstance(e, dict)]
        return _keep_in_root([EditedFile(path, _locate_texts(path, texts))], root)

    if tool == "apply_patch" or (
        tool in EDIT_TOOLS
        and isinstance(tool_input.get("command"), str)
        and "*** Begin Patch" in tool_input.get("command", "")
    ):
        return _keep_in_root(_apply_patch_files(tool_input.get("command"), base), root)

    if tool not in EDIT_TOOLS:
        return []
    path = _abs_path(tool_input.get("file_path"), base)
    if path is None:
        return []
    response = payload.get("tool_response")
    ranges = _structured_patch_ranges(response)
    if ranges is None:
        if tool == "Write":
            ranges = None
        elif tool == "MultiEdit":
            edits = (
                tool_input.get("edits")
                if isinstance(tool_input.get("edits"), list)
                else []
            )
            ranges = _locate_texts(
                path, [e.get("new_string") for e in edits if isinstance(e, dict)]
            )
        else:
            ranges = _locate_texts(path, [tool_input.get("new_string")])
    return _keep_in_root([EditedFile(path, ranges)], root)


def _structured_patch_ranges(response: Any) -> list[tuple[int, int]] | None:
    """Added-line ranges from Claude Code's Edit/Write ``structuredPatch``."""
    if not isinstance(response, dict):
        return None
    if response.get("type") == "create":
        return None
    hunks = response.get("structuredPatch")
    if not isinstance(hunks, list) or not hunks:
        return None
    added: list[int] = []
    for hunk in hunks:
        if not isinstance(hunk, dict):
            return None
        line_no = hunk.get("newStart")
        lines = hunk.get("lines")
        if not isinstance(line_no, int) or not isinstance(lines, list):
            return None
        for text in lines:
            if not isinstance(text, str):
                continue
            if text.startswith("+"):
                added.append(line_no)
                line_no += 1
            elif text.startswith("-") or text.startswith("\\"):
                continue
            else:
                line_no += 1
    return _merge_lines(added)


def _apply_patch_files(patch: Any, base: Path) -> list[EditedFile]:
    """Files and added blocks from a Codex ``apply_patch`` envelope."""
    if not isinstance(patch, str):
        return []
    files: list[tuple[Path, bool, list[list[str]]]] = []
    current: tuple[Path, bool, list[list[str]]] | None = None
    block: list[str] = []

    def flush_block():
        if current is not None and block:
            current[2].append(list(block))
        block.clear()

    for line in patch.splitlines():
        header = None
        for prefix, whole in (("*** Add File: ", True), ("*** Update File: ", False)):
            if line.startswith(prefix):
                header = (line[len(prefix) :].strip(), whole)
        if header is not None:
            flush_block()
            path = _abs_path(header[0], base)
            current = (path, header[1], []) if path is not None else None
            if current is not None:
                files.append(current)
            continue
        if line.startswith("*** Move to: ") and current is not None:
            flush_block()
            moved = _abs_path(line[len("*** Move to: ") :].strip(), base)
            if moved is not None:
                files[-1] = current = (moved, current[1], current[2])
            continue
        if line.startswith("*** "):
            flush_block()
            if not line.startswith("*** End of File"):
                current = None if line.startswith("*** Delete File: ") else current
            continue
        if line.startswith("+"):
            block.append(line[1:])
        else:
            flush_block()
    flush_block()

    edited = []
    for path, whole, blocks in files:
        if whole:
            edited.append(EditedFile(path, None))
        else:
            edited.append(
                EditedFile(path, _locate_texts(path, ["\n".join(b) for b in blocks]))
            )
    return edited


def _locate_texts(path: Path, texts: list[Any]) -> list[tuple[int, int]]:
    content = _read_text(path)
    if content is None:
        return []
    ranges: list[tuple[int, int]] = []
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            continue
        needle = text.strip("\n")
        start = 0
        hits = 0
        while hits < MAX_OCCURRENCES:
            idx = content.find(needle, start)
            if idx < 0:
                break
            first = content.count("\n", 0, idx) + 1
            ranges.append((first, first + needle.count("\n")))
            start = idx + max(len(needle), 1)
            hits += 1
    return _merge_ranges(ranges)


def _check_file(path: Path, root: Path, deps: HookDeps):
    """Return (findings, lines, stat_key) or None when the file is not checkable."""
    try:
        stat = path.stat()
    except OSError:
        return None
    if not path.is_file() or stat.st_size > MAX_SCAN_BYTES:
        return None
    suffix = path.suffix.lower()
    text = _read_text(path) or ""
    lines = text.splitlines()
    stat_key = [stat.st_mtime_ns, stat.st_size]
    if suffix in CODE_SUFFIXES:
        findings = _verify_findings(path, root, deps)
        if _is_test_path(path, root):
            # ``verify`` skips secrets in test files; a live key is still a leak.
            findings.extend(_secret_findings(path, root, text, ignore_tests=False))
    elif _secret_scannable(path):
        findings = _secret_findings(path, root, text + "\n", ignore_tests=False)
        if findings and _is_ignored_env_file(path, root):
            # A gitignored .env file is exactly where the key should live.
            findings = []
    else:
        return None
    from skylos.commands.hook_policy import classify_findings

    classify_findings(findings, path, text)
    return findings, lines, stat_key


def _is_test_path(path: Path, root: Path) -> bool:
    from skylos.rules.secrets import IS_TEST_PATH

    return bool(IS_TEST_PATH.search(_rel(path, root)))


def _is_ignored_env_file(path: Path, root: Path) -> bool:
    if not path.name.lower().startswith(".env"):
        return False
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", "--", str(path)],
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def hook_verify(target: str | Path, root: Path) -> dict[str, Any]:
    """The verify call every edit hook makes (also used to warm its caches).

    Project-wide facts (module surfaces, installed distributions) come from
    the persistent caches under ``.skylos/cache``, so a warm call re-parses
    only files that changed since the last one.
    """
    from skylos.constants import parse_exclude_folders
    from skylos.rules.ai_defect.module_facts_index import module_facts_index_session
    from skylos.verify_change import verify_change_path

    from skylos.core.safe_cache_io import redirect_project_caches

    # Outside a Git repo every project cache lives under the user cache too.
    state_root = _state_root(root)
    with redirect_project_caches(root, state_root), module_facts_index_session(
        state_root
    ):
        return verify_change_path(
            str(target),
            exclude_folders=list(parse_exclude_folders(use_defaults=True)),
            include_security_findings=True,
            behavior_comparison=False,
        )


def _verify_findings(path: Path, root: Path, deps: HookDeps) -> list[dict[str, Any]]:
    if deps.verify is None:
        result = hook_verify(path, root)
    else:
        result = deps.verify(
            str(path), include_security_findings=True, behavior_comparison=False
        )
    findings = []
    for raw in result.get("findings") or []:
        rng = raw.get("range") or {}
        file_name = str(rng.get("file") or "")
        if file_name and Path(file_name).name != path.name:
            continue
        findings.append(
            {
                "path": str(path),
                "line": _int(rng.get("start_line")),
                "rule_id": str(raw.get("rule_id") or ""),
                "severity": str(raw.get("severity") or ""),
                "message": str(raw.get("message") or ""),
                "fix": str(raw.get("suggested_fix") or ""),
                "category": str(raw.get("category") or ""),
                "vibe": str(raw.get("vibe_category") or ""),
                "metadata": raw.get("metadata")
                if isinstance(raw.get("metadata"), dict)
                else {},
            }
        )
    if _verify_parse_incomplete(result):
        findings.append(
            {
                "path": str(path),
                "line": 0,
                "file_level": True,
                "rule_id": PARSE_INCOMPLETE_RULE,
                "severity": "HIGH",
                "message": (
                    "Skylos could not parse this file (syntax error), so it was "
                    "not checked; fix the syntax and re-run"
                ),
                "fix": "",
                "category": "analysis",
                "vibe": "",
                "metadata": {"reason": "parse_error"},
            }
        )
    return findings


def _verify_parse_incomplete(result: dict[str, Any]) -> bool:
    """True when verify could not parse the target (status incomplete)."""
    if not isinstance(result, dict) or result.get("status") != "incomplete":
        return False
    coverage = result.get("coverage")
    checks = coverage.get("checks") if isinstance(coverage, dict) else None
    for check in checks or ():
        if not isinstance(check, dict):
            continue
        for reason in check.get("reasons") or ():
            if isinstance(reason, dict) and reason.get("code") == "parse_error":
                return True
    return False


def _secret_scannable(path: Path) -> bool:
    from skylos.rules.secrets import ALLOWED_FILE_SUFFIXES

    name = path.name.lower()
    return name.endswith(ALLOWED_FILE_SUFFIXES) or name.startswith(".env")


def _secret_findings(
    path: Path, root: Path, text: str, *, ignore_tests: bool = True
) -> list[dict[str, Any]]:
    from skylos.rules.secrets import scan_ctx

    ctx = {"relpath": _rel(path, root), "lines": text.splitlines(True), "tree": None}
    findings = []
    for raw in scan_ctx(ctx, ignore_tests=ignore_tests):
        provider = str(raw.get("provider") or "secret").replace("_", " ")
        findings.append(
            {
                "path": str(path),
                "line": _int(raw.get("line")),
                "rule_id": str(raw.get("rule_id") or "SKY-S101"),
                "severity": str(raw.get("severity") or "CRITICAL"),
                "message": f"Hard-coded {provider} secret",
                "fix": "Load it from the environment or a secret manager and rotate it.",
                "category": "secret",
            }
        )
    return findings


# --------------------------------------------------------------------------
# pre-read
# --------------------------------------------------------------------------


def _handle_pre_read(payload, root, client, deps, record):
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    if client != "cursor" and payload.get("tool_name") not in {None, "Read"}:
        record["outcome"] = "skip"
        return _allow_output("pre-read", client)
    raw_path = (
        payload.get("file_path") if client == "cursor" else tool_input.get("file_path")
    )
    path = _abs_path(raw_path, _cwd(payload, root))
    if path is None or not _secret_scannable(path):
        record["outcome"] = "skip"
        return _allow_output("pre-read", client)

    text = payload.get("content") if client == "cursor" else None
    if not isinstance(text, str):
        text = _read_scannable(path)
    if text is None:
        record["outcome"] = "skip"
        return _allow_output("pre-read", client)

    # Unlike ``skylos -a``, test files are scanned: a live key in
    # tests/conftest.py reaches the model provider just the same.
    findings = _secret_findings(path, root, text, ignore_tests=False)
    window = _read_window(tool_input)
    if window is not None:
        findings = [f for f in findings if window[0] <= f["line"] <= window[1]]
    record["findings"] = len(findings)
    if not findings:
        record["outcome"] = "pass"
        return _allow_output("pre-read", client)

    record["outcome"] = "block"
    lines = sorted({f["line"] for f in findings})
    kinds = sorted({f["message"].replace("Hard-coded ", "") for f in findings})
    shown = ", ".join(str(n) for n in lines[:MAX_ITEMS])
    more = f" (+{len(lines) - MAX_ITEMS} more)" if len(lines) > MAX_ITEMS else ""
    reason = (
        f"Skylos blocked reading {_rel(path, root)}: it contains "
        f"{len(findings)} likely secret(s) ({'; '.join(kinds[:4])}) on line(s) "
        f"{shown}{more}. Reading it would send the credential to the model "
        "provider. Read only the lines you need with offset/limit that skip "
        "those lines, or ask the user to move the secret into the environment "
        "or a secret manager."
    )
    if client == "cursor":
        return _cursor_read_deny(reason)
    return _deny_output(client, reason)


def _read_window(tool_input: dict[str, Any]) -> tuple[int, int] | None:
    offset = tool_input.get("offset")
    limit = tool_input.get("limit")
    if not isinstance(offset, int) and not isinstance(limit, int):
        return None
    start = offset if isinstance(offset, int) and offset > 0 else 1
    if isinstance(limit, int) and limit > 0:
        # +/-1 slack: offset may be 0- or 1-based depending on the client.
        return max(1, start - 1), start + limit
    return max(1, start - 1), sys.maxsize


def _read_scannable(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="ignore")


# --------------------------------------------------------------------------
# pre-bash
# --------------------------------------------------------------------------


def _handle_pre_bash(payload, root, client, deps, record):
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = (
        payload.get("command") if client == "cursor" else tool_input.get("command")
    )
    if not isinstance(command, str):
        record["outcome"] = "skip"
        return _allow_output("pre-bash", client)

    if not _INSTALL_HINT_RE.search(command):
        # Fast path: unrelated commands never import the registry checker.
        record["outcome"] = "skip"
        return _allow_output("pre-bash", client)

    checker = deps.install_checker
    if checker is None:
        from skylos.rules.ai_defect.install_command import check_install_command

        checker = check_install_command
    if deps.install_checker is None:
        result = checker(command, root, cache_root=_state_root(root))
    else:
        result = checker(command, root)
    findings = result.get("findings") or []
    record["packages"] = len(result.get("packages") or [])
    record["findings"] = len(findings)
    if not findings:
        record["outcome"] = "pass"
        return _allow_output("pre-bash", client)

    record["outcome"] = "block"
    items = [f"- {f.get('message')}" for f in findings[:MAX_ITEMS]]
    reason = (
        "Skylos blocked this install: "
        + (
            "1 package looks"
            if len(findings) == 1
            else f"{len(findings)} packages look"
        )
        + " hallucinated or typosquatted.\n"
        + "\n".join(items)
        + "\nCheck the real package name (docs, registry search) and retry. "
        "If the package is internal, install it with your private index/registry "
        "flag so Skylos skips the public-registry check. If this package is "
        "correct, add it to [tool.skylos] hooks_allow_packages in pyproject.toml."
    )
    return _deny_output(client, reason)


# --------------------------------------------------------------------------
# stop
# --------------------------------------------------------------------------


def _handle_stop(payload, root, client, deps, record):
    if client == "cursor" and payload.get("status") not in {None, "completed"}:
        record["outcome"] = "skip"
        return _allow_output("stop", client)
    session_id = _session_id(payload)
    state = _load_session_state(_state_root(root))
    session = state.get("sessions", {}).get(session_id)
    if not isinstance(session, dict) or not session.get("files"):
        record["outcome"] = "skip"
        return _allow_output("stop", client)

    open_findings: list[dict[str, Any]] = []
    refreshed: dict[str, dict[str, Any]] = {}
    for rel, info in sorted(session["files"].items()):
        if not isinstance(info, dict):
            continue
        introduced = set(info.get("introduced") or [])
        if not introduced:
            continue
        path = (root / rel).resolve()
        current = _current_findings(path, root, deps)
        if current is None:
            continue
        refreshed[rel] = current["update"]
        open_findings.extend(
            f
            for f in current["findings"]
            if f.get("key") in introduced and f.get("blocking", True)
        )

    if refreshed:
        _update_session(
            _state_root(root), session_id, refreshed, replace_introduced=False
        )
    open_findings = dedupe_by_line(open_findings)
    record["findings"] = len(open_findings)
    if not open_findings:
        record["outcome"] = "pass"
        return _allow_output("stop", client)

    digest = hashlib.sha256(
        "\n".join(sorted(f"{f['path']}|{f.get('key')}" for f in open_findings)).encode()
    ).hexdigest()[:16]
    looping = (
        bool(payload.get("stop_hook_active")) or _int(payload.get("loop_count")) > 0
    )
    if looping and session.get("last_stop_digest") == digest:
        # Same issues after we already asked once: let the agent stop rather
        # than loop, and tell the user.
        record["outcome"] = "gave-up"
        if client == "cursor":
            return {}
        return {
            "systemMessage": (
                f"Skylos: {len(open_findings)} issue(s) introduced this session are "
                f"still open. {_rerun_hint(open_findings, root)}"
            )
        }

    _set_stop_digest(_state_root(root), session_id, digest)
    record["outcome"] = "block"
    reason = _format_problems(
        open_findings,
        root,
        header=(
            f"Skylos: {len(open_findings)} issue(s) you introduced in this session "
            "are still open. Fix them (or explain why they are false positives) "
            "before finishing:"
        ),
        footer=_rerun_hint(open_findings, root),
    )
    return _stop_block_output(client, reason)


def _current_findings(path: Path, root: Path, deps: HookDeps):
    """Re-verify ``path`` now, exactly as ``hook recheck`` does.

    Never trust the cached post-edit result: an issue can be fixed from
    another file (defining the missing ``crud.delete_item`` in crud.py fixes
    the call site in items.py without touching items.py). Only files with
    open introduced issues get here, so this stays a handful of checks.
    """
    if not path.is_file():
        return None
    checked = _check_file(path, root, deps)
    if checked is None:
        return None
    raw, lines, new_stat = checked
    session_findings = [_session_finding(f, lines) for f in raw]
    return {
        "findings": [{**f, "path": str(path)} for f in session_findings],
        "update": {"stat": new_stat, "findings": session_findings},
    }


# --------------------------------------------------------------------------
# Session state (.skylos/agent-session.json)
# --------------------------------------------------------------------------


def _session_id(payload: dict[str, Any]) -> str:
    for key in ("session_id", "conversation_id"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:128]
    return "default"


def _load_session_state(root: Path) -> dict[str, Any]:
    from skylos.core.safe_cache_io import load_project_json_cache

    state = load_project_json_cache(root, SESSION_PATH)
    if state.get("schema_version") != 1 or not isinstance(state.get("sessions"), dict):
        return {"schema_version": 1, "sessions": {}}
    return state


def _mutate_session(root: Path, session_id: str, mutate) -> None:
    from skylos.core.safe_cache_io import project_cache_lock, save_project_json_cache

    with project_cache_lock(root, SESSION_LOCK_PATH, timeout_seconds=5) as locked:
        if not locked:
            return
        state = _load_session_state(root)
        sessions = state["sessions"]
        session = sessions.get(session_id)  # skylos: ignore[SKY-D216] sessions is a JSON dict, not an HTTP client
        if not isinstance(session, dict):
            session = {"files": {}}
        session.setdefault("files", {})
        mutate(session)
        session["updated"] = int(time.time())
        sessions[session_id] = session
        _prune_sessions(sessions)
        save_project_json_cache(root, SESSION_PATH, state)


def _update_session(
    root: Path,
    session_id: str,
    updates: dict[str, dict[str, Any]],
    *,
    replace_introduced: bool = True,
) -> None:
    if not updates:
        return

    def mutate(session):
        files = session["files"]
        for rel, update in updates.items():
            entry = files.get(rel) if isinstance(files.get(rel), dict) else {}
            if replace_introduced and "introduced" in update:
                # Keep earlier keys that are still present in the file; add new ones.
                present = {f.get("key") for f in update.get("findings", [])}
                kept = {k for k in entry.get("introduced", []) if k in present}
                entry["introduced"] = sorted(kept | set(update["introduced"]))
            entry["stat"] = update.get("stat")
            entry["findings"] = update.get("findings", [])
            files[rel] = entry

    _mutate_session(root, session_id, mutate)


def _set_stop_digest(root: Path, session_id: str, digest: str) -> None:
    def mutate(session):
        session["last_stop_digest"] = digest

    _mutate_session(root, session_id, mutate)


def _prune_sessions(sessions: dict[str, Any]) -> None:
    now = time.time()
    for key in list(sessions):
        entry = sessions[key]
        if (
            not isinstance(entry, dict)
            or now - _int(entry.get("updated")) > SESSION_TTL_SECONDS
        ):
            sessions.pop(key, None)
    if len(sessions) > MAX_SESSIONS:
        ordered = sorted(sessions, key=lambda k: _int(sessions[k].get("updated")))
        for key in ordered[: len(sessions) - MAX_SESSIONS]:
            sessions.pop(key, None)


def _finding_key(finding: dict[str, Any], lines: list[str]) -> str:
    """Line-shift-stable identity: rule + hashed source line (never raw text)."""
    line_no = finding.get("line") or 0
    text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    digest = hashlib.sha256(_WS_RE.sub(" ", text.strip()).encode()).hexdigest()[:16]
    return f"{finding.get('rule_id')}:{digest}"


def _session_finding(finding: dict[str, Any], lines: list[str]) -> dict[str, Any]:
    return {
        "key": _finding_key(finding, lines),
        "blocking": bool(finding.get("blocking", True)),
        "line": finding.get("line"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "message": _clean_message(finding.get("message"), MAX_MESSAGE_CHARS),
        "fix": _clean_message(finding.get("fix"), MAX_FIX_CHARS),
    }


# --------------------------------------------------------------------------
# Formatting and helpers
# --------------------------------------------------------------------------


def _format_problems(problems, root: Path, *, header: str, footer: str) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranked = sorted(
        problems,
        key=lambda f: (
            order.get(str(f.get("severity")).upper(), 4),
            str(f.get("path")),
            f.get("line") or 0,
        ),
    )
    lines = [header]
    for finding in ranked[:MAX_ITEMS]:
        message = _clean_message(finding.get("message"), MAX_MESSAGE_CHARS)
        fix = _clean_message(finding.get("fix"), MAX_FIX_CHARS)
        location = (
            f"{_display_path(finding.get('path'), root)}:{finding.get('line') or '?'}"
        )
        entry = f"- {location} {finding.get('rule_id')} {message}"
        if fix:
            entry += f" -> {fix}"
        lines.append(entry)
    if len(ranked) > MAX_ITEMS:
        lines.append(f"- ...and {len(ranked) - MAX_ITEMS} more")
    if footer:
        lines.append(footer)
    return "\n".join(lines)


def _rerun_hint(problems, root: Path) -> str:
    """The command that applies this hook's own blocking policy to the files."""
    import shlex

    paths = sorted({_display_path(f.get("path"), root) for f in problems})
    if len(paths) <= MAX_HINT_FILES:
        quoted = " ".join(shlex.quote(p) for p in paths)
        return f"Check again with: {self_command()} hook recheck {quoted}"
    return (
        f"Check again with: {self_command()} hook recheck --session "
        f"(rechecks all {len(paths)} files with open issues: "
        f"{', '.join(paths[:MAX_HINT_FILES])} and {len(paths) - MAX_HINT_FILES} more)"
    )


def self_command() -> str:
    """How to invoke *this* Skylos from a shell (PATH may hold an older one)."""
    import shlex
    import shutil

    argv0 = sys.argv[0] if sys.argv else ""
    name = Path(argv0).name.lower()
    if name in {"skylos", "skylos.exe"}:
        script = Path(argv0).absolute()
        found = shutil.which("skylos")
        if found and Path(found).absolute() == script:
            return "skylos"
        return shlex.quote(str(script))
    return f"{shlex.quote(sys.executable)} -m skylos.entry"


def _format_notes(notes, root: Path) -> str:
    shown = []
    for finding in notes[:MAX_NOTES]:
        location = (
            f"{_display_path(finding.get('path'), root)}:{finding.get('line') or '?'}"
        )
        message = _clean_message(finding.get("message"), MAX_NOTE_CHARS)
        shown.append(f"{location} {finding.get('rule_id')} {message}")
    more = f" (+{len(notes) - MAX_NOTES} more)" if len(notes) > MAX_NOTES else ""
    return (
        "Skylos notes (not blocking; fix only if relevant): "
        + "; ".join(shown)
        + more
    )


def _display_path(value: Any, root: Path) -> str:
    if not value:
        return "?"
    return _rel(Path(str(value)), root)


def _clean_message(value: Any, limit: int) -> str:
    text = _REDACTED_RE.sub("", str(value or ""))
    text = _WS_RE.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _cwd(payload: dict[str, Any], root: Path) -> Path:
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd and Path(cwd).is_dir():
        return Path(cwd)
    return root


def _abs_path(value: Any, base: Path) -> Path | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    path = Path(value.strip()).expanduser()
    if not path.is_absolute():
        path = base / path
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _keep_in_root(items: list[EditedFile], root: Path) -> list[EditedFile]:
    kept = []
    for item in items:
        try:
            item.path.relative_to(root)
        except ValueError:
            continue
        kept.append(item)
    return kept


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _in_ranges(line: int, ranges: list[tuple[int, int]] | None) -> bool:
    if ranges is None:
        return True
    return any(start <= line <= end for start, end in ranges)


def _merge_lines(lines: list[int]) -> list[tuple[int, int]]:
    return _merge_ranges([(n, n) for n in lines])


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _in_git_repo(root: Path) -> bool:
    return any((parent / ".git").exists() for parent in (root, *root.parents))


def user_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "skylos"


def _state_root(root: Path) -> Path:
    """Where session state and the log live for ``root``.

    Inside a Git repo that is the project itself (``.skylos/`` is gitignored
    by the installer). A user-level install can fire in any directory, so
    outside a repo the state goes under the user cache instead.
    """
    if _in_git_repo(root):
        return root
    digest = hashlib.sha256(str(root).encode()).hexdigest()[:16]
    base = user_cache_dir() / "projects" / digest
    with contextlib.suppress(OSError):
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base


def _log(root: Path | None, record: dict[str, Any]) -> None:
    """Append one JSON line to .skylos/hook.log; never raises, never logs content."""
    if root is None:
        return
    try:
        base = _state_root(root)
        log_dir = base / ".skylos"
        if log_dir.is_symlink():
            return
        log_dir.mkdir(exist_ok=True)
        path = base / LOG_PATH
        if path.is_symlink():
            return
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            os.replace(path, path.with_name("hook.log.1"))
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **record}
        fd = os.open(path, flags, 0o600)  # skylos: ignore[SKY-D215] fixed log path under selected project root; no-follow open
        try:
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except Exception:
        return


_HANDLERS = {
    "post-edit": _handle_post_edit,
    "pre-read": _handle_pre_read,
    "pre-bash": _handle_pre_bash,
    "stop": _handle_stop,
}
