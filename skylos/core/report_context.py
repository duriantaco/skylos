"""Local context for ``skylos feedback``: what failed last, with paths and
secrets masked.

Nothing in this module touches the network. ``skylos feedback`` only builds a
URL and hands it to the browser. Loading the page gives skylos.dev the URL's
masked context; the user's message is sent only when they press Send there.

The only file written is ``~/.skylos/last_error.json`` (mode 0600, never
through a symlink): the last command that exited with code 2 or more, or
crashed, as ``skylos <path> -a --format json`` style text. It never holds file
paths, tokens, exception messages, code or environment variables, and records
older than 24 hours are ignored. Recording is skipped for ``skylos hook`` (it
runs on every agent edit) and ``skylos feedback`` itself, and switched off
entirely by ``SKYLOS_FEEDBACK_CONTEXT=0``.

(Not ``feedback.py``: ``skylos/llm/feedback.py`` is unrelated verifier
weighting.)
"""

from __future__ import annotations

import json
import os
import platform
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

FEEDBACK_URL = "https://skylos.dev/feedback"
GITHUB_NEW_ISSUE_URL = "https://github.com/duriantaco/skylos/issues/new"

DISABLE_ENV = "SKYLOS_FEEDBACK_CONTEXT"
RECORD_DIRNAME = ".skylos"
RECORD_NAME = "last_error.json"
RECORD_SCHEMA = 1
RECORD_MAX_AGE_SECONDS = 24 * 60 * 60
RECORD_MAX_BYTES = 4096
# Commands that never leave a record: hooks run on every agent edit, and
# reporting a problem must not overwrite the problem being reported.
UNRECORDED_COMMANDS = frozenset({"hook", "feedback"})
# Ctrl+C conventionally exits 130: the user stopped it, nothing failed.
UNRECORDED_EXIT_CODES = frozenset({130})

COMMAND_MAX_CHARS = 300
TOKEN_MAX_CHARS = 40
URL_MAX_CHARS = 1800
FIELD_MAX_CHARS = 64
ERROR_TYPE_MAX_CHARS = 80
FRAME_MAX_CHARS = 200

KINDS = ("bug", "wrong-finding", "idea", "question")
_KIND_PARAM = {
    "bug": "bug",
    "wrong-finding": "wrong_finding",
    "idea": "idea",
    "question": "question",
}
_GITHUB_TEMPLATE = {
    "bug": "bug_report.yml",
    "question": "bug_report.yml",
    "wrong-finding": "false_positive.yml",
    "idea": "feature_request.yml",
}

PATH_MASK = "<path>"
SECRET_MASK = "<redacted>"
URL_MASK = "<url>"
ELLIPSIS = "…"

_SENSITIVE_FLAG_RE = re.compile(
    r"token|key|secret|passw|auth|api|webhook|header|cookie|url|credential",
    re.IGNORECASE,
)
_DRIVE_RE = re.compile(r"^[A-Za-z]:(?:[\\/]|$)")
_FILE_IN_DIR_RE = re.compile(r"/[^/]*\.[A-Za-z0-9]{1,8}$")
_TOKEN_PREFIX_RE = re.compile(
    r"^(?:sk[-_]|rk_|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|"
    r"npm_|pypi-|hf_|AKIA|ASIA|AIza|eyJ)",
)
_TOKEN_CHARSET_RE = re.compile(r"^[A-Za-z0-9_\-+/=.:]+$")
_CI_MARKERS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "TF_BUILD",
    "BITBUCKET_BUILD_NUMBER",
)


def _cut(value: str, limit: int) -> str:
    value = str(value)
    if len(value) <= limit:
        return value
    return value[: max(limit - 1, 0)] + ELLIPSIS


def _looks_like_path(value: str, exists: Callable[[str], bool]) -> bool:
    if value.startswith(("/", "~", "./", "../", ".\\", "..\\")):
        return True
    if "\\" in value or _DRIVE_RE.match(value):
        return True
    if _FILE_IN_DIR_RE.search(value):
        return True
    try:
        return bool(exists(value))
    except (OSError, ValueError):
        return False


def _looks_like_token(value: str) -> bool:
    if len(value) >= 12 and _TOKEN_PREFIX_RE.match(value):
        return True
    if len(value) < 24 or not _TOKEN_CHARSET_RE.match(value):
        return False
    return any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value)


def _mask_value(value: str, exists: Callable[[str], bool]) -> str:
    if not value:
        return value
    if "://" in value or value.lower().startswith(("http:", "https:", "git@")):
        return URL_MASK
    if _looks_like_path(value, exists):
        return PATH_MASK
    if _looks_like_token(value):
        return SECRET_MASK
    return _cut(value, TOKEN_MAX_CHARS)


def _mask_flag_name(name: str, exists: Callable[[str], bool]) -> str:
    if not name.startswith("--") and len(name) > 2:
        # ``-o/tmp/out.json``: a short option with its value attached.
        return name[:2] + _mask_value(name[2:], exists)
    if "/" in name or "\\" in name or _looks_like_token(name):
        return SECRET_MASK
    return _cut(name, TOKEN_MAX_CHARS)


def _redact_text(text: str) -> str:
    try:
        from skylos.audit.redaction import redact_text
    except ImportError:  # pragma: no cover - the module ships with skylos
        return text
    return redact_text(text)


def _mask_flag(token: str, exists: Callable[[str], bool]) -> tuple[str, bool]:
    """The masked flag, and whether the next token is its secret value."""

    name, separator, value = token.partition("=")
    sensitive = bool(_SENSITIVE_FLAG_RE.search(name))
    shown = _mask_flag_name(name, exists)
    if not separator:
        return shown, sensitive
    masked = SECRET_MASK if sensitive else _mask_value(value, exists)
    return f"{shown}={masked}", False


def redact_argv(
    argv: Sequence[str],
    *,
    exists: Callable[[str], bool] = os.path.exists,
) -> str:
    """Turn ``sys.argv`` into a command line safe to show and send.

    ``argv[0]`` becomes ``skylos``; flags are kept; the value of any flag
    named like a credential or URL becomes ``<redacted>``; anything that looks
    like a path (exists on disk, absolute, ``~``, ``./``, a drive letter, a
    backslash, or ``dir/file.ext``) becomes ``<path>``; URLs become ``<url>``;
    token-shaped values become ``<redacted>``; other values are cut to 40
    characters. The result is capped at 300 characters.
    """

    parts = ["skylos"]
    secret_value_next = False
    for raw in list(argv)[1:]:
        token = str(raw)
        if secret_value_next and not token.startswith("--"):
            # The secret's value (it may itself start with a single dash).
            parts.append(SECRET_MASK)
            secret_value_next = False
        elif token.startswith("-") and token not in {"-", "--"}:
            shown, secret_value_next = _mask_flag(token, exists)
            parts.append(shown)
        else:
            secret_value_next = False
            parts.append(token if token == "--" else _mask_value(token, exists))
    return _cut(_redact_text(" ".join(parts)), COMMAND_MAX_CHARS)


def _os_label() -> str:
    system = platform.system()
    machine = platform.machine() or "unknown"
    if system == "Darwin":
        release = platform.mac_ver()[0] or platform.release()
        label = f"macOS {release} ({machine})"
    elif system == "Windows":
        label = f"Windows {platform.release()} ({machine})"
    elif system:
        label = f"{system} {platform.release()} ({machine})"
    else:
        label = "unknown"
    return _cut(_redact_text(label), FIELD_MAX_CHARS)


def environment_summary() -> dict[str, str]:
    """The Skylos version, OS and Python version: nothing else."""

    try:
        import skylos

        version = str(skylos.__version__)
    except (ImportError, AttributeError):  # pragma: no cover - defensive
        version = "unknown"
    return {
        "version": _cut(version, FIELD_MAX_CHARS),
        "os": _os_label(),
        "python": _cut(platform.python_version(), FIELD_MAX_CHARS),
    }


def recording_disabled(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return str(env.get(DISABLE_ENV, "")).strip() == "0"


def is_ci(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    for name in _CI_MARKERS:
        value = str(env.get(name) or "").strip().lower()
        if value and value not in {"0", "false", "no"}:
            return True
    return False


def record_path(home: str | os.PathLike[str] | None = None) -> Path | None:
    """``~/.skylos/last_error.json`` with the home directory resolved.

    The home directory itself may sit behind a system symlink (macOS temp
    homes live under ``/var`` → ``/private/var``); it is resolved once here so
    the no-symlink writer can refuse links below it.
    """

    try:
        base = Path(home) if home is not None else Path.home()
        return Path(os.path.realpath(base)) / RECORD_DIRNAME / RECORD_NAME
    except (OSError, RuntimeError, ValueError):
        return None


def should_record(
    argv: Sequence[str], environ: Mapping[str, str] | None = None
) -> bool:
    command = str(argv[1]) if len(argv) > 1 else ""
    return not recording_disabled(environ) and command not in UNRECORDED_COMMANDS


def _write_record(path: Path, payload: dict) -> bool:
    from skylos.core.safe_cache_io import write_text_no_symlink

    directory = path.parent
    if directory.is_symlink():
        return False
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir() or path.is_symlink():
        return False
    temporary = directory / f".{RECORD_NAME}.{os.getpid()}.tmp"
    try:
        temporary.unlink(missing_ok=True)
        if not write_text_no_symlink(temporary, json.dumps(payload, sort_keys=True)):
            return False
        os.replace(temporary, path)
        return True
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def record_failure(
    argv: Sequence[str],
    exit_code: int,
    *,
    error_type: str | None = None,
    skylos_frame: str | None = None,
    now: float | None = None,
    home: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Remember the failed command for ``skylos feedback``. Never raises."""

    try:
        if not should_record(argv, environ) or exit_code in UNRECORDED_EXIT_CODES:
            return False
        path = record_path(home)
        if path is None:
            return False
        payload = {
            "schema": RECORD_SCHEMA,
            "ts": int(time.time() if now is None else now),
            "version": environment_summary()["version"],
            "command": redact_argv(argv),
            "exit_code": int(exit_code),
            "error_type": _cut(error_type, ERROR_TYPE_MAX_CHARS)
            if error_type
            else None,
            "skylos_frame": _cut(skylos_frame, FRAME_MAX_CHARS)
            if skylos_frame
            else None,
        }
        return _write_record(path, payload)
    except Exception:  # noqa: BLE001 - recording must never change a run's outcome
        return False


def _optional_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return _cut(_redact_text(value.strip()), limit)


def _read_record(home: str | os.PathLike[str] | None) -> object:
    from skylos.core.safe_cache_io import read_text_no_symlink

    try:
        path = record_path(home)
        if path is None or path.parent.is_symlink():
            return None
        text = read_text_no_symlink(path, max_bytes=RECORD_MAX_BYTES)
        return None if text is None else json.loads(text)
    except (OSError, ValueError):
        return None


def load_last_failure(
    *,
    now: float | None = None,
    home: str | os.PathLike[str] | None = None,
) -> dict | None:
    """The last recorded failure, or None (missing, unreadable, corrupt, a
    symlink, from another schema, or older than 24 hours)."""

    data = _read_record(home)
    if not isinstance(data, dict) or data.get("schema") != RECORD_SCHEMA:
        return None
    ts = data.get("ts")
    exit_code = data.get("exit_code")
    command = _optional_text(data.get("command"), COMMAND_MAX_CHARS)
    well_formed = (
        isinstance(ts, (int, float))
        and not isinstance(ts, bool)
        and isinstance(exit_code, int)
        and not isinstance(exit_code, bool)
        and command is not None
        and command.startswith("skylos")
    )
    if not well_formed:
        return None
    age = (time.time() if now is None else now) - cast(float, ts)
    # A record from the future (clock skew beyond five minutes) is untrusted.
    if not -300 <= age <= RECORD_MAX_AGE_SECONDS:
        return None
    return {
        "ts": ts,
        "age_seconds": max(int(age), 0),
        "command": command,
        "exit_code": exit_code,
        "error_type": _optional_text(data.get("error_type"), ERROR_TYPE_MAX_CHARS),
        "skylos_frame": _optional_text(data.get("skylos_frame"), FRAME_MAX_CHARS),
    }


def describe_age(seconds: int) -> str:
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} h ago"


def _fit_url(base: str, params: list[tuple[str, str]], shrink_key: str) -> str:
    """Encode ``params``; if the URL is over 1,800 characters, cut the
    ``shrink_key`` value (ending it with an ellipsis), then drop optional
    trailing values until it fits."""

    def build(items: list[tuple[str, str]]) -> str:
        return f"{base}?{urlencode(items)}"

    url = build(params)
    if len(url) <= URL_MAX_CHARS:
        return url
    items = list(params)
    for index, (key, value) in enumerate(items):
        if key != shrink_key:
            continue
        keep = len(value)
        while keep > 0 and len(build(items)) > URL_MAX_CHARS:
            keep = max(keep - 20, 0)
            items[index] = (key, value[:keep] + ELLIPSIS)
        break
    while len(build(items)) > URL_MAX_CHARS and len(items) > 1:
        items.pop()
    return build(items)


def build_feedback_url(
    env: Mapping[str, str],
    failure: Mapping[str, object] | None = None,
    *,
    kind: str | None = None,
) -> str:
    params: list[tuple[str, str]] = [("src", "cli")]
    if kind and kind != "bug":
        params.append(("type", _KIND_PARAM.get(kind, "bug")))
    params += [
        ("v", str(env.get("version", ""))),
        ("os", str(env.get("os", ""))),
        ("py", str(env.get("python", ""))),
    ]
    if failure:
        params += [
            ("cmd", str(failure.get("command") or "")),
            ("exit", str(failure.get("exit_code"))),
        ]
        if failure.get("error_type"):
            params.append(("err", str(failure["error_type"])))
        if failure.get("skylos_frame"):
            params.append(("frame", str(failure["skylos_frame"])))
    return _fit_url(FEEDBACK_URL, params, "cmd")


def _failure_summary(failure: Mapping[str, object]) -> str:
    summary = f"{failure.get('command')} (exit {failure.get('exit_code')}"
    if failure.get("error_type"):
        where = failure.get("skylos_frame")
        summary += f"; {failure['error_type']}" + (f" at {where}" if where else "")
    return summary + ")"


def build_github_issue_url(
    env: Mapping[str, str],
    failure: Mapping[str, object] | None = None,
    *,
    kind: str | None = None,
) -> str:
    """A prefilled GitHub issue form. Never ``labels=`` or ``assignees=``:
    GitHub answers 404 to non-collaborators who send them (the forms set
    their own labels)."""

    kind = kind or "bug"
    template = _GITHUB_TEMPLATE.get(kind, "bug_report.yml")
    params: list[tuple[str, str]] = [("template", template)]
    if template == "feature_request.yml":
        return _fit_url(GITHUB_NEW_ISSUE_URL, params, "")
    params.append(("version", str(env.get("version", ""))))
    if template == "bug_report.yml":
        params += [
            ("os", str(env.get("os", ""))),
            ("python", str(env.get("python", ""))),
        ]
        if failure:
            params.append(("command", _failure_summary(failure)))
    return _fit_url(GITHUB_NEW_ISSUE_URL, params, "command")
