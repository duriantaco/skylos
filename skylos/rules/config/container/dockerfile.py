# skylos: ignore[SKY-Q802] Concrete config rule modules are intentional leaf scanners.
from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.config.findings import config_finding
from skylos.security.command_guard import scan_shell_command


SKIP_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
MAX_DOCKERFILE_BYTES = 1_000_000
INSTRUCTION_RE = re.compile(r"^\s*(?P<instruction>[A-Z]+)(?:\s|$)", re.I)
RUN_OPTION_RE = re.compile(
    r"^--(?:mount|network|security)"
    r"(?:=(?:\"[^\"]*\"|'[^']*'|[^\s]+)|\s+(?:\"[^\"]*\"|'[^']*'|[^\s]+))"
    r"\s*"
)
SHELL_INTERPRETERS = {"bash", "dash", "ksh", "sh", "zsh"}
ADD_VALUE_FLAGS = {"--checksum", "--chown", "--chmod", "--exclude", "--keep-git-dir"}
SECRET_REFERENCE_SUFFIXES = ("_FILE", "_PATH", "_DIR", "_NAME", "_ARN")
REMOTE_URL_RE = re.compile(r"^https?://", re.I)
SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:"
    r"API_KEY|ACCESS_KEY|CLIENT_SECRET|CREDENTIALS?|PASSWORD|PASSWD|"
    r"PRIVATE_KEY|SECRET|TOKEN"
    r")(?:_|$)",
    re.I,
)


def _finding(
    *,
    rule_id: str,
    name: str,
    message: str,
    file: Path,
    line: int,
    severity: str,
    value: str,
) -> dict[str, Any]:
    return config_finding(
        rule_id=rule_id,
        domain="container",
        provider="dockerfile",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="container",
    )


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(
        ".dockerfile"
    )


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_dockerfile_scan_path(path: Path, *, root: Path | None = None) -> Path | None:
    candidate = Path(path).resolve()
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not candidate.is_file() or not _is_dockerfile(candidate):
        return None
    return candidate


def _discover_dockerfiles(root: Path, changed_files: set[str] | None) -> list[Path]:
    if root.is_file():
        candidate = _resolve_dockerfile_scan_path(root)
        return [candidate] if candidate is not None else []

    if changed_files is not None:
        candidates = []
        for raw_path in changed_files:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            candidate = _resolve_dockerfile_scan_path(path, root=root)
            if candidate is not None:
                candidates.append(candidate)
        return sorted(set(candidates))

    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if _is_dockerfile(path):
                candidates.append(path)
    return sorted(candidates)


def _iter_instructions(lines: list[str]) -> Iterator[tuple[int, str, str]]:
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = INSTRUCTION_RE.match(line)
        if not match:
            idx += 1
            continue

        instruction = match.group("instruction").upper()
        start_line = idx + 1
        body = line[match.end() :].strip()
        while _line_continues(lines[idx]) and idx + 1 < len(lines):
            body = body.rstrip().removesuffix("\\").rstrip()
            idx += 1
            body = f"{body} {lines[idx].strip()}".strip()

        yield start_line, instruction, body
        idx += 1


def _line_continues(line: str) -> bool:
    stripped = line.rstrip()
    return bool(stripped) and stripped.endswith("\\")


def _commands_from_run_body(body: str) -> Iterator[str]:
    stripped = _strip_run_options(body.strip())
    if not stripped:
        return

    json_command = _json_run_command(stripped)
    if json_command:
        yield json_command
        return

    yield stripped


def _add_sources_from_body(body: str) -> tuple[list[str], bool]:
    tokens = _instruction_tokens(body)
    if not tokens:
        return [], False

    sources: list[str] = []
    has_checksum = False
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token == "--checksum":
            has_checksum = True
            idx += 2
            continue
        if token.startswith("--checksum="):
            has_checksum = True
            idx += 1
            continue
        if token.startswith("--"):
            flag_name = token.split("=", 1)[0]
            if "=" in token or flag_name not in ADD_VALUE_FLAGS:
                idx += 1
            else:
                idx += 2
            continue
        sources.append(token)
        idx += 1

    if len(sources) <= 1:
        return [], has_checksum
    return sources[:-1], has_checksum


def _instruction_tokens(body: str) -> list[str]:
    stripped = body.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
            return raw
        return []
    return _shell_tokens(stripped)


def _secret_assignments_from_body(instruction: str, body: str) -> list[tuple[str, str]]:
    tokens = _instruction_tokens(body)
    if not tokens:
        return []

    assignments: list[tuple[str, str]] = []
    if instruction == "ARG":
        for token in tokens:
            if "=" not in token:
                continue
            name, value = token.split("=", 1)
            assignments.append((name, value))
        return assignments

    if instruction != "ENV":
        return []

    equals_tokens = [
        token for token in tokens if "=" in token and not token.startswith("=")
    ]
    if equals_tokens:
        for token in equals_tokens:
            name, value = token.split("=", 1)
            assignments.append((name, value))
        return assignments

    if len(tokens) >= 2:
        assignments.append((tokens[0], " ".join(tokens[1:])))
    return assignments


def _secret_value_is_literal(value: str) -> bool:
    raw = value.strip()
    if not raw:
        return False
    if raw.startswith("$"):
        return False
    return True


def _secret_name_is_sensitive(name: str) -> bool:
    normalized = name.strip()
    if not normalized:
        return False
    if normalized.upper().endswith(SECRET_REFERENCE_SUFFIXES):
        return False
    return SECRET_NAME_RE.search(normalized) is not None


def _scan_remote_add(
    findings: list[dict[str, Any]],
    *,
    file_path: Path,
    lines: list[str],
    line: int,
    body: str,
    ignore: set[str],
) -> None:
    rule_id = "SKY-D342"
    if rule_id in ignore or _is_inline_ignored(lines, line, rule_id):
        return
    sources, has_checksum = _add_sources_from_body(body)
    if has_checksum:
        return
    if not any(REMOTE_URL_RE.match(source) for source in sources):
        return
    findings.append(
        _finding(
            rule_id=rule_id,
            name="dockerfile-remote-add-without-checksum",
            message=(
                "Dockerfile ADD fetches a remote URL without a checksum. "
                "Download with a pinned digest/checksum or vendor the artifact."
            ),
            file=file_path,
            line=line,
            severity="HIGH",
            value="ADD remote URL",
        )
    )


def _scan_secret_build_values(
    findings: list[dict[str, Any]],
    *,
    file_path: Path,
    lines: list[str],
    line: int,
    instruction: str,
    body: str,
    ignore: set[str],
) -> None:
    rule_id = "SKY-D343"
    if rule_id in ignore or _is_inline_ignored(lines, line, rule_id):
        return
    for name, value in _secret_assignments_from_body(instruction, body):
        if not _secret_name_is_sensitive(name):
            continue
        if not _secret_value_is_literal(value):
            continue
        findings.append(
            _finding(
                rule_id=rule_id,
                name="dockerfile-literal-secret-build-value",
                message=(
                    f"Dockerfile {instruction} sets secret-looking `{name}` to a "
                    "literal value. Use build secrets or runtime secret injection "
                    "instead of baking credentials into image layers."
                ),
                file=file_path,
                line=line,
                severity="HIGH",
                value=f"{instruction} {name}",
            )
        )
        return


def _strip_run_options(body: str) -> str:
    stripped = body.lstrip()
    while stripped.startswith("--"):
        match = RUN_OPTION_RE.match(stripped)
        if match is None:
            break
        stripped = stripped[match.end() :].lstrip()
    return stripped


def _json_run_command(body: str) -> str | None:
    if not body.startswith("["):
        return None
    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        return None
    if len(raw) >= 3 and raw[0].rsplit("/", 1)[-1].lower() in SHELL_INTERPRETERS:
        if raw[1] in {"-c", "-lc", "-ec", "-euxc"}:
            return raw[2]
    return " ".join(shlex.quote(item) for item in raw)


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:
        return command.split()


def _is_inline_ignored(lines: list[str], line: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    for idx in (line - 2, line - 1):
        if 0 <= idx < len(lines) and needle in lines[idx]:
            return True
    return False


def scan_dockerfile_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    file_path = Path(path).resolve()
    root_path = Path(root).resolve() if root is not None else None
    if root_path is not None and not _is_under_root(file_path, root_path):
        return []

    text = read_text_no_symlink(file_path, max_bytes=MAX_DOCKERFILE_BYTES, encoding="utf-8")
    if text is None:
        return []

    ignored = ignore or set()
    lines = text.splitlines()
    findings: list[dict[str, Any]] = []
    for line, instruction, body in _iter_instructions(lines):
        if instruction == "RUN":
            for command in _commands_from_run_body(body):
                for risk in scan_shell_command(command):
                    if risk.rule_id in ignored or _is_inline_ignored(
                        lines, line, risk.rule_id
                    ):
                        continue
                    findings.append(
                        _finding(
                            rule_id=risk.rule_id,
                            name="dockerfile-run-command-risk",
                            message=risk.message,
                            file=file_path,
                            line=line,
                            severity=risk.severity,
                            value=risk.rule_id,
                        )
                    )
        elif instruction == "ADD":
            _scan_remote_add(
                findings,
                file_path=file_path,
                lines=lines,
                line=line,
                body=body,
                ignore=ignored,
            )
        elif instruction in {"ARG", "ENV"}:
            _scan_secret_build_values(
                findings,
                file_path=file_path,
                lines=lines,
                line=line,
                instruction=instruction,
                body=body,
                ignore=ignored,
            )
    return findings


def scan_dockerfiles(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_dockerfiles(root_path, changed_files):
        findings.extend(scan_dockerfile_file(file_path, root=root_path, ignore=ignore))
    return findings
