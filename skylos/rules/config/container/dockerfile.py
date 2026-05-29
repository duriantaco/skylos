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
RUN_RE = re.compile(r"^\s*RUN(?:\s|$)", re.I)
RUN_OPTION_RE = re.compile(
    r"^--(?:mount|network|security)"
    r"(?:=(?:\"[^\"]*\"|'[^']*'|[^\s]+)|\s+(?:\"[^\"]*\"|'[^']*'|[^\s]+))"
    r"\s*"
)
SHELL_INTERPRETERS = {"bash", "dash", "ksh", "sh", "zsh"}


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


def _iter_run_instructions(lines: list[str]) -> Iterator[tuple[int, str]]:
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if not RUN_RE.match(line):
            idx += 1
            continue

        start_line = idx + 1
        body = RUN_RE.sub("", line, count=1).strip()
        while _line_continues(lines[idx]) and idx + 1 < len(lines):
            body = body.rstrip().removesuffix("\\").rstrip()
            idx += 1
            body = f"{body} {lines[idx].strip()}".strip()

        yield start_line, body
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
    for line, body in _iter_run_instructions(lines):
        for command in _commands_from_run_body(body):
            for risk in scan_shell_command(command):
                if risk.rule_id in ignored or _is_inline_ignored(lines, line, risk.rule_id):
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
