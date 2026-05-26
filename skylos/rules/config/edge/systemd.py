# skylos: ignore[SKY-Q802] Concrete config rule modules are intentional leaf scanners.
from __future__ import annotations

import logging
import os
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skylos.rules.config.findings import config_finding


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

MAX_UNIT_BYTES = 512_000
UNIT_SUFFIXES = {".service"}
logger = logging.getLogger(__name__)
EDGE_MARKERS = (
    "camera",
    "can0",
    "cuda",
    "gpio",
    "gpiochip",
    "i2c",
    "jetson",
    "l4t",
    "nvargus",
    "nvidia",
    "robot",
    "ros2",
    "roslaunch",
    "spidev",
    "v4l2",
)
DANGEROUS_CAPABILITIES = {
    "CAP_DAC_OVERRIDE",
    "CAP_NET_ADMIN",
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
}
MUTABLE_EXEC_PREFIXES = (
    "/dev/shm/",
    "/home/",
    "/media/",
    "/mnt/",
    "/run/user/",
    "/tmp/",
    "/var/tmp/",
)
MUTABLE_EXEC_RE = re.compile(
    r"(?<!\S)[!+\-@]*(/(?:dev/shm|home|media|mnt|run/user|tmp|var/tmp)/[^\s;|&]+)"
)


@dataclass(frozen=True)
class UnitEntry:
    section: str
    key: str
    value: str
    line: int


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
        domain="edge",
        provider="systemd",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="service",
    )


def _is_systemd_service_file(path: Path) -> bool:
    return path.suffix.lower() in UNIT_SUFFIXES


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_systemd_scan_path(
    path: str | Path,
    *,
    root: Path | None = None,
) -> Path | None:
    candidate = Path(path).resolve()
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not candidate.is_file() or not _is_systemd_service_file(candidate):
        return None
    return candidate


def _discover_systemd_files(
    root: Path,
    changed_files: set[str] | None,
) -> list[Path]:
    if root.is_file():
        candidate = _resolve_systemd_scan_path(root)
        return [candidate] if candidate is not None else []

    if changed_files is not None:
        candidates = []
        for raw_path in changed_files:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            candidate = _resolve_systemd_scan_path(path, root=root)
            if candidate is not None:
                candidates.append(candidate)
        return sorted(set(candidates))

    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if _is_systemd_service_file(path):
                candidates.append(path)
    return sorted(candidates)


def _read_unit_lines(path: Path) -> list[str] | None:
    try:
        file_stat = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or path.is_symlink()
            or file_stat.st_size > MAX_UNIT_BYTES
        ):
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(  # skylos: ignore[SKY-D215] validated no-follow systemd unit
            path,
            flags,
        )
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_UNIT_BYTES + 1).splitlines()
    except OSError:
        logger.debug("Unable to read systemd unit safely: %s", path, exc_info=True)
        return None


def _parse_unit(lines: list[str]) -> list[UnitEntry]:
    section = ""
    entries: list[UnitEntry] = []
    continuation = ""
    continuation_line = 0

    for lineno, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continuation = ""
            continuation_line = 0
            continue

        if continuation:
            continuation += stripped
            if continuation.endswith("\\"):
                continuation = continuation[:-1].rstrip()
                continue
            _append_entry(entries, section, continuation, continuation_line)
            continuation = ""
            continuation_line = 0
            continue

        if stripped.endswith("\\"):
            continuation = stripped[:-1].rstrip()
            continuation_line = lineno
            continue

        _append_entry(entries, section, stripped, lineno)

    if continuation:
        _append_entry(entries, section, continuation, continuation_line or 1)
    return entries


def _append_entry(
    entries: list[UnitEntry],
    section: str,
    stripped_line: str,
    line: int,
) -> None:
    if "=" not in stripped_line:
        return
    key, value = stripped_line.split("=", 1)
    key = key.strip()
    if not key:
        return
    entries.append(UnitEntry(section, key, value.strip(), line))


def _service_entries(entries: list[UnitEntry]) -> list[UnitEntry]:
    return [entry for entry in entries if entry.section == "service"]


def _values(entries: list[UnitEntry], key: str) -> list[UnitEntry]:
    return [entry for entry in entries if entry.key.lower() == key.lower()]


def _first_value(entries: list[UnitEntry], key: str) -> UnitEntry | None:
    values = _values(entries, key)
    return values[-1] if values else None


def _service_name(path: Path, entries: list[UnitEntry]) -> str:
    description = _first_value(entries, "Description")
    if description is not None and description.value:
        return description.value
    return path.name


def _edge_context(path: Path, entries: list[UnitEntry]) -> bool:
    text = " ".join([path.name, *(entry.value for entry in entries)]).lower()
    if any(marker in text for marker in EDGE_MARKERS):
        return True
    if "/dev/" in text:
        return True
    return "--device" in text or "--runtime=nvidia" in text or "network=host" in text


def _runs_as_root(service_entries: list[UnitEntry]) -> tuple[bool, UnitEntry | None]:
    user = _first_value(service_entries, "User")
    if user is None:
        return True, None
    return user.value.strip().lower() in {"", "0", "root"}, user


def _entry_line(entry: UnitEntry | None) -> int:
    return entry.line if entry is not None else 1


def _is_inline_ignored(lines: list[str], line: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    for idx in (line - 2, line - 1):
        if 0 <= idx < len(lines) and needle in lines[idx]:
            return True
    return False


def _add_finding(
    findings: list[dict[str, Any]],
    lines: list[str],
    finding: dict[str, Any],
) -> None:
    if _is_inline_ignored(lines, int(finding.get("line", 1)), str(finding["rule_id"])):
        return
    findings.append(finding)


def _exec_values(service_entries: list[UnitEntry]) -> list[UnitEntry]:
    return [
        entry
        for entry in service_entries
        if entry.key.lower()
        in {"execstart", "execstartpre", "execstartpost", "execreload"}
    ]


def _strip_systemd_exec_prefix(command: str) -> str:
    stripped = command.strip()
    while stripped and stripped[0] in "-+!@":
        stripped = stripped[1:].lstrip()
    return stripped


def _exec_path(command: str) -> str:
    stripped = _strip_systemd_exec_prefix(command)
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        tokens = stripped.split()
    return tokens[0] if tokens else ""


def _mutable_exec_path(command: str) -> str:
    executable = _exec_path(command)
    if executable.startswith(MUTABLE_EXEC_PREFIXES):
        return executable
    match = MUTABLE_EXEC_RE.search(command)
    return match.group(1) if match else ""


def _systemd_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _has_no_new_privileges(service_entries: list[UnitEntry]) -> bool:
    entry = _first_value(service_entries, "NoNewPrivileges")
    return entry is not None and _systemd_bool(entry.value)


def _has_protect_system(service_entries: list[UnitEntry]) -> bool:
    entry = _first_value(service_entries, "ProtectSystem")
    return entry is not None and entry.value.strip().lower() in {"full", "strict"}


def _has_private_tmp(service_entries: list[UnitEntry]) -> bool:
    entry = _first_value(service_entries, "PrivateTmp")
    return entry is not None and _systemd_bool(entry.value)


def _broad_privilege_entry(service_entries: list[UnitEntry]) -> UnitEntry | None:
    for entry in service_entries:
        key = entry.key.lower()
        value = entry.value.strip()
        upper_value = value.upper()
        if key == "ambientcapabilities":
            caps = set(re.findall(r"CAP_[A-Z0-9_]+", upper_value))
            if caps & DANGEROUS_CAPABILITIES:
                return entry
        if key == "capabilityboundingset":
            # A leading "~" removes the listed capabilities from the bounding
            # set, so it is a hardening pattern rather than a broad grant.
            if value.startswith("~"):
                continue
            caps = set(re.findall(r"CAP_[A-Z0-9_]+", upper_value))
            if caps & DANGEROUS_CAPABILITIES:
                return entry
        if key == "deviceallow":
            lowered = value.lower()
            if lowered in {"*", "/dev/*", "char-*", "block-*"}:
                return entry
            if lowered.startswith(("/dev/*", "char-*", "block-*")):
                return entry
    for entry in _exec_values(service_entries):
        if re.search(r"\bdocker\s+run\b.*\s--privileged(?:\s|$)", entry.value):
            return entry
    return None


def _scan_root_edge_service(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    entries: list[UnitEntry],
    service_entries: list[UnitEntry],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D333"
    if rule_id in ignore:
        return
    runs_as_root, user_entry = _runs_as_root(service_entries)
    if not runs_as_root:
        return
    exec_entry = _first_value(service_entries, "ExecStart")
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Systemd edge service runs as root",
            message=(
                f"Systemd service `{_service_name(path, entries)}` runs with root "
                "privileges in an edge/device context. Set a dedicated non-root "
                "`User=` where device access does not require root."
            ),
            file=path,
            line=_entry_line(user_entry or exec_entry),
            severity="HIGH",
            value=f"{path.name}:User=root",
        ),
    )


def _scan_mutable_exec_path(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    entries: list[UnitEntry],
    service_entries: list[UnitEntry],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D334"
    if rule_id in ignore:
        return
    runs_as_root, _ = _runs_as_root(service_entries)
    if not runs_as_root:
        return
    for entry in _exec_values(service_entries):
        mutable_path = _mutable_exec_path(entry.value)
        if not mutable_path:
            continue
        _add_finding(
            findings,
            lines,
            _finding(
                rule_id=rule_id,
                name="Systemd root service executes mutable path",
                message=(
                    f"Systemd service `{_service_name(path, entries)}` runs as root "
                    f"and executes `{mutable_path}` from a user-writable location. "
                    "Move the executable under a root-owned directory and lock down "
                    "file permissions."
                ),
                file=path,
                line=entry.line,
                severity="HIGH",
                value=f"{path.name}:{mutable_path}",
            ),
        )
        return


def _scan_missing_sandboxing(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    entries: list[UnitEntry],
    service_entries: list[UnitEntry],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D335"
    if rule_id in ignore:
        return
    runs_as_root, _ = _runs_as_root(service_entries)
    if not runs_as_root:
        return
    missing = []
    if not _has_no_new_privileges(service_entries):
        missing.append("NoNewPrivileges=true")
    if not _has_protect_system(service_entries):
        missing.append("ProtectSystem=full or strict")
    if not _has_private_tmp(service_entries):
        missing.append("PrivateTmp=true")
    if not missing:
        return
    exec_entry = _first_value(service_entries, "ExecStart")
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Systemd edge service missing sandboxing",
            message=(
                f"Systemd service `{_service_name(path, entries)}` is an edge/device "
                f"service without common sandboxing controls: {', '.join(missing)}."
            ),
            file=path,
            line=_entry_line(exec_entry),
            severity="MEDIUM",
            value=f"{path.name}:sandboxing",
        ),
    )


def _scan_broad_privileges(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    entries: list[UnitEntry],
    service_entries: list[UnitEntry],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D336"
    if rule_id in ignore:
        return
    privilege_entry = _broad_privilege_entry(service_entries)
    if privilege_entry is None:
        return
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Systemd broad edge service privilege",
            message=(
                f"Systemd service `{_service_name(path, entries)}` grants broad "
                "capability, device, or privileged container access. Reduce it to "
                "the specific devices and capabilities required."
            ),
            file=path,
            line=privilege_entry.line,
            severity="HIGH",
            value=f"{path.name}:{privilege_entry.key}",
        ),
    )


def scan_systemd_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve() if root is not None else None
    file_path = _resolve_systemd_scan_path(path, root=root_path)
    if file_path is None:
        return []
    lines = _read_unit_lines(file_path)
    if lines is None:
        return []

    entries = _parse_unit(lines)
    service_entries = _service_entries(entries)
    if not service_entries or not _edge_context(file_path, entries):
        return []

    ignore = ignore or set()
    findings: list[dict[str, Any]] = []
    _scan_root_edge_service(file_path, lines, findings, entries, service_entries, ignore)
    _scan_mutable_exec_path(file_path, lines, findings, entries, service_entries, ignore)
    _scan_missing_sandboxing(
        file_path, lines, findings, entries, service_entries, ignore
    )
    _scan_broad_privileges(file_path, lines, findings, entries, service_entries, ignore)
    return findings


def scan_systemd(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_systemd_files(root_path, changed_files):
        findings.extend(scan_systemd_file(file_path, root=root_path, ignore=ignore))
    return findings
