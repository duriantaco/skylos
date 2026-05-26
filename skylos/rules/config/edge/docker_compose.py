# skylos: ignore[SKY-Q802] Concrete config rule modules are intentional leaf scanners.
from __future__ import annotations

import logging
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from skylos.rules.config.findings import config_finding

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


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

COMPOSE_EXACT_NAMES = {
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
}
COMPOSE_SUFFIXES = {".yaml", ".yml"}
MAX_YAML_BYTES = 1_000_000
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000
logger = logging.getLogger(__name__)

HOST_CONTROL_PATHS = (
    "/dev",
    "/proc",
    "/run/docker.sock",
    "/run/udev",
    "/sys",
    "/var/run/docker.sock",
)
DEVICE_PATH_RE = re.compile(
    r"^/dev/(?:"
    r"video\d+|tty(?:USB|ACM|AMA|S|THS)?\d*|serial(?:/.*)?|"
    r"bus/usb(?:/.*)?|gpiochip\d*|i2c-\d+|spidev\d+\.\d+|"
    r"can\d+|nvhost.*|nvidia.*"
    r")(?:$|[:/])"
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
        domain="edge",
        provider="docker_compose",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="container",
    )


def _is_compose_file(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() not in COMPOSE_SUFFIXES:
        return False
    return (
        name in COMPOSE_EXACT_NAMES
        or name.startswith("compose.")
        or name.startswith("docker-compose.")
    )


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_compose_scan_path(
    path: str | Path,
    *,
    root: Path | None = None,
) -> Path | None:
    candidate = Path(path).resolve()
    if root is not None and not _is_under_root(candidate, root):
        return None
    if not candidate.is_file() or not _is_compose_file(candidate):
        return None
    return candidate


def _discover_compose_files(
    root: Path,
    changed_files: set[str] | None,
) -> list[Path]:
    if root.is_file():
        candidate = _resolve_compose_scan_path(root)
        return [candidate] if candidate is not None else []

    if changed_files is not None:
        candidates = []
        for raw_path in changed_files:
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            candidate = _resolve_compose_scan_path(path, root=root)
            if candidate is not None:
                candidates.append(candidate)
        return sorted(set(candidates))

    candidates: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        base = Path(current_root)
        for filename in filenames:
            path = base / filename
            if _is_compose_file(path):
                candidates.append(path)
    return sorted(candidates)


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if yaml is None:
        return None
    try:
        source = _read_limited_text(path, MAX_YAML_BYTES)
        if source is None:
            return None
        raw = yaml.safe_load(source)
    except Exception:
        logger.debug("Unable to parse Docker Compose YAML: %s", path, exc_info=True)
        return None
    if not isinstance(raw, dict):
        return None
    if not _yaml_graph_is_safe(raw):
        return None
    return raw


def _read_limited_text(path: Path, max_bytes: int) -> str | None:
    try:
        file_stat = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or path.is_symlink()
            or file_stat.st_size > max_bytes
        ):
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(  # skylos: ignore[SKY-D215] validated no-follow compose file
            path,
            flags,
        )
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_bytes + 1)
    except OSError:
        logger.debug("Unable to read Docker Compose file safely: %s", path, exc_info=True)
        return None


def _yaml_graph_is_safe(value: Any) -> bool:
    active: set[int] = set()
    visited: set[int] = set()
    node_count = [0]
    return _yaml_node_is_safe(value, 0, active, visited, node_count)


def _yaml_node_is_safe(
    value: Any,
    depth: int,
    active: set[int],
    visited: set[int],
    node_count: list[int],
) -> bool:
    if depth > MAX_YAML_GRAPH_DEPTH:
        return False
    node_count[0] += 1
    if node_count[0] > MAX_YAML_GRAPH_NODES:
        return False

    children = _yaml_children(value)
    if children is None:
        return True

    value_id = id(value)
    if value_id in active:
        return False
    if value_id in visited:
        return True

    active.add(value_id)
    safe = all(
        _yaml_node_is_safe(child, depth + 1, active, visited, node_count)
        for child in children
    )
    active.remove(value_id)
    visited.add(value_id)
    return safe


def _yaml_children(value: Any) -> tuple[Any, ...] | None:
    if isinstance(value, dict):
        return tuple(value.values())
    if isinstance(value, list):
        return tuple(value)
    return None


def _line_for_contains(lines: list[str], needle: str, *, start: int = 1) -> int:
    if not needle:
        return 1
    for lineno, line in enumerate(lines, 1):
        if lineno < start:
            continue
        if needle in line:
            return lineno
    return 1


def _line_for_service_field(
    lines: list[str],
    service_name: str,
    field: str,
) -> int:
    service_line = _line_for_contains(lines, f"{service_name}:")
    if service_line <= 0:
        service_line = 1
    pattern = re.compile(rf"^\s*{re.escape(field)}\s*:")
    line = _line_for_contains(lines, f"{field}:", start=service_line)
    if line != 1:
        return line
    for lineno, text in enumerate(lines, 1):
        if lineno < service_line:
            continue
        if pattern.search(text):
            return lineno
    return service_line


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


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _iter_services(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    services = data.get("services")
    if not isinstance(services, dict):
        return
    for name, service in services.items():
        if isinstance(service, dict):
            yield str(name), service


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                yield key
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)


def _iter_sequence(value: Any) -> Iterator[Any]:
    if isinstance(value, list):
        yield from value
    elif isinstance(value, (dict, str)):
        yield value


def _compose_path_parts(value: str) -> tuple[str, ...]:
    raw = value.strip()
    if not raw:
        return ()
    if raw.startswith("${"):
        return ()
    return tuple(part.strip() for part in raw.split(":") if part.strip())


def _compose_host_path(value: str) -> str:
    parts = _compose_path_parts(value)
    return parts[0] if parts else ""


def _path_is_host_control_path(value: str) -> bool:
    normalized = value.strip().rstrip("/")
    if not normalized or normalized.startswith("${"):
        return False
    if normalized in HOST_CONTROL_PATHS:
        return True
    if any(normalized.startswith(f"{prefix}/") for prefix in HOST_CONTROL_PATHS):
        return True
    return DEVICE_PATH_RE.match(normalized) is not None


def _iter_host_paths(entries: Any) -> Iterator[tuple[str, str]]:
    for entry in _iter_sequence(entries):
        if isinstance(entry, str):
            host_path = _compose_host_path(entry)
            if _path_is_host_control_path(host_path):
                yield host_path, entry
        elif isinstance(entry, dict):
            source = str(entry.get("source") or entry.get("src") or "")
            if _path_is_host_control_path(source):
                yield source, source


def _iter_device_like_refs(service: dict[str, Any]) -> Iterator[str]:
    for _, original in _iter_host_paths(service.get("devices")):
        yield original
    for _, original in _iter_host_paths(service.get("volumes")):
        yield original


def _has_gpu_runtime(service: dict[str, Any]) -> bool:
    runtime = str(service.get("runtime") or "").strip().lower()
    if runtime == "nvidia":
        return True
    if "gpus" in service:
        return True
    environment = service.get("environment")
    for value in _string_values(environment):
        if value.startswith("NVIDIA_") or "NVIDIA_VISIBLE_DEVICES" in value:
            return True
    return False


def _has_edge_runtime_context(service: dict[str, Any]) -> bool:
    if _has_gpu_runtime(service):
        return True
    image = str(service.get("image") or "").lower()
    service_text = " ".join(_string_values(service)).lower()
    markers = ("jetson", "l4t", "nvidia", "cuda", "ros:", "ros2")
    return any(marker in image or marker in service_text for marker in markers)


def _network_mode_is_host(service: dict[str, Any]) -> bool:
    return str(service.get("network_mode") or "").strip().lower() == "host"


def _scan_privileged_device_access(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    service_name: str,
    service: dict[str, Any],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D330"
    if rule_id in ignore:
        return
    refs = list(_iter_device_like_refs(service))
    if not _is_truthy(service.get("privileged")) or not (
        refs or _has_gpu_runtime(service)
    ):
        return
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Docker Compose privileged edge container",
            message=(
                f"Compose service `{service_name}` runs privileged with device or "
                "GPU access. Remove privileged mode and grant only required devices "
                "or capabilities."
            ),
            file=path,
            line=_line_for_service_field(lines, service_name, "privileged"),
            severity="HIGH",
            value=f"{service_name}:privileged",
        ),
    )


def _scan_host_control_mounts(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    service_name: str,
    service: dict[str, Any],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D331"
    if rule_id in ignore:
        return
    refs = list(_iter_device_like_refs(service))
    if not refs:
        return
    field = "devices" if "devices" in service else "volumes"
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Docker Compose host device exposure",
            message=(
                f"Compose service `{service_name}` exposes host device or control "
                "paths to the container. Keep mounts device-specific, read-only "
                "where possible, and avoid Docker socket or broad `/dev` access."
            ),
            file=path,
            line=_line_for_service_field(lines, service_name, field),
            severity="HIGH",
            value=f"{service_name}:{refs[0]}",
        ),
    )


def _scan_host_network_edge_service(
    path: Path,
    lines: list[str],
    findings: list[dict[str, Any]],
    service_name: str,
    service: dict[str, Any],
    ignore: set[str],
) -> None:
    rule_id = "SKY-D332"
    if rule_id in ignore:
        return
    if not _network_mode_is_host(service):
        return
    if not (_has_edge_runtime_context(service) or list(_iter_device_like_refs(service))):
        return
    _add_finding(
        findings,
        lines,
        _finding(
            rule_id=rule_id,
            name="Docker Compose host networking on edge service",
            message=(
                f"Compose service `{service_name}` uses host networking in an "
                "edge/device runtime. Bind only required ports and keep control "
                "services off untrusted networks."
            ),
            file=path,
            line=_line_for_service_field(lines, service_name, "network_mode"),
            severity="MEDIUM",
            value=f"{service_name}:network_mode=host",
        ),
    )


def scan_docker_compose_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve() if root is not None else None
    file_path = _resolve_compose_scan_path(path, root=root_path)
    if file_path is None:
        return []
    data = _load_yaml(file_path)
    if data is None:
        return []

    source = _read_limited_text(file_path, MAX_YAML_BYTES)
    lines = source.splitlines() if source is not None else []

    ignore = ignore or set()
    findings: list[dict[str, Any]] = []
    for service_name, service in _iter_services(data):
        _scan_privileged_device_access(
            file_path, lines, findings, service_name, service, ignore
        )
        _scan_host_control_mounts(
            file_path, lines, findings, service_name, service, ignore
        )
        _scan_host_network_edge_service(
            file_path, lines, findings, service_name, service, ignore
        )
    return findings


def scan_docker_compose(
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    for file_path in _discover_compose_files(root_path, changed_files):
        findings.extend(scan_docker_compose_file(file_path, root=root_path, ignore=ignore))
    return findings
