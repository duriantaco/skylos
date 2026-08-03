# skylos: ignore[SKY-Q502] Cross-layer deployment proof is one bounded scanner.
from __future__ import annotations

import ast
import io
import logging
import os
import re
import stat
import tokenize
from dataclasses import dataclass
from functools import lru_cache
from itertools import islice
from pathlib import Path
from typing import Any, Iterator

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.findings import config_finding

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


if yaml is not None:

    class _UniqueKeySafeLoader(yaml.SafeLoader):
        pass

    def _construct_unique_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )
else:  # pragma: no cover - guarded by scan_deployment_exposure.
    _UniqueKeySafeLoader = None


logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_MANIFEST_BYTES = 64_000_000
MAX_MANIFEST_FILES = 2_000
MAX_DISCOVERED_MANIFESTS = 20_000
MAX_WALKED_DIRECTORIES = 10_000
MAX_DOCUMENTS_PER_FILE = 256
MAX_YAML_GRAPH_DEPTH = 100
MAX_YAML_GRAPH_NODES = 50_000
MAX_REQUIRED_GUARDS = 32

SKIP_DIR_NAMES = {
    ".cache",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
DEPLOYMENT_DIR_NAMES = {
    "deploy",
    "deployment",
    "deployments",
    "k8s",
    "kubernetes",
    "manifests",
}
PROJECT_MARKERS = (".git", ".skylos", "pyproject.toml")

EXPOSURE_SCOPE_ANNOTATION = "skylos.dev/network-scope"
BACKEND_PROTOCOL_ANNOTATION = "skylos.dev/backend-protocol"
SOURCE_FILE_ANNOTATION = "skylos.dev/source-file"
REQUIRED_GUARDS_ANNOTATION = "skylos.dev/required-guards"
EXTERNAL_SCOPE_VALUES = {"external", "internet", "public"}

WORKLOAD_API_VERSIONS = {
    "DaemonSet": "apps/v1",
    "Deployment": "apps/v1",
    "Pod": "v1",
    "ReplicaSet": "apps/v1",
    "StatefulSet": "apps/v1",
}
FASTAPI_ROUTE_METHODS = {
    "api_route",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "trace",
    "websocket",
}
FLASK_ROUTE_METHODS = {"delete", "get", "patch", "post", "put", "route"}
SENSITIVE_ROUTE_SEGMENTS = {
    "actuator",
    "admin",
    "debug",
    "internal",
    "manage",
    "management",
    "metrics",
    "pprof",
}
DEPENDENCY_CALLS = {"Depends", "Security"}
SERVER_EXECUTABLES = {"flask", "gunicorn", "uvicorn"}
PYTHON_EXECUTABLE_RE = re.compile(r"^python(?:3(?:\.\d+)?)?$")
TARGET_RE = re.compile(
    r"^(?P<module>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*):"
    r"(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)$"
)
SAFE_GUARD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


@dataclass(frozen=True)
class _TextFile:
    path: Path
    text: str
    lines: tuple[str, ...]


@dataclass(frozen=True)
class _IngressPath:
    file: _TextFile
    line: int
    start_line: int
    end_line: int
    namespace: str
    ingress_name: str
    host: str
    path: str
    path_type: str
    service_name: str
    service_port: str | int


@dataclass(frozen=True)
class _ServicePort:
    name: str | None
    port: int
    target_port: str | int


@dataclass(frozen=True)
class _Service:
    file: _TextFile
    line: int
    start_line: int
    end_line: int
    namespace: str
    name: str
    selector: tuple[tuple[str, str], ...]
    ports: tuple[_ServicePort, ...]


@dataclass(frozen=True)
class _Container:
    name: str
    image: str
    command: tuple[str, ...]
    ports: tuple[tuple[str | None, int], ...]
    line: int
    end_line: int


@dataclass(frozen=True)
class _Workload:
    file: _TextFile
    line: int
    start_line: int
    end_line: int
    namespace: str
    kind: str
    name: str
    labels: tuple[tuple[str, str], ...]
    containers: tuple[_Container, ...]
    source_file: str | None
    required_guards: tuple[str, ...]
    source_line: int | None
    contract_line: int | None


@dataclass(frozen=True)
class _Entrypoint:
    server: str
    module: str
    symbol: str
    host: str
    port: int


@dataclass(frozen=True)
class _Route:
    file: _TextFile
    line: int
    method: str
    path: str
    handler: str
    guards: tuple[str, ...]


@dataclass(frozen=True)
class _ProofChain:
    ingress: _IngressPath
    service: _Service
    workload: _Workload
    container: _Container
    service_port: _ServicePort


def _is_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _infer_project_root(manifest: Path) -> Path:
    parents = [manifest.parent, *manifest.parents[1:8]]
    for candidate in parents:
        try:
            if any((candidate / marker).exists() for marker in PROJECT_MARKERS):
                return candidate.resolve(strict=True)
        except OSError:
            continue
    if manifest.parent.name.lower() in DEPLOYMENT_DIR_NAMES:
        return manifest.parent.parent.resolve(strict=True)
    return manifest.parent.resolve(strict=True)


def _normalize_scan_target(root: str | Path) -> tuple[Path, Path | None] | None:
    candidate = Path(root).expanduser()
    try:
        if candidate.is_symlink():
            return None
        requested = candidate.resolve(strict=True)
    except OSError:
        return None
    if requested.is_dir():
        return requested, None
    if requested.is_file() and requested.suffix.lower() in {".yaml", ".yml"}:
        return _infer_project_root(requested), requested
    return None


def _normalize_changed_paths(root: Path, changed_files: set[str]) -> set[Path]:
    normalized: set[Path] = set()
    for raw_path in changed_files:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=False)
        except OSError:
            continue
        if _is_under_root(resolved, root):
            normalized.add(resolved)
    return normalized


def _manifest_priority(path: Path, root: Path) -> tuple[int, str]:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    parts = {part.lower() for part in relative.parts[:-1]}
    name = path.name.lower()
    likely = bool(parts & DEPLOYMENT_DIR_NAMES) or any(
        marker in name for marker in ("k8s", "kubernetes", "manifest", "rendered")
    )
    return (0 if likely else 1, relative.as_posix())


def _discover_manifest_paths(root: Path, direct_file: Path | None) -> list[Path]:
    if direct_file is not None:
        return [direct_file]

    candidates: list[Path] = []
    walked_directories = 0
    for current_root, dirnames, filenames in os.walk(root, followlinks=False):
        walked_directories += 1
        if walked_directories > MAX_WALKED_DIRECTORIES:
            break
        base = Path(current_root)
        safe_dirs: list[str] = []
        for dirname in sorted(dirnames):
            directory = base / dirname
            try:
                if dirname not in SKIP_DIR_NAMES and not directory.is_symlink():
                    safe_dirs.append(dirname)
            except OSError:
                continue
        dirnames[:] = safe_dirs

        for filename in filenames:
            path = base / filename
            if path.suffix.lower() in {".yaml", ".yml"}:
                candidates.append(path)
                if len(candidates) >= MAX_DISCOVERED_MANIFESTS:
                    break
        if len(candidates) >= MAX_DISCOVERED_MANIFESTS:
            break
    candidates.sort(key=lambda path: _manifest_priority(path, root))
    return candidates[:MAX_MANIFEST_FILES]


def _read_text_file(root: Path, path: Path) -> _TextFile | None:
    try:
        file_stat = path.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        path.is_symlink()
        or not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_size > MAX_FILE_BYTES
    ):
        return None
    source = read_project_text_no_symlink(
        root,
        path,
        max_bytes=MAX_FILE_BYTES,
        encoding="utf-8",
        errors="replace",
    )
    if source is None:
        return None
    return _TextFile(path, source, tuple(source.splitlines()))


def _read_manifest_files(root: Path, paths: list[Path]) -> list[_TextFile]:
    files: list[_TextFile] = []
    total_bytes = 0
    for path in paths:
        try:
            file_size = path.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if total_bytes + file_size > MAX_TOTAL_MANIFEST_BYTES:
            break
        file = _read_text_file(root, path)
        if file is None:
            continue
        total_bytes += file_size
        files.append(file)
    return files


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

    children: tuple[Any, ...] | None = None
    if isinstance(value, dict):
        children = tuple(value.keys()) + tuple(value.values())
    elif isinstance(value, list):
        children = tuple(value)
    if children is None:
        return isinstance(value, (str, int, float, bool, type(None)))

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


def _load_manifest_yaml(file: _TextFile) -> list[Any] | None:
    try:
        return list(
            islice(
                yaml.load_all(file.text, Loader=_UniqueKeySafeLoader),
                MAX_DOCUMENTS_PER_FILE + 1,
            )
        )
    except Exception:
        logger.debug("Unable to parse Kubernetes YAML: %s", file.path, exc_info=True)
        return None


def _manifest_documents(file: _TextFile) -> list[dict[str, Any]]:
    if yaml is None or _UniqueKeySafeLoader is None:
        return []
    documents = _load_manifest_yaml(file)
    if documents is None or len(documents) > MAX_DOCUMENTS_PER_FILE:
        return []
    resources: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict) or not _yaml_graph_is_safe(document):
            continue
        if document.get("kind") == "List":
            continue
        if _is_kubernetes_resource(document):
            resources.append(document)
    return resources


def _is_kubernetes_resource(value: dict[str, Any]) -> bool:
    return isinstance(value.get("apiVersion"), str) and isinstance(
        value.get("kind"), str
    )


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    if not all(
        isinstance(key, str) and isinstance(child, str) for key, child in value.items()
    ):
        return {}
    result: dict[str, str] = {}
    for key, child in value.items():
        result[key] = child
    return result


def _resource_metadata(resource: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    metadata = _mapping(resource.get("metadata"))
    raw_name = metadata.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) else ""
    raw_namespace = metadata.get("namespace")
    if raw_namespace is None:
        namespace = "default"
    elif isinstance(raw_namespace, str):
        namespace = raw_namespace.strip()
    else:
        namespace = ""
    annotations = _string_mapping(metadata.get("annotations"))
    return name, namespace, annotations


def _is_dynamic_value(value: str) -> bool:
    return any(marker in value for marker in ("${", "$(", "{{", "{%"))


def _unquote_yaml_scalar(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'":
        return stripped[1:-1]
    return stripped


def _yaml_document_spans(file: _TextFile) -> tuple[tuple[int, int], ...]:
    """Return inclusive, one-based line spans for YAML documents."""

    separator = re.compile(r"^---\s*(?:#.*)?$")
    spans: list[tuple[int, int]] = []
    start = 1
    for line_number, line in enumerate(file.lines, 1):
        if not separator.match(line):
            continue
        if start <= line_number - 1:
            spans.append((start, line_number - 1))
        start = line_number + 1
    if start <= len(file.lines):
        spans.append((start, len(file.lines)))
    return tuple(spans)


def _resource_span(file: _TextFile, kind: str, name: str) -> tuple[int, int] | None:
    matches: list[tuple[int, int]] = []
    for start, end in _yaml_document_spans(file):
        kind_line = _top_level_yaml_field_line(file, "kind", kind, start=start, end=end)
        name_line = _metadata_name_line(file, name, start=start, end=end)
        if kind_line is not None and name_line is not None:
            matches.append((start, end))
    return matches[0] if len(matches) == 1 else None


def _mapping_child_span(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded YAML span parser
    file: _TextFile,
    key: str,
    *,
    start: int,
    end: int,
    parent_indent: int,
) -> tuple[int, int, int] | None:
    """Locate one direct block-mapping child without searching nested siblings."""

    content: list[tuple[int, int]] = []
    for line_number in range(start, end + 1):
        line = file.lines[line_number - 1]
        stripped = line.lstrip(" ")
        if (
            not stripped
            or stripped.startswith("#")
            or "\t" in line[: len(line) - len(stripped)]
        ):
            continue
        indent = len(line) - len(stripped)
        if indent > parent_indent:
            content.append((indent, line_number))
    if not content:
        return None
    direct_indent = min(indent for indent, _ in content)
    pattern = re.compile(
        rf"^ {{{direct_indent}}}['\"]?{re.escape(key)}['\"]?\s*:\s*(?P<value>.*?)\s*(?:#.*)?$"
    )
    matches = [
        line_number
        for indent, line_number in content
        if indent == direct_indent and pattern.match(file.lines[line_number - 1])
    ]
    if len(matches) != 1:
        return None
    line_number = matches[0]
    block_end = end
    for candidate in range(line_number + 1, end + 1):
        line = file.lines[candidate - 1]
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent <= direct_indent:
            block_end = candidate - 1
            break
    return line_number, block_end, direct_indent


def _resource_mapping_path_span(
    file: _TextFile,
    kind: str,
    name: str,
    path: tuple[str, ...],
) -> tuple[int, int, int] | None:
    span = _resource_span(file, kind, name)
    if span is None:
        return None
    start, end = span
    parent_indent = -1
    match: tuple[int, int, int] | None = None
    for key in path:
        match = _mapping_child_span(
            file,
            key,
            start=start,
            end=end,
            parent_indent=parent_indent,
        )
        if match is None:
            return None
        line, end, parent_indent = match
        start = line + 1
    return match


def _resource_annotation_line(
    file: _TextFile,
    kind: str,
    name: str,
    annotation: str,
    value: str,
    *,
    pod_template: bool,
) -> int | None:
    path = (
        ("metadata", "annotations")
        if not pod_template
        else ("spec", "template", "metadata", "annotations")
    )
    annotations = _resource_mapping_path_span(file, kind, name, path)
    if annotations is None:
        return None
    annotation_entry = _mapping_child_span(
        file,
        annotation,
        start=annotations[0] + 1,
        end=annotations[1],
        parent_indent=annotations[2],
    )
    if annotation_entry is None:
        return None
    line = annotation_entry[0]
    pattern = re.compile(
        rf"^\s*['\"]?{re.escape(annotation)}['\"]?\s*:\s*(?P<value>.*?)\s*(?:#.*)?$"
    )
    match = pattern.match(file.lines[line - 1])
    if match is None or _unquote_yaml_scalar(match.group("value")) != value:
        return None
    return line


def _container_item_span(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded YAML list parser
    file: _TextFile,
    kind: str,
    workload_name: str,
    container_name: str,
) -> tuple[int, int] | None:
    path = (
        ("spec", "containers")
        if kind == "Pod"
        else ("spec", "template", "spec", "containers")
    )
    containers = _resource_mapping_path_span(file, kind, workload_name, path)
    if containers is None:
        return None
    entries: list[tuple[int, int]] = []
    item_pattern = re.compile(
        r"^(?P<indent> *)-\s+name\s*:\s*(?P<value>.*?)\s*(?:#.*)?$"
    )
    candidates: list[tuple[int, int]] = []
    for line_number in range(containers[0] + 1, containers[1] + 1):
        match = item_pattern.match(file.lines[line_number - 1])
        if match is not None:
            candidates.append((len(match.group("indent")), line_number))
    if not candidates:
        return None
    direct_indent = min(indent for indent, _ in candidates)
    for indent, line_number in candidates:
        if indent != direct_indent:
            continue
        match = item_pattern.match(file.lines[line_number - 1])
        if (
            match is None
            or _unquote_yaml_scalar(match.group("value")) != container_name
        ):
            continue
        item_end = containers[1]
        for candidate in range(line_number + 1, containers[1] + 1):
            line = file.lines[candidate - 1]
            stripped = line.lstrip(" ")
            if not stripped or stripped.startswith("#"):
                continue
            candidate_indent = len(line) - len(stripped)
            if candidate_indent <= direct_indent:
                item_end = candidate - 1
                break
        entries.append((line_number, item_end))
    return entries[0] if len(entries) == 1 else None


def _container_command_token_line(
    file: _TextFile,
    container: _Container,
    token: str,
) -> int | None:
    matches: list[int] = []
    for key in ("command", "args"):
        block = _mapping_child_span(
            file,
            key,
            start=container.line + 1,
            end=container.end_line,
            parent_indent=len(file.lines[container.line - 1])
            - len(file.lines[container.line - 1].lstrip(" ")),
        )
        if block is None:
            continue
        matches.extend(_yaml_sequence_scalar_lines(file, block, key, token))
    return matches[-1] if matches else None


def _yaml_sequence_scalar_lines(
    file: _TextFile,
    block: tuple[int, int, int],
    key: str,
    expected: str,
) -> list[int]:
    if yaml is None or _UniqueKeySafeLoader is None:
        return []
    start, end, indent = block
    snippet = "\n".join(
        line[indent:] if len(line) >= indent else ""
        for line in file.lines[start - 1 : end]
    )
    try:
        document = yaml.compose(snippet, Loader=_UniqueKeySafeLoader)
    except Exception:
        logger.debug(
            "Unable to inspect YAML scalar lines: %s", file.path, exc_info=True
        )
        return []
    if not isinstance(document, yaml.nodes.MappingNode) or len(document.value) != 1:
        return []
    key_node, value_node = document.value[0]
    if (
        not isinstance(key_node, yaml.nodes.ScalarNode)
        or key_node.value != key
        or not isinstance(value_node, yaml.nodes.SequenceNode)
    ):
        return []
    return [
        start + item.start_mark.line
        for item in value_node.value
        if isinstance(item, yaml.nodes.ScalarNode) and item.value == expected
    ]


def _top_level_yaml_field_line(
    file: _TextFile,
    field: str,
    value: str | int,
    *,
    start: int,
    end: int,
) -> int | None:
    pattern = re.compile(
        rf"^(?P<indent> *){re.escape(field)}\s*:\s*(?P<value>.*?)\s*(?:#.*)?$"
    )
    matches: list[tuple[int, int, str]] = []
    expected = str(value)
    for line_number in range(start, end + 1):
        match = pattern.match(file.lines[line_number - 1])
        if match is None:
            continue
        actual = _unquote_yaml_scalar(match.group("value"))
        matches.append((len(match.group("indent")), line_number, actual))
    if not matches:
        return None
    minimum_indent = min(indent for indent, _, _ in matches)
    minimum_matches = [
        line
        for indent, line, actual in matches
        if indent == minimum_indent and actual == expected
    ]
    return minimum_matches[0] if len(minimum_matches) == 1 else None


def _metadata_name_line(
    file: _TextFile,
    name: str,
    *,
    start: int,
    end: int,
) -> int | None:
    metadata_pattern = re.compile(r"^(?P<indent> *)metadata\s*:\s*(?:#.*)?$")
    name_pattern = re.compile(r"^(?P<indent> +)name\s*:\s*(?P<value>.*?)\s*(?:#.*)?$")
    metadata_entries: list[tuple[int, int]] = []
    for line_number in range(start, end + 1):
        match = metadata_pattern.match(file.lines[line_number - 1])
        if match is not None:
            metadata_entries.append((len(match.group("indent")), line_number))
    if not metadata_entries:
        return None
    root_indent = min(indent for indent, _ in metadata_entries)
    roots = [line for indent, line in metadata_entries if indent == root_indent]
    if len(roots) != 1:
        return None

    for line_number in range(roots[0] + 1, end + 1):
        line = file.lines[line_number - 1]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= root_indent:
            break
        match = name_pattern.match(line)
        if match is not None and _unquote_yaml_scalar(match.group("value")) == name:
            return line_number
    return None


def _resource_identity_line(file: _TextFile, kind: str, name: str) -> int | None:
    span = _resource_span(file, kind, name)
    if span is None:
        return None
    return _metadata_name_line(file, name, start=span[0], end=span[1])


def _annotations_have_external_scope(annotations: dict[str, str]) -> bool:
    return (
        annotations.get(EXPOSURE_SCOPE_ANNOTATION, "").strip().lower()
        in EXTERNAL_SCOPE_VALUES
        and annotations.get(BACKEND_PROTOCOL_ANNOTATION, "").strip().lower() == "http"
    )


def _has_ambiguous_transport(  # skylos: ignore[SKY-Q301,SKY-Q306] explicit allowlist
    annotations: dict[str, str],
) -> bool:
    for key, value in annotations.items():
        normalized_key = key.lower()
        normalized_value = value.strip().lower()
        if "rewrite" in normalized_key or "use-regex" in normalized_key:
            if normalized_value not in {"", "0", "false", "off"}:
                return True
        if (
            "backend-protocol" in normalized_key or "serversscheme" in normalized_key
        ) and normalized_value not in {"", "http"}:
            return True
        if (
            any(
                marker in normalized_key for marker in ("ssl-services", "grpc-services")
            )
            and normalized_value
        ):
            return True
        if any(
            marker in normalized_key for marker in ("server-ssl", "ssl-passthrough")
        ) and normalized_value not in {"", "0", "false", "off", "no"}:
            return True
        if normalized_key.startswith("konghq.com/") and normalized_value:
            return True
        if (
            any(
                marker in normalized_key
                for marker in ("snippet", "middlewares", "app-protocols")
            )
            and normalized_value
        ):
            return True
    return False


def _backend_identity(value: Any) -> tuple[str, str | int] | None:
    backend = _mapping(value)
    service = _mapping(backend.get("service"))
    name = service.get("name")
    port = _mapping(service.get("port"))
    if not isinstance(name, str) or not name.strip() or _is_dynamic_value(name):
        return None
    number = port.get("number")
    port_name = port.get("name")
    if ("number" in port) == ("name" in port):
        return None
    if (
        isinstance(number, int)
        and not isinstance(number, bool)
        and 1 <= number <= 65535
    ):
        return name.strip(), int(number)
    if (
        isinstance(port_name, str)
        and port_name.strip()
        and not _is_dynamic_value(port_name)
    ):
        return name.strip(), port_name.strip()
    return None


def _parse_ingresses(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded manifest parser
    file: _TextFile, resources: list[dict[str, Any]]
) -> list[_IngressPath]:
    paths: list[_IngressPath] = []
    for resource in resources:
        if (
            resource.get("apiVersion") != "networking.k8s.io/v1"
            or resource.get("kind") != "Ingress"
        ):
            continue
        name, namespace, annotations = _resource_metadata(resource)
        resource_line = _resource_identity_line(file, "Ingress", name)
        resource_span = _resource_span(file, "Ingress", name)
        if (
            not name
            or resource_line is None
            or resource_span is None
            or _is_dynamic_value(name)
            or not namespace
            or _is_dynamic_value(namespace)
            or not _annotations_have_external_scope(annotations)
            or _has_ambiguous_transport(annotations)
        ):
            continue
        spec = _mapping(resource.get("spec"))
        raw_rules = spec.get("rules")
        if raw_rules is not None and not isinstance(raw_rules, list):
            continue
        rules = _sequence(raw_rules)
        default_backend = _backend_identity(spec.get("defaultBackend"))
        if default_backend is not None and not rules:
            service_name, service_port = default_backend
            paths.append(
                _IngressPath(
                    file=file,
                    line=resource_line,
                    start_line=resource_span[0],
                    end_line=resource_span[1],
                    namespace=namespace,
                    ingress_name=name,
                    host="*",
                    path="/",
                    path_type="Prefix",
                    service_name=service_name,
                    service_port=service_port,
                )
            )

        for rule in rules:
            rule_map = _mapping(rule)
            raw_host = rule_map.get("host")
            if raw_host is not None and not isinstance(raw_host, str):
                continue
            host = (raw_host or "*").strip() or "*"
            if _is_dynamic_value(host):
                continue
            http = _mapping(rule_map.get("http"))
            for path_item in _sequence(http.get("paths")):
                path_map = _mapping(path_item)
                path_type = str(path_map.get("pathType") or "").strip()
                route_path = str(path_map.get("path") or "/").strip() or "/"
                backend = _backend_identity(path_map.get("backend"))
                if (
                    path_type not in {"Exact", "Prefix"}
                    or backend is None
                    or not route_path.startswith("/")
                    or _is_dynamic_value(route_path)
                ):
                    continue
                service_name, service_port = backend
                paths.append(
                    _IngressPath(
                        file=file,
                        line=resource_line,
                        start_line=resource_span[0],
                        end_line=resource_span[1],
                        namespace=namespace,
                        ingress_name=name,
                        host=host,
                        path=route_path,
                        path_type=path_type,
                        service_name=service_name,
                        service_port=service_port,
                    )
                )
    return paths


def _parse_services(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded manifest parser
    file: _TextFile, resources: list[dict[str, Any]]
) -> list[_Service]:
    services: list[_Service] = []
    for resource in resources:
        if resource.get("apiVersion") != "v1" or resource.get("kind") != "Service":
            continue
        name, namespace, annotations = _resource_metadata(resource)
        resource_line = _resource_identity_line(file, "Service", name)
        resource_span = _resource_span(file, "Service", name)
        spec = _mapping(resource.get("spec"))
        raw_service_type = spec.get("type")
        if raw_service_type is not None and not isinstance(raw_service_type, str):
            continue
        service_type = (raw_service_type or "ClusterIP").strip()
        selector = tuple(sorted(_string_mapping(spec.get("selector")).items()))
        if (
            not name
            or resource_line is None
            or resource_span is None
            or _is_dynamic_value(name)
            or not namespace
            or _is_dynamic_value(namespace)
            or not selector
            or service_type not in {"ClusterIP", "LoadBalancer", "NodePort"}
            or _has_ambiguous_transport(annotations)
            or any(
                _is_dynamic_value(key) or _is_dynamic_value(value)
                for key, value in selector
            )
        ):
            continue
        ports: list[_ServicePort] = []
        for raw_port in _sequence(spec.get("ports")):
            port = _mapping(raw_port)
            protocol = str(port.get("protocol") or "TCP").strip().upper()
            port_number = port.get("port")
            if (
                protocol != "TCP"
                or not isinstance(port_number, int)
                or isinstance(port_number, bool)
                or not 1 <= port_number <= 65535
            ):
                continue
            raw_name = port.get("name")
            if raw_name is not None and not isinstance(raw_name, str):
                continue
            port_name = raw_name.strip() if isinstance(raw_name, str) else None
            if port_name is not None and (
                not port_name
                or _is_dynamic_value(port_name)
                or port_name.lower().startswith("https")
            ):
                continue
            if port_number == 443:
                continue
            app_protocol = port.get("appProtocol")
            if app_protocol is not None and (
                not isinstance(app_protocol, str)
                or app_protocol.strip().lower() != "http"
            ):
                continue
            target = port.get("targetPort", port_number)
            if isinstance(target, str):
                target = target.strip()
                if not target or _is_dynamic_value(target):
                    continue
            elif (
                not isinstance(target, int)
                or isinstance(target, bool)
                or not 1 <= target <= 65535
            ):
                continue
            ports.append(_ServicePort(port_name, int(port_number), target))
        if ports:
            services.append(
                _Service(
                    file=file,
                    line=resource_line,
                    start_line=resource_span[0],
                    end_line=resource_span[1],
                    namespace=namespace,
                    name=name,
                    selector=selector,
                    ports=tuple(ports),
                )
            )
    return services


def _command_parts(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return []
    if not value or any(not item or _is_dynamic_value(item) for item in value):
        return []
    return list(value)


def _parse_required_guards(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    guards = []
    for raw_guard in value.split(","):
        guard = raw_guard.strip()
        if not guard or not SAFE_GUARD_RE.fullmatch(guard):
            return ()
        if guard not in guards:
            guards.append(guard)
        if len(guards) > MAX_REQUIRED_GUARDS:
            return ()
    return tuple(guards)


def _safe_source_file(value: str | None) -> str | None:
    if value is None or _is_dynamic_value(value):
        return None
    path = Path(value.strip())
    if (
        not value.strip()
        or path.is_absolute()
        or path.suffix.lower() != ".py"
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return path.as_posix()


def _parse_containers(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded container parser
    file: _TextFile,
    pod_spec: dict[str, Any],
    *,
    resource_kind: str,
    resource_name: str,
    resource_line: int,
) -> tuple[_Container, ...]:
    containers: list[_Container] = []
    for raw_container in _sequence(pod_spec.get("containers")):
        container = _mapping(raw_container)
        raw_name = container.get("name")
        raw_image = container.get("image")
        name = raw_name.strip() if isinstance(raw_name, str) else ""
        image = raw_image.strip() if isinstance(raw_image, str) else ""
        command_values = _command_parts(container.get("command"))
        args_value = container.get("args")
        args_values = _command_parts(args_value) if args_value is not None else []
        container_span = _container_item_span(
            file,
            resource_kind,
            resource_name,
            name,
        )
        if (
            not name
            or not image
            or _is_dynamic_value(name)
            or _is_dynamic_value(image)
            or not command_values
            or (args_value is not None and not args_values)
            or container_span is None
        ):
            continue
        ports: list[tuple[str | None, int]] = []
        for raw_port in _sequence(container.get("ports")):
            port = _mapping(raw_port)
            protocol = str(port.get("protocol") or "TCP").strip().upper()
            port_number = port.get("containerPort")
            if (
                protocol != "TCP"
                or not isinstance(port_number, int)
                or isinstance(port_number, bool)
                or not 1 <= port_number <= 65535
            ):
                continue
            raw_name = port.get("name")
            if raw_name is not None and not isinstance(raw_name, str):
                continue
            port_name = raw_name.strip() if isinstance(raw_name, str) else None
            if port_name is not None and (
                not port_name or _is_dynamic_value(port_name)
            ):
                continue
            ports.append((port_name, int(port_number)))
        containers.append(
            _Container(
                name=name,
                image=image,
                command=tuple([*command_values, *args_values]),
                ports=tuple(ports),
                line=container_span[0],
                end_line=container_span[1],
            )
        )
    return tuple(containers)


def _parse_workloads(  # skylos: ignore[SKY-C304,SKY-Q301,SKY-Q306] bounded manifest parser
    file: _TextFile, resources: list[dict[str, Any]]
) -> list[_Workload]:
    workloads: list[_Workload] = []
    for resource in resources:
        kind = str(resource.get("kind") or "")
        if WORKLOAD_API_VERSIONS.get(kind) != resource.get("apiVersion"):
            continue
        name, namespace, resource_annotations = _resource_metadata(resource)
        resource_line = _resource_identity_line(file, kind, name)
        resource_span = _resource_span(file, kind, name)
        spec = _mapping(resource.get("spec"))
        controller_selector: dict[str, str] = {}
        if kind == "Pod":
            metadata = _mapping(resource.get("metadata"))
            labels = _string_mapping(metadata.get("labels"))
            annotations = resource_annotations
            pod_spec = spec
        else:
            replicas = spec.get("replicas", 1)
            if kind == "DaemonSet" and "replicas" in spec:
                continue
            if kind in {"Deployment", "ReplicaSet", "StatefulSet"} and (
                not isinstance(replicas, int)
                or isinstance(replicas, bool)
                or replicas <= 0
            ):
                continue
            selector_spec = _mapping(spec.get("selector"))
            if selector_spec.get("matchExpressions") not in (None, []):
                continue
            controller_selector = _string_mapping(selector_spec.get("matchLabels"))
            template = _mapping(spec.get("template"))
            template_metadata = _mapping(template.get("metadata"))
            labels = _string_mapping(template_metadata.get("labels"))
            annotations = _string_mapping(template_metadata.get("annotations"))
            pod_spec = _mapping(template.get("spec"))
        containers = _parse_containers(
            file,
            pod_spec,
            resource_kind=kind,
            resource_name=name,
            resource_line=resource_line or 1,
        )
        source_file = _safe_source_file(annotations.get(SOURCE_FILE_ANNOTATION))
        required_guards = _parse_required_guards(
            annotations.get(REQUIRED_GUARDS_ANNOTATION)
        )
        pod_template = kind != "Pod"
        source_line = (
            _resource_annotation_line(
                file,
                kind,
                name,
                SOURCE_FILE_ANNOTATION,
                annotations[SOURCE_FILE_ANNOTATION],
                pod_template=pod_template,
            )
            if SOURCE_FILE_ANNOTATION in annotations
            else None
        )
        contract_line = (
            _resource_annotation_line(
                file,
                kind,
                name,
                REQUIRED_GUARDS_ANNOTATION,
                annotations[REQUIRED_GUARDS_ANNOTATION],
                pod_template=pod_template,
            )
            if REQUIRED_GUARDS_ANNOTATION in annotations
            else None
        )
        if (
            name
            and resource_line is not None
            and resource_span is not None
            and not _is_dynamic_value(name)
            and namespace
            and not _is_dynamic_value(namespace)
            and labels
            and containers
            and not any(
                _is_dynamic_value(key) or _is_dynamic_value(value)
                for key, value in labels.items()
            )
            and (
                kind == "Pod"
                or (
                    controller_selector
                    and not any(
                        _is_dynamic_value(key) or _is_dynamic_value(value)
                        for key, value in controller_selector.items()
                    )
                    and all(
                        labels.get(key) == value
                        for key, value in controller_selector.items()
                    )
                )
            )
        ):
            workloads.append(
                _Workload(
                    file=file,
                    line=resource_line,
                    start_line=resource_span[0],
                    end_line=resource_span[1],
                    namespace=namespace,
                    kind=kind,
                    name=name,
                    labels=tuple(sorted(labels.items())),
                    containers=containers,
                    source_file=source_file,
                    required_guards=required_guards,
                    source_line=source_line,
                    contract_line=contract_line,
                )
            )
    return workloads


def _labels_match(
    selector: tuple[tuple[str, str], ...], labels: tuple[tuple[str, str], ...]
) -> bool:
    label_map = dict(labels)
    return bool(selector) and all(
        label_map.get(key) == value for key, value in selector
    )


def _service_port(service: _Service, ingress: _IngressPath) -> _ServicePort | None:
    matches = [
        port
        for port in service.ports
        if (isinstance(ingress.service_port, str) and port.name == ingress.service_port)
        or (isinstance(ingress.service_port, int) and port.port == ingress.service_port)
    ]
    return matches[0] if len(matches) == 1 else None


def _container_for_port(
    workload: _Workload, service_port: _ServicePort
) -> _Container | None:
    matches: list[_Container] = []
    for container in workload.containers:
        if isinstance(service_port.target_port, str):
            if any(name == service_port.target_port for name, _ in container.ports):
                matches.append(container)
        elif any(port == service_port.target_port for _, port in container.ports):
            matches.append(container)
    if len(matches) == 1:
        return matches[0]
    if (
        not matches
        and isinstance(service_port.target_port, int)
        and len(workload.containers) == 1
    ):
        return workload.containers[0]
    return None


def _proof_chains(
    ingresses: list[_IngressPath],
    services: list[_Service],
    workloads: list[_Workload],
) -> Iterator[_ProofChain]:
    for ingress in ingresses:
        service_matches = [
            service
            for service in services
            if service.namespace == ingress.namespace
            and service.name == ingress.service_name
        ]
        if len(service_matches) != 1:
            continue
        service = service_matches[0]
        port = _service_port(service, ingress)
        if port is None:
            continue
        workload_matches = [
            workload
            for workload in workloads
            if workload.namespace == service.namespace
            and _labels_match(service.selector, workload.labels)
        ]
        if len(workload_matches) != 1:
            continue
        workload = workload_matches[0]
        container = _container_for_port(workload, port)
        if container is not None:
            yield _ProofChain(ingress, service, workload, container, port)


def _server_index(tokens: tuple[str, ...]) -> tuple[int, str] | None:
    if not tokens:
        return None
    executable = tokens[0]
    if executable in SERVER_EXECUTABLES:
        return 0, executable
    if (
        PYTHON_EXECUTABLE_RE.fullmatch(executable)
        and len(tokens) >= 3
        and tokens[1] == "-m"
        and tokens[2] in SERVER_EXECUTABLES
    ):
        return 2, tokens[2]
    return None


def _option_value(tokens: tuple[str, ...], *names: str) -> str | None:
    values: list[str] = []
    for index, token in enumerate(tokens):
        for name in names:
            if token == name and index + 1 < len(tokens):
                values.append(tokens[index + 1])
            if token.startswith(f"{name}="):
                values.append(token.split("=", 1)[1])
    return values[0] if len(values) == 1 else None


def _flask_command(
    tokens: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Split Flask group options from the actual `run` subcommand arguments."""

    value_options = {"--app", "-A", "--env-file"}
    flag_options = {"--debug", "--no-debug"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "run":
            run_args = tokens[index + 1 :]
            if any(
                token in {"--app", "-A"}
                or token.startswith("--app=")
                or token.startswith("-A=")
                for token in run_args
            ):
                return None
            return tokens[:index], run_args
        if token in value_options:
            if index + 1 >= len(tokens):
                return None
            index += 2
            continue
        if any(token.startswith(f"{name}=") for name in value_options):
            index += 1
            continue
        if token in flag_options:
            index += 1
            continue
        return None
    return None


def _boolean_flag_state(
    tokens: tuple[str, ...], positive: str, negative: str
) -> bool | None:
    state: bool | None = None
    for token in tokens:
        if token == positive:
            state = True
        elif token == negative:
            state = False
    return state


def _supported_options(
    tokens: tuple[str, ...],
    *,
    value_options: set[str],
    flag_options: set[str],
) -> bool:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in value_options:
            if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                return False
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in value_options):
            index += 1
            continue
        if token in flag_options:
            index += 1
            continue
        return False
    return True


def _server_binding(server: str, tokens: tuple[str, ...]) -> tuple[str, int] | None:
    if server in {"flask", "uvicorn"}:
        host = _option_value(tokens, "--host")
        raw_port = _option_value(tokens, "--port")
    elif server == "gunicorn":
        bind = _option_value(tokens, "--bind", "-b")
        if bind is None or bind.startswith("unix:") or ":" not in bind:
            return None
        host, raw_port = bind.rsplit(":", 1)
        host = host.strip("[]")
    else:  # pragma: no cover - guarded by _server_index.
        return None
    if host not in {"0.0.0.0", "::"} or raw_port is None:
        return None
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        return None
    return (host, port) if 1 <= port <= 65535 else None


def _entrypoint(container: _Container) -> _Entrypoint | None:
    server_info = _server_index(container.command)
    if server_info is None:
        return None
    server_index, server = server_info
    remaining = container.command[server_index + 1 :]
    if "--" in remaining:
        return None
    target: re.Match[str] | None = None
    if server == "flask":
        flask_command = _flask_command(remaining)
        if flask_command is None:
            return None
        group_args, run_args = flask_command
        if not _supported_options(
            run_args,
            value_options={"--host", "--port"},
            flag_options={
                "--debug",
                "--no-debug",
                "--reload",
                "--no-reload",
                "--debugger",
                "--no-debugger",
                "--with-threads",
                "--without-threads",
            },
        ):
            return None
        raw_target = _option_value(group_args, "--app", "-A")
        if raw_target is not None:
            target = TARGET_RE.fullmatch(raw_target)
        binding_tokens = run_args
    else:
        if remaining:
            target = TARGET_RE.fullmatch(remaining[0])
        value_options = (
            {"--host", "--port"} if server == "uvicorn" else {"--bind", "-b"}
        )
        if not _supported_options(
            remaining[1:],
            value_options=value_options,
            flag_options={"--reload"},
        ):
            return None
        binding_tokens = remaining
    binding = _server_binding(server, binding_tokens)
    if target is None or binding is None:
        return None
    host, port = binding
    return _Entrypoint(
        server=server,
        module=target.group("module"),
        symbol=target.group("symbol"),
        host=host,
        port=port,
    )


def _target_port_number(chain: _ProofChain) -> int | None:
    target = chain.service_port.target_port
    if isinstance(target, int):
        return target
    matches = [port for name, port in chain.container.ports if name == target]
    return matches[0] if len(matches) == 1 else None


def _entrypoint_reaches_service(chain: _ProofChain, entrypoint: _Entrypoint) -> bool:
    return _target_port_number(chain) == entrypoint.port


def _module_suffix(module: str) -> str:
    return module.replace(".", "/") + ".py"


def _resolve_contracted_source(
    root: Path,
    workload: _Workload,
    entrypoint: _Entrypoint,
) -> _TextFile | None:
    source_file = workload.source_file
    if source_file is None or source_file != _module_suffix(entrypoint.module):
        return None
    path = root / source_file
    return _read_text_file(root, path)


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_literals(node: ast.AST | None) -> list[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_literal_string(item) for item in node.elts]
        return (
            [value for value in values if value is not None]
            if all(value is not None for value in values)
            else None
        )
    return None


def _alias_local_name(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> str:
    if alias.asname:
        return alias.asname
    if isinstance(node, ast.Import):
        return alias.name.split(".", 1)[0]
    return alias.name


def _symbol_has_conflicting_binding(  # skylos: ignore[SKY-Q301,SKY-Q306] conservative AST proof
    module: ast.Module,
    symbol: str,
    *,
    allowed_nodes: set[int],
) -> bool:
    base_symbol = symbol.split(".", 1)[0]
    for node in ast.walk(module):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(
                _alias_local_name(node, alias) == base_symbol
                and id(alias) not in allowed_nodes
                for alias in node.names
            ):
                return True
        if (
            isinstance(node, ast.Name)
            and node.id == base_symbol
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and id(node) not in allowed_nodes
        ):
            return True
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            dotted = _dotted_name(node)
            if dotted == symbol or (
                symbol == base_symbol and dotted.startswith(f"{symbol}.")
            ):
                return True
        if (
            isinstance(node, ast.Call)
            and _dotted_name(node.func) in {"setattr", "delattr"}
            and len(node.args) >= 2
        ):
            target = _dotted_name(node.args[0])
            attribute = _literal_string(node.args[1])
            mutated = f"{target}.{attribute}" if target and attribute else ""
            if mutated == symbol or (
                symbol == base_symbol and mutated.startswith(f"{symbol}.")
            ):
                return True
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == base_symbol
            and id(node) not in allowed_nodes
        ):
            return True
    return False


def _framework_bindings(  # skylos: ignore[SKY-Q301,SKY-Q306] conservative AST proof
    module: ast.Module,
) -> tuple[dict[str, str], set[str]]:
    constructors: dict[str, str] = {}
    dependency_calls: set[str] = set()
    allowed_bindings: dict[str, set[int]] = {}
    for node in module.body:
        if isinstance(node, ast.ImportFrom):
            if node.level != 0:
                continue
            imported_module = str(node.module or "")
            if imported_module == "fastapi":
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    if alias.name == "FastAPI":
                        constructors[local_name] = "fastapi"
                        allowed_bindings.setdefault(local_name, set()).add(id(alias))
                    elif alias.name in DEPENDENCY_CALLS:
                        dependency_calls.add(local_name)
                        allowed_bindings.setdefault(local_name, set()).add(id(alias))
            elif imported_module == "flask":
                for alias in node.names:
                    if alias.name == "Flask":
                        local_name = alias.asname or alias.name
                        constructors[local_name] = "flask"
                        allowed_bindings.setdefault(local_name, set()).add(id(alias))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "fastapi":
                    constructors[f"{local_name}.FastAPI"] = "fastapi"
                    dependency_calls.update(
                        {f"{local_name}.Depends", f"{local_name}.Security"}
                    )
                    allowed_bindings.setdefault(local_name, set()).add(id(alias))
                elif alias.name == "flask":
                    constructors[f"{local_name}.Flask"] = "flask"
                    allowed_bindings.setdefault(local_name, set()).add(id(alias))
    constructors = {
        name: framework
        for name, framework in constructors.items()
        if not _symbol_has_conflicting_binding(
            module,
            name,
            allowed_nodes=allowed_bindings.get(name.split(".", 1)[0], set()),
        )
    }
    dependency_calls = {
        name
        for name in dependency_calls
        if not _symbol_has_conflicting_binding(
            module,
            name,
            allowed_nodes=allowed_bindings.get(name.split(".", 1)[0], set()),
        )
    }
    return constructors, dependency_calls


def _dependency_guard(node: ast.AST, dependency_calls: set[str]) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if _dotted_name(node.func) not in dependency_calls:
        return None
    return _dotted_name(node.args[0]) if node.args else None


def _route_identity(  # skylos: ignore[SKY-Q301,SKY-Q306] fail-closed route proof
    decorator: ast.AST, app_symbol: str, framework: str
) -> tuple[ast.Call, tuple[str, ...], str] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(
        decorator.func, ast.Attribute
    ):
        return None
    method_name = decorator.func.attr
    supported_methods = (
        FASTAPI_ROUTE_METHODS if framework == "fastapi" else FLASK_ROUTE_METHODS
    )
    if (
        method_name not in supported_methods
        or _dotted_name(decorator.func.value) != app_symbol
    ):
        return None
    keyword_names = [keyword.arg for keyword in decorator.keywords]
    if any(name is None for name in keyword_names) or len(keyword_names) != len(
        set(keyword_names)
    ):
        return None
    path_keyword = "path" if framework == "fastapi" else "rule"
    wrong_path_keyword = "rule" if framework == "fastapi" else "path"
    if wrong_path_keyword in keyword_names:
        return None
    path_keywords = [
        keyword for keyword in decorator.keywords if keyword.arg == path_keyword
    ]
    if decorator.args:
        if len(decorator.args) != 1 or path_keywords:
            return None
        path = _literal_string(decorator.args[0])
    else:
        if len(path_keywords) != 1:
            return None
        path = _literal_string(path_keywords[0].value)
    if path is None or not path.startswith("/"):
        return None

    methods: set[str] = set()
    if method_name == "route":
        methods.add("GET")
    elif method_name == "api_route":
        methods.add("GET")
    else:
        methods.add(method_name.upper())
    for keyword in decorator.keywords:
        if keyword.arg == "methods":
            if method_name not in {"route", "api_route"}:
                return None
            literal_methods = _string_literals(keyword.value)
            if not literal_methods:
                return None
            methods = {method.upper() for method in literal_methods}
    if not methods:
        return None
    return decorator, tuple(sorted(methods)), path


def _guards_from_dependencies(value: ast.AST, dependency_calls: set[str]) -> list[str]:
    values = (
        value.elts if isinstance(value, (ast.List, ast.Tuple, ast.Set)) else [value]
    )
    return [
        guard for item in values if (guard := _dependency_guard(item, dependency_calls))
    ]


def _route_guards(  # skylos: ignore[SKY-Q301,SKY-Q306] framework guard proof
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    route_decorator: ast.Call,
    route_index: int,
    all_route_decorators: set[ast.Call],
    dependency_calls: set[str],
    framework: str,
) -> tuple[str, ...]:
    guards: list[str] = []
    for decorator in function.decorator_list[route_index + 1 :]:
        if decorator not in all_route_decorators:
            name = _dotted_name(decorator)
            if name:
                guards.append(name)
    if framework != "fastapi":
        return tuple(dict.fromkeys(guards))
    for keyword in route_decorator.keywords:
        if keyword.arg == "dependencies":
            guards.extend(_guards_from_dependencies(keyword.value, dependency_calls))
    defaults = [*function.args.defaults]
    defaults.extend(value for value in function.args.kw_defaults if value is not None)
    guards.extend(
        guard
        for default in defaults
        if (guard := _dependency_guard(default, dependency_calls))
    )
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    for argument in arguments:
        if argument.annotation is None:
            continue
        guards.extend(
            guard
            for child in ast.walk(argument.annotation)
            if (guard := _dependency_guard(child, dependency_calls))
        )
    return tuple(dict.fromkeys(guards))


def _app_identity_and_guards(  # skylos: ignore[SKY-Q301,SKY-Q306] framework AST proof
    module: ast.Module,
    app_symbol: str,
    constructors: dict[str, str],
    dependency_calls: set[str],
) -> tuple[str | None, tuple[str, ...], int]:
    assignments: list[ast.Assign | ast.AnnAssign] = []
    allowed_targets: set[int] = set()
    for node in module.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        matching_targets = [
            target
            for target in targets
            if isinstance(target, ast.Name) and target.id == app_symbol
        ]
        if matching_targets:
            assignments.append(node)
            allowed_targets.update(id(target) for target in matching_targets)
    if len(assignments) != 1:
        return None, (), 0
    if _symbol_has_conflicting_binding(
        module,
        app_symbol,
        allowed_nodes=allowed_targets,
    ):
        return None, (), 0

    assignment = assignments[0]
    guards: list[str] = []
    if not isinstance(assignment.value, ast.Call):
        return None, (), 0
    constructor = _dotted_name(assignment.value.func)
    framework = constructors.get(constructor)
    if framework is None or not _valid_app_constructor_call(
        assignment.value, framework
    ):
        return None, (), 0
    for keyword in assignment.value.keywords:
        if framework == "fastapi" and keyword.arg == "dependencies":
            guards.extend(_guards_from_dependencies(keyword.value, dependency_calls))
    return framework, tuple(dict.fromkeys(guards)), assignment.lineno


def _valid_app_constructor_call(call: ast.Call, framework: str) -> bool:
    keyword_names = [keyword.arg for keyword in call.keywords]
    if any(name is None for name in keyword_names) or len(keyword_names) != len(
        set(keyword_names)
    ):
        return False
    if framework == "fastapi":
        return not call.args
    import_name_count = keyword_names.count("import_name")
    return (len(call.args) == 1 and import_name_count == 0) or (
        not call.args and import_name_count == 1
    )


def _has_route_graph_mutation(  # skylos: ignore[SKY-Q301,SKY-Q306] conservative AST proof
    module: ast.Module, app_symbol: str, *, after_line: int
) -> bool:
    route_collections = {
        f"{app_symbol}.routes",
        f"{app_symbol}.router.routes",
        f"{app_symbol}.url_map",
    }
    direct_mutators = {
        f"{app_symbol}.add_api_route",
        f"{app_symbol}.add_route",
        f"{app_symbol}.add_url_rule",
        f"{app_symbol}.include_router",
        f"{app_symbol}.mount",
        f"{app_symbol}.register_blueprint",
        f"{app_symbol}.router.add_api_route",
    }

    def contains_app_reference(node: ast.AST | None) -> bool:
        return node is not None and any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id == app_symbol
            for child in ast.walk(node)
        )

    for node in ast.walk(module):
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and node.lineno > after_line
        ):
            if contains_app_reference(node.value):
                return True
        if isinstance(node, ast.Attribute) and node.lineno > after_line:
            referenced = _dotted_name(node)
            if referenced in route_collections or referenced == f"{app_symbol}.router":
                return True
        if not isinstance(node, ast.Call) or node.lineno <= after_line:
            continue
        if any(contains_app_reference(argument) for argument in node.args) or any(
            contains_app_reference(keyword.value) for keyword in node.keywords
        ):
            return True
        called = _dotted_name(node.func)
        if called in direct_mutators or any(
            called.startswith(f"{collection}.") for collection in route_collections
        ):
            return True
        if (
            called in {"getattr", "setattr", "delattr"}
            and node.args
            and _dotted_name(node.args[0]).startswith(app_symbol)
        ):
            return True
    return False


def _route_pattern_can_match(  # skylos: ignore[SKY-Q301,SKY-Q306] bounded path matcher
    pattern: str, target: str
) -> bool:
    pattern_parts = [part for part in pattern.split("/") if part]
    target_parts = [part for part in target.split("/") if part]
    pattern_index = 0
    target_index = 0
    while pattern_index < len(pattern_parts):
        part = pattern_parts[pattern_index]
        if part.startswith("{") and part.endswith("}"):
            converter = part[1:-1].partition(":")[2] or "str"
            if converter == "path":
                return True
        if target_index >= len(target_parts):
            return False
        target_part = target_parts[target_index]
        if part.startswith("{") and part.endswith("}"):
            if target_part.startswith("{") and target_part.endswith("}"):
                return False
            if converter == "str":
                matches = bool(target_part)
            elif converter == "int":
                matches = bool(re.fullmatch(r"[0-9]+", target_part))
            elif converter == "float":
                matches = bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", target_part))
            elif converter == "uuid":
                matches = bool(
                    re.fullmatch(
                        r"[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?"
                        r"[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}",
                        target_part,
                    )
                )
            else:
                matches = False
            if not matches:
                return False
        else:
            if part != target_part:
                return False
        pattern_index += 1
        target_index += 1
    return target_index == len(target_parts)


def _remove_shadowed_fastapi_routes(routes: list[_Route]) -> list[_Route]:
    registered: list[_Route] = []
    reachable: list[_Route] = []
    for route in routes:
        shadowed = any(
            earlier.method == route.method
            and _route_pattern_can_match(earlier.path, route.path)
            for earlier in registered
        )
        registered.append(route)
        if not shadowed:
            reachable.append(route)
    return reachable


def _remove_duplicate_flask_routes(routes: list[_Route]) -> list[_Route]:
    seen: set[tuple[str, str]] = set()
    reachable: list[_Route] = []
    for route in routes:
        identity = (route.method, route.path)
        if identity not in seen:
            seen.add(identity)
            reachable.append(route)
    return reachable


def _routes_for_app(  # skylos: ignore[SKY-Q301,SKY-Q306] fail-closed route proof
    file: _TextFile, app_symbol: str, expected_framework: str
) -> list[_Route]:
    try:
        module = ast.parse(file.text)
        compile(module, str(file.path), "exec", dont_inherit=True)
    except (SyntaxError, TypeError, ValueError):
        return []
    constructors, dependency_calls = _framework_bindings(module)
    framework, app_guards, app_line = _app_identity_and_guards(
        module,
        app_symbol,
        constructors,
        dependency_calls,
    )
    if (
        framework is None
        or framework != expected_framework
        or _has_route_graph_mutation(module, app_symbol, after_line=app_line)
    ):
        return []

    routes: list[_Route] = []
    for node in module.body:
        if (
            not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            or node.lineno <= app_line
        ):
            continue
        identities: list[tuple[int, ast.Call, tuple[str, ...], str]] = []
        for decorator_index, decorator in enumerate(node.decorator_list):
            identity = _route_identity(decorator, app_symbol, framework)
            if identity is not None:
                identities.append((decorator_index, *identity))
        if not identities:
            continue
        route_decorators = {identity[1] for identity in identities}
        for decorator_index, decorator, methods, path in reversed(identities):
            guards = tuple(
                dict.fromkeys(
                    [
                        *app_guards,
                        *_route_guards(
                            node,
                            decorator,
                            decorator_index,
                            route_decorators,
                            dependency_calls,
                            framework,
                        ),
                    ]
                )
            )
            line = max(1, int(getattr(decorator, "lineno", node.lineno)))
            for method in methods:
                routes.append(
                    _Route(
                        file=file,
                        line=line,
                        method=method,
                        path=path,
                        handler=node.name,
                        guards=guards,
                    )
                )
    if framework == "fastapi":
        return _remove_shadowed_fastapi_routes(routes)
    return _remove_duplicate_flask_routes(routes)


def _route_is_sensitive(path: str) -> bool:
    segments = [
        segment.lower()
        for segment in path.split("/")
        if segment and not segment.startswith(("{", ":"))
    ]
    return bool(set(segments) & SENSITIVE_ROUTE_SEGMENTS)


def _ingress_reaches_route(ingress: _IngressPath, route: _Route) -> bool:
    if ingress.path_type == "Exact":
        return ingress.path == route.path
    ingress_parts = [part for part in ingress.path.split("/") if part]
    route_parts = [part for part in route.path.split("/") if part]
    return route_parts[: len(ingress_parts)] == ingress_parts


def _guard_matches(observed: str, required: str) -> bool:
    return observed == required


def _missing_required_guards(
    route: _Route, required: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        guard
        for guard in required
        if not any(_guard_matches(observed, guard) for observed in route.guards)
    )


def _yaml_code_and_comment(line: str) -> tuple[str, str]:
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif quote == "'":
            if char == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 2
                continue
            if char == "'":
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index], line[index:]
        index += 1
    return line, ""


@lru_cache(maxsize=8)
def _python_comments(file: _TextFile) -> dict[int, str]:
    comments: dict[int, str] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(file.text).readline)
        for token in tokens:
            if token.type == tokenize.COMMENT:
                comments[token.start[0]] = token.string
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return {}
    return comments


@lru_cache(maxsize=8)
def _yaml_multiline_scalar_lines(file: _TextFile) -> frozenset[int]:
    if yaml is None or _UniqueKeySafeLoader is None:
        return frozenset()
    try:
        documents = list(yaml.compose_all(file.text, Loader=_UniqueKeySafeLoader))
    except Exception:
        logger.debug(
            "Unable to inspect YAML multiline scalars: %s", file.path, exc_info=True
        )
        return frozenset()

    lines: set[int] = set()
    for document in documents:
        pending = [document]
        visited: set[int] = set()
        while pending:
            node = pending.pop()
            if node is None or id(node) in visited:
                continue
            visited.add(id(node))
            if isinstance(node, yaml.nodes.ScalarNode):
                if node.style in {"|", ">"}:
                    lines.update(
                        range(
                            node.start_mark.line + 2,
                            node.end_mark.line + 1,
                        )
                    )
                elif node.end_mark.line > node.start_mark.line:
                    lines.update(
                        range(
                            node.start_mark.line + 1,
                            node.end_mark.line + 2,
                        )
                    )
            elif isinstance(node, yaml.nodes.MappingNode):
                for key_node, value_node in node.value:
                    pending.extend((key_node, value_node))
            elif isinstance(node, yaml.nodes.SequenceNode):
                pending.extend(node.value)
    return frozenset(lines)


def _comment_at_line(file: _TextFile, line_number: int) -> str:
    if not 1 <= line_number <= len(file.lines):
        return ""
    if file.path.suffix.lower() == ".py":
        return _python_comments(file).get(line_number, "")
    if line_number in _yaml_multiline_scalar_lines(file):
        return ""
    return _yaml_code_and_comment(file.lines[line_number - 1])[1]


def _is_inline_ignored(file: _TextFile, line: int, rule_id: str) -> bool:
    needle = f"skylos: ignore[{rule_id}]"
    for line_number in (line - 1, line):
        if needle in _comment_at_line(file, line_number):
            return True
    return False


def _finding_contributors(
    chain: _ProofChain,
    *,
    source: _TextFile | None = None,
    source_line: int = 1,
    command_flag: str | None = None,
) -> list[tuple[_TextFile, int]]:
    if command_flag is not None:
        command_line = _container_command_token_line(
            chain.workload.file, chain.container, command_flag
        )
        if command_line is None:
            return []
        return [
            (chain.workload.file, command_line),
            (chain.ingress.file, chain.ingress.line),
            (chain.service.file, chain.service.line),
            (chain.workload.file, chain.workload.line),
        ]

    contributors: list[tuple[_TextFile, int]] = []
    if source is not None:
        contributors.append((source, source_line))
    if chain.workload.source_line is not None:
        contributors.append((chain.workload.file, chain.workload.source_line))
    if chain.workload.contract_line is None:
        return []
    contributors.extend(
        [
            (chain.workload.file, chain.workload.contract_line),
            (chain.ingress.file, chain.ingress.line),
            (chain.service.file, chain.service.line),
            (chain.workload.file, chain.container.line),
        ]
    )
    return contributors


def _anchor(
    contributors: list[tuple[_TextFile, int]], changed_paths: set[Path]
) -> tuple[Path, int]:
    for file, line in contributors:
        if file.path in changed_paths:
            return file.path, line
    file, line = contributors[0]
    return file.path, line


def _proof_metadata(
    chain: _ProofChain,
    entrypoint: _Entrypoint,
    *,
    source: _TextFile | None,
    route: _Route | None,
    required_guards: tuple[str, ...] = (),
    missing_guards: tuple[str, ...] = (),
    sink: str,
) -> dict[str, Any]:
    evidence_files = list(
        dict.fromkeys(
            str(path)
            for path in (
                source.path if source is not None else None,
                chain.ingress.file.path,
            )
            if path is not None
        )
    )
    trace = (
        f"bundle {chain.ingress.file.path.name}: Ingress "
        f"{chain.ingress.namespace}/{chain.ingress.ingress_name} "
        f"{chain.ingress.host}{chain.ingress.path} -> Service "
        f"{chain.service.name}:{chain.service_port.port} -> "
        f"{chain.workload.kind} {chain.workload.name} -> container "
        f"{chain.container.name} -> {entrypoint.server} "
        f"{entrypoint.module}:{entrypoint.symbol}@{entrypoint.host}:{entrypoint.port}"
    )
    if route is not None:
        trace += f" -> {route.method} {route.path} ({route.handler})"
    return {
        "proof_state": "correlated_static",
        "bundle_file": str(chain.ingress.file.path),
        "contract": {
            "network_scope": "external",
            "backend_protocol": "http",
            "source_file": chain.workload.source_file,
            "required_guards": list(required_guards),
        },
        "ingress": {
            "namespace": chain.ingress.namespace,
            "name": chain.ingress.ingress_name,
            "host": chain.ingress.host,
            "path": chain.ingress.path,
            "path_type": chain.ingress.path_type,
        },
        "service": {
            "name": chain.service.name,
            "port": chain.service_port.port,
            "target_port": chain.service_port.target_port,
        },
        "workload": {
            "kind": chain.workload.kind,
            "name": chain.workload.name,
            "container": chain.container.name,
        },
        "entrypoint": {
            "server": entrypoint.server,
            "module": entrypoint.module,
            "symbol": entrypoint.symbol,
            "host": entrypoint.host,
            "port": entrypoint.port,
        },
        "route": (
            {
                "file": str(route.file.path),
                "line": route.line,
                "method": route.method,
                "path": route.path,
                "handler": route.handler,
                "observed_guards": list(route.guards),
                "missing_guards": list(missing_guards),
            }
            if route is not None
            else None
        ),
        "sink": sink,
        "trace": trace,
        "evidence_files": evidence_files,
    }


def _related_locations(
    chain: _ProofChain,
    *,
    source: _TextFile | None = None,
) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    if source is not None:
        locations.append(
            {
                "file": str(source.path),
                "start_line": 1,
                "end_line": max(1, len(source.lines)),
            }
        )
    locations.extend(
        [
            {
                "file": str(chain.ingress.file.path),
                "start_line": chain.ingress.start_line,
                "end_line": chain.ingress.end_line,
            },
            {
                "file": str(chain.service.file.path),
                "start_line": chain.service.start_line,
                "end_line": chain.service.end_line,
            },
            {
                "file": str(chain.workload.file.path),
                "start_line": chain.workload.start_line,
                "end_line": chain.workload.end_line,
            },
            {
                "file": str(chain.workload.file.path),
                "start_line": chain.container.line,
                "end_line": chain.container.end_line,
            },
        ]
    )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for location in locations:
        key = (
            str(location["file"]),
            int(location["start_line"]),
            int(location["end_line"]),
        )
        if key not in seen:
            seen.add(key)
            unique.append(location)
    return unique


def _finding(
    *,
    rule_id: str,
    name: str,
    message: str,
    file: Path,
    line: int,
    severity: str,
    category: str,
    value: str,
    metadata: dict[str, Any],
    related_locations: list[dict[str, Any]],
) -> dict[str, Any]:
    finding = config_finding(
        rule_id=rule_id,
        domain="deployment",
        provider="kubernetes",
        name=name,
        message=message,
        file=file,
        line=line,
        severity=severity,
        value=value,
        finding_type="deployment_exposure",
        category=category,
    )
    finding["metadata"] = metadata
    finding["related_locations"] = related_locations
    sources: list[dict[str, Any]] = [
        {
            "kind": "rendered_kubernetes_bundle",
            "file": metadata["bundle_file"],
        },
        metadata["ingress"],
        metadata["service"],
        metadata["workload"],
    ]
    if metadata.get("route") is not None:
        sources.append(metadata["route"])
    finding["evidence_contract"] = {
        "schema_version": 1,
        "proof_state": "candidate",
        "sources": sources,
        "sinks": [metadata["sink"]],
        "symbols": [metadata["workload"]["container"]],
        "traces": [metadata["trace"]],
        "limitations": [
            "This is a correlated static desired-state proof; Skylos does not query the live cluster.",
            "Network scope, backend protocol, source file, and required guards are repository-owned declarative assertions.",
            "The source annotation does not prove that the analyzed file was built into the referenced image.",
            "A literal bare executable name does not attest the server binary's provenance inside the image.",
            "Guard analysis verifies exact framework wiring, not the guard implementation's semantics.",
        ],
    }
    return finding


def _should_emit(
    contributors: list[tuple[_TextFile, int]],
    *,
    changed_files: set[str] | None,
    changed_paths: set[Path],
    rule_id: str,
) -> bool:
    if changed_files is not None and not any(
        file.path in changed_paths for file, _ in contributors
    ):
        return False
    return not any(
        _is_inline_ignored(file, line, rule_id) for file, line in contributors
    )


def _route_findings(
    root: Path,
    chain: _ProofChain,
    entrypoint: _Entrypoint,
    *,
    changed_files: set[str] | None,
    changed_paths: set[Path],
) -> list[dict[str, Any]]:
    if (
        not chain.workload.required_guards
        or chain.workload.source_line is None
        or chain.workload.contract_line is None
    ):
        return []
    source = _resolve_contracted_source(root, chain.workload, entrypoint)
    if source is None:
        return []

    findings: list[dict[str, Any]] = []
    expected_framework = "fastapi" if entrypoint.server == "uvicorn" else "flask"
    for route in _routes_for_app(source, entrypoint.symbol, expected_framework):
        if not _route_is_sensitive(route.path) or not _ingress_reaches_route(
            chain.ingress, route
        ):
            continue
        missing = _missing_required_guards(route, chain.workload.required_guards)
        if not missing:
            continue
        contributors = _finding_contributors(
            chain, source=source, source_line=route.line
        )
        if not _should_emit(
            contributors,
            changed_files=changed_files,
            changed_paths=changed_paths,
            rule_id="SKY-DEP001",
        ):
            continue
        anchor_file, anchor_line = _anchor(contributors, changed_paths)
        metadata = _proof_metadata(
            chain,
            entrypoint,
            source=source,
            route=route,
            required_guards=chain.workload.required_guards,
            missing_guards=missing,
            sink=f"externally reachable route missing guard {', '.join(missing)}",
        )
        findings.append(
            _finding(
                rule_id="SKY-DEP001",
                name="Externally deployed route is missing a required auth guard",
                message=(
                    f"Deployment contract for `{chain.workload.name}` requires "
                    f"{', '.join(chain.workload.required_guards)} on externally "
                    f"reachable sensitive routes, but {route.method} `{route.path}` "
                    f"is missing {', '.join(missing)}. Add the required FastAPI/Flask "
                    "dependency or decorator, or narrow the Ingress path."
                ),
                file=anchor_file,
                line=anchor_line,
                severity="HIGH",
                category="SECURITY",
                value=f"{chain.ingress.host}{route.path}:{','.join(missing)}",
                metadata=metadata,
                related_locations=_related_locations(chain, source=source),
            )
        )
    return findings


def _server_mode_finding(
    chain: _ProofChain,
    entrypoint: _Entrypoint,
    *,
    rule_id: str,
    flag: str,
    changed_files: set[str] | None,
    changed_paths: set[Path],
) -> dict[str, Any] | None:
    contributors = _finding_contributors(chain, command_flag=flag)
    if not contributors or not _should_emit(
        contributors,
        changed_files=changed_files,
        changed_paths=changed_paths,
        rule_id=rule_id,
    ):
        return None
    anchor_file, anchor_line = _anchor(contributors, changed_paths)
    if rule_id == "SKY-DEP002":
        name = "External Ingress exposes the Flask development debugger"
        message = (
            f"External Ingress `{chain.ingress.ingress_name}` routes to Flask "
            f"container `{chain.container.name}` with `{flag}`. The interactive "
            "development debugger must not be exposed; remove debug mode and run a "
            "production WSGI server."
        )
        severity = "HIGH"
        category = "SECURITY"
        sink = "externally reachable Flask development debugger"
    else:
        name = "External Ingress routes to a reload-mode application server"
        message = (
            f"External Ingress `{chain.ingress.ingress_name}` routes to "
            f"{entrypoint.server} container `{chain.container.name}` with `{flag}` "
            "enabling reload mode. "
            "Remove automatic reload from the deployed workload."
        )
        severity = "MEDIUM"
        category = "RELIABILITY"
        sink = f"externally reachable {entrypoint.server} reload mode"
    metadata = _proof_metadata(
        chain,
        entrypoint,
        source=None,
        route=None,
        sink=sink,
    )
    return _finding(
        rule_id=rule_id,
        name=name,
        message=message,
        file=anchor_file,
        line=anchor_line,
        severity=severity,
        category=category,
        value=f"{chain.workload.name}:{chain.container.name}:{flag}",
        metadata=metadata,
        related_locations=_related_locations(chain),
    )


def scan_deployment_exposure(  # skylos: ignore[SKY-C304,SKY-Q301,SKY-Q306] bounded proof orchestrator
    root: str | Path,
    *,
    changed_files: set[str] | None = None,
    ignore: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Correlate one rendered Kubernetes bundle with its declared app contract."""

    normalized = _normalize_scan_target(root)
    if normalized is None or yaml is None:
        return []
    root_path, direct_file = normalized
    changed_paths = (
        _normalize_changed_paths(root_path, changed_files)
        if changed_files is not None
        else set()
    )
    if direct_file is not None and changed_files is None:
        changed_paths.add(direct_file)

    manifest_paths = _discover_manifest_paths(root_path, direct_file)
    if changed_files is not None and not any(
        path in changed_paths for path in manifest_paths
    ):
        changed_source = any(path.suffix.lower() == ".py" for path in changed_paths)
        if not changed_source:
            return []

    ignored = ignore or set()
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for manifest in _read_manifest_files(root_path, manifest_paths):
        resources = _manifest_documents(manifest)
        ingresses = _parse_ingresses(manifest, resources)
        services = _parse_services(manifest, resources)
        workloads = _parse_workloads(manifest, resources)
        if not ingresses or not services or not workloads:
            continue

        for chain in _proof_chains(ingresses, services, workloads):
            entrypoint = _entrypoint(chain.container)
            if entrypoint is None or not _entrypoint_reaches_service(chain, entrypoint):
                continue

            if "SKY-DEP001" not in ignored:
                for finding in _route_findings(
                    root_path,
                    chain,
                    entrypoint,
                    changed_files=changed_files,
                    changed_paths=changed_paths,
                ):
                    route = _mapping(finding.get("metadata")).get("route") or {}
                    key = (
                        "SKY-DEP001",
                        str(manifest.path),
                        str(route.get("file") or ""),
                        f"{route.get('method')}:{route.get('path')}:"
                        f"{','.join(route.get('missing_guards') or [])}",
                        f"{chain.ingress.namespace}/{chain.ingress.ingress_name}:"
                        f"{chain.ingress.path}",
                        f"{chain.service.name}>{chain.workload.kind}/"
                        f"{chain.workload.name}>{chain.container.name}",
                    )
                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)

            command = chain.container.command
            flask_debugger_flag: str | None = None
            if entrypoint.server == "flask":
                debug_state = _boolean_flag_state(command, "--debug", "--no-debug")
                debugger_state = _boolean_flag_state(
                    command, "--debugger", "--no-debugger"
                )
                if debugger_state is True:
                    flask_debugger_flag = "--debugger"
                elif debugger_state is None and debug_state is True:
                    flask_debugger_flag = "--debug"
            if "SKY-DEP002" not in ignored and flask_debugger_flag is not None:
                finding = _server_mode_finding(
                    chain,
                    entrypoint,
                    rule_id="SKY-DEP002",
                    flag=flask_debugger_flag,
                    changed_files=changed_files,
                    changed_paths=changed_paths,
                )
                key = (
                    "SKY-DEP002",
                    str(manifest.path),
                    chain.ingress.ingress_name,
                    chain.ingress.path,
                    chain.workload.name,
                    chain.container.name,
                )
                if finding is not None and key not in seen:
                    seen.add(key)
                    findings.append(finding)

            if "SKY-DEP003" not in ignored and entrypoint.server in SERVER_EXECUTABLES:
                reload_state = _boolean_flag_state(command, "--reload", "--no-reload")
                reload_flag = "--reload" if reload_state is True else None
                if (
                    entrypoint.server == "flask"
                    and reload_state is None
                    and _boolean_flag_state(command, "--debug", "--no-debug") is True
                ):
                    reload_flag = "--debug"
                if reload_flag is None:
                    continue
                finding = _server_mode_finding(
                    chain,
                    entrypoint,
                    rule_id="SKY-DEP003",
                    flag=reload_flag,
                    changed_files=changed_files,
                    changed_paths=changed_paths,
                )
                key = (
                    "SKY-DEP003",
                    str(manifest.path),
                    chain.ingress.ingress_name,
                    chain.ingress.path,
                    chain.workload.name,
                    chain.container.name,
                )
                if finding is not None and key not in seen:
                    seen.add(key)
                    findings.append(finding)

    return findings
