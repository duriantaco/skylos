"""Source-only Kubernetes YAML loading; no rendering or cluster access."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
from typing import Any

from skylos.core.file_discovery import should_exclude_path
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.config.cicd.yaml_source import YamlSource
from skylos.rules.config.deployment.exposure import SKIP_DIR_NAMES

try:
    import yaml
    from yaml.events import AliasEvent
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode

    from skylos.rules.config.cicd.yaml_source import _LocationLoader
except ImportError:  # pragma: no cover - PyYAML is a runtime dependency.
    yaml = None


MAX_FILES = 256
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 8_000_000
MAX_DIRECTORIES = 10_000
MAX_DOCUMENTS = 256
MAX_NODES = 50_000
MAX_DEPTH = 64
_RAW_API_KEY = re.compile(
    r"(?:^|[\n{,])\s*(?:apiVersion|\"apiVersion\"|'apiVersion')\s*:"
)
_RAW_KIND_KEY = re.compile(r"(?:^|[\n{,])\s*(?:kind|\"kind\"|'kind')\s*:")


if yaml is not None:

    class _ManifestLoader(_LocationLoader):
        def compose_node(self, parent, index):
            if self.check_event(AliasEvent):
                raise ValueError("Kubernetes YAML aliases are not evaluated")
            return super().compose_node(parent, index)

    # Kubernetes JSON values use strings, rather than Python date objects.
    _ManifestLoader.add_constructor(
        "tag:yaml.org,2002:timestamp",
        yaml.constructor.SafeConstructor.construct_yaml_str,
    )


@dataclass(frozen=True)
class Manifest:
    file: Path
    data: dict[str, Any]
    source: YamlSource

    def line(self, path: tuple[Any, ...] = ()) -> int:
        return self.source.line_for_path(path) or 1


@dataclass
class Project:
    manifests: list[Manifest] = field(default_factory=list)
    analysis_errors: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(
        default_factory=lambda: {
            "status": "complete",
            "files_discovered": 0,
            "files_read": 0,
            "files_parsed": 0,
            "documents_parsed": 0,
            "discovery_errors": [],
        }
    )

    def error(self, file, kind, message, line=1, *, hard=True):
        record = {
            "rule_id": "SKY-ANALYSIS-INCOMPLETE",
            "severity": "HIGH",
            "kind": kind,
            "error_type": "KubernetesManifestUnresolved",
            "file": str(file),
            "line": max(1, line),
            "column": 1,
            "message": message,
        }
        self.coverage["status"] = "incomplete"
        if hard:
            self.analysis_errors.append(record)
        else:
            self.coverage["discovery_errors"].append(record)


def _yaml_path(path):
    return path.suffix.lower() in {".yaml", ".yml"}


def _absolute(path, base):
    # Resolve filesystem aliases in ancestors, never the selected final symlink.
    candidate = Path(os.path.abspath(base / path))
    return candidate.parent.resolve() / candidate.name


def _discover(root, project, changed_files, scan_paths, exclude_folders):
    if root.is_symlink() or not root.exists():
        project.error(
            root,
            "kubernetes_scope_error",
            "Kubernetes scan root is missing or a symlink",
            hard=False,
        )
        return root, []
    root = root.resolve()
    if not root.is_file() and not root.is_dir():
        project.error(
            root,
            "kubernetes_scope_error",
            "Kubernetes scan root is not a regular file or directory",
            hard=False,
        )
        return root, []
    base = root.parent if root.is_file() else root
    if root.is_file() and not _yaml_path(root):
        return base, []
    changed = (
        None
        if changed_files is None
        else {_absolute(Path(p), base) for p in changed_files}
    )
    selected = (
        None if scan_paths is None else {_absolute(Path(p), base) for p in scan_paths}
    )

    def chosen(path):
        if changed is not None and path not in changed:
            return False
        if selected is not None and not any(
            path == item or path.is_relative_to(item) for item in selected
        ):
            return False
        return not should_exclude_path(path, base, exclude_folders)

    if root.is_file():
        return base, [root] if chosen(root) else []

    found = []

    def walk_error(error):
        project.error(
            getattr(error, "filename", None) or base,
            "kubernetes_discovery_error",
            "Could not enumerate potential Kubernetes manifests",
            hard=False,
        )

    for count, (directory, dirs, names) in enumerate(
        os.walk(base, followlinks=False, onerror=walk_error), 1
    ):
        if count > MAX_DIRECTORIES:
            project.error(
                base,
                "kubernetes_budget_exceeded",
                "Kubernetes directory discovery budget exhausted",
                hard=False,
            )
            break
        parent = Path(directory)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in SKIP_DIR_NAMES
            and not (parent / name).is_symlink()
            and not should_exclude_path(parent / name, base, exclude_folders)
        ]
        for name in sorted(names):
            path = parent / name
            if not _yaml_path(path) or not chosen(path):
                continue
            if len(found) >= MAX_FILES:
                project.error(
                    path,
                    "kubernetes_budget_exceeded",
                    "Kubernetes YAML file discovery budget exhausted",
                    hard=False,
                )
                return base, found
            found.append(path)
    return base, found


def _validate_mapping_keys(root):
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, MappingNode):
            if node.tag != "tag:yaml.org,2002:map":
                raise ValueError("Unsupported Kubernetes YAML mapping tag")
            seen = set()
            for key, value in node.value:
                if (
                    not isinstance(key, ScalarNode)
                    or key.tag != "tag:yaml.org,2002:str"
                ):
                    raise ValueError(
                        "Kubernetes YAML requires literal string keys; merge keys are unsupported"
                    )
                if key.value in seen:
                    raise ValueError("Kubernetes YAML contains duplicate mapping keys")
                seen.add(key.value)
                pending.append(value)
        elif isinstance(node, SequenceNode):
            if node.tag != "tag:yaml.org,2002:seq":
                raise ValueError("Unsupported Kubernetes YAML sequence tag")
            pending.extend(node.value)
        elif node.tag not in {
            "tag:yaml.org,2002:str",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:null",
            "tag:yaml.org,2002:timestamp",
        }:
            raise ValueError("Unsupported Kubernetes YAML scalar tag")


def _finite_values(root):
    pending = [root]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Kubernetes YAML contains a non-finite number")


def _manifest_hint(text):
    """Recognize decoded keys even when strict construction cannot succeed.

    This is only an identity hint for reporting uncertainty. It never supplies
    policy values or makes an unsupported document safe.
    """
    if yaml is None:
        return True
    stack = []
    try:
        for count, token in enumerate(yaml.scan(text), 1):
            if count > MAX_NODES * 3:
                return True  # Lexical uncertainty must not hide a parse limit.
            if isinstance(
                token, (yaml.tokens.DocumentStartToken, yaml.tokens.DocumentEndToken)
            ):
                stack.clear()
            elif isinstance(
                token,
                (yaml.tokens.BlockMappingStartToken, yaml.tokens.FlowMappingStartToken),
            ):
                stack.append({"mapping": True, "key": False, "identity": set()})
            elif isinstance(
                token,
                (
                    yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowSequenceStartToken,
                ),
            ):
                stack.append({"mapping": False})
            elif isinstance(
                token,
                (
                    yaml.tokens.BlockEndToken,
                    yaml.tokens.FlowMappingEndToken,
                    yaml.tokens.FlowSequenceEndToken,
                ),
            ):
                if stack:
                    stack.pop()
            elif stack and stack[-1]["mapping"]:
                current = stack[-1]
                if isinstance(token, yaml.tokens.KeyToken):
                    current["key"] = True
                elif isinstance(token, yaml.tokens.ValueToken):
                    current["key"] = False
                elif isinstance(token, yaml.tokens.ScalarToken) and current["key"]:
                    current["key"] = False
                    if token.value in {"apiVersion", "kind"}:
                        current["identity"].add(token.value)
                        if len(current["identity"]) == 2:
                            return True
    except yaml.YAMLError:
        if _RAW_API_KEY.search(text) and _RAW_KIND_KEY.search(text):
            return True
        return None  # Malformed YAML prevents reliable manifest classification.
    return False


def load_project(root, *, changed_files=None, scan_paths=None, exclude_folders=None):
    project = Project()
    base, paths = _discover(
        Path(root), project, changed_files, scan_paths, exclude_folders
    )
    project.coverage["files_discovered"] = len(paths)
    total = 0
    for path in paths:
        text = read_project_text_no_symlink(
            base, path, max_bytes=MAX_FILE_BYTES, encoding="utf-8"
        )
        if text is None:
            project.error(
                path,
                "kubernetes_source_read_error",
                "Could not safely read potential Kubernetes YAML within the file budget",
                hard=False,
            )
            continue
        total += len(text.encode("utf-8"))
        if total > MAX_TOTAL_BYTES:
            project.error(
                path,
                "kubernetes_budget_exceeded",
                "Kubernetes total YAML byte budget exhausted",
                hard=False,
            )
            break
        project.coverage["files_read"] += 1
        hinted = _manifest_hint(text)
        if yaml is None:
            if hinted is not False:
                project.error(
                    path,
                    "kubernetes_parser_unavailable",
                    "Kubernetes YAML parser is unavailable",
                )
            continue
        loader = _ManifestLoader(text, MAX_DEPTH, MAX_NODES)
        documents = 0
        try:
            while loader.check_node():
                documents += 1
                if documents > MAX_DOCUMENTS:
                    raise ValueError("Kubernetes YAML document budget exhausted")
                node = loader.get_node()
                if node is None:
                    continue
                _validate_mapping_keys(node)
                if not isinstance(node, MappingNode):
                    if hinted is not False:
                        raise ValueError("Kubernetes YAML document must be a mapping")
                    continue
                source = YamlSource(node, loader)
                data = loader.construct_document(node)
                _finite_values(data)
                source.data = data
                project.manifests.append(Manifest(path, data, source))
                project.coverage["documents_parsed"] += 1
            project.coverage["files_parsed"] += 1
        except (ValueError, TypeError, RecursionError, yaml.YAMLError) as error:
            if hinted:
                mark = getattr(error, "problem_mark", None)
                project.error(
                    path,
                    "kubernetes_parse_error",
                    "Kubernetes YAML is malformed, ambiguous, or exceeds static parsing limits",
                    (mark.line + 1) if mark is not None else 1,
                )
            elif hinted is None:
                project.error(
                    path,
                    "kubernetes_identification_incomplete",
                    "Malformed YAML prevented reliable Kubernetes manifest identification",
                    hard=False,
                )
        finally:
            loader.dispose()
    return project
