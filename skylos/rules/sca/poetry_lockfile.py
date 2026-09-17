"""Bounded, data-only inventories for Poetry lock formats 1.0, 1.1, 2.0, 2.1.

Poetry's locker records all resolved packages, but does not record the project's
direct dependency list. Groups and markers describe possible environments, not
what is installed on this machine. Source URLs and artifact names are never
copied to findings, followed, downloaded, or used to execute target code.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import stat

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.rules.sca.lockfile_types import (
    LockfileInventory,
    LockfileLimitError,
    LockfileParseError,
)
from skylos.rules.sca.uv_lockfile import _name, _package_lines, _public_registry

MAX_POETRY_LOCK_BYTES = 10_000_000
MAX_DEPENDENCY_EDGES = 100_000
MAX_TREE_NODES = 200_000
MAX_TREE_DEPTH = 64
_FORMATS = {"1.0", "1.1", "2.0", "2.1"}
_VERSION = re.compile(
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\Z",
    re.IGNORECASE,
)
_SPEC = re.compile(r"[A-Za-z0-9.*+<>=!~^|, _!-]+\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?=[\s\[(@;]|$)")


def _version(value):
    return (
        isinstance(value, str) and len(value) <= 256 and bool(_VERSION.fullmatch(value))
    )


def _text(value, field):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or "://" in value
        or "@" in value
    ):
        raise LockfileParseError(f"poetry.lock {field} must be a bounded text value")
    return value


def _label(value, field):
    if not isinstance(value, str) or len(value) > 256 or not _LABEL.fullmatch(value):
        raise LockfileParseError(f"poetry.lock {field} has an invalid label")
    return value


def _labels(value, field):
    if not isinstance(value, list):
        raise LockfileParseError(f"poetry.lock {field} must be an array")
    return sorted({_label(item, field) for item in value})


def _boolean(package, key):
    value = package.get(key)
    if key in package and type(value) is not bool:
        raise LockfileParseError(f"poetry.lock {key} must be a boolean")
    return value


def _tree_bound(data):
    pending = [(data, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
            raise LockfileLimitError("poetry.lock TOML tree exceeds limit")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)


def _source(package):
    if "source" not in package:
        # Poetry's default PyPI packages omit source entirely; custom indexes
        # and direct origins are explicitly serialized by Locker._dump_package.
        return "registry_unspecified", None
    source = package["source"]
    if not isinstance(source, dict) or not source:
        return "unknown", "invalid_package_source"
    kind = source.get("type")
    if not isinstance(kind, str) or not isinstance(source.get("url"), str):
        return "unknown", "invalid_package_source"
    if not source["url"]:
        return "unknown", "invalid_package_source"
    if kind == "directory":
        return kind, None
    if kind in {"git", "url", "file"}:
        return kind, "non_registry_source"
    if kind == "legacy":
        if set(source) - {"type", "url", "reference"}:
            return kind, "invalid_package_source"
        if _public_registry({"registry": source["url"]}):
            return "registry", None
        return kind, "non_public_registry"
    return "unknown", "unsupported_package_source"


def _workspace_path(source):
    value = source["url"]
    if value in {".", "./"}:
        return ""
    if value.startswith("./"):
        value = value[2:]
    if (
        not value
        or len(value) > 4096
        or ":" in value
        or "\\" in value
        or any(ord(char) < 32 for char in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        return None
    return value


def _markers(package, groups):
    result = {}
    for key in ("marker", "markers"):
        if key not in package:
            continue
        value = package[key]
        if isinstance(value, str):
            result[key] = _text(value, key)
        elif key == "markers" and isinstance(value, dict):
            if any(group not in groups for group in value):
                raise LockfileParseError(
                    "poetry.lock marker group is not recorded in groups"
                )
            result["groups"] = {
                group: _text(marker, "group marker")
                for group, marker in sorted(value.items())
            }
        else:
            raise LockfileParseError(
                "poetry.lock markers must be text or a group table"
            )
    requirements = package.get("requirements", {})
    if not isinstance(requirements, dict):
        raise LockfileParseError("poetry.lock requirements must be a table")
    if set(requirements) - {"python", "platform"}:
        raise LockfileParseError("poetry.lock legacy requirements are unsupported")
    if requirements:
        result["requirements"] = {
            key: _text(value, "legacy requirement")
            for key, value in sorted(requirements.items())
        }
    return result


def _extras(value):
    if not isinstance(value, dict):
        raise LockfileParseError("poetry.lock extras must be a table")
    extras = {}
    for label, requirements in value.items():
        _label(label, "extra")
        if not isinstance(requirements, list):
            raise LockfileParseError("poetry.lock extra requirements must be arrays")
        extras[label] = []
        for requirement in requirements:
            # PEP 508 direct references may carry credentials. Preserve the
            # package's identity, not an arbitrary requirement/source URL.
            if not isinstance(requirement, str) or len(requirement) > 4096:
                raise LockfileParseError("poetry.lock extra requirement is invalid")
            match = _REQUIREMENT_NAME.match(requirement)
            name = _name(match.group(1)) if match else None
            if name is None:
                raise LockfileParseError(
                    "poetry.lock extra requirement has invalid name"
                )
            item = {"name": name}
            if "@" in requirement or "://" in requirement:
                item["source_type"] = "non_registry"
            else:
                item["requirement"] = _text(requirement, "extra requirement")
            extras[label].append(item)
    return extras


def _edges(package, budget):
    values = package.get("dependencies", {})
    if not isinstance(values, dict):
        raise LockfileParseError("poetry.lock dependencies must be a table")
    edges = []
    for raw_name, raw_specs in values.items():
        name = _name(raw_name)
        if name is None:
            raise LockfileParseError("poetry.lock dependency has invalid name")
        specs = raw_specs if isinstance(raw_specs, list) else [raw_specs]
        if not specs:
            raise LockfileParseError(
                "poetry.lock dependency constraints must not be empty"
            )
        for spec in specs:
            if len(edges) >= budget:
                raise LockfileLimitError("poetry.lock exceeds dependency edge limit")
            edge = {"name": name, "section": "dependencies"}
            if isinstance(spec, str):
                spec = {"version": spec}
            if not isinstance(spec, dict) or not spec:
                raise LockfileParseError("poetry.lock dependency constraint is invalid")
            if set(spec) - {
                "version",
                "extras",
                "optional",
                "markers",
                "python",
                "platform",
                "path",
                "git",
                "url",
                "branch",
                "tag",
                "rev",
                "subdirectory",
                "develop",
                "source",
            }:
                raise LockfileParseError(
                    "poetry.lock dependency constraint field is unsupported"
                )
            source_keys = set(spec) & {"path", "git", "url", "source"}
            if source_keys:
                edge["source_type"] = (
                    "local" if source_keys == {"path"} else "non_registry"
                )
            elif "version" not in spec:
                raise LockfileParseError(
                    "poetry.lock dependency version or source is missing"
                )
            if "version" in spec:
                version_spec = _text(spec["version"], "dependency version")
                if not _SPEC.fullmatch(version_spec):
                    raise LockfileParseError(
                        "poetry.lock dependency version is unsupported"
                    )
                edge["version_spec"] = version_spec
                exact = version_spec.removeprefix("==").removeprefix("=").strip()
                if _version(exact):
                    edge["version"] = exact
            for key in ("markers", "python", "platform"):
                if key in spec:
                    edge[key] = _text(spec[key], "dependency " + key)
            if "optional" in spec:
                edge["optional"] = _boolean(spec, "optional")
            if "develop" in spec:
                _boolean(spec, "develop")
            if "extras" in spec:
                edge["extras"] = _labels(spec["extras"], "dependency extras")
            edges.append(edge)
    return edges


def _connect(nodes):
    by_name = defaultdict(list)
    by_version = defaultdict(list)
    for node in nodes:
        if node["name"]:
            by_name[node["name"]].append(node)
            if isinstance(node["version"], str):
                by_version[(node["name"], node["version"])].append(node)
    for node in nodes:
        record = node["record"]
        if record is None:
            continue
        for edge in record["dependencies"]:
            candidates = by_name.get(edge["name"], [])
            if not candidates:
                # The root project is not a [[package]], but a locked package
                # may depend back on it. A lock alone cannot distinguish that
                # valid case from a missing node; do not claim a complete graph.
                edge["resolution"] = "dependency_not_recorded"
                record["dependency_graph_complete"] = False
                continue
            if "version" in edge:
                candidates = by_version.get((edge["name"], edge["version"]), [])
                if not candidates:
                    # Poetry may serialize equivalent PEP 440 spellings such
                    # as 1.0 and 1.0.0. Inventory every recorded version without
                    # pretending to normalize/resolve those requirements.
                    edge["resolution"] = "version_constraint_not_evaluated"
                    record["dependency_graph_complete"] = False
                    continue
            if len(candidates) == 1 and "source_type" not in edge:
                # For a range, do not invent version-constraint evaluation.
                # A sole name match is useful evidence but not a proven edge.
                if "version" in edge or edge.get("version_spec") == "*":
                    edge["package_path"] = candidates[0]["package_path"]
                else:
                    edge["resolution"] = "version_constraint_not_evaluated"
                    record["dependency_graph_complete"] = False
            else:
                edge["resolution"] = "source_or_environment_not_resolved"
                record["dependency_graph_complete"] = False


def parse_poetry_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Inventory every locked environment; never read project code or sources."""
    if text is None:
        text = read_text_no_symlink(
            path, max_bytes=MAX_POETRY_LOCK_BYTES, encoding="utf-8"
        )
    if text is None:
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_size > MAX_POETRY_LOCK_BYTES:
                raise LockfileLimitError("poetry.lock exceeds byte limit")
        except OSError:
            pass
        raise LockfileParseError(
            "poetry.lock is unreadable, unsafe, oversized, or invalid UTF-8"
        )
    try:
        if len(text.encode("utf-8")) > MAX_POETRY_LOCK_BYTES:
            raise LockfileLimitError("poetry.lock exceeds byte limit")
        data = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise LockfileParseError("poetry.lock is not valid TOML") from exc
    _tree_bound(data)
    metadata = data.get("metadata")
    if (
        not isinstance(metadata, dict)
        or not isinstance(metadata.get("lock-version"), str)
        or metadata["lock-version"] not in _FORMATS
    ):
        raise LockfileParseError(
            "Unsupported poetry.lock format; expected 1.0, 1.1, 2.0, or 2.1"
        )
    format_version = metadata["lock-version"]
    major, minor = (int(part) for part in format_version.split("."))
    requires_python = metadata.get("python-versions")
    if requires_python is not None:
        requires_python = _text(requires_python, "metadata python-versions")
    packages = data.get("package")
    if not isinstance(packages, list) or not all(
        isinstance(package, dict) for package in packages
    ):
        raise LockfileParseError("poetry.lock must contain a package array")
    if len(packages) > max_packages:
        raise LockfileLimitError("poetry.lock exceeds package limit")
    try:
        lines = _package_lines(text + "\n")
    except LockfileParseError as exc:
        raise LockfileParseError(
            "Unsupported poetry.lock TOML location syntax"
        ) from exc
    if len(lines) != len(packages):
        raise LockfileParseError("poetry.lock packages must use [[package]] tables")
    root_extras = _extras(data.get("extras", {}))
    enabled_extras = defaultdict(set)
    for label, requirements in root_extras.items():
        for requirement in requirements:
            enabled_extras[requirement["name"]].add(label)
    inventory = LockfileInventory(format_version=major, package_count=len(packages))
    nodes = []
    edge_count = 0
    for index, (package, line) in enumerate(zip(packages, lines)):
        name, version = _name(package.get("name")), package.get("version")
        kind, reason = _source(package)
        package_path = f"package[{index}]"
        node = {
            "name": name,
            "version": version,
            "package_path": package_path,
            "record": None,
        }
        nodes.append(node)
        edges = _edges(package, MAX_DEPENDENCY_EDGES - edge_count)
        edge_count += len(edges)
        if name is None:
            reason = "invalid_package_name"
        elif kind == "directory":
            inventory.local_package_count += 1
            inventory.non_registry_names.append(name)
            relative = _workspace_path(package["source"])
            if relative is not None:
                inventory.workspace_paths.append(relative)
            continue
        elif not _version(version) and reason is None:
            reason = "invalid_locked_version"
        if reason:
            issue = {"reason": reason, "package": name, "line": line}
            if name:
                issue["name"] = name
                if kind not in {"registry", "registry_unspecified"}:
                    inventory.non_registry_names.append(name)
            if _version(version):
                issue["version"] = version
            inventory.unresolved.append(issue)
            continue
        groups = _labels(package.get("groups", []), "groups")
        if "category" in package:
            category = _label(package["category"], "category")
            groups = sorted(set(groups) | {category})
        optional = _boolean(package, "optional")
        _boolean(package, "develop")
        python_versions = package.get("python-versions")
        if python_versions is not None:
            python_versions = _text(python_versions, "python-versions")
        record = {
            "name": name,
            "version": version,
            "ecosystem": "PyPI",
            "file": str(path),
            "line": line,
            "snippet": f"{name}=={version}",
            "exact": True,
            "lockfile_version": major,
            "lockfile_revision": minor,
            "package_path": package_path,
            "source_type": kind,
            "environment_scope": "all_locked_environments",
            "marker_evaluation": "not_evaluated",
            "requires_python": python_versions,
            "lockfile_requires_python": requires_python,
            "dependency_kind": "unknown",
            "dependency_kinds": ["unknown"],
            "dependency_groups": groups,
            "dependency_optional": optional,
            "dependency_dev": False
            if "main" in groups
            else True
            if groups == ["dev"]
            else None,
            "dependency_markers": _markers(package, groups),
            "dependency_extras": sorted(enabled_extras.get(name, [])),
            "dependency_extra_requirements": _extras(package.get("extras", {})),
            "dependency_roots": [],
            "dependency_sections": ["dependencies"],
            "dependency_graph_complete": True,
            "dependencies": edges,
        }
        node["record"] = record
        inventory.dependencies.append(record)
    inventory.non_registry_names = sorted(set(inventory.non_registry_names))
    inventory.workspace_paths = sorted(set(inventory.workspace_paths))
    _connect(nodes)
    return inventory
