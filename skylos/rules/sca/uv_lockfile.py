"""Read uv's universal lockfile without installing or executing project code.

Only explicit public PyPI registry identities are suitable for OSV queries.
All locked environments are inventoried; markers are evidence, not evaluated
against the scanner's Python/platform. See uv-resolver/src/lock/mod.rs for the
version 1 wire format (revisions are backwards compatible).
"""

from __future__ import annotations

import re
import stat
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit

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

MAX_UV_LOCK_BYTES = 10_000_000
MAX_GRAPH_STATES = 100_000
MAX_DEPENDENCY_EDGES = 100_000
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
# uv serializes normalized PEP 440 versions, including epochs and local builds.
_VERSION = re.compile(
    r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?\Z"
)
_TOKEN = re.compile(
    r"(?P<space>[ \t\r]+)|(?P<comment>\#[^\n]*)|(?P<newline>\n)"
    r'|(?P<string>"""(?:[^"\\]|\\.|"(?!""))*"{3,5}'
    r"|'''(?:[^']|'(?!''))*'{3,5}"
    r'|"(?:[^"\\\n]|\\.)*"|\'[^\'\n]*\')'
    r'|(?P<punct>[\[\]{},=.])|(?P<bare>[^\s\[\]{},=.#"\']+)',
    re.DOTALL,
)
_LOCAL_SOURCES = frozenset({"virtual", "editable", "directory"})
_SOURCE_TYPES = _LOCAL_SOURCES | {"registry", "git", "url", "path"}


def _name(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 256 or not _NAME.fullmatch(value):
        return None
    return re.sub(r"[-_.]+", "-", value).lower()


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise LockfileParseError(f"uv.lock {field} must be an array of strings")
    return value


def _version(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) <= 256 and bool(_VERSION.fullmatch(value))
    )


def _source_type(source: object) -> str:
    if not isinstance(source, dict):
        return "unknown"
    kinds = set(source) & _SOURCE_TYPES
    if len(kinds) != 1:
        return "unknown"
    kind = next(iter(kinds))
    return kind if isinstance(source[kind], str) and source[kind] else "unknown"


def _public_registry(source: dict) -> bool:
    # Do not expose credentials or treat private mirrors as public identities.
    if set(source) != {"registry"}:
        return False
    try:
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in source["registry"]):
            return False
        url = urlsplit(source["registry"])
        return (
            url.scheme == "https"
            and url.hostname in {"pypi.org", "pypi.python.org"}
            and url.port in {None, 443}
            and url.username is None
            and url.password is None
            and url.path in {"/simple", "/simple/"}
            and not url.query
            and not url.fragment
        )
    except (ValueError, TypeError):
        return False


def _package_lines(text: str) -> list[int]:
    """Locate package names lexically, with table/array/string scope intact.

    tomllib has already validated values. We retain only a statement's key or
    table header, skipping potentially large wheels/dependency arrays. Strings
    consume their complete contents, so metadata and comments cannot supply a
    different package's source location.
    """
    table: tuple = ()
    locations: list[int] = []
    prefix: list[tuple[str, str, int]] = []
    value = False
    depth = 0
    line = 1
    offset = 0

    def keys(tokens):
        return tuple(
            tomllib.loads("key=" + token)["key"] if kind == "string" else token
            for token, kind, _ in tokens
            if token != "."
        )

    for match in _TOKEN.finditer(text):
        if match.start() != offset:
            raise LockfileParseError("Unsupported uv.lock TOML location syntax")
        offset = match.end()
        token, kind = match.group(), match.lastgroup
        token_line = line
        line += token.count("\n")
        if kind in {"space", "comment"}:
            continue
        if token == "\n" and depth == 0:
            if prefix and prefix[0][0] == "[":
                array = len(prefix) > 1 and prefix[1][0] == "["
                border = 2 if array else 1
                table = keys(prefix[border:-border])
                if array and table == ("package",):
                    locations.append(prefix[0][2])
            prefix = []
            value = False
            continue
        if not value:
            if token == "=":
                if table == ("package",) and keys(prefix) == ("name",):
                    if not locations:
                        raise LockfileParseError(
                            "uv.lock package table is not an array"
                        )
                    locations[-1] = prefix[0][2]
                value = True
            else:
                prefix.append((token, kind, token_line))
        if kind == "punct":
            if token in {"[", "{"}:
                depth += 1
            elif token in {"]", "}"}:
                depth -= 1
    if offset != len(text):
        raise LockfileParseError("Unsupported uv.lock TOML location syntax")
    return locations


def _edges(package: dict) -> list[dict]:
    sections = [("dependencies", None, package.get("dependencies", []))]
    for section in ("optional-dependencies", "dev-dependencies", "dependency-groups"):
        groups = package.get(section, {})
        if not isinstance(groups, dict):
            raise LockfileParseError(f"uv.lock {section} must be a table")
        sections.extend((section, group, values) for group, values in groups.items())
    if "dev-dependencies" in package and "dependency-groups" in package:
        raise LockfileParseError("uv.lock has duplicate dependency group aliases")
    result = []
    for section, group, values in sections:
        if not isinstance(values, list):
            raise LockfileParseError(
                f"uv.lock {section} must contain dependency arrays"
            )
        for value in values:
            if not isinstance(value, dict) or _name(value.get("name")) is None:
                raise LockfileParseError(
                    "uv.lock dependency has an invalid package name"
                )
            edge = {"name": _name(value["name"]), "section": section}
            if group is not None:
                edge["group"] = group
            for key in ("version", "marker"):
                if key in value:
                    if not isinstance(value[key], str):
                        raise LockfileParseError(
                            f"uv.lock dependency {key} must be a string"
                        )
                    edge[key] = value[key]
            if "source" in value:
                if not isinstance(value["source"], dict):
                    raise LockfileParseError(
                        "uv.lock dependency source must be a table"
                    )
                edge["_source"] = value["source"]
                edge["source_type"] = _source_type(value["source"])
            if "extra" in value:
                edge["extras"] = _strings(value["extra"], "dependency extra")
            result.append(edge)
    return result


def _manifest_edges(manifest: dict) -> list[dict]:
    """Use non-project requirements as context for existing locked nodes.

    Requirements are not resolved distributions. An exact pin can select a
    version, but other specifiers only provide context when the recorded name
    is unambiguous. Unresolved contexts stay visible through _connect.
    """
    groups = manifest.get("dependency-groups", {})
    if not isinstance(groups, dict):
        raise LockfileParseError("uv.lock manifest dependency-groups must be a table")
    sections = [("dependencies", None, manifest.get("requirements", []))]
    sections.extend(
        ("dependency-groups", group, values) for group, values in groups.items()
    )
    edges = []
    for section, group, values in sections:
        if not isinstance(values, list):
            raise LockfileParseError("uv.lock manifest requirements must be arrays")
        for value in values:
            if not isinstance(value, dict) or _name(value.get("name")) is None:
                raise LockfileParseError(
                    "uv.lock manifest requirement has invalid name"
                )
            edge = {"name": _name(value["name"]), "section": section}
            if group is not None:
                edge["group"] = group
            if "marker" in value:
                if not isinstance(value["marker"], str):
                    raise LockfileParseError("uv.lock manifest marker must be a string")
                edge["marker"] = value["marker"]
            if "extras" in value:
                edge["extras"] = _strings(value["extras"], "manifest extras")
            if "specifier" in value:
                specifier = value["specifier"]
                if not isinstance(specifier, str):
                    raise LockfileParseError(
                        "uv.lock manifest specifier must be a string"
                    )
                if specifier.startswith("==") and _version(specifier[2:]):
                    edge["version"] = specifier[2:]
            edges.append(edge)
    return edges


def _connect(nodes: list[dict], inventory: LockfileInventory) -> None:
    by_name: dict[str, list[int]] = defaultdict(list)
    by_version: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, node in enumerate(nodes):
        if node["name"]:
            by_name[node["name"]].append(index)
            if isinstance(node["version"], str):
                by_version[(node["name"], node["version"])].append(index)
    for node in nodes:
        for edge in node["edges"]:
            candidates = by_name.get(edge["name"], [])
            if "version" in edge:
                candidates = by_version.get((edge["name"], edge["version"]), [])
            source = edge.pop("_source", None)
            if source is not None:
                candidates = [i for i in candidates if nodes[i]["source"] == source]
            if len(candidates) != 1:
                inventory.unresolved.append(
                    {
                        "reason": "missing_locked_dependency"
                        if not candidates
                        else "ambiguous_locked_dependency",
                        "package": node["name"],
                        "dependency": edge["name"],
                        "line": node["line"],
                    }
                )
                continue
            edge["_target"] = candidates[0]
            edge["package_path"] = f"package[{candidates[0]}]"
            if edge.get("marker"):
                nodes[candidates[0]]["context_markers"].add(edge["marker"])
            nodes[candidates[0]]["extras"].update(edge.get("extras", []))


def _contexts(nodes: list[dict], roots: set[int]) -> None:
    """Propagate only recorded dependency edges, selecting requested extras.

    Groups and root extras are all inventoried. Their labels describe possible
    paths in the universal lock, and never imply a production installation.
    """
    queue = deque()
    states: dict[tuple, set[str]] = {}

    def enqueue(edge, root, group, section, optional, dev, markers, direct=False):
        target = edge.get("_target")
        if target is None:
            return
        node = nodes[target]
        node["kinds"].add("direct" if direct else "transitive")
        markers = markers | set(node["markers"])
        if edge.get("marker"):
            markers.add(edge["marker"])
        for extra in [None, *edge.get("extras", [])]:
            key = (target, root, group, section, optional, dev, extra)
            if key not in states or not markers <= states[key]:
                states.setdefault(key, set()).update(markers)
                queue.append(key)
                if len(states) + len(queue) > MAX_GRAPH_STATES:
                    raise LockfileLimitError(
                        "uv.lock dependency graph exceeds context limit"
                    )

    for index in sorted(roots):
        node = nodes[index]
        for edge in node["edges"]:
            section = edge["section"]
            optional = section == "optional-dependencies"
            group = (
                f"extra:{edge['group']}"
                if optional
                else edge.get("group", "production")
            )
            enqueue(
                edge,
                node["name"],
                group,
                section,
                optional,
                section in {"dev-dependencies", "dependency-groups"},
                set(node["markers"]),
                direct=True,
            )
    processed = 0
    while queue:
        processed += 1
        if processed > MAX_GRAPH_STATES:
            raise LockfileLimitError("uv.lock dependency graph exceeds traversal limit")
        key = queue.popleft()
        index, root, group, section, optional, dev, extra = key
        node = nodes[index]
        node["roots"].add(root)
        node["groups"].add(group)
        node["sections"].add(section)
        node["optional"].add(optional)
        node["dev"].add(dev)
        node["context_markers"].update(states[key])
        for edge in node["edges"]:
            if (extra is None and edge["section"] == "dependencies") or (
                extra is not None
                and edge["section"] == "optional-dependencies"
                and edge["group"] == extra
            ):
                enqueue(edge, root, group, section, optional, dev, states[key])


def parse_uv_lock(
    path: Path, *, text: str | None = None, max_packages: int = 5000
) -> LockfileInventory:
    """Return public packages and explicit gaps from a format 1 uv.lock."""
    if text is None:
        text = read_text_no_symlink(path, max_bytes=MAX_UV_LOCK_BYTES, encoding="utf-8")
    if text is None:
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_size > MAX_UV_LOCK_BYTES:
                raise LockfileLimitError("uv.lock exceeds byte limit")
        except OSError:
            pass
        raise LockfileParseError(
            "uv.lock is unreadable, unsafe, oversized, or invalid UTF-8"
        )
    try:
        if len(text.encode("utf-8")) > MAX_UV_LOCK_BYTES:
            raise LockfileLimitError("uv.lock exceeds byte limit")
        data = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise LockfileParseError("uv.lock is not valid TOML") from exc
    if type(data.get("version")) is not int or data["version"] != 1:
        raise LockfileParseError("Only uv.lock format version 1 is supported")
    revision = data.get("revision", 0)
    if type(revision) is not int or revision < 0:
        raise LockfileParseError("uv.lock revision must be a nonnegative integer")
    packages = data.get("package")
    if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
        raise LockfileParseError("uv.lock must contain a package array")
    if len(packages) > max_packages:
        raise LockfileLimitError("uv.lock exceeds package limit")
    lines = _package_lines(text + "\n")
    if len(lines) != len(packages):
        raise LockfileParseError("uv.lock packages must use [[package]] tables")
    manifest = data.get("manifest", {})
    if not isinstance(manifest, dict):
        raise LockfileParseError("uv.lock manifest must be a table")
    members = {
        _name(n) for n in _strings(manifest.get("members", []), "manifest members")
    }
    if None in members:
        raise LockfileParseError("uv.lock manifest has invalid workspace names")
    global_markers = _strings(data.get("resolution-markers", []), "resolution-markers")
    supported = _strings(data.get("supported-markers", []), "supported-markers")
    required = _strings(data.get("required-markers", []), "required-markers")
    requires_python = data.get("requires-python")
    if requires_python is not None and not isinstance(requires_python, str):
        raise LockfileParseError("uv.lock requires-python must be a string")
    inventory = LockfileInventory(format_version=1, package_count=len(packages))
    nodes = []
    roots = set()
    workspace_paths = set()
    edge_count = 0
    for index, (package, line) in enumerate(zip(packages, lines)):
        name = _name(package.get("name"))
        version = package.get("version")
        source = package.get("source")
        kind = _source_type(source)
        markers = _strings(
            package.get("resolution-markers", []), "package resolution-markers"
        )
        node = {
            "name": name,
            "version": version,
            "source": source,
            "line": line,
            "edges": _edges(package),
            "markers": markers,
            "kinds": set(),
            "roots": set(),
            "groups": set(),
            "sections": set(),
            "extras": set(),
            "optional": set(),
            "dev": set(),
            "context_markers": set(),
            "record": None,
        }
        edge_count += len(node["edges"])
        if edge_count > MAX_DEPENDENCY_EDGES:
            raise LockfileLimitError("uv.lock exceeds dependency edge limit")
        nodes.append(node)
        reason = None
        if name is None:
            reason = "invalid_package_name"
        elif kind in _LOCAL_SOURCES:
            inventory.local_package_count += 1
            inventory.non_registry_names.append(name)
            if source[kind] == "." or name in members:
                roots.add(index)
                workspace_paths.add(source[kind])
            continue
        elif kind == "unknown":
            reason = "unsupported_package_source"
        elif kind != "registry":
            reason = "non_registry_source"
        elif not _public_registry(source):
            reason = "non_public_registry"
        elif not _version(version):
            reason = "invalid_locked_version"
        if reason:
            issue = {"reason": reason, "package": name, "line": line}
            if name:
                issue["name"] = name
            if _version(version):
                issue["version"] = version
            inventory.unresolved.append(issue)
            continue
        node["record"] = {
            "name": name,
            "version": version,
            "ecosystem": "PyPI",
            "file": str(path),
            "line": line,
            "snippet": f"{name}=={version}",
            "exact": True,
            "lockfile_version": 1,
            "lockfile_revision": revision,
            "package_path": f"package[{index}]",
            "source_type": "registry",
            "environment_scope": "all_locked_environments",
            "marker_evaluation": "not_evaluated",
            "lockfile_resolution_markers": global_markers,
            "lockfile_supported_markers": supported,
            "lockfile_required_markers": required,
            "requires_python": requires_python,
        }
    manifest_edges = _manifest_edges(manifest)
    if edge_count + len(manifest_edges) > MAX_DEPENDENCY_EDGES:
        raise LockfileLimitError("uv.lock exceeds dependency edge limit")
    if manifest_edges:
        roots.add(len(nodes))
        nodes.append(
            {
                "name": "<manifest>",
                "version": None,
                "source": None,
                "line": 1,
                "edges": manifest_edges,
                "markers": [],
                "record": None,
            }
        )
    inventory.non_registry_names = sorted(set(inventory.non_registry_names))
    inventory.workspace_paths = sorted(workspace_paths)
    _connect(nodes, inventory)
    _contexts(nodes, roots)
    for node in nodes:
        record = node["record"]
        if record is None:
            continue
        record.update(
            dependency_kind="direct"
            if "direct" in node["kinds"]
            else "transitive"
            if node["kinds"]
            else "unknown",
            dependency_kinds=sorted(node["kinds"]) or ["unknown"],
            dependency_groups=sorted(node["groups"]),
            dependency_sections=sorted(node["sections"]),
            dependency_roots=sorted(node["roots"]),
            dependency_extras=sorted(node["extras"]),
            dependency_markers=sorted(set(node["markers"]) | node["context_markers"]),
            dependency_optional=all(node["optional"]) if node["optional"] else None,
            dependency_dev=all(node["dev"]) if node["dev"] else None,
            dependencies=[
                {k: v for k, v in edge.items() if not k.startswith("_")}
                for edge in node["edges"]
            ],
        )
        inventory.dependencies.append(record)
    return inventory
