"""Static, data-only reading of Maven ``pom.xml`` dependency versions.

Maven's effective model inherits the parent POM's properties and
``<dependencyManagement>``, then interpolates ``${...}``. This reads the POM
and any parent POM inside the scan root found through ``<relativePath>``
(default ``../pom.xml``) as inert XML. It never runs Maven, downloads a parent
POM or BOM, or activates profiles. A version that needs any of those is left
unresolved, never guessed. Plugin dependencies are build tooling, not project
dependencies. A dependency on a POM built in the same reactor (reached through
``<modules>`` inside the scan root) is not a public package; matching
``${project.version}`` or a shared groupId is not proof of that.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from xml.parsers import expat

from skylos.core.safe_cache_io import read_text_no_symlink, strip_utf8_bom

MAX_POM_BYTES = 10_000_000
MAX_PARENT_DEPTH = 10
MAX_INTERPOLATION_PASSES = 10
MAX_PROPERTY_CHARS = 1024
MAX_REACTOR_POMS = 2000
_UNSAFE_DECLARATION = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.I)
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z0-9_.-]{1,256})\}")
_COORDINATE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}\Z")
_EXACT_VERSION = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
_META_VERSIONS = frozenset({"LATEST", "RELEASE"})
_DEFAULT_TYPE = "jar"
_DEPENDENCY_PATH = ("project", "dependencies", "dependency")


@dataclass
class _Declaration:
    group: str | None
    artifact: str | None
    version: str | None
    scope: str | None
    optional: bool
    line: int
    artifact_type: str | None = None
    classifier: str | None = None


@dataclass
class _Model:
    path: Path
    group: str | None
    artifact: str | None
    version: str | None
    parent: dict | None
    properties: dict = field(default_factory=dict)
    managed: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    profile_dependency_count: int = 0


class PomCache:
    """POMs read once per scan: models by real path, module trees, coordinates."""

    def __init__(self) -> None:
        self.models: dict[Path, _Model | None] = {}
        self.trees: dict[Path, tuple[list[_Model], frozenset[Path]]] = {}
        self.coordinates: dict[Path, tuple] = {}
        self._root: Path | None = None

    def bind_root(self, root: Path | None) -> None:
        if root != self._root:
            self.trees.clear()
            self.coordinates.clear()
            self._root = root

    def model(self, path: Path, *, root: Path) -> _Model | None:
        # Check the requested filename before looking in the real-path cache:
        # resolving it first would erase a final symlink before the safe read.
        real = _guarded_pom_path(path, root)
        if real is None or not path.is_file():
            self.trees.clear()
            self.coordinates.clear()
            return None
        if real not in self.models:
            self.models[real] = _read_model(path)
        return self.models[real]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(node: ET.Element | None, name: str) -> ET.Element | None:
    if node is None:
        return None
    for child in node:
        if _local(child.tag) == name:
            return child
    return None


def _children(node: ET.Element | None, name: str) -> list[ET.Element]:
    return [child for child in _children_of(node) if _local(child.tag) == name]


def _children_of(node: ET.Element | None) -> list[ET.Element]:
    if node is None:
        return []
    return list(node)


def _text(node: ET.Element | None, name: str) -> str | None:
    child = _child(node, name)
    if child is None:
        return None
    return (child.text or "").strip()


def _root(text: str) -> ET.Element | None:
    if _UNSAFE_DECLARATION.search(text):
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if _local(root.tag) != "project":
        return None
    return root


def pom_is_valid(text: str) -> bool:
    return _root(text) is not None


def _dependency_lines(text: str) -> list[int]:
    """Start lines of ``project/dependencies/dependency``; comments excluded."""
    parser = expat.ParserCreate(namespace_separator="}")
    stack: list[str] = []
    lines: list[int] = []

    def on_start(tag, _attributes):
        stack.append(_local(tag))
        if tuple(stack) == _DEPENDENCY_PATH:
            lines.append(parser.CurrentLineNumber)

    def on_end(_tag):
        stack.pop()

    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.Parse(text, True)
    return lines


def _declaration(node: ET.Element, line: int) -> _Declaration:
    return _Declaration(
        group=_text(node, "groupId"),
        artifact=_text(node, "artifactId"),
        version=_text(node, "version"),
        scope=_text(node, "scope"),
        optional=_text(node, "optional") == "true",
        line=line,
        artifact_type=_text(node, "type"),
        classifier=_text(node, "classifier"),
    )


def _model(path: Path, text: str) -> _Model | None:
    root = _root(text)
    if root is None:
        return None
    parent_node = _child(root, "parent")
    parent = None
    if parent_node is not None:
        parent = {
            "group": _text(parent_node, "groupId"),
            "artifact": _text(parent_node, "artifactId"),
            "version": _text(parent_node, "version"),
            "relative_path": _text(parent_node, "relativePath"),
        }
    group = _text(root, "groupId")
    version = _text(root, "version")
    if parent is not None:
        group = group or parent["group"]
        version = version or parent["version"]
    model = _Model(
        path=path,
        group=group,
        artifact=_text(root, "artifactId"),
        version=version,
        parent=parent,
    )
    for prop in _children_of(_child(root, "properties")):
        if isinstance(prop.tag, str):
            model.properties[_local(prop.tag)] = (prop.text or "").strip()
    managed = _child(_child(root, "dependencyManagement"), "dependencies")
    for node in _children(managed, "dependency"):
        model.managed.append(_declaration(node, 0))
    nodes = _children(_child(root, "dependencies"), "dependency")
    lines = _dependency_lines(text)
    if len(lines) != len(nodes):
        return None
    model.dependencies = [_declaration(node, line) for node, line in zip(nodes, lines)]
    for module in _children(_child(root, "modules"), "module"):
        name = (module.text or "").strip()
        if name:
            model.modules.append(name)
    for profile in _children(_child(root, "profiles"), "profile"):
        model.profile_dependency_count += len(
            _children(_child(profile, "dependencies"), "dependency")
        )
    return model


def _read_model(path: Path) -> _Model | None:
    text = read_text_no_symlink(path, max_bytes=MAX_POM_BYTES, encoding="utf-8")
    if text is None:
        return None
    return _model(path, strip_utf8_bom(text))


def _parent_model(model: _Model, root: Path | None, cache: PomCache) -> _Model | None:
    """The declared parent when it is a matching POM inside the scan root."""
    parent = model.parent
    if root is None or parent is None:
        return None
    relative = parent["relative_path"]
    if relative is None:
        relative = "../pom.xml"
    if not relative or "\x00" in relative or len(relative) > 1024:
        return None
    candidate = model.path.parent / relative
    if candidate.is_dir():
        candidate = candidate / "pom.xml"
    candidate = _guarded_pom_path(candidate, root)
    if candidate is None or candidate == _real(model.path):
        return None
    loaded = cache.model(candidate, root=root)
    if loaded is None or (loaded.group, loaded.artifact, loaded.version) != (
        parent["group"],
        parent["artifact"],
        parent["version"],
    ):
        return None
    return loaded


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _guarded_pom_path(path: Path, root: Path | None) -> Path | None:
    """A non-symlink POM filename whose resolved location stays in scope."""
    try:
        if path.is_symlink():
            return None
        real = _real(path)
        if root is not None and not real.is_relative_to(root):
            return None
        return real
    except (OSError, ValueError):
        return None


def _lineage(model: _Model, root: Path | None, cache: PomCache) -> list[_Model]:
    """Models from the eldest ancestor found inside the scan root to ``model``."""
    chain = [model]
    seen = {_real(model.path)}
    current = model
    while current.parent is not None and len(chain) <= MAX_PARENT_DEPTH:
        parent = _parent_model(current, root, cache)
        if parent is None or _real(parent.path) in seen:
            break
        chain.append(parent)
        seen.add(_real(parent.path))
        current = parent
    return list(reversed(chain))


def _module_pom(model: _Model, module: str, root: Path) -> Path | None:
    if "\x00" in module or len(module) > 1024:
        return None
    candidate = model.path.parent / module
    if candidate.is_dir():
        candidate = candidate / "pom.xml"
    candidate = _guarded_pom_path(candidate, root)
    if candidate is None or not candidate.is_file():
        return None
    return candidate


def _module_tree(
    aggregator: _Model, root: Path, cache: PomCache
) -> tuple[list[_Model], frozenset[Path]]:
    """The aggregator and every POM its ``<modules>`` reach inside the scan root."""
    key = _real(aggregator.path)
    if key in cache.trees:
        cached = cache.trees[key]
        if all(cache.model(member.path, root=root) is member for member in cached[0]):
            return cached
        cache.trees.pop(key, None)
        cache.coordinates.clear()
    tree = [aggregator]
    seen = {key}
    index = 0
    examined = 0
    while index < len(tree) and examined < MAX_REACTOR_POMS:
        current = tree[index]
        index += 1
        for module in current.modules[: MAX_REACTOR_POMS - examined]:
            examined += 1
            candidate = _module_pom(current, module, root)
            if candidate is None or candidate in seen:
                continue
            seen.add(candidate)
            loaded = cache.model(candidate, root=root)
            if loaded is not None:
                tree.append(loaded)
    cache.trees[key] = (tree, frozenset(seen))
    return cache.trees[key]


def _reactor(
    model: _Model, chain: list[_Model], root: Path | None, cache: PomCache
) -> list[_Model]:
    """POMs built with ``model``: every module tree inside the scan root holding it.

    Candidate aggregators are the POM itself, its local parents and the
    ``pom.xml`` of each enclosing directory up to the scan root.
    """
    if root is None:
        return []
    own = _real(model.path)
    aggregators = list(chain)
    for directory in own.parents:
        if not directory.is_relative_to(root):
            break
        candidate = directory / "pom.xml"
        if directory != own.parent and candidate.is_file():
            loaded = cache.model(candidate, root=root)
            if loaded is not None:
                aggregators.append(loaded)
    members = []
    for aggregator in aggregators:
        tree, paths = _module_tree(aggregator, root, cache)
        if own in paths:
            members.extend(tree)
    return members


def _coordinates(member: _Model, root: Path | None, cache: PomCache) -> tuple:
    key = _real(member.path)
    if key not in cache.coordinates:
        properties = _properties(_lineage(member, root, cache), member)
        cache.coordinates[key] = (
            _interpolate(member.group, properties),
            _interpolate(member.artifact, properties),
            _exact_version(_interpolate(member.version, properties)),
        )
    return cache.coordinates[key]


def _built_in_reactor(
    reactor: list[tuple], group: str, artifact: str, version: str | None
) -> bool:
    """Maven takes a reactor project for a dependency with its group/artifact/version."""
    return any(
        (member_group, member_artifact) == (group, artifact)
        and (member_version is None or version is None or member_version == version)
        for member_group, member_artifact, member_version in reactor
    )


def _properties(chain: list[_Model], model: _Model) -> dict[str, str]:
    properties: dict[str, str] = {}
    for item in chain:
        properties.update(item.properties)
    builtins = {
        "groupId": model.group,
        "artifactId": model.artifact,
        "version": model.version,
    }
    if model.parent is not None:
        builtins["parent.groupId"] = model.parent["group"]
        builtins["parent.version"] = model.parent["version"]
    for key, value in builtins.items():
        if value is None:
            continue
        properties[f"project.{key}"] = value
        properties[f"pom.{key}"] = value
        properties.setdefault(key, value)
    return properties


def _interpolate(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None
    result = value
    for _ in range(MAX_INTERPOLATION_PASSES):
        keys = _PLACEHOLDER.findall(result)
        if not keys:
            if "${" in result:
                return None
            return result
        if any(key not in properties for key in keys):
            return None
        result = _PLACEHOLDER.sub(lambda match: properties[match.group(1)], result)
        if len(result) > MAX_PROPERTY_CHARS:
            return None
    return None


def _exact_version(value: str | None) -> str | None:
    if value is None or value in _META_VERSIONS:
        return None
    if not _EXACT_VERSION.fullmatch(value):
        return None
    return value


def _management_key(
    declaration: _Declaration, properties: dict[str, str]
) -> tuple | None:
    """Maven's management key: groupId, artifactId, type (jar) and classifier."""
    key = (
        _interpolate(declaration.group, properties),
        _interpolate(declaration.artifact, properties),
        _interpolate(declaration.artifact_type or _DEFAULT_TYPE, properties),
        _interpolate(declaration.classifier or "", properties),
    )
    if None in key:
        return None
    return key


def _managed(chain: list[_Model], properties: dict[str, str]) -> dict:
    managed = {}
    for item in chain:
        for declaration in item.managed:
            if declaration.scope == "import":
                continue
            key = _management_key(declaration, properties)
            if key is not None:
                managed[key] = declaration
    return managed


def pom_inventory(
    path: Path,
    text: str,
    *,
    root: Path | None = None,
    cache: PomCache | None = None,
) -> tuple[list[dict], int]:
    """A POM's exact dependency versions and the count Skylos is responsible for.

    The count includes profile dependencies and every dependency whose version
    stays unresolved; ``system`` scope and reactor modules are not counted.
    """
    path = Path(path)
    if root is not None:
        root = Path(root).resolve()
    if _guarded_pom_path(path, root) is None:
        return [], 0
    if cache is None:
        cache = PomCache()
    cache.bind_root(root)
    model = _model(path, text)
    if model is None:
        return [], 0
    cache.models.setdefault(_real(path), model)
    chain = _lineage(model, root, cache)
    properties = _properties(chain, model)
    managed = _managed(chain, properties)
    reactor = []
    if model.dependencies:
        reactor = [
            _coordinates(member, root, cache)
            for member in _reactor(model, chain, root, cache)
        ]
    counted = model.profile_dependency_count
    dependencies = []
    for declaration in model.dependencies:
        if declaration.scope == "system":
            continue
        group = _interpolate(declaration.group, properties)
        artifact = _interpolate(declaration.artifact, properties)
        if (
            group is None
            or artifact is None
            or not _COORDINATE.fullmatch(group)
            or not _COORDINATE.fullmatch(artifact)
        ):
            counted += 1
            continue
        managing = None
        key = _management_key(declaration, properties)
        if key is not None:
            managing = managed.get(key)
        raw_version = declaration.version
        scope = declaration.scope
        if managing is not None:
            if raw_version is None:
                raw_version = managing.version
            if scope is None:
                scope = managing.scope
        version = _exact_version(_interpolate(raw_version, properties))
        if _built_in_reactor(reactor, group, artifact, version):
            continue
        counted += 1
        if version is None or scope == "system":
            continue
        dependencies.append(
            {
                "name": f"{group}:{artifact}",
                "version": version,
                "ecosystem": "Maven",
                "file": str(path),
                "line": declaration.line,
                "snippet": f"{group}:{artifact}:{raw_version}",
                "version_spec": raw_version,
                "exact": True,
                "dependency_section": "dependencies",
                "dependency_kind": "direct",
                "dependency_dev": scope == "test",
                "dependency_optional": declaration.optional,
            }
        )
    return dependencies, counted


def parse_pom_xml(
    path: Path,
    *,
    text: str | None = None,
    root: Path | None = None,
    cache: PomCache | None = None,
) -> list[dict]:
    """Exact versions of a POM's own dependencies, as Maven would resolve them."""
    path = Path(path)
    if root is not None:
        root = Path(root).resolve()
    if _guarded_pom_path(path, root) is None:
        return []
    if text is None:
        text = read_text_no_symlink(path, max_bytes=MAX_POM_BYTES, encoding="utf-8")
        if text is None:
            return []
        text = strip_utf8_bom(text)
    return pom_inventory(path, text, root=root, cache=cache)[0]
