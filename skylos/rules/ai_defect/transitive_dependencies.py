"""Distributions that declared dependencies bring along, from static records.

A lockfile records each locked package's own dependencies (``uv.lock``,
``poetry.lock``, ``pdm.lock``); installed metadata records the same as
``Requires-Dist``. Starting from the declared distributions, only
unconditional edges are followed, plus the extras an edge requests. A
package that is merely present in a lockfile or environment, or reachable
only under a marker (platform, Python version, an extra nobody requested),
is not brought along. Lockfiles are parsed as TOML; nothing is installed,
resolved or executed.
"""

from __future__ import annotations

import re
from collections import deque

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

LOCKFILE_NAMES = ("uv.lock", "poetry.lock", "pdm.lock")
MAX_LOCKFILE_BYTES = 10_000_000
MAX_LOCKED_PACKAGES = 20_000
MAX_EDGES_PER_PACKAGE = 2_000
MAX_CLOSURE_STATES = 100_000
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_POETRY_EXTRA_ENTRY = re.compile(
    r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?"
)
_EXTRA_ONLY_MARKER = re.compile(r'extra == "([^"]+)"\Z')
_LOCAL_UV_SOURCES = frozenset({"editable", "virtual", "directory"})


def normalize(name):
    return re.sub(r"[-_.]+", "-", str(name).strip()).lower()


def _valid_name(value):
    return isinstance(value, str) and len(value) <= 256 and bool(_NAME.fullmatch(value))


def _extras(value):
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(_valid_name(item) for item in value):
        return None
    return frozenset(normalize(item) for item in value)


class LockGraph:
    """Unconditional locked edges.

    ``requires[name][extra]`` holds ``(dependency, requested extras)`` pairs;
    ``extra`` is None for the base dependencies. ``project_requires`` holds
    the edges of the project's own (local) entries, which carry the extras
    its declarations request. ``versions[name]`` holds every locked version
    of a package (None when an entry records none).
    """

    def __init__(self, requires, project_requires=frozenset(), versions=None):
        self.requires = requires
        self.project_requires = frozenset(project_requires)
        self.versions = versions or {}


def _record_version(versions, name, package):
    version = package.get("version")
    if not isinstance(version, str):
        version = None
    versions.setdefault(name, set()).add(version)


def _merge_entry(merged, name, edges):
    """A package locked more than once (forked resolutions) keeps only the
    edges every locked entry records."""
    if name not in merged:
        merged[name] = edges
        return
    previous = merged[name]
    merged[name] = {
        extra: previous[extra] & edges[extra]
        for extra in set(previous) & set(edges)
    }


def _uv_edges(entries):
    edges = set()
    if not isinstance(entries, list) or len(entries) > MAX_EDGES_PER_PACKAGE:
        return None
    for entry in entries:
        if not isinstance(entry, dict) or not _valid_name(entry.get("name")):
            return None
        if entry.get("marker"):
            continue
        extras = _extras(entry.get("extra"))
        if extras is None:
            return None
        edges.add((normalize(entry["name"]), extras))
    return frozenset(edges)


def _parse_uv_lock(data):
    packages = data.get("package", [])
    if not isinstance(packages, list) or len(packages) > MAX_LOCKED_PACKAGES:
        return None
    merged = {}
    project = set()
    versions = {}
    for package in packages:
        if not isinstance(package, dict) or not _valid_name(package.get("name")):
            return None
        name = normalize(package["name"])
        _record_version(versions, name, package)
        base = _uv_edges(package.get("dependencies", []))
        if base is None:
            return None
        edges = {None: base}
        optional = package.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            return None
        for extra, entries in optional.items():
            extra_edges = _uv_edges(entries)
            if extra_edges is None or not _valid_name(extra):
                return None
            edges[normalize(extra)] = extra_edges
        source = package.get("source", {})
        if isinstance(source, dict) and set(source) & _LOCAL_UV_SOURCES:
            project.update(base)
            for extra_edges in edges.values():
                project.update(extra_edges)
            for section in ("dev-dependencies", "dependency-groups"):
                groups = package.get(section, {})
                if not isinstance(groups, dict):
                    return None
                for entries in groups.values():
                    group_edges = _uv_edges(entries)
                    if group_edges is None:
                        return None
                    project.update(group_edges)
        _merge_entry(merged, name, edges)
    return LockGraph(merged, project, versions)


def _parse_poetry_lock(data):
    packages = data.get("package", [])
    if not isinstance(packages, list) or len(packages) > MAX_LOCKED_PACKAGES:
        return None
    merged = {}
    versions = {}
    for package in packages:
        if not isinstance(package, dict) or not _valid_name(package.get("name")):
            return None
        _record_version(versions, normalize(package["name"]), package)
        dependencies = package.get("dependencies", {})
        declared_extras = package.get("extras", {})
        if not isinstance(dependencies, dict) or not isinstance(declared_extras, dict):
            return None
        if len(dependencies) > MAX_EDGES_PER_PACKAGE:
            return None
        base = set()
        conditional = set()
        requested = {}
        for raw_name, spec in dependencies.items():
            if not _valid_name(raw_name):
                return None
            dependency = normalize(raw_name)
            if isinstance(spec, str):
                base.add((dependency, frozenset()))
                continue
            if not isinstance(spec, dict):
                conditional.add(dependency)
                continue
            extras = _extras(spec.get("extras"))
            if extras is None:
                return None
            requested[dependency] = extras
            if any(spec.get(key) for key in ("markers", "python", "platform")):
                conditional.add(dependency)
            elif not spec.get("optional"):
                base.add((dependency, extras))
        edges = {None: frozenset(base)}
        for extra, entries in declared_extras.items():
            if not _valid_name(extra) or not isinstance(entries, list):
                return None
            extra_edges = set()
            for entry in entries:
                if not isinstance(entry, str):
                    return None
                match = _POETRY_EXTRA_ENTRY.match(entry)
                if match is None:
                    return None
                dependency = normalize(match.group(1))
                if dependency in conditional:
                    continue
                extras = requested.get(dependency, frozenset())
                if match.group(2):
                    extras = extras | frozenset(
                        normalize(item) for item in match.group(2).split(",") if item.strip()
                    )
                extra_edges.add((dependency, extras))
            edges[normalize(extra)] = frozenset(extra_edges)
        _merge_entry(merged, normalize(package["name"]), edges)
    return LockGraph(merged, versions=versions)


def _requirement_edge(raw):
    """``(name, extras)`` for an unconditional requirement string, else None."""
    if not isinstance(raw, str):
        return None
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        return None
    if requirement.marker is not None or requirement.url:
        return None
    return normalize(requirement.name), frozenset(normalize(e) for e in requirement.extras)


def _parse_pdm_lock(data):
    packages = data.get("package", [])
    if not isinstance(packages, list) or len(packages) > MAX_LOCKED_PACKAGES:
        return None
    merged = {}
    versions = {}
    for package in packages:
        if not isinstance(package, dict) or not _valid_name(package.get("name")):
            return None
        _record_version(versions, normalize(package["name"]), package)
        dependencies = package.get("dependencies", [])
        if not isinstance(dependencies, list) or len(dependencies) > MAX_EDGES_PER_PACKAGE:
            return None
        extras = _extras(package.get("extras"))
        if extras is None:
            return None
        edges = frozenset(
            edge for edge in map(_requirement_edge, dependencies) if edge is not None
        )
        name = normalize(package["name"])
        keys = extras or {None}
        entry = merged.setdefault(name, {})
        for key in keys:
            if key in entry:
                entry[key] = entry[key] & edges
            else:
                entry[key] = edges
    return LockGraph(merged, versions=versions)


_LOCKFILE_PARSERS = {
    "uv.lock": _parse_uv_lock,
    "poetry.lock": _parse_poetry_lock,
    "pdm.lock": _parse_pdm_lock,
}


def parse_lockfile(filename, text):
    """The graph of one lockfile, or None when it cannot be read exactly."""
    parser = _LOCKFILE_PARSERS.get(filename)
    if parser is None or not isinstance(text, str):
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return parser(data)


def _closure(start, edges_of):
    seen = set()
    queue = deque(start)
    while queue and len(seen) < MAX_CLOSURE_STATES:
        state = queue.popleft()
        if state in seen:
            continue
        seen.add(state)
        for dependency, extras in edges_of(state):
            queue.append((dependency, None))
            queue.extend((dependency, extra) for extra in extras)
    return frozenset(name for name, _extra in seen)


def lockfile_closure(graph, declared_specs):
    """Distributions the lockfile brings along with the declared ones.

    ``declared_specs`` maps a declared name to its version specifier, None
    when the declaration has a marker or a URL. Only a declaration that
    applies everywhere, and that every locked version of the package
    satisfies, is a root: a lock entry for ``jinja2; python_version < '3'``
    or a stale lock outside ``jinja2<3`` brings nothing along.
    """
    roots = set()
    for name, specifier in declared_specs.items():
        versions = graph.versions.get(normalize(name), ())
        if specifier is None or not versions:
            continue
        if all(
            version is not None and _version_satisfies(version, specifier)
            for version in versions
        ):
            roots.add(normalize(name))
    start = [(name, None) for name in sorted(roots)]
    for dependency, extras in sorted(graph.project_requires):
        if dependency in roots:
            start.extend((dependency, extra) for extra in sorted(extras))

    def edges_of(state):
        name, extra = state
        return graph.requires.get(name, {}).get(extra, frozenset())

    return _closure(start, edges_of) - roots


def _version_satisfies(version, specifier):
    try:
        return SpecifierSet(specifier).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion, TypeError):
        return False


def installed_closure(declared_specs, installed):
    """Installed distributions that installed, declared ones require.

    ``declared_specs`` maps a declared name to its version specifier (None
    when it is conditional or unknown). ``installed`` maps a name to
    ``(version, requirement strings)``. A declared distribution only counts
    when its installed version satisfies the declaration, and every edge
    only when the installed target satisfies the requirement.
    """
    start = []
    for name, specifier in sorted(declared_specs.items()):
        record = installed.get(normalize(name))
        if specifier is None or record is None:
            continue
        if _version_satisfies(record[0], specifier):
            start.append((normalize(name), None))

    def edges_of(state):
        name, extra = state
        edges = []
        for raw in installed.get(name, ("", ()))[1]:
            try:
                requirement = Requirement(raw)
            except (InvalidRequirement, TypeError):
                continue
            if requirement.url:
                continue
            if requirement.marker is None:
                required_by = None
            else:
                match = _EXTRA_ONLY_MARKER.match(str(requirement.marker))
                if match is None:
                    continue
                required_by = normalize(match.group(1))
            if required_by != extra:
                continue
            target = normalize(requirement.name)
            record = installed.get(target)
            if record is None or not _version_satisfies(record[0], str(requirement.specifier)):
                continue
            edges.append(
                (target, frozenset(normalize(item) for item in requirement.extras))
            )
        return edges

    roots = {name for name, _extra in start}
    return _closure(start, edges_of) - roots
