"""How a Cargo workspace depends on each locked crate, read from its manifests.

Cargo.lock records every resolved package and its edges, but not why an edge
exists. The workspace's own ``Cargo.toml`` files say so: ``[dependencies]``,
``[build-dependencies]`` and ``[dev-dependencies]`` (also under
``[target.'cfg(..)'.*]``), with ``optional = true`` entries that only a
feature turns on. Like cargo-deny's graph, this walks those manifests and the
lockfile edges statically and gives each locked registry package the strongest
way a local package (workspace member or path dependency) reaches it:

``normal``
    through a dependency that is not optional, or an optional one that a
    default feature, or a feature another local package requests, enables.
``build-only``
    only through build-dependencies.
``optional-feature``
    only through optional dependencies no default or requested feature
    enables (a user can still turn them on; they stay listed).
``dev-only``
    only through dev-dependencies, or through an optional dependency that only
    the package's own test, bench and example targets (``tests/``,
    ``benches/``, ``examples/``) name: a test-only feature such as clap's
    ``unstable-shell-tests``.

The walk is conservative. A lockfile edge no manifest entry explains, a
dependency table that cannot be read, or a local package with no manifest
makes the whole lockfile unclassified (``None``), and every edge that might
be normal counts as normal. Only a package no normal, build or optional path
reaches is dev-only.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_text_no_symlink

NORMAL = "normal"
BUILD = "build-only"
OPTIONAL = "optional-feature"
DEV = "dev-only"
_RANK = {NORMAL: 0, BUILD: 1, OPTIONAL: 2, DEV: 3}

_MAX_MANIFEST_BYTES = 1_000_000
_MAX_MANIFESTS = 2_000
_MAX_SOURCE_FILES = 5_000
_MAX_SOURCE_BYTES = 2_000_000
_SECTIONS = {
    "dependencies": NORMAL,
    "build-dependencies": BUILD,
    "build_dependencies": BUILD,
    "dev-dependencies": DEV,
    "dev_dependencies": DEV,
}
_DEV_TARGET_DIRS = frozenset({"tests", "benches", "examples"})
_SKIP_DIRS = frozenset({"target", ".git", "node_modules"})


class _Unclassified(Exception):
    """The manifests do not explain the lockfile; keep every kind unknown."""


def _load_toml(path: Path) -> dict:
    text = read_text_no_symlink(path, max_bytes=_MAX_MANIFEST_BYTES, encoding="utf-8")
    if text is None:
        raise _Unclassified(f"unreadable manifest {path}")
    try:
        data = tomllib.loads(text)
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise _Unclassified(f"invalid manifest {path}") from exc
    if not isinstance(data, dict):
        raise _Unclassified(f"invalid manifest {path}")
    return data


def _table(value) -> dict:
    return value if isinstance(value, dict) else {}


def _dependency_tables(manifest: dict):
    """Yield (section kind, table) for top-level and target-specific tables."""
    scopes = [manifest]
    scopes.extend(_table(spec) for spec in _table(manifest.get("target")).values())
    for scope in scopes:
        for section, kind in _SECTIONS.items():
            table = scope.get(section)
            if table is None:
                continue
            if not isinstance(table, dict):
                raise _Unclassified(f"{section} is not a table")
            yield kind, table


class _Manifest:
    def __init__(self, path: Path, data: dict, workspace_deps: dict):
        self.path = path
        self.dir = path.parent
        package = _table(data.get("package"))
        self.name = package.get("name")
        version = package.get("version")
        self.version = version if isinstance(version, str) else None
        self.data = data
        self.features = {
            name: [item for item in items if isinstance(item, str)]
            for name, items in _table(data.get("features")).items()
            if isinstance(items, list)
        }
        # real package name -> [(kind, optional, key, spec)]
        self.entries: dict[str, list] = {}
        self.path_deps: list[Path] = []
        for kind, table in _dependency_tables(data):
            for key, spec in table.items():
                spec = spec if isinstance(spec, dict) else {}
                inherited = {}
                if spec.get("workspace") is True:
                    inherited = _table(workspace_deps.get(key))
                    if not inherited and not isinstance(workspace_deps.get(key), str):
                        raise _Unclassified(f"workspace dependency {key} is undefined")
                real = spec.get("package") or inherited.get("package") or key
                if not isinstance(real, str):
                    raise _Unclassified(f"dependency {key} has no package name")
                features = [
                    item
                    for item in (
                        list(spec.get("features") or [])
                        + list(inherited.get("features") or [])
                    )
                    if isinstance(item, str)
                ]
                self.entries.setdefault(real, []).append(
                    (kind, spec.get("optional") is True, key, features)
                )
                if isinstance(spec.get("path"), str):
                    self.path_deps.append(self.dir / spec["path"])
                elif isinstance(inherited.get("path"), str):
                    self.path_deps.append(Path(inherited["_root"]) / inherited["path"])

    def optional_keys(self) -> set[str]:
        return {
            key
            for entries in self.entries.values()
            for kind, optional, key, _features in entries
            if optional and kind != DEV
        }


def _workspace_manifests(root: Path):
    root_manifest = root / "Cargo.toml"
    if not root_manifest.is_file():
        raise _Unclassified("no Cargo.toml next to Cargo.lock")
    data = _load_toml(root_manifest)
    workspace = _table(data.get("workspace"))
    workspace_deps = {}
    for key, spec in _table(workspace.get("dependencies")).items():
        if isinstance(spec, dict):
            workspace_deps[key] = {**spec, "_root": str(root)}
        else:
            workspace_deps[key] = spec
    pending = []
    if "package" in data:
        pending.append(root_manifest)
    # ``[patch]`` and ``[replace]`` path entries become local packages too.
    for registry in _table(data.get("patch")).values():
        for spec in _table(registry).values():
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                pending.append(root / spec["path"] / "Cargo.toml")
    for spec in _table(data.get("replace")).values():
        if isinstance(spec, dict) and isinstance(spec.get("path"), str):
            pending.append(root / spec["path"] / "Cargo.toml")
    excluded = {
        (root / item).resolve()
        for item in workspace.get("exclude") or []
        if isinstance(item, str)
    }
    for pattern in workspace.get("members") or []:
        if not isinstance(pattern, str):
            raise _Unclassified("workspace member is not a string")
        matches = (
            sorted(root.glob(pattern))
            if any(c in pattern for c in "*?[")
            else [root / pattern]
        )
        for member in matches:
            if member.resolve() in excluded or not (member / "Cargo.toml").is_file():
                continue
            pending.append(member / "Cargo.toml")
    manifests = {}
    while pending:
        path = pending.pop()
        try:
            key = path.resolve()
        except OSError as exc:
            raise _Unclassified(str(exc)) from exc
        if key in manifests:
            continue
        if len(manifests) >= _MAX_MANIFESTS:
            raise _Unclassified("too many manifests")
        if not path.is_file():
            raise _Unclassified(f"path dependency without manifest {path}")
        manifest = _Manifest(path, _load_toml(path), workspace_deps)
        if not isinstance(manifest.name, str):
            raise _Unclassified(f"manifest without package name {path}")
        if manifest.version is None:
            package_version = _table(data.get("workspace")).get("package")
            version = _table(package_version).get("version")
            manifest.version = version if isinstance(version, str) else None
        manifests[key] = manifest
        for dep in manifest.path_deps:
            pending.append(dep / "Cargo.toml")
    return list(manifests.values())


def _parse_edge(text: str):
    parts = text.split(" ")
    name = parts[0]
    version = parts[1] if len(parts) > 1 else None
    source = None
    if len(parts) > 2 and parts[2].startswith("(") and parts[-1].endswith(")"):
        source = " ".join(parts[2:])[1:-1]
    return name, version, source


def _resolve_edges(packages):
    """Lock key (index) -> list of target indexes. Raises on an ambiguous edge."""
    by_name: dict[str, list[int]] = {}
    for index, package in enumerate(packages):
        by_name.setdefault(package.get("name"), []).append(index)
    edges = {}
    for index, package in enumerate(packages):
        targets = []
        for raw in package.get("dependencies") or []:
            if not isinstance(raw, str):
                raise _Unclassified("invalid lock edge")
            name, version, source = _parse_edge(raw)
            candidates = by_name.get(name, [])
            if version is not None:
                candidates = [
                    i for i in candidates if packages[i].get("version") == version
                ]
            if source is not None:
                candidates = [
                    i for i in candidates if packages[i].get("source") == source
                ]
            if len(candidates) != 1:
                raise _Unclassified(f"ambiguous lock edge {raw}")
            targets.append(candidates[0])
        edges[index] = targets
    return edges


class _FeatureState:
    """Features enabled on local packages by defaults and normal dependents."""

    def __init__(self, manifests_by_lock):
        self.manifests = manifests_by_lock
        self.requested = {index: {"default"} for index in manifests_by_lock}
        self.enabled_keys = {index: set() for index in manifests_by_lock}

    def solve(self, local_by_name):
        changed = True
        rounds = 0
        while changed:
            rounds += 1
            if rounds > 200:
                raise _Unclassified("feature graph did not settle")
            changed = False
            for index, manifest in self.manifests.items():
                optional = manifest.optional_keys()
                seen = set()
                stack = list(self.requested[index])
                while stack:
                    feature = stack.pop()
                    if feature in seen:
                        continue
                    seen.add(feature)
                    if feature not in manifest.features:
                        # An optional dependency is also an implicit feature.
                        if (
                            feature in optional
                            and feature not in self.enabled_keys[index]
                        ):
                            self.enabled_keys[index].add(feature)
                            changed = True
                        continue
                    for item in manifest.features[feature]:
                        if item.startswith("dep:"):
                            key = item[4:]
                            if key not in self.enabled_keys[index]:
                                self.enabled_keys[index].add(key)
                                changed = True
                        elif "/" in item:
                            key, sub = item.split("/", 1)
                            weak = key.endswith("?")
                            key = key.rstrip("?")
                            if not weak and key not in self.enabled_keys[index]:
                                self.enabled_keys[index].add(key)
                                changed = True
                            changed |= self._request_from_key(
                                manifest, key, sub, local_by_name
                            )
                        else:
                            stack.append(item)
                # Normal and build dependents request features of local packages.
                for real, entries in manifest.entries.items():
                    target = local_by_name.get(real)
                    if target is None:
                        continue
                    for kind, opt, key, features in entries:
                        if kind == DEV or (opt and key not in self.enabled_keys[index]):
                            continue
                        for feature in features:
                            if feature not in self.requested[target]:
                                self.requested[target].add(feature)
                                changed = True
        return self

    def _request_from_key(self, manifest, key, feature, local_by_name):
        for real, entries in manifest.entries.items():
            if not any(entry[2] == key for entry in entries):
                continue
            target = local_by_name.get(real)
            if target is not None and feature not in self.requested[target]:
                self.requested[target].add(feature)
                return True
        return False


def _lib_names(key: str, real: str) -> set[str]:
    return {key.replace("-", "_"), real.replace("-", "_")}


def _only_dev_targets_use(manifest: _Manifest, names: set[str], nested: set[Path]):
    """True when the crate names appear in the package's sources, and only in
    its test, bench and example targets. Unknown or over budget is False."""
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        + "|".join(re.escape(n) for n in sorted(names))
        + r")(?![A-Za-z0-9_])"
    )
    found = False
    files = 0
    base = manifest.dir
    stack = [base]
    while stack:
        folder = stack.pop()
        try:
            children = sorted(folder.iterdir())
        except OSError:
            return False
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name in _SKIP_DIRS or child.name.startswith("."):
                    continue
                if child.resolve() in nested:
                    continue
                stack.append(child)
                continue
            if child.suffix != ".rs":
                continue
            files += 1
            if files > _MAX_SOURCE_FILES:
                return False
            text = read_text_no_symlink(
                child, max_bytes=_MAX_SOURCE_BYTES, encoding="utf-8", errors="replace"
            )
            if text is None:
                return False
            if not pattern.search(text):
                continue
            relative = child.relative_to(base).parts
            if relative and relative[0] in _DEV_TARGET_DIRS:
                found = True
                continue
            return False
    return found


def classify(
    lock_path: Path, packages: list[dict]
) -> dict[int, tuple[str, str]] | None:
    """Map each registry package index to (kind, reason), or None when the
    manifests cannot explain the lockfile."""
    try:
        return _classify(Path(lock_path), packages)
    except (_Unclassified, OSError, ValueError, RecursionError):
        return None


def _classify(lock_path: Path, packages: list[dict]):
    root = lock_path.parent
    manifests = _workspace_manifests(root)
    edges = _resolve_edges(packages)
    local = [i for i, p in enumerate(packages) if "source" not in p]
    by_name_version = {}
    for manifest in manifests:
        by_name_version.setdefault((manifest.name, manifest.version), []).append(
            manifest
        )
    manifests_by_lock = {}
    for index in local:
        package = packages[index]
        found = by_name_version.get((package.get("name"), package.get("version")))
        if not found:
            same_name = [m for m in manifests if m.name == package.get("name")]
            found = same_name if len(same_name) == 1 else None
        if not found or len(found) != 1:
            raise _Unclassified(f"no manifest for local package {package.get('name')}")
        manifests_by_lock[index] = found[0]
    local_by_name = {}
    for index in local:
        name = packages[index].get("name")
        if name in local_by_name:
            raise _Unclassified(f"two local packages named {name}")
        local_by_name[name] = index
    features = _FeatureState(manifests_by_lock).solve(local_by_name)
    nested = {m.dir.resolve() for m in manifests}

    seeds = {NORMAL: set(), BUILD: set(), OPTIONAL: set(), DEV: set()}
    reasons = {}
    dev_use_cache = {}
    for index in local:
        manifest = manifests_by_lock[index]
        enabled = features.enabled_keys[index]
        for target in edges[index]:
            if "source" not in packages[target]:
                continue  # each local package is its own root
            name = packages[target].get("name")
            entries = manifest.entries.get(name)
            if not entries:
                raise _Unclassified(f"lock edge {name} is not in {manifest.path}")
            best = None
            why = None
            for kind, optional, key, _features in entries:
                if optional and kind != DEV and key not in enabled:
                    cache_key = (index, key, name)
                    if cache_key not in dev_use_cache:
                        own_nested = nested - {manifest.dir.resolve()}
                        dev_use_cache[cache_key] = _only_dev_targets_use(
                            manifest, _lib_names(key, name), own_nested
                        )
                    if dev_use_cache[cache_key]:
                        kind, reason = (
                            DEV,
                            (
                                f"optional dependency `{key}` of {manifest.name} that only "
                                "its tests, benches and examples use"
                            ),
                        )
                    else:
                        kind, reason = (
                            OPTIONAL,
                            (
                                f"optional dependency `{key}` of {manifest.name} that no "
                                "default feature enables"
                            ),
                        )
                elif kind == DEV:
                    reason = f"dev-dependency of {manifest.name}"
                elif kind == BUILD:
                    reason = f"build-dependency of {manifest.name}"
                else:
                    reason = f"dependency of {manifest.name}"
                if best is None or _RANK[kind] < _RANK[best]:
                    best, why = kind, reason
            seeds[best].add(target)
            reasons.setdefault((best, target), why)

    def reach(start):
        seen = set()
        stack = list(start)
        origin = {node: node for node in start}
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for nxt in edges.get(node, ()):
                if "source" not in packages[nxt] or nxt in seen:
                    continue
                origin.setdefault(nxt, origin[node])
                stack.append(nxt)
        return seen, origin

    result = {}
    claimed = set()
    for kind in (NORMAL, BUILD, OPTIONAL, DEV):
        reached, origin = reach(seeds[kind])
        for node in reached - claimed:
            seed = origin[node]
            why = reasons.get((kind, seed), "")
            if seed != node:
                via = packages[seed].get("name")
                why = f"through {via}, {why}" if why else f"through {via}"
            result[node] = (kind, why)
        claimed |= reached
    return result
