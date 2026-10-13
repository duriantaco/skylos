"""Dependencies a change adds or changes, for the approval guard.

Every changed dependency manifest and lockfile is read at the base and at
head and compared entry by entry. Declarations are pooled per ecosystem
across the changed files, so moving a package between sections or files
(``devDependencies`` to ``dependencies``, ``setup.py`` to
``pyproject.toml``), reformatting, reordering and the project's own version
bumps are not changes. A package the repository builds itself (a workspace
package, a path dependency, a module of the same repository) is never a
dependency change.

Reported, one entry per head file:

* a declaration whose package is new, or whose version or source changed;
* a locked package that is new, or whose locked version or checksum changed;
* a lockfile removed while its project stays (installs are no longer pinned);
* a manifest or lockfile that changed but could not be read or parsed, since
  a dependency change cannot be ruled out.

Nothing is installed or run and no registry is contacted.
"""

from __future__ import annotations

import configparser
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from xml.etree import ElementTree

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

MAX_PROJECT_MANIFESTS = 3000
_LISTED = 3

def _load_yaml(text):
    """Parse YAML with PyYAML's safe loader (the C one when available)."""
    if hasattr(yaml, "CSafeLoader"):
        return yaml.load(text, Loader=yaml.CSafeLoader)
    return yaml.safe_load(text)

# Directories whose files are installed packages, not this project's manifests.
_VENDORED_DIRS = frozenset({"node_modules", "bower_components", ".venv", "venv"})

# Lockfiles whose format is not compared entry by entry: any change counts.
_OPAQUE_LOCKS = {
    "bun.lockb": "npm",
    "deno.lock": "npm",
    "pixi.lock": "pypi",
    "conda-lock.yml": "pypi",
    "mix.lock": "hex",
    "Package.resolved": "swift",
    "flake.lock": "nix",
    "MODULE.bazel.lock": "bazel",
}
# lockfile name -> (format, ecosystem)
_LOCKFILES = {
    "package-lock.json": ("npm_lock", "npm"),
    "npm-shrinkwrap.json": ("npm_lock", "npm"),
    "yarn.lock": ("yarn_lock", "npm"),
    "pnpm-lock.yaml": ("pnpm_lock", "npm"),
    "bun.lock": ("bun_lock", "npm"),
    "poetry.lock": ("python_toml_lock", "pypi"),
    "pdm.lock": ("python_toml_lock", "pypi"),
    "uv.lock": ("python_toml_lock", "pypi"),
    "Pipfile.lock": ("pipfile_lock", "pypi"),
    "Cargo.lock": ("cargo_lock", "cargo"),
    "composer.lock": ("composer_lock", "composer"),
    "Gemfile.lock": ("gemfile_lock", "rubygems"),
    "gems.locked": ("gemfile_lock", "rubygems"),
    "go.sum": ("go_sum", "go"),
    "go.work.sum": ("go_sum", "go"),
    "pubspec.lock": ("pubspec_lock", "pub"),
    "packages.lock.json": ("nuget_lock", "nuget"),
    "gradle.lockfile": ("gradle_lock", "maven"),
    **{name: ("opaque", ecosystem) for name, ecosystem in _OPAQUE_LOCKS.items()},
}
LOCKFILE_NAMES = frozenset(_LOCKFILES)
_NUGET_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
_NUGET_NAMES = frozenset(
    {"Directory.Packages.props", "Directory.Build.props", "packages.config"}
)


@dataclass(frozen=True)
class DependencyChange:
    file: str
    line: int | None
    reason: str


class _Unreadable(Exception):
    """A dependency file that changed cannot be compared."""


@dataclass
class _Pool:
    """Declarations (or locked packages) in one snapshot."""

    # (ecosystem, key) -> {value: [(file, needle)]}
    entries: dict[tuple[str, str], dict[str, list[tuple[str, str]]]] = field(
        default_factory=dict
    )

    def add(self, ecosystem: str, key: str, value: str, file: str, needle: str):
        slot = self.entries.setdefault((ecosystem, key), {})
        slot.setdefault(value, []).append((file, needle))


# ---------------------------------------------------------------------------
# Which files are dependency files
# ---------------------------------------------------------------------------


def dependency_file_kind(path: str) -> tuple[str, str] | None:
    """("manifest" | "lockfile", format) for a dependency file, else None."""
    pure = PurePosixPath(path)
    if _VENDORED_DIRS.intersection(pure.parts[:-1]):
        return None
    name = pure.name
    lower = name.lower()
    if name in _LOCKFILES:
        return "lockfile", _LOCKFILES[name][0]
    if lower.endswith(".lockfile") and "gradle" in path.lower():
        return "lockfile", "gradle_lock"
    if name == "package.json":
        return "manifest", "npm"
    if name == "pyproject.toml":
        return "manifest", "pyproject"
    if name == "setup.py":
        return "manifest", "setup_py"
    if name == "setup.cfg":
        return "manifest", "setup_cfg"
    if name == "Pipfile":
        return "manifest", "pipfile"
    if _is_requirements_file(pure):
        return "manifest", "requirements"
    if name in {"environment.yml", "environment.yaml"}:
        return "manifest", "conda"
    if name == "go.mod":
        return "manifest", "gomod"
    if name == "Cargo.toml":
        return "manifest", "cargo"
    if name == "composer.json":
        return "manifest", "composer"
    if name in {"Gemfile", "gems.rb"}:
        return "manifest", "gemfile"
    if lower.endswith(".gemspec"):
        return "manifest", "gemspec"
    if name == "pom.xml":
        return "manifest", "maven"
    if name in {"build.gradle", "build.gradle.kts"}:
        return "manifest", "gradle"
    if lower.endswith(".versions.toml") and "gradle" in pure.parts[:-1]:
        return "manifest", "gradle_catalog"
    if name == "pubspec.yaml":
        return "manifest", "pubspec"
    if lower.endswith(_NUGET_SUFFIXES) or name in _NUGET_NAMES:
        return "manifest", "nuget"
    return None


def is_lockfile(path: str) -> bool:
    kind = dependency_file_kind(path)
    return kind is not None and kind[0] == "lockfile"


def _is_requirements_file(path: PurePosixPath) -> bool:
    name = path.name.lower()
    if not name.endswith((".txt", ".in")):
        return False
    if "requirements" in name or "constraints" in name:
        return True
    return path.parent.name.lower() == "requirements"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def dependency_changes(
    changed: Iterable,
    *,
    base_text: Callable[[str], str | None],
    head_text: Callable[[str], str | None],
    head_paths: Iterable[str] = (),
) -> list[DependencyChange]:
    """Changed dependencies, one ``DependencyChange`` per head file.

    ``changed`` holds ``ChangedFile``-like objects (``path``, ``base_path``,
    ``status``). ``base_text``/``head_text`` return a file's text at the base
    and at head, or None when it cannot be read; a changed dependency file
    that cannot be read is reported, never skipped. ``head_paths`` lists every
    path at head: the repository's own packages are found there, and whether
    a removed lockfile's project remains.
    """
    head_paths = [p for p in head_paths if p]
    manifests = (_Pool(), _Pool())
    locks = (_Pool(), _Pool())
    texts: dict[str, str] = {}
    sources: dict[str, str] = {}  # head path -> its path at the base
    results: list[DependencyChange] = []
    ecosystems: set[str] = set()
    removed_locks: list[str] = []
    lock_dirs_at_head: set[str] = set()

    for item in changed:
        paths = [p for p in (item.base_path, item.path) if p]
        kind = next((k for k in map(dependency_file_kind, reversed(paths)) if k), None)
        if kind is None:
            continue
        role, fmt = kind
        head_path = None if item.status == "deleted" else item.path
        base_path = item.base_path
        shown = head_path or base_path
        if role == "lockfile":
            if head_path is None:
                removed_locks.append(base_path)
                if fmt != "opaque":
                    # Its packages still count as "before" for a lockfile
                    # that replaces it (another package manager).
                    try:
                        before = _read(base_text, base_path)
                        _extract_into(fmt, before, base_path, locks[0], ecosystems)
                    except _Unreadable:
                        pass
                continue
            lock_dirs_at_head.add(str(PurePosixPath(head_path).parent))
        try:
            before = _read(base_text, base_path) if base_path else None
            after = _read(head_text, head_path) if head_path else None
            if before == after:
                continue
            if fmt == "opaque":
                results.append(
                    DependencyChange(
                        shown,
                        None,
                        f"lockfile {PurePosixPath(shown).name} changed (this format "
                        "is not compared entry by entry)",
                    )
                )
                continue
            base_pool, head_pool = locks if role == "lockfile" else manifests
            if before is not None:
                _extract_into(fmt, before, base_path, base_pool, ecosystems)
            if after is not None:
                _extract_into(fmt, after, head_path, head_pool, ecosystems)
                texts[head_path] = after
                if base_path:
                    sources[head_path] = base_path
        except _Unreadable as exc:
            results.append(
                DependencyChange(
                    shown,
                    None,
                    f"{PurePosixPath(shown).name} changed but could not be compared "
                    f"({exc}); a dependency change cannot be ruled out",
                )
            )

    own = _project_packages(ecosystems, head_paths, head_text) if ecosystems else {}
    results += _compare(*manifests, own, texts, locked=False, sources=sources)
    results += _compare(*locks, own, texts, locked=True, sources=sources)

    head_set = set(head_paths)
    for path in removed_locks:
        directory = str(PurePosixPath(path).parent)
        if directory in lock_dirs_at_head:
            continue  # replaced by another lockfile, compared above
        if _project_remains(directory, path, head_set):
            results.append(
                DependencyChange(
                    path,
                    None,
                    f"removes lockfile {PurePosixPath(path).name} while its project "
                    "stays: installs are no longer pinned to it",
                )
            )
    return sorted(results, key=lambda c: (c.file, c.line or 0, c.reason))


def _read(reader: Callable[[str], str | None], path: str) -> str:
    text = reader(path)
    if text is None:
        raise _Unreadable("not readable as UTF-8 text within the size limit")
    return text.lstrip("\ufeff")


def _extract_into(fmt, text, path, pool: _Pool, ecosystems: set[str]) -> None:
    try:
        items = list(_EXTRACTORS[fmt](text, path))
    except _Unreadable:
        raise
    except ElementTree.ParseError as exc:
        raise _Unreadable("invalid XML") from exc
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        yaml.YAMLError,
        configparser.Error,
    ) as exc:
        raise _Unreadable(f"could not parse it: {type(exc).__name__}") from exc
    for ecosystem, key, value, needle in items:
        ecosystems.add(ecosystem)
        pool.add(ecosystem, key, value, path, needle)


def _compare(
    base: _Pool,
    head: _Pool,
    own: dict[str, set[str]],
    texts: dict[str, str],
    *,
    locked: bool,
    sources: dict[str, str] | None = None,
) -> list[DependencyChange]:
    sources = sources or {}
    per_file: dict[str, list[tuple[str, str]]] = {}  # file -> [(text, needle)]
    for (ecosystem, key), values in sorted(head.entries.items()):
        if key in own.get(ecosystem, ()):
            continue
        before = base.entries.get((ecosystem, key), {})
        for value in values:
            if value in before:
                continue
            for file, needle in values[value]:
                # Show the value this file had, when it had one.
                origin = sources.get(file, file)
                same_file = [
                    old
                    for old, places in before.items()
                    if any(place == origin for place, _ in places)
                ]
                text = _describe(
                    _display(key), value, same_file or list(before), locked
                )
                entries = per_file.setdefault(file, [])
                if all(text != existing for existing, _ in entries):
                    entries.append((text, needle))
    results = []
    for file, entries in per_file.items():
        line = None
        if not locked:
            lines = texts.get(file, "").splitlines()
            found = [_find_line(lines, needle) for _, needle in entries]
            line = min((n for n in found if n is not None), default=None)
        count = len(entries)
        if locked:
            noun = "locked package" if count == 1 else "locked packages"
        else:
            noun = "dependency" if count == 1 else "dependencies"
        shown = "; ".join(text for text, _ in entries[:_LISTED])
        if count > _LISTED:
            shown += f" (+{count - _LISTED} more)"
        results.append(
            DependencyChange(file, line, f"adds or changes {count} {noun}: {shown}")
        )
    return results


def _describe(key: str, value: str, before: list[str], locked: bool) -> str:
    if locked:
        # Locked values are "version checksum": compared whole, shown by version.
        version = value.split(" ", 1)[0]
        old_versions = sorted({old.split(" ", 1)[0] for old in before})
        if not before:
            return f"{key}@{_short(version)}"
        if version in old_versions:
            return f"{key}@{_short(version)} (checksum changed)"
        return f"{key} {_short(old_versions[0])} -> {_short(version)}"
    if before:
        return f"{key} {_short(min(before))} -> {_short(value)}"
    return f"{key} ({_short(value)})" if value else key


def _find_line(lines: list[str], needle: str) -> int | None:
    if not needle:
        return None
    for candidate in (f'"{needle}"', f"'{needle}'", needle):
        for number, line in enumerate(lines, 1):
            if candidate in line:
                return number
    return None


def _display(key: str) -> str:
    for prefix in ("option:", "override:", "source:"):
        if key.startswith(prefix):
            return key[len(prefix) :]
    return key


def _short(value: str, limit: int = 60) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _project_remains(directory: str, removed: str, head_paths: set[str]) -> bool:
    ecosystem = _LOCKFILES.get(PurePosixPath(removed).name, (None, None))[1]
    prefix = "" if directory in {"", "."} else directory + "/"
    for path in head_paths:
        if not path.startswith(prefix) or "/" in path[len(prefix) :]:
            continue
        kind = dependency_file_kind(path)
        if (
            kind
            and kind[0] == "manifest"
            and _MANIFEST_ECOSYSTEM.get(kind[1]) == ecosystem
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# The repository's own packages
# ---------------------------------------------------------------------------


def _project_packages(
    ecosystems: set[str],
    head_paths: list[str],
    head_text: Callable[[str], str | None],
) -> dict[str, set[str]]:
    """Names of the packages this repository builds itself, per ecosystem."""
    readers = {
        "package.json": ("npm", _npm_own_name),
        "Cargo.toml": ("cargo", _cargo_own_name),
        "pyproject.toml": ("pypi", _pyproject_own_name),
        "setup.cfg": ("pypi", _setup_cfg_own_name),
        "setup.py": ("pypi", _setup_py_own_name),
        "go.mod": ("go", _gomod_own_name),
        "composer.json": ("composer", _composer_own_name),
        "pubspec.yaml": ("pub", _pubspec_own_name),
        "pom.xml": ("maven", _maven_own_name),
    }
    names: dict[str, set[str]] = {}
    read = 0
    for path in head_paths:
        pure = PurePosixPath(path)
        reader = readers.get(pure.name)
        if reader is None or reader[0] not in ecosystems:
            continue
        if _VENDORED_DIRS.intersection(pure.parts[:-1]):
            continue
        read += 1
        if read > MAX_PROJECT_MANIFESTS:
            break  # fewer own packages known: more is reported, never less
        text = head_text(path)
        if text is None:
            continue
        try:
            own = reader[1](text.lstrip("\ufeff"))
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
            yaml.YAMLError,
            configparser.Error,
            ElementTree.ParseError,
            _Unreadable,
        ):  # an unreadable manifest names no package
            own = None
        if isinstance(own, str) and own.strip():
            names.setdefault(reader[0], set()).add(_normalize(reader[0], own))
    return names


def _npm_own_name(text):
    data = json.loads(text)
    return data.get("name") if isinstance(data, dict) else None


def _cargo_own_name(text):
    return _get(tomllib.loads(text), "package", "name")


def _pyproject_own_name(text):
    data = tomllib.loads(text)
    return _get(data, "project", "name") or _get(data, "tool", "poetry", "name")


def _setup_cfg_own_name(text):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text)
    if parser.has_option("metadata", "name"):
        name = parser.get("metadata", "name").strip()
        return None if name.startswith(("attr:", "file:")) else name
    return None


def _setup_py_own_name(text):
    from skylos.core.python_requirements import parse_setup_py_text

    parsed = parse_setup_py_text(text, "setup.py")
    return getattr(parsed, "name", None)


def _gomod_own_name(text):
    for line in text.splitlines():
        match = re.match(r"^\s*module\s+(\S+)", line)
        if match:
            return match.group(1).strip('"')
    return None


def _composer_own_name(text):
    data = json.loads(text)
    return data.get("name") if isinstance(data, dict) else None


def _pubspec_own_name(text):
    data = _load_yaml(text)
    return data.get("name") if isinstance(data, dict) else None


def _maven_own_name(text):
    root = _xml_root(text)
    group = _xml_child_text(root, "groupId") or _xml_child_text(
        _xml_child(root, "parent"), "groupId"
    )
    artifact = _xml_child_text(root, "artifactId")
    return f"{group}:{artifact}" if group and artifact else None


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _normalize(ecosystem: str, name: str) -> str:
    name = str(name).strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in {"go", "maven"}:
        return name
    return name.lower()


def _spec(value) -> str:
    if isinstance(value, str):
        return " ".join(value.split())
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def _pep508(item: str):
    """(ecosystem, key, value, needle) for one PEP 508 requirement string."""
    item = item.strip()
    match = _REQ_NAME_RE.match(item)
    if match is None:
        return None
    name = match.group(1)
    rest = re.sub(r"\s+", "", item[match.end() :]).lower()
    return "pypi", _normalize("pypi", name), rest, name


# ---------------------------------------------------------------------------
# Manifests: each yields (ecosystem, key, value, needle)
# ---------------------------------------------------------------------------

_NPM_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)
_NPM_LOCAL_PREFIXES = ("workspace:", "file:", "link:", "portal:", "./", "../", "/")


def _npm_manifest(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("package.json is not an object")
    for section in _NPM_SECTIONS:
        for name, spec in _as_dict(data.get(section)).items():
            value = _spec(spec)
            if value.startswith(_NPM_LOCAL_PREFIXES):
                continue
            yield "npm", _normalize("npm", name), value, name
    overrides = {
        "overrides": data.get("overrides"),
        "resolutions": data.get("resolutions"),
        "pnpm.overrides": _get(data, "pnpm", "overrides"),
        "pnpm.patchedDependencies": _get(data, "pnpm", "patchedDependencies"),
    }
    for section, table in overrides.items():
        for path, value in _flatten(_as_dict(table)):
            if isinstance(value, str) and value.startswith(_NPM_LOCAL_PREFIXES):
                continue
            yield "npm", f"override:{section} {path}", _spec(value), path.split(">")[0]


def _flatten(table: dict, prefix: str = "", depth: int = 0):
    if depth > 32:
        return
    for key, value in table.items():
        path = f"{prefix}>{key}" if prefix else str(key)
        if isinstance(value, dict):
            yield from _flatten(value, path, depth + 1)
        else:
            yield path, value


_REQ_OPTION_RE = re.compile(
    r"\s--(?:hash|global-option|install-option|config-settings|config-setting)"
    r"(?:\s*=\s*|\s+)\S+"
)
_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_EDITABLE_RE = re.compile(r"^(?:-e|--editable)(?:\s*=\s*|\s+)(\S+)")


def _requirements_manifest(text, _path):
    for line in _logical_lines(text):
        line = _REQ_OPTION_RE.sub("", " " + _strip_comment(line)).strip()
        if not line:
            continue
        if line.startswith("-"):
            editable = _EDITABLE_RE.match(line)
            if editable:
                target = editable.group(1)
                if target.startswith((".", "/", "file:")):
                    continue  # the project itself or a local directory
                egg = _EGG_RE.search(target)
                if egg:
                    yield "pypi", _normalize("pypi", egg.group(1)), target, egg.group(1)
                    continue
            option = " ".join(line.split())
            yield "pypi", f"option:{option}", "", option
            continue
        parsed = _pep508(line)
        if parsed is None:
            yield "pypi", f"option:{line}", "", line
        else:
            yield parsed


def _logical_lines(text: str):
    buffer = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
            continue
        yield buffer + line
        buffer = ""
    if buffer:
        yield buffer


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    return re.sub(r"\s+#.*$", "", stripped)


def _pyproject_manifest(text, _path):
    data = tomllib.loads(text)
    lists: list[list] = []
    project = _as_dict(data.get("project"))
    lists.append(_as_list(project.get("dependencies")))
    lists += [
        _as_list(g) for g in _as_dict(project.get("optional-dependencies")).values()
    ]
    lists += [_as_list(g) for g in _as_dict(data.get("dependency-groups")).values()]
    lists.append(_as_list(_get(data, "build-system", "requires")))
    uv = _as_dict(_get(data, "tool", "uv"))
    for key in ("dev-dependencies", "constraint-dependencies", "override-dependencies"):
        lists.append(_as_list(uv.get(key)))
    lists += [
        _as_list(g)
        for g in _as_dict(_get(data, "tool", "pdm", "dev-dependencies")).values()
    ]
    for env in _as_dict(_get(data, "tool", "hatch", "envs")).values():
        if isinstance(env, dict):
            lists.append(_as_list(env.get("dependencies")))
            lists.append(_as_list(env.get("extra-dependencies")))
    for items in lists:
        for item in items:
            parsed = _pep508(item) if isinstance(item, str) else None
            if parsed:
                yield parsed
    for name, source in _as_dict(uv.get("sources")).items():
        if not _local_source(source):
            yield "pypi", f"source:{_normalize('pypi', name)}", _spec(source), name
    poetry = _as_dict(_get(data, "tool", "poetry"))
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [
        _as_dict(group).get("dependencies")
        for group in _as_dict(poetry.get("group")).values()
    ]
    for table in tables:
        for name, value in _as_dict(table).items():
            if name.lower() == "python" or _local_source(value):
                continue
            yield "pypi", _normalize("pypi", name), _spec(value), name


def _local_source(value) -> bool:
    if isinstance(value, dict):
        return bool(value.get("path") or value.get("workspace"))
    if isinstance(value, list) and value:
        return all(_local_source(v) for v in value)
    return False


def _setup_py_manifest(text, path):
    from skylos.core.python_requirements import parse_setup_py_text

    parsed = parse_setup_py_text(text, path)
    if parsed is None:
        raise ValueError("setup.py is not Python 3")
    # Requirements built at run time (read from a file, computed) are not
    # followed; a requirements file they read is compared on its own.
    for group in (parsed.install, parsed.setup, parsed.tests, *parsed.extras.values()):
        for item, _line in group:
            result = _pep508(item)
            if result:
                yield result


_SETUP_CFG_KEYS = ("install_requires", "setup_requires", "tests_require")


def _setup_cfg_manifest(text, _path):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text)
    values = []
    if parser.has_section("options"):
        values += [
            parser.get("options", key)
            for key in _SETUP_CFG_KEYS
            if parser.has_option("options", key)
        ]
    if parser.has_section("options.extras_require"):
        values += [value for _, value in parser.items("options.extras_require")]
    for value in values:
        value = value.strip()
        if value.startswith(("file:", "attr:")):
            continue  # read from another file, compared on its own
        chunks = value.splitlines() if "\n" in value else value.split(";")
        for chunk in chunks:
            chunk = _strip_comment(chunk)
            result = _pep508(chunk) if chunk else None
            if result:
                yield result


def _pipfile_manifest(text, _path):
    data = tomllib.loads(text)
    for section in ("packages", "dev-packages"):
        for name, value in _as_dict(data.get(section)).items():
            if not _local_source(value):
                yield "pypi", _normalize("pypi", name), _spec(value), name
    for source in _as_list(data.get("source")):
        if isinstance(source, dict) and source.get("url"):
            url = str(source["url"])
            yield "pypi", f"option:index {url}", "", url


def _conda_manifest(text, _path):
    data = _load_yaml(text)
    if not isinstance(data, dict):
        raise TypeError("environment file is not a mapping")
    for item in _as_list(data.get("dependencies")):
        if isinstance(item, str):
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(.*)$", item.strip())
            if match:
                rest = re.sub(r"\s+", "", match.group(2))
                yield "conda", match.group(1).lower(), rest, match.group(1)
        elif isinstance(item, dict):
            for pip_item in _as_list(item.get("pip")):
                parsed = _pep508(pip_item) if isinstance(pip_item, str) else None
                if parsed:
                    yield parsed
    for channel in _as_list(data.get("channels")):
        yield "conda", f"option:channel {channel}", "", str(channel)


_GO_REQUIRE_RE = re.compile(r"^([^\s()]+)\s+(v\S+)")


def _gomod_manifest(text, _path):
    block = None
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
            else:
                yield from _gomod_directive(block, line)
            continue
        keyword, _, rest = line.partition(" ")
        rest = rest.strip()
        if keyword in {"require", "replace"}:
            if rest == "(":
                block = keyword
            else:
                yield from _gomod_directive(keyword, rest)


def _gomod_directive(keyword: str, line: str):
    if keyword == "require":
        match = _GO_REQUIRE_RE.match(line)
        if match:
            module = match.group(1).strip('"')
            yield "go", module, match.group(2), module
        return
    if "=>" not in line:
        return
    old, new = (part.strip() for part in line.split("=>", 1))
    if not old or new.startswith((".", "/")):
        return  # replaced by a local directory
    module = old.split()[0]
    yield "go", f"override:replace {module}", " ".join(new.split()), module


_CARGO_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def _cargo_manifest(text, _path):
    data = tomllib.loads(text)
    tables = [data.get(section) for section in _CARGO_SECTIONS]
    for target in _as_dict(data.get("target")).values():
        if isinstance(target, dict):
            tables += [target.get(section) for section in _CARGO_SECTIONS]
    tables.append(_get(data, "workspace", "dependencies"))
    for table in tables:
        for name, value in _as_dict(table).items():
            if isinstance(value, dict) and (
                value.get("path") or value.get("workspace")
            ):
                continue  # a crate of this repository, or the workspace's entry
            package = value.get("package", name) if isinstance(value, dict) else name
            yield "cargo", _normalize("cargo", str(package)), _spec(value), name
    for registry, patches in _as_dict(data.get("patch")).items():
        for name, value in _as_dict(patches).items():
            if isinstance(value, dict) and value.get("path"):
                continue
            yield "cargo", f"override:patch {registry} {name}", _spec(value), name


def _composer_manifest(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("composer.json is not an object")
    for section in ("require", "require-dev"):
        for name, spec in _as_dict(data.get(section)).items():
            lowered = name.lower()
            if lowered == "php" or lowered.startswith(("ext-", "lib-", "composer-")):
                continue  # the PHP runtime and its extensions, not packages
            yield "composer", lowered, _spec(spec), name
    for repository in _as_list(data.get("repositories")):
        if isinstance(repository, dict) and repository.get("type") != "path":
            url = str(repository.get("url") or "")
            yield "composer", f"option:repository {_spec(repository)}", "", url


_GEM_RE = re.compile(r"""^gem\s*\(?\s*["']([^"']+)["']\s*(.*)$""")
_GEMSPEC_RE = re.compile(
    r"""\.add_(?:runtime_|development_)?dependency\s*\(?\s*["']([^"']+)["']\s*(.*)$"""
)
_GEM_SOURCE_RE = re.compile(r"""^source\s*\(?\s*["']([^"']+)["']""")


def _gemfile_manifest(text, _path):
    for raw in text.splitlines():
        line = _strip_comment(raw)
        source = _GEM_SOURCE_RE.match(line)
        if source:
            url = source.group(1)
            yield "rubygems", f"option:source {url}", "", url
            continue
        match = _GEM_RE.match(line)
        if match is None or re.search(r"\bpath\s*(?::|=>)", match.group(2)):
            continue
        yield (
            "rubygems",
            match.group(1).lower(),
            _gem_rest(match.group(2)),
            match.group(1),
        )


def _gemspec_manifest(text, _path):
    for raw in text.splitlines():
        match = _GEMSPEC_RE.search(_strip_comment(raw))
        if match:
            name = match.group(1)
            yield "rubygems", name.lower(), _gem_rest(match.group(2)), name


def _gem_rest(rest: str) -> str:
    rest = re.sub(r"\b(?:require|group|groups|platforms?)\s*(?::|=>)\s*[^,]+", "", rest)
    return re.sub(r"[\s)]+", "", rest).strip(",")


def _maven_manifest(text, _path):
    root = _xml_root(text)
    properties = _xml_child(root, "properties")
    for prop in list(properties) if properties is not None else ():
        name = _local(prop.tag)
        if "version" in name.lower():
            yield "maven", f"property:{name}", (prop.text or "").strip(), f"<{name}>"
    for element in root.iter():
        tag = _local(element.tag)
        if tag not in {"dependency", "plugin", "extension", "parent"}:
            continue
        artifact = _xml_child_text(element, "artifactId")
        if not artifact or _xml_child_text(element, "scope") == "system":
            continue
        group = _xml_child_text(element, "groupId") or (
            "org.apache.maven.plugins" if tag == "plugin" else ""
        )
        version = _xml_child_text(element, "version") or ""
        yield "maven", f"{group}:{artifact}", version, f"<artifactId>{artifact}<"


_GRADLE_CONFIGURATIONS = (
    r"(?:[A-Za-z]+(?:Implementation|Api|CompileOnly|RuntimeOnly)|implementation|api|"
    r"compileOnly|runtimeOnly|compile|testCompile|annotationProcessor|kapt|ksp|"
    r"classpath|developmentOnly|lintChecks|detektPlugins)"
)
_GRADLE_DEP_RE = re.compile(
    rf"""^\s*{_GRADLE_CONFIGURATIONS}\s*\(?\s*"""
    r"""(?:(?:platform|enforcedPlatform)\s*\(\s*)?["']([^"':\s]+):([^"':\s]+)(?::([^"'\s]+))?["']"""
)
_GRADLE_PLUGIN_RE = re.compile(
    r"""^\s*id\s*\(?\s*["']([^"']+)["']\s*\)?\s*version\s*\(?\s*["']([^"']+)["']"""
)


def _gradle_manifest(text, _path):
    for raw in text.splitlines():
        line = raw.split("//", 1)[0]
        match = _GRADLE_DEP_RE.match(line)
        if match:
            group, artifact, version = match.groups()
            coordinate = f"{group}:{artifact}"
            yield "maven", coordinate, version or "", coordinate
            continue
        plugin = _GRADLE_PLUGIN_RE.match(line)
        if plugin:
            yield "maven", f"plugin:{plugin.group(1)}", plugin.group(2), plugin.group(1)


def _gradle_catalog_manifest(text, _path):
    data = tomllib.loads(text)
    for section in ("versions", "libraries", "plugins", "bundles"):
        for name, value in _as_dict(data.get(section)).items():
            yield "maven", f"catalog:{section}.{name}", _spec(value), name


def _pubspec_manifest(text, _path):
    data = _load_yaml(text)
    if not isinstance(data, dict):
        raise TypeError("pubspec.yaml is not a mapping")
    for section in ("dependencies", "dev_dependencies", "dependency_overrides"):
        for name, value in _as_dict(data.get(section)).items():
            if isinstance(value, dict) and (value.get("path") or value.get("sdk")):
                continue  # a local package or the Flutter/Dart SDK
            key = str(name).lower()
            if section == "dependency_overrides":
                key = f"override:{key}"
            yield "pub", key, _spec(value), str(name)


_NUGET_TAGS = frozenset(
    {"PackageReference", "PackageVersion", "GlobalPackageReference", "package"}
)


def _nuget_manifest(text, _path):
    root = _xml_root(text)
    for element in root.iter():
        if _local(element.tag) not in _NUGET_TAGS:
            continue
        attributes = {k.lower(): v for k, v in element.attrib.items()}
        name = (
            attributes.get("include")
            or attributes.get("update")
            or attributes.get("id")
        )
        if not name:
            continue
        version = attributes.get("version") or _xml_child_text(element, "Version") or ""
        yield "nuget", name.lower(), version.strip(), name


# ---------------------------------------------------------------------------
# Lockfiles: each yields (ecosystem, name, version [checksum], needle)
# ---------------------------------------------------------------------------


def _locked(ecosystem: str, name: str, version: str, checksum=None):
    value = str(version)
    if isinstance(checksum, str) and checksum:
        value += f" {checksum}"
    return ecosystem, _normalize(ecosystem, name), value, str(name)


def _npm_lock(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("lockfile is not an object")
    packages = data.get("packages")
    if isinstance(packages, dict):
        for location, entry in packages.items():
            if not isinstance(entry, dict) or "node_modules/" not in location:
                continue  # the root project or a workspace package's folder
            if entry.get("link"):
                continue  # a link to a workspace package
            name = entry.get("name") or location.rsplit("node_modules/", 1)[1]
            version = entry.get("version")
            if isinstance(version, str) and not version.startswith(("file:", "link:")):
                yield _locked("npm", name, version, entry.get("integrity"))
        return
    yield from _npm_lock_v1(data.get("dependencies"))


def _npm_lock_v1(dependencies, depth: int = 0):
    if depth > 64:
        return
    for name, entry in _as_dict(dependencies).items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and not version.startswith(("file:", "link:")):
            yield _locked("npm", name, version, entry.get("integrity"))
        yield from _npm_lock_v1(entry.get("dependencies"), depth + 1)


def _descriptor_name(descriptor: str) -> str | None:
    descriptor = descriptor.strip().strip("\"'")
    at = descriptor.find("@", 1)
    return descriptor[:at] if at > 0 else None


_LOCAL_DESCRIPTOR_RE = re.compile(r"@(?:workspace|link|portal|file):")


def _yarn_lock(text, _path):
    names: list[str] = []
    version = checksum = None
    local = False
    entries = []

    def flush():
        if names and version and not local:
            for name in dict.fromkeys(names):
                entries.append(_locked("npm", name, version, checksum))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            flush()
            header = raw.rstrip().rstrip(":")
            names, version, checksum, local = [], None, None, False
            if header.strip("\"'") == "__metadata":
                continue
            for descriptor in header.split(","):
                cleaned = descriptor.strip().strip("\"'")
                if _LOCAL_DESCRIPTOR_RE.search(cleaned):
                    local = True
                name = _descriptor_name(cleaned)
                if name:
                    names.append(name)
            continue
        if raw.startswith("    "):
            continue  # dependencies of the entry
        stripped = raw.strip()
        match = re.match(r'^version:?\s+"?([^"\s]+)"?', stripped)
        if match:
            version = match.group(1)
            continue
        match = re.match(r'^(?:integrity|checksum):?\s+"?([^"\s]+)"?', stripped)
        if match:
            checksum = match.group(1)
            continue
        if re.match(r"^linkType:\s+soft", stripped):
            local = True
    flush()
    return entries


def _pnpm_lock(text, _path):
    in_packages = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            in_packages = raw.rstrip() == "packages:"
            continue
        if not in_packages or raw.startswith("   ") or not raw.startswith("  "):
            continue
        key = raw.strip().rstrip(":").strip("\"'")
        key = re.sub(r"\(.*\)$", "", key).lstrip("/")
        name, version = _pnpm_key(key)
        if not name or not version or ":" in version:
            continue  # file:, link:, git and tarball URLs
        yield _locked("npm", name, version)


def _pnpm_key(key: str) -> tuple[str | None, str | None]:
    at = key.rfind("@")
    if at > 0:
        return key[:at], key[at + 1 :]
    parts = key.split("/")  # lockfile v5: name/1.2.3, @scope/name/1.2.3
    if len(parts) >= 2:
        return "/".join(parts[:-1]), parts[-1]
    return None, None


_BUN_ENTRY_RE = re.compile(r'^\s*"([^"]+)":\s*\[\s*"([^"]+)"')


def _bun_lock(text, _path):
    in_packages = False
    for raw in text.splitlines():
        if re.match(r'^\s{2}"packages":\s*\{', raw):
            in_packages = True
            continue
        if not in_packages:
            continue
        if re.match(r"^\s{2}\}", raw):
            in_packages = False
            continue
        match = _BUN_ENTRY_RE.match(raw)
        name = _descriptor_name(match.group(2)) if match else None
        if not name:
            continue
        version = match.group(2)[len(name) + 1 :]
        if not version.startswith(("workspace:", "file:", "link:")):
            yield _locked("npm", name, version)


def _python_toml_lock(text, _path):
    for package in _toml_packages(text):
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or version is None:
            continue
        source = package.get("source")
        if isinstance(source, dict) and (
            source.get("editable")
            or source.get("virtual")
            or source.get("path")
            or source.get("directory")
            or source.get("workspace")
            or source.get("type") in {"directory", "file"}
        ):
            continue  # the project itself or a local path (uv, poetry)
        if package.get("editable") or package.get("path"):
            continue  # pdm: an editable local package
        yield _locked("pypi", name, str(version))


def _cargo_lock(text, _path):
    for package in _toml_packages(text):
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not package.get("source"):
            continue  # the workspace's own crates carry no source
        yield _locked("cargo", name, str(version), package.get("checksum"))


def _toml_packages(text: str) -> list[dict]:
    packages = tomllib.loads(text).get("package", [])
    if not isinstance(packages, list):
        raise TypeError("[[package]] is not an array of tables")
    return [p for p in packages if isinstance(p, dict)]


def _pipfile_lock(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("Pipfile.lock is not an object")
    for section in ("default", "develop"):
        for name, entry in _as_dict(data.get(section)).items():
            if (
                not isinstance(entry, dict)
                or entry.get("path")
                or entry.get("editable")
            ):
                continue
            version = entry.get("version") or entry.get("ref") or entry.get("git") or ""
            yield _locked("pypi", name, str(version).lstrip("="))


def _composer_lock(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("composer.lock is not an object")
    for section in ("packages", "packages-dev"):
        for package in _as_list(data.get(section)):
            if not isinstance(package, dict) or not isinstance(
                package.get("name"), str
            ):
                continue
            if _get(package, "dist", "type") == "path":
                continue
            reference = _get(package, "source", "reference") or _get(
                package, "dist", "reference"
            )
            version = str(package.get("version") or "")
            yield _locked("composer", package["name"], version, reference)


def _gemfile_lock(text, _path):
    section = None
    for raw in text.splitlines():
        if raw and not raw.startswith(" "):
            section = raw.strip()
            continue
        if section not in {"GEM", "GIT"}:
            continue  # PATH holds local gems; the rest is metadata
        match = re.match(r"^ {4}([^\s(]+) \(([^)]+)\)\s*$", raw)
        if match:
            yield _locked("rubygems", match.group(1), match.group(2))


def _go_sum(text, _path):
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) == 3:
            yield _locked("go", parts[0], parts[1], parts[2])


def _pubspec_lock(text, _path):
    data = _load_yaml(text)
    if not isinstance(data, dict):
        raise TypeError("pubspec.lock is not a mapping")
    for name, entry in _as_dict(data.get("packages")).items():
        if not isinstance(entry, dict) or entry.get("source") in {"path", "sdk"}:
            continue
        checksum = _get(entry, "description", "sha256")
        yield _locked("pub", str(name), str(entry.get("version") or ""), checksum)


def _nuget_lock(text, _path):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise TypeError("packages.lock.json is not an object")
    for framework in _as_dict(data.get("dependencies")).values():
        for name, entry in _as_dict(framework).items():
            if not isinstance(entry, dict) or entry.get("type") == "Project":
                continue
            resolved = str(entry.get("resolved") or "")
            yield _locked("nuget", name, resolved, entry.get("contentHash"))


def _gradle_lock(text, _path):
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "empty=")):
            continue
        parts = line.split("=", 1)[0].split(":")
        if len(parts) >= 3:
            yield _locked("maven", f"{parts[0]}:{parts[1]}", parts[2])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(data, *keys):
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


_UNSAFE_XML_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _xml_root(text: str):
    if _UNSAFE_XML_RE.search(text):
        raise _Unreadable("XML with a DOCTYPE or ENTITY declaration is not read")
    return ElementTree.fromstring(text)


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _xml_child(element, name: str):
    if element is None:
        return None
    for child in list(element):
        if _local(child.tag) == name:
            return child
    return None


def _xml_child_text(element, name: str) -> str | None:
    child = _xml_child(element, name)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


_EXTRACTORS: dict[str, Callable] = {
    "npm": _npm_manifest,
    "pyproject": _pyproject_manifest,
    "requirements": _requirements_manifest,
    "setup_py": _setup_py_manifest,
    "setup_cfg": _setup_cfg_manifest,
    "pipfile": _pipfile_manifest,
    "conda": _conda_manifest,
    "gomod": _gomod_manifest,
    "cargo": _cargo_manifest,
    "composer": _composer_manifest,
    "gemfile": _gemfile_manifest,
    "gemspec": _gemspec_manifest,
    "maven": _maven_manifest,
    "gradle": _gradle_manifest,
    "gradle_catalog": _gradle_catalog_manifest,
    "pubspec": _pubspec_manifest,
    "nuget": _nuget_manifest,
    "npm_lock": _npm_lock,
    "yarn_lock": _yarn_lock,
    "pnpm_lock": _pnpm_lock,
    "bun_lock": _bun_lock,
    "python_toml_lock": _python_toml_lock,
    "cargo_lock": _cargo_lock,
    "pipfile_lock": _pipfile_lock,
    "composer_lock": _composer_lock,
    "gemfile_lock": _gemfile_lock,
    "go_sum": _go_sum,
    "pubspec_lock": _pubspec_lock,
    "nuget_lock": _nuget_lock,
    "gradle_lock": _gradle_lock,
}
_MANIFEST_ECOSYSTEM = {
    "npm": "npm",
    "pyproject": "pypi",
    "requirements": "pypi",
    "setup_py": "pypi",
    "setup_cfg": "pypi",
    "pipfile": "pypi",
    "conda": "pypi",
    "gomod": "go",
    "cargo": "cargo",
    "composer": "composer",
    "gemfile": "rubygems",
    "gemspec": "rubygems",
    "maven": "maven",
    "gradle": "maven",
    "gradle_catalog": "maven",
    "pubspec": "pub",
    "nuget": "nuget",
}
