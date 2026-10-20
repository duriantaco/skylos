"""Positive source context for human advice views, never for analysis or gates.

An unknown context keeps advice visible. Repository metadata may explain why a
maintainability check concerns sample or copied code; it cannot establish that
the code is safe, unused, or exempt from a configured quality gate.
"""

from __future__ import annotations

import ast
import base64
import builtins
import csv
import hashlib
import io
import re
import shlex
import stat
from collections.abc import Mapping
from email.parser import Parser
from email.errors import MessageError
from fnmatch import fnmatchcase
from functools import lru_cache
from itertools import islice
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.core.test_paths import _is_test_parts, _uses_test_framework
from skylos.reporting.finding_types import get_finding_type
from skylos.rules.quality._pytest_collection import is_collected_pytest_file

_MAX_BYTES = 2_000_000
_MAX_METADATA_BYTES = 128_000
_MAX_DEPTH = 64
_SAMPLE_DIRS = frozenset({"example", "examples", "docs_src", "doc_src"})
# Conventional folder names; each needs a second fact below before it applies.
_NESTED_TEST_DIRS = frozenset({"test", "tests", "testing"})
_TOOLING_DIRS = frozenset({"docs", "doc", "scripts", "tools"})
_BENCHMARK_DIRS = frozenset({"bench", "benchmark", "benchmarks"})
_READMES = ("README", "README.md", "README.rst", "README.txt")
_LICENSES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.txt")
_LICENSES = (
    *_LICENSES, "LICENCE", "LICENCE.md", "LICENCE.txt", "LICENSE.BSD",
    "LICENSE.APACHE", "LICENSE-MIT", "LICENSE-APACHE",
)
_VENDOR_DIRS = frozenset({"vendor", "_vendor", "vendored", "_vendored", "third_party"})
_CONTEXT_MARKERS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "tox.ini",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
)
_BUILTIN_NAMES = frozenset(vars(builtins)) | {"__builtins__"}
_COPY_PROVENANCE = re.compile(
    r"\b(?:copied|taken|derived|vendored)\s+from\s+\S+"
    r"|\bvendored\s+(?:copy|version|code|dependency)\b",
    re.IGNORECASE,
)
_WHOLE_TREE_PROVENANCE = re.compile(
    r"\A\s*(?:"
    r"a\s+subset(?:\s+of\s+[\w.+/-]+)?\s+(?:taken|copied|derived)\s+from\s+"
    r"|(?:this|the)\s+(?:directory|package|folder|subtree)\s+is\s+"
    r"(?:a\s+vendored\s+(?:copy|version)\s+of\s+|(?:copied|taken|derived|vendored)\s+from\s+)"
    r"|vendored\s+(?:copy|version)\s+of\s+)",
    re.IGNORECASE,
)
_UPSTREAM = re.compile(
    r"https?://\S+|\b(?:cpython|python\s+\d)|\bcommit\s+(?:hash\s*:)?\s*[0-9a-f]{7,40}\b",
    re.IGNORECASE,
)
_FIRST_PARTY = re.compile(
    r"\bfirst.party\b|\bre.?writ(?:ten|ing|e)\b|\bre.?implement(?:ed|ation)\b"
    r"|\bmaintained\s+(?:here|locally|in.house)\b|\bindependently\s+maintained\b",
    re.IGNORECASE,
)


def _guarded_file(filename, project_root):
    if not isinstance(filename, (str, Path)) or not filename or project_root is None:
        return None
    try:
        root = Path(project_root).resolve(strict=True)
        path = Path(filename)
        if not path.is_absolute():
            path = root / path
        relative = path.relative_to(root)
        if (
            not relative.parts
            or ".." in relative.parts
            or len(relative.parts) > _MAX_DEPTH
        ):
            return None
        current = root
        for part in relative.parts:
            current /= part
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                return None
        if not stat.S_ISREG(info.st_mode):
            return None
        return root, path, relative, info
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _context_root(scan_root):
    """Anchor folder conventions to the checkout, even for a package scan.

    A real Git boundary wins over nested project manifests. Source archives
    can use the nearest project/config marker; without one, retain the
    caller's explicit root. Markers are only inspected, never followed or run.
    """
    closest_project = None
    current = scan_root
    for _ in range(_MAX_DEPTH):
        try:
            git = (current / ".git").lstat()
        except FileNotFoundError:
            pass
        except OSError:
            return None
        else:
            if stat.S_ISDIR(git.st_mode) or stat.S_ISREG(git.st_mode):
                return current
            return None
        if closest_project is None:
            for marker in _CONTEXT_MARKERS:
                try:
                    info = (current / marker).lstat()
                except FileNotFoundError:
                    continue
                except OSError:
                    return None
                if stat.S_ISREG(info.st_mode):
                    closest_project = current
                    break
                return None
        if current.parent == current:
            return closest_project or scan_root
        current = current.parent
    return None


@lru_cache(maxsize=128)
def _read(root, path, size, mtime_ns, ctime_ns, inode, limit):
    return read_project_text_no_symlink(root, path, max_bytes=limit, errors="strict")


def _text(root, path, *, limit=_MAX_METADATA_BYTES):
    guarded = _guarded_file(path, root)
    if guarded is None:
        return None
    _, path, _, info = guarded
    if info.st_size > limit:
        return None
    return _read(
        str(root),
        str(path),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_ino,
        limit,
    )


@lru_cache(maxsize=128)
def _parse(root, path, size, mtime_ns, ctime_ns, inode):
    source = _read(root, path, size, mtime_ns, ctime_ns, inode, _MAX_BYTES)
    if source is None:
        return None
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _tree(root, path, info):
    if info.st_size > _MAX_BYTES:
        return None
    return _parse(
        str(root),
        str(path),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_ino,
    )


@lru_cache(maxsize=128)
def _toml(source):
    try:
        return tomllib.loads(source)
    except (ValueError, RecursionError):
        return None


def _project_document(root):
    source = _text(root, root / "pyproject.toml")
    return _toml(source) if source is not None else None


def _package_path(value):
    if not isinstance(value, str) or Path(value).is_absolute():
        return None
    return _literal_directory(value)


def _declared_package_paths(document):
    """Literal package declarations; uncertain/dynamic declarations add no proof."""
    if not isinstance(document, dict):
        return ()
    tool = document.get("tool", {})
    if not isinstance(tool, dict):
        return ()
    paths = []
    setuptools = tool.get("setuptools", {})
    if isinstance(setuptools, dict):
        packages = setuptools.get("packages")
        package_dirs = setuptools.get("package-dir", {})
        if isinstance(packages, list) and isinstance(package_dirs, dict):
            base = package_dirs.get("", ".")
            for package in packages:
                if isinstance(package, str) and all(part.isidentifier() for part in package.split(".")):
                    value = package_dirs.get(package, str(Path(base) / package.replace(".", "/"))) if isinstance(base, str) else None
                    path = _package_path(value)
                    if path is not None:
                        paths.append(path)
    poetry = tool.get("poetry", {})
    if isinstance(poetry, dict) and isinstance(poetry.get("packages"), list):
        for package in poetry["packages"]:
            if isinstance(package, dict):
                include, base = package.get("include"), package.get("from", ".")
                if isinstance(include, str) and isinstance(base, str):
                    path = _package_path(str(Path(base) / include))
                    if path is not None:
                        paths.append(path)
    hatch = tool.get("hatch", {})
    try:
        packages = hatch["build"]["targets"]["wheel"].get("packages", [])
    except (KeyError, TypeError, AttributeError):
        packages = []
    if isinstance(packages, list):
        paths.extend(path for item in packages if (path := _package_path(item)) is not None)
    return tuple(paths)


def _shipped_package(root, relative):
    document = _project_document(root)
    if any(relative.is_relative_to(path) for path in _declared_package_paths(document)):
        return True
    parts = relative.parts
    # A regular package within src, including a child of a namespace package,
    # is library layout. Its bench/examples module names are not sample proof.
    if len(parts) > 2 and parts[0] == "src" and parts[1].isidentifier():
        if any(
            _guarded_file(root.joinpath(*parts[:index], "__init__.py"), root)
            for index in range(2, len(parts))
        ):
            return True
    if isinstance(document, dict):
        try:
            selection = document["tool"]["setuptools"]["packages"]["find"]
            where = selection.get("where", ["."])
            includes = selection.get("include", ["*"])
            excludes = selection.get("exclude", [])
            if all(
                isinstance(values, list) and all(isinstance(value, str) for value in values)
                for values in (where, includes, excludes)
            ):
                for value in where:
                    base = Path(".") if value == "." else _package_path(value)
                    if base is None or not relative.is_relative_to(base):
                        continue
                    package = ".".join(relative.relative_to(base).parts[:-1])
                    if package and any(fnmatchcase(package, pattern) for pattern in includes) and not any(
                        fnmatchcase(package, pattern) for pattern in excludes
                    ):
                        return True
        except (KeyError, TypeError, AttributeError):
            pass
        project = document.get("project", {})
        name = project.get("name") if isinstance(project, dict) else None
        if isinstance(name, str) and len(parts) > 1:
            normalized = re.sub(r"[-_.]+", "_", name).lower()
            return parts[0].lower() == normalized and bool(
                _guarded_file(root / parts[0] / "__init__.py", root)
            )
    return False


def _sample_path(parts):
    """Conventional checkout and package sample folders, not arbitrary ancestors."""
    dirs = [part.lower() for part in parts[:-1]]
    candidates = dirs[:1]
    if len(dirs) > 1:
        candidates.append(dirs[1])
    if len(dirs) > 2 and dirs[0] == "src":
        candidates.append(dirs[2])
    if any(part in _SAMPLE_DIRS for part in candidates):
        return "example"
    if any(part in _BENCHMARK_DIRS for part in candidates):
        return "profiling"
    return None


def _explicit_project_sample_path(scan_root, context_root, path, relative):
    """An explicitly scanned nested app owns its sample-folder conventions.

    Keep the checkout anchor for test, pytest and vendor evidence. Only sample
    ancestor names can be overridden, and only by a bounded, parsed project
    identity between the requested scan root and its checkout boundary.
    """
    current = scan_root
    for _ in range(_MAX_DEPTH):
        if current == context_root or not current.is_relative_to(context_root):
            break
        source = _text(context_root, current / "pyproject.toml")
        if source is not None:
            try:
                document = tomllib.loads(source)
                project = document.get("project", {})
                name = project.get("name") if isinstance(project, dict) else None
                if name is None:
                    tool = document.get("tool", {})
                    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
                    name = poetry.get("name") if isinstance(poetry, dict) else None
                if isinstance(name, str) and re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name
                ):
                    return path.relative_to(current)
            except (TypeError, ValueError, RecursionError):
                pass
        current = current.parent
    return relative


def _declared_vendor(root, path):
    # A root README describes the project itself, not a vendored subtree.
    for directory in list(path.parents)[:8]:
        if directory == root:
            break
        for name in _READMES:
            source = _text(root, directory / name)
            if source is None:
                continue
            # A later local rewrite/ownership declaration is evidence too;
            # paragraph placement must not restore the copied-code label.
            if _FIRST_PARTY.search(source):
                return False
            if re.search(r"\bnot\s+(?:vendored|copied|taken|derived)\b", source, re.I):
                continue
            paragraph = re.split(r"\n\s*\n", source.strip(), maxsplit=1)[0]
            # A copied-file mention does not describe its first-party
            # siblings. The README must introduce the enclosing tree itself
            # as copied, with its upstream identified in that declaration.
            if not (
                _WHOLE_TREE_PROVENANCE.search(paragraph)
                and _COPY_PROVENANCE.search(paragraph)
                and _UPSTREAM.search(paragraph)
            ):
                continue
            if re.search(
                r"\b(?:only|except|excluding)\b[^\n.]*\.(?:py|pyi|js|ts)\b"
                r"|\bfirst.party\b",
                source,
                re.I,
            ):
                continue
            for license_name in _LICENSES:
                license_text = _text(root, directory / license_name)
                if license_text and re.search(
                    r"\b(?:copyright|permission|licen[cs]e)\b", license_text, re.I
                ):
                    return True
    return _configured_vendor(root, path) or _recorded_vendor(root, path)


def _license_present(root, directory):
    return any(
        source and re.search(r"\b(?:copyright|permission|licen[cs]e)\b", source, re.I)
        for name in _LICENSES
        if (source := _text(root, directory / name)) is not None
    )


@lru_cache(maxsize=128)
def _pinned_inventory(source):
    result = []
    try:
        for line in source.splitlines():
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            requirement = Requirement(value)
            pins = list(requirement.specifier)
            if requirement.url or len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
                return ()
            result.append(re.sub(r"[-_.]+", "_", requirement.name).lower())
            if len(result) > 256:
                return ()
    except (InvalidRequirement, ValueError):
        return ()
    return tuple(result)


def _configured_vendor(root, path):
    document = _project_document(root)
    try:
        config = document["tool"]["vendoring"]
        destination = _package_path(config["destination"])
        inventory_path = _package_path(config["requirements"])
        if destination is None or inventory_path is None:
            return False
        relative = path.relative_to(root / destination)
        protected = config.get("protected-files", [])
        if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
            return False
        if any(_package_path(item) is None for item in protected):
            return False
        if relative.as_posix() in protected:
            return False
        source = _text(root, root / inventory_path)
        if source is None:
            return False
        inventory = _pinned_inventory(source)
        project = document.get("project", {})
        own_name = project.get("name", "") if isinstance(project, dict) else ""
        if not isinstance(own_name, str):
            return False
        own_name = re.sub(r"[-_.]+", "_", own_name).lower()
        aliases = config.get("license", {}).get("directories", {})
        if not isinstance(aliases, dict):
            return False
        for name in inventory:
            if name == own_name:
                continue
            directory = next(
                (value for key, value in aliases.items() if re.sub(r"[-_.]+", "_", key).lower() == name),
                name,
            )
            package = _package_path(directory)
            if package is not None and relative.is_relative_to(package):
                if _license_present(root, root / destination / package):
                    return True
            elif (
                package is not None
                and len(package.parts) == 1
                and len(relative.parts) == 1
                and relative.suffix in {".py", ".pyi"}
                and relative.stem == package.name
            ):
                for license_name in _LICENSES:
                    source = _text(root, root / destination / f"{package.name}.{license_name}")
                    if source and re.search(r"\b(?:copyright|permission|licen[cs]e)\b", source, re.I):
                        return True
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    return False


@lru_cache(maxsize=128)
def _source_hash(root, path, size, mtime_ns, ctime_ns, inode):
    source = read_project_text_no_symlink(
        root, path, max_bytes=_MAX_BYTES, errors="strict", newline=""
    )
    if source is None:
        return None
    return base64.urlsafe_b64encode(hashlib.sha256(source.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")


def _recorded_vendor(root, path):
    """A wheel's exact file inventory, provenance, license and content digest.

    A vendor-looking directory alone proves nothing. The RECORD must attest
    this current file; unlisted wrappers, siblings and changed copies remain.
    """
    for directory in list(path.parents)[:8]:
        if directory == root:
            break
        if directory.name not in _VENDOR_DIRS:
            continue
        try:
            entries = list(islice(directory.iterdir(), 257))
        except OSError:
            return False
        if len(entries) > 256:
            return False
        for entry in entries:
            if not entry.name.endswith(".dist-info"):
                continue
            record = _text(root, entry / "RECORD")
            if record is None:
                continue
            relative = path.relative_to(directory).as_posix()
            row = _wheel_record_rows(record).get(relative)
            if row is None:
                continue
            metadata = _text(root, entry / "METADATA")
            if metadata is None:
                continue
            try:
                headers = Parser().parsestr(metadata, headersonly=True)
            except (MessageError, ValueError, TypeError, RecursionError):
                continue
            name, version = headers.get("Name"), headers.get("Version")
            if not name or not version or len(headers.get_all("Name", [])) != 1 or len(headers.get_all("Version", [])) != 1:
                continue
            try:
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
                    continue
                Requirement(f"{name}=={version}")
            except InvalidRequirement:
                continue
            normalized = re.sub(r"[-_.]+", "_", name).lower()
            stem = re.sub(r"[-_.]+", "_", entry.name[:-10]).lower()
            if stem != re.sub(r"[-_.]+", "_", f"{name}-{version}").lower():
                continue
            document = _project_document(root)
            project = (document or {}).get("project", {})
            own_name = project.get("name", "") if isinstance(project, dict) else ""
            if not isinstance(own_name, str):
                continue
            if normalized == re.sub(r"[-_.]+", "_", own_name).lower():
                continue
            if not any("https://" in value or "http://" in value for key in ("Home-page", "Project-URL") for value in headers.get_all(key, [])):
                continue
            if not _wheel_license_present(root, entry, headers):
                continue
            digest, size = row
            guarded = _guarded_file(path, root)
            if guarded is None or size != str(guarded[-1].st_size) or not digest.startswith("sha256="):
                continue
            info = guarded[-1]
            actual = _source_hash(str(root), str(path), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino)
            if actual is not None and digest == "sha256=" + actual:
                return True
    return False


@lru_cache(maxsize=128)
def _wheel_record_rows(source):
    rows = {}
    try:
        for row in csv.reader(io.StringIO(source)):
            if len(row) == 3:
                rows[row[0]] = (row[1], row[2]) if row[0] not in rows else None
    except csv.Error:
        return {}
    return rows


def _wheel_license_present(root, directory, metadata):
    if _license_present(root, directory) or _license_present(root, directory / "licenses"):
        return True
    declared = metadata.get_all("License-File", [])
    if len(declared) > 32:
        return False
    for value in declared:
        path = _package_path(value)
        if path is None:
            continue
        for base in (directory, directory / "licenses"):
            source = _text(root, base / path)
            if source and re.search(r"\b(?:copyright|permission|licen[cs]e)\b", source, re.I):
                return True
    return False


def _literal_directory(value):
    if not isinstance(value, str) or any(char in value for char in "*?[]\\"):
        return None
    path = Path(value.lstrip("/"))
    if not path.parts or any(part in {".", ".."} for part in path.parts):
        return None
    return path


@lru_cache(maxsize=128)
def _distribution_paths(root, size, mtime_ns, ctime_ns, inode):
    source = _read(
        root,
        str(Path(root) / "pyproject.toml"),
        size,
        mtime_ns,
        ctime_ns,
        inode,
        _MAX_METADATA_BYTES,
    )
    if source is None:
        return None
    try:
        targets = tomllib.loads(source)["tool"]["hatch"]["build"]["targets"]
        excluded = targets["sdist"]["exclude"]
        included = targets["wheel"]["only-include"]
        if (
            not isinstance(excluded, list)
            or not isinstance(included, list)
            or not included
        ):
            return None
        excluded = tuple(_literal_directory(item) for item in excluded)
        included = tuple(_literal_directory(item) for item in included)
        if any(item is None for item in (*excluded, *included)):
            return None
        return excluded, included
    except (KeyError, TypeError, ValueError, RecursionError):
        return None


def _excluded_from_distributions(root, relative):
    guarded = _guarded_file(root / "pyproject.toml", root)
    if guarded is None:
        return False
    info = guarded[-1]
    if info.st_size > _MAX_METADATA_BYTES:
        return False
    paths = _distribution_paths(
        str(root), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino
    )
    hatch_excluded = bool(
        paths
        and any(relative.is_relative_to(part) for part in paths[0])
        and not any(relative.is_relative_to(part) for part in paths[1])
    )
    document = _project_document(root)
    if not isinstance(document, dict):
        return False
    tool = document.get("tool", {})
    build_system = document.get("build-system", {})
    if not isinstance(tool, dict) or not isinstance(build_system, dict):
        return False
    backend = build_system.get("build-backend")
    if hatch_excluded and backend in {None, "hatchling.build"}:
        try:
            build = tool["hatch"]["build"]
            wheel = build["targets"]["wheel"]
            if not build.get("force-include") and not wheel.get("force-include"):
                return True
        except (KeyError, TypeError, AttributeError):
            return False
    if backend == "poetry.core.masonry.api":
        poetry = tool.get("poetry", {})
        if not isinstance(poetry, dict) or poetry.get("include"):
            return False
        excluded = poetry.get("exclude", [])
        if not isinstance(excluded, list):
            return False
        for value in excluded:
            if not isinstance(value, str):
                return False
            directory = _literal_directory(value.removesuffix("/**"))
            if directory is not None and relative.is_relative_to(directory):
                return True
    elif backend in {"setuptools.build_meta", "setuptools.build_meta:__legacy__"}:
        setuptools = tool.get("setuptools", {})
        if not isinstance(setuptools, dict) or any(
            setuptools.get(key) for key in ("data-files", "script-files", "py-modules")
        ):
            return False
        wheel_roots = list(_declared_package_paths({"tool": {"setuptools": setuptools}}))
        try:
            where = setuptools["packages"]["find"].get("where", [])
        except (KeyError, TypeError, AttributeError):
            where = []
        if isinstance(where, list):
            wheel_roots.extend(path for value in where if (path := _package_path(value)) is not None)
        if not wheel_roots or any(relative.is_relative_to(path) for path in wheel_roots):
            return False
        manifest = _text(root, root / "MANIFEST.in")
        if manifest is None:
            return False
        pruned = False
        try:
            for line in manifest.splitlines():
                words = shlex.split(line, comments=True)
                if not words:
                    continue
                if words[0] == "prune" and len(words) == 2:
                    directory = _literal_directory(words[1])
                    if directory is not None and relative.is_relative_to(directory):
                        pruned = True
                elif pruned and words[0] not in {"exclude", "recursive-exclude", "global-exclude", "prune"}:
                    return False
        except ValueError:
            return False
        return pruned
    return False


def _data_expression(node, assigned):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_data_expression(item, assigned) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None
            and _data_expression(key, assigned)
            and _data_expression(value, assigned)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return isinstance(node.operand, ast.Constant) and isinstance(
            node.operand.value, (int, float, complex)
        )
    if not isinstance(node, ast.Call) or any(
        keyword.arg is None for keyword in node.keywords
    ):
        return False
    function = node.func
    if isinstance(function, ast.Name):
        if function.id not in {"set", "frozenset", "list", "tuple", "dict"}:
            return False
        if function.id in assigned:
            return False
    elif isinstance(function, ast.Attribute):
        # Formatter inputs often wrap their literals in an intentionally
        # unresolved sample constructor, e.g. some.Structure(...).
        while isinstance(function, ast.Attribute):
            function = function.value
        if (
            not isinstance(function, ast.Name)
            or function.id in assigned
            or function.id in _BUILTIN_NAMES
        ):
            return False
    else:
        return False
    return all(_data_expression(item, assigned) for item in node.args) and all(
        _data_expression(keyword.value, assigned) for keyword in node.keywords
    )


def _profile_data(tree):
    if tree is None:
        return False
    body = tree.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if not isinstance(body[0].value.value, str):
            return False
        body = body[1:]
    if not body or any(
        not isinstance(node, ast.Assign)
        or any(not isinstance(target, ast.Name) for target in node.targets)
        for node in body
    ):
        return False
    assigned = {target.id for node in body for target in node.targets}
    return (
        all(_data_expression(node.value, assigned) for node in body)
        and sum(isinstance(node, ast.Constant) for node in ast.walk(tree)) >= 128
        and any(
            isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict))
            for node in ast.walk(tree)
        )
    )


def _file_context(filename, project_root):
    guarded = _guarded_file(filename, project_root)
    if guarded is None:
        return None
    root, path, relative, info = guarded
    scan_root = root
    context_root = _context_root(root)
    if context_root is None:
        return None
    if context_root != root:
        guarded = _guarded_file(path, context_root)
        if guarded is None:
            return None
        root, path, relative, info = guarded
    if _is_test_parts(relative.parts):
        return "test"
    if is_collected_pytest_file(path, root):
        return "test"
    if path.suffix.lower() in {".py", ".pyi", ".pyw"} and (
        path.name.startswith("test_") or path.stem.endswith("_test")
    ):
        tree = _tree(root, path, info)
        if tree is not None and _uses_test_framework(tree):
            return "test"
    sample = _sample_path(relative.parts)
    sample_root, sample_relative = root, relative
    if sample is not None:
        sample_relative = _explicit_project_sample_path(scan_root, root, path, relative)
        sample = _sample_path(sample_relative.parts)
        if sample_relative != relative:
            # The nested project's identity also owns its package declarations.
            sample_root = path.parents[len(sample_relative.parts) - 1]
    if (
        sample is not None
        and not _shipped_package(root, relative)
        and (
            sample_root == root
            or not _shipped_package(sample_root, sample_relative)
        )
    ):
        return sample
    if _declared_vendor(root, path):
        return "vendored"
    if (
        len(relative.parts) > 1
        and relative.parts[0] == "profiling"
        and path.suffix == ".py"
        and not _shipped_package(root, relative)
        and _excluded_from_distributions(root, relative)
        and _profile_data(_tree(root, path, info))
    ):
        return "profiling"
    return _conventional_context(root, path, relative, info)


def _conventional_context(root, path, relative, info):
    """Folder conventions confirmed by file facts, or declared source ownership.

    A nested ``tests`` folder counts only when the module imports a test
    framework; generated context requires an explicit repository attribute or
    an executable bundle structure. A comment does not establish ownership.
    Vendor context requires the provenance checks above. A folder name must
    not override first-party ownership or a missing/invalid copy inventory.
    """
    directories = [part.lower() for part in relative.parts[:-1]]
    if (
        path.suffix.lower() in {".py", ".pyi", ".pyw"}
        and _NESTED_TEST_DIRS.intersection(directories)
    ):
        tree = _tree(root, path, info)
        if tree is not None and _uses_test_framework(tree):
            return "test"
    if directories and (
        directories[0].startswith(".") or directories[0] in _TOOLING_DIRS
    ) and not _shipped_package(root, relative):
        return "tooling"
    from skylos.core.generated_files import (
        REASON_LINGUIST_GENERATED,
        _linguist_attribute,
        _looks_bundled,
    )

    if _linguist_attribute(path, root) == REASON_LINGUIST_GENERATED:
        return "generated"
    if path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        if _looks_bundled(path):
            return "generated"
    return None


def _clone_context(finding, project_root):
    # Legacy clone exports include at most four members in their message.
    # Parse only the complete, unambiguous scanner format; a representative
    # file or a truncated preview cannot establish the group's context.
    message = finding.get("message")
    if not isinstance(message, str) or len(message) > 16_000:
        return None
    group = re.fullmatch(
        r"Clone group detected \(type[123], sim=(?:0\.\d+|1(?:\.0+)?), "
        r"members=([2-4])\) examples: ([^\r\n]+)",
        message,
    )
    if group is None:
        return None
    members = group[2].split(", ")
    if len(members) != int(group[1]):
        return None
    contexts = set()
    representative = _guarded_file(
        finding.get("file") or finding.get("file_path"), project_root
    )
    if representative is None:
        return None
    locations = set()
    for index, member in enumerate(members):
        match = re.fullmatch(
            r"([^(),\r\n]+):([0-9]{1,10})-([0-9]{1,10}) \((?:function|class) ([^()]+)\)", member
        )
        if match is None or not (0 < int(match[2]) <= int(match[3])):
            return None
        guarded = _guarded_file(match[1], project_root)
        if guarded is None:
            return None
        location = (str(guarded[1]), int(match[2]), int(match[3]))
        if location in locations:
            return None
        locations.add(location)
        if index == 0 and (
            guarded[1] != representative[1] or finding.get("line") != int(match[2])
        ):
            return None
        context = _file_context(match[1], project_root)
        if context is None:
            return None
        contexts.add(context)
    return next(iter(contexts)) if len(contexts) == 1 else None


def advice_source_context(finding, project_root=None) -> str | None:
    """Explain a proven local context for a built-in advice finding.

    No root, missing evidence, malformed metadata, and symlinked or escaping
    paths all preserve the advice in the ordinary view. Source and metadata
    reads are bounded and cached by file stat, so edits invalidate evidence.
    """
    if not isinstance(finding, Mapping) or get_finding_type(finding) != "advice":
        return None
    if str(finding.get("rule_id") or finding.get("id")).upper() == "SKY-C401":
        return _clone_context(finding, project_root)
    return _file_context(finding.get("file") or finding.get("file_path"), project_root)
