from __future__ import annotations

import ast
import logging
import os
import re
import site
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    read_project_text_no_symlink,
    read_text_no_symlink,
    save_project_json_cache,
)
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS
from skylos.core.file_discovery import discover_source_files

# ---------------------------------------------------------------------------
# The mapping file uses the pipreqs format: "import_name:dist_name" per line.
# Source: https://github.com/bndr/pipreqs/blob/master/pipreqs/mapping
# License: Apache-2.0
#
# We look for it in the same directory as this source file.
# ---------------------------------------------------------------------------

_IMPORT_TO_DIST_MAPPING: dict[str, str] | None = None
_MAPPING_FILENAME = "pipreqs_import_mapping.txt"
MAX_DEPENDENCY_MANIFEST_BYTES = 5_000_000
MAX_DEPENDENCY_SCOPE_COMPONENTS = 256
MAX_DEPENDENCY_SCOPE_PATH_CHARS = 4096
MAX_PYTHON_SOURCE_ROOTS = 256
MAX_PYTHON_LAYOUT_CANDIDATES = 1024
CONVENTIONAL_PYTHON_SOURCE_ROOT = Path("src")
PYTHON_SOURCE_SUFFIXES = frozenset({".py", ".pyi", ".pyw"})
logger = logging.getLogger(__name__)


def _load_import_to_dist_mapping() -> dict[str, str]:
    global _IMPORT_TO_DIST_MAPPING
    if _IMPORT_TO_DIST_MAPPING is not None:
        return _IMPORT_TO_DIST_MAPPING

    mapping: dict[str, str] = {}
    mapping_path = Path(__file__).with_name(_MAPPING_FILENAME)

    if mapping_path.exists():
        try:
            for line in mapping_path.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                import_name, dist_name = line.split(":", 1)
                import_name = import_name.strip()
                dist_name = dist_name.strip()
                if import_name and dist_name:
                    mapping[import_name] = dist_name
        except OSError as exc:
            logger.debug("Failed to load import mapping from %s: %s", mapping_path, exc)

    _SUPPLEMENT = {
        "cv2": "opencv-python",
        "cv": "opencv-python",
        "docx": "python-docx",
        "pptx": "python-pptx",
        "skimage": "scikit-image",
        "attr": "attrs",
        "attrs": "attrs",
        "jose": "python-jose",
        "wx": "wxPython",
        "pkg_resources": "setuptools",
        "lxml": "lxml",
        "webdriver": "selenium",
        "gi": "PyGObject",
        "nacl": "PyNaCl",
        "ldap": "python-ldap",
        "bson": "pymongo",
        "gridfs": "pymongo",
    }
    for imp, dist in _SUPPLEMENT.items():
        if imp not in mapping:
            mapping[imp] = dist

    _IMPORT_TO_DIST_MAPPING = mapping
    return _IMPORT_TO_DIST_MAPPING


RULE_ID_HALLUCINATION = "SKY-D222"
RULE_ID_UNDECLARED = "SKY-D223"

SEV_CRITICAL = "CRITICAL"
SEV_MEDIUM = "MEDIUM"

IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z_][\w\.]*)", re.MULTILINE)
FROM_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w\.]*)\s+import\b", re.MULTILINE)

REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")

DEPENDENCY_MANIFEST_FILENAMES = ("requirements.txt", "pyproject.toml", "setup.py")


def _normalize_name(name):
    if name is None:
        return ""

    cleaned = str(name).strip()
    cleaned = cleaned.lower()
    cleaned = re.sub(r"[-_.]+", "-", cleaned)
    return cleaned


def _get_stdlib_modules():
    std = getattr(sys, "stdlib_module_names", None)
    if std:
        return set(std)

    return {
        "os",
        "sys",
        "re",
        "json",
        "math",
        "time",
        "datetime",
        "typing",
        "pathlib",
        "subprocess",
        "asyncio",
        "itertools",
        "functools",
        "collections",
        "logging",
        "hashlib",
        "hmac",
        "base64",
        "random",
        "threading",
        "multiprocessing",
        "http",
        "urllib",
        "email",
        "socket",
        "unittest",
        "doctest",
        "dataclasses",
        "statistics",
    }


def _build_installed_module_mapping():
    mapping = {}

    try:
        from importlib.metadata import packages_distributions

        pkg_dist = packages_distributions()
        for module, dists in pkg_dist.items():
            if module not in mapping:
                mapping[module] = set()
            for d in dists:
                mapping[module].add(_normalize_name(d))
    except ImportError as exc:
        logger.debug("importlib.metadata unavailable: %s", exc)
    except (RuntimeError, ValueError) as exc:
        logger.debug("Failed to inspect installed package metadata: %s", exc)

    site_packages_dirs = []

    try:
        site_packages_dirs.extend(site.getsitepackages())
    except (AttributeError, OSError) as exc:
        logger.debug("Failed to inspect site-packages directories: %s", exc)

    try:
        user_site = site.getusersitepackages()
        if user_site:
            site_packages_dirs.append(user_site)
    except (AttributeError, OSError) as exc:
        logger.debug("Failed to inspect user site-packages directory: %s", exc)

    try:
        import sys

        if hasattr(sys, "prefix") and sys.prefix != sys.base_prefix:
            venv_site = Path(sys.prefix) / "lib"
            for pydir in venv_site.glob("python*/site-packages"):
                site_packages_dirs.append(str(pydir))
    except OSError as exc:
        logger.debug("Failed to inspect virtualenv site-packages directory: %s", exc)

    for sp_dir in site_packages_dirs:
        sp_path = Path(sp_dir)
        if not sp_path.exists():
            continue

        for dist_info in sp_path.glob("*.dist-info"):
            metadata_file = dist_info / "METADATA"
            dist_name = None
            if metadata_file.exists():
                try:
                    for line in metadata_file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines():
                        if line.startswith("Name:"):
                            dist_name = line.split(":", 1)[1].strip()
                            break
                except OSError as exc:
                    logger.debug(
                        "Failed to read package metadata %s: %s", metadata_file, exc
                    )

            if not dist_name:
                base_name = dist_info.name.replace(".dist-info", "")
                parts = base_name.split("-")
                name_parts = []
                for p in parts:
                    if p and p[0].isdigit():
                        break
                    name_parts.append(p)

                if name_parts:
                    dist_name = "-".join(name_parts)
                else:
                    dist_name = base_name

            normalized_dist = _normalize_name(dist_name)

            top_level_file = dist_info / "top_level.txt"
            if top_level_file.exists():
                try:
                    content = top_level_file.read_text(
                        encoding="utf-8", errors="ignore"
                    )
                    for line in content.strip().splitlines():
                        module = line.strip()
                        if module:
                            if module not in mapping:
                                mapping[module] = set()
                            mapping[module].add(normalized_dist)
                except OSError as exc:
                    logger.debug(
                        "Failed to read top-level metadata %s: %s", top_level_file, exc
                    )
                continue

            record_file = dist_info / "RECORD"
            if record_file.exists():
                try:
                    content = record_file.read_text(encoding="utf-8", errors="ignore")
                    top_levels = set()
                    for line in content.splitlines():
                        if not line.strip():
                            continue
                        file_path = line.split(",")[0]
                        parts = file_path.split("/")
                        if len(parts) >= 1:
                            first = parts[0]
                            if first.endswith(".dist-info"):
                                continue
                            if first.startswith("__"):
                                continue
                            if first.endswith(".py"):
                                mod_name = first[:-3]
                                if mod_name and not mod_name.startswith("_"):
                                    top_levels.add(mod_name)
                            elif "/" in file_path or len(parts) > 1:
                                if not first.startswith("_") and first not in (
                                    "bin",
                                    "scripts",
                                ):
                                    top_levels.add(first)

                    for module in top_levels:
                        if module not in mapping:
                            mapping[module] = set()
                        mapping[module].add(normalized_dist)
                except OSError as exc:
                    logger.debug(
                        "Failed to read package record %s: %s", record_file, exc
                    )

    return mapping


def _get_possible_packages(import_name, installed_mapping):
    result = {import_name, _normalize_name(import_name)}

    if import_name in installed_mapping:
        result.update(installed_mapping[import_name])

    return result


def _extract_imports(src):
    modules = set()

    if not src:
        return modules

    for match in IMPORT_RE.finditer(src):
        raw = match.group(1)
        if raw:
            top = raw.split(".")[0]
            if top:
                modules.add(top)

    for match in FROM_RE.finditer(src):
        raw = match.group(1)
        if raw:
            top = raw.split(".")[0]
            if top:
                modules.add(top)

    return modules


def _collect_local_modules(repo_root):
    local = set()

    try:
        for p in repo_root.iterdir():
            if p.name.startswith("."):
                continue

            mode = p.lstat().st_mode
            if stat.S_ISREG(mode):
                if p.suffix == ".py":
                    local.add(p.stem)
                continue

            if stat.S_ISDIR(mode):
                if _is_local_python_file(repo_root, Path(p.name) / "__init__.py"):
                    local.add(p.name)

    except OSError as exc:
        logger.debug("Failed to collect local modules from %s: %s", repo_root, exc)

    return local


def _contained_importer_path(repo_root, file_path, *, diff_path=False):
    try:
        raw_path = os.fspath(file_path)
    except TypeError:
        return None
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or len(raw_path) > MAX_DEPENDENCY_SCOPE_PATH_CHARS
        or "\x00" in raw_path
    ):
        return None

    if diff_path:
        if (
            raw_path != raw_path.strip()
            or "\\" in raw_path
            or re.match(r"^[A-Za-z]:", raw_path)
        ):
            return None
        relative = PurePosixPath(raw_path)
        if (
            not relative.parts
            or relative.as_posix() != raw_path
            or relative.is_absolute()
            or ".." in relative.parts
        ):
            return None
        path = repo_root.joinpath(*relative.parts)
    else:
        path = Path(raw_path)
        if not path.is_absolute():
            path = repo_root / path

    path = Path(os.path.abspath(path))
    try:
        relative_path = path.relative_to(repo_root)
    except ValueError:
        return None
    if (
        not relative_path.parts
        or len(relative_path.parts) > MAX_DEPENDENCY_SCOPE_COMPONENTS
        or any(part in {"", ".", ".."} for part in relative_path.parts)
    ):
        return None
    return relative_path


def _known_python_files(repo_root, py_files):
    known = set()
    for file_path in py_files or ():
        relative = _contained_importer_path(repo_root, file_path)
        if relative is not None and relative.suffix in PYTHON_SOURCE_SUFFIXES:
            known.add(relative)
    return frozenset(known)


def _dependency_context_python_files(repo_root, py_files):
    if (
        _supports_directory_fd_access(require_scandir=True)
        and _supports_directory_fd_access()
    ):
        return ()

    files = list(py_files or ())
    try:
        # On platforms without held directory handles, only the analyzer's
        # normal Git-visible inventory is trusted as local-module evidence.
        # Walking ignored trees or probing ad hoc paths would let untrusted
        # repositories impose unbounded work or race symlink/junction checks.
        files.extend(
            discover_source_files(
                repo_root,
                PYTHON_SOURCE_SUFFIXES,
                exclude_folders=DEFAULT_EXCLUDE_FOLDERS,
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        pass
    return files


def _collect_known_root_modules(known_files):
    modules = set()
    for relative in known_files:
        if len(relative.parts) == 1 and relative.suffix == ".py":
            modules.add(relative.stem)
        elif (
            len(relative.parts) == 2
            and relative.name == "__init__.py"
            and relative.parts[0].isidentifier()
        ):
            modules.add(relative.parts[0])
    return modules


def _collect_known_source_root_modules(
    known_files, source_roots, *, require_package_marker=False
):
    modules = set()
    roots_by_parts = {source_root.parts: source_root for source_root in source_roots}
    for relative in known_files:
        parts = relative.parts
        for prefix_size in range(len(parts)):
            source_root = roots_by_parts.get(parts[:prefix_size])
            if source_root is None:
                continue
            source_parts = parts[prefix_size:]
            if len(source_parts) == 1:
                source_file = Path(source_parts[0])
                if source_file.suffix == ".py":
                    modules.add(source_file.stem)
                continue
            module = source_parts[0]
            if not module.isidentifier():
                continue
            if (
                require_package_marker
                and (source_root / module / "__init__.py") not in known_files
            ):
                continue
            modules.add(module)
    return modules


def _contained_directory(repo_root, relative_directory, *, allow_missing=False):
    if relative_directory.is_absolute() or ".." in relative_directory.parts:
        return None
    current = repo_root
    try:
        resolved_root = repo_root.resolve(strict=True)
        for part in relative_directory.parts:
            current /= part
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                return current if allow_missing else None
            if not stat.S_ISDIR(mode):
                return None
            current.resolve(strict=True).relative_to(resolved_root)
        return current
    except (OSError, RuntimeError, ValueError):
        return None


def _supports_directory_fd_access(*, require_scandir=False):
    supported = (
        os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )
    if require_scandir:
        supported = supported and os.scandir in os.supports_fd
    return supported


def _directory_open_flags(*, follow_symlinks=False):
    flags = os.O_RDONLY | os.O_DIRECTORY
    if not follow_symlinks:
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _close_directory_fd(directory_fd):
    if directory_fd is None:
        return True
    try:
        os.close(directory_fd)
        return True
    except OSError:
        return False


def _open_contained_directory_fd(repo_root, relative_directory):
    if (
        not _supports_directory_fd_access()
        or relative_directory.is_absolute()
        or ".." in relative_directory.parts
    ):
        return None
    directory_fd = None
    try:
        resolved_root = repo_root.resolve(strict=True)
        directory_fd = os.open(  # skylos: ignore[SKY-D215,SKY-D325] bounded no-follow directory traversal
            resolved_root,
            _directory_open_flags(),
        )
        for part in relative_directory.parts:
            next_fd = os.open(
                part,
                _directory_open_flags(),
                dir_fd=directory_fd,
            )
            previous_fd = directory_fd
            directory_fd = next_fd
            if not _close_directory_fd(previous_fd):
                _close_directory_fd(directory_fd)
                directory_fd = None
                return None
        return directory_fd
    except (OSError, RuntimeError, ValueError):
        _close_directory_fd(directory_fd)
        return None


def _is_local_python_file(repo_root, relative_path):
    if not _supports_directory_fd_access():
        return False
    directory_fd = _open_contained_directory_fd(repo_root, relative_path.parent)
    if directory_fd is None:
        return False
    try:
        file_stat = os.stat(
            relative_path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        return stat.S_ISREG(file_stat.st_mode)
    except OSError:
        return False
    finally:
        _close_directory_fd(directory_fd)


def _context_has_local_python_file(ctx, relative_path):
    if _supports_directory_fd_access():
        return _is_local_python_file(ctx["repo_root"], relative_path)
    return relative_path in ctx["known_python_files"]


def _configured_python_path(candidate):
    if not isinstance(candidate, str) or candidate != candidate.strip():
        return None
    if (
        not candidate
        or len(candidate) > MAX_DEPENDENCY_SCOPE_PATH_CHARS
        or "\\" in candidate
        or re.match(r"^[A-Za-z]:", candidate)
    ):
        return None
    relative = PurePosixPath(candidate)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) > MAX_DEPENDENCY_SCOPE_COMPONENTS
    ):
        return None
    return Path(*relative.parts)


def _configured_python_layout(repo_root):
    text = read_project_text_no_symlink(
        repo_root,
        "pyproject.toml",
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if text is None:
        return set(), set(), set(), set()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError):
        return set(), set(), set(), set()

    tool = data.get("tool")
    if not isinstance(tool, dict):
        return set(), set(), set(), set()
    setuptools = tool.get("setuptools", {})
    if not isinstance(setuptools, dict):
        return set(), set(), set(), set()
    packages = setuptools.get("packages")
    raw_package_find = packages.get("find", {}) if isinstance(packages, dict) else {}
    package_find = raw_package_find if isinstance(raw_package_find, dict) else {}
    raw_candidates = package_find.get("where", [])
    if isinstance(raw_candidates, str):
        candidates = [raw_candidates]
    elif isinstance(raw_candidates, list):
        candidates = raw_candidates
    else:
        candidates = []
    roots = set()
    package_dir = setuptools.get("package-dir", {})
    if isinstance(package_dir, dict):
        default_root = _configured_python_path(package_dir.get(""))
        if default_root is not None:
            roots.add(default_root)
    for index, candidate in enumerate(candidates):
        if index >= MAX_PYTHON_LAYOUT_CANDIDATES:
            break
        if len(roots) >= MAX_PYTHON_SOURCE_ROOTS:
            break
        relative = _configured_python_path(candidate)
        if relative is not None:
            roots.add(relative)

    mapped_modules = set()
    mapped_package_directories = set()
    if isinstance(package_dir, dict):
        for index, (package, directory) in enumerate(package_dir.items()):
            if index >= MAX_PYTHON_LAYOUT_CANDIDATES:
                break
            if len(mapped_package_directories) >= MAX_PYTHON_SOURCE_ROOTS:
                break
            if (
                not isinstance(package, str)
                or not package
                or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", package)
            ):
                continue
            relative = _configured_python_path(directory)
            if (
                relative is not None
                and _contained_directory(repo_root, relative) is not None
            ):
                mapped_modules.add(package.split(".", 1)[0])
                mapped_package_directories.add(relative)
    marker_required_roots = (
        set(roots) if package_find.get("namespaces") is False else set()
    )
    return roots, marker_required_roots, mapped_modules, mapped_package_directories


def _configured_python_source_roots(repo_root):
    roots, _marker_roots, _mapped_modules, _mapped_directories = (
        _configured_python_layout(repo_root)
    )
    return roots


def _source_root_modules_from_fd(directory_fd, *, require_package_marker):
    modules = set()
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                entry_stat = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(entry_stat.st_mode):
                    path = Path(entry.name)
                    if path.suffix == ".py":
                        modules.add(path.stem)
                    continue
                if not stat.S_ISDIR(entry_stat.st_mode):
                    continue
                if not require_package_marker:
                    modules.add(entry.name)
                    continue

                child_fd = None
                try:
                    child_fd = os.open(
                        entry.name,
                        _directory_open_flags(),
                        dir_fd=directory_fd,
                    )
                    init_stat = os.stat(
                        "__init__.py",
                        dir_fd=child_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISREG(init_stat.st_mode):
                        modules.add(entry.name)
                except OSError:
                    continue
                finally:
                    _close_directory_fd(child_fd)
    except OSError:
        return set()
    return modules


def _collect_source_root_modules(
    repo_root, source_roots, *, require_package_marker=False
):
    modules = set()
    for source_root in source_roots:
        if not _supports_directory_fd_access(require_scandir=True):
            continue
        directory_fd = _open_contained_directory_fd(repo_root, source_root)
        if directory_fd is None:
            continue
        try:
            modules.update(
                _source_root_modules_from_fd(
                    directory_fd,
                    require_package_marker=require_package_marker,
                )
            )
        finally:
            _close_directory_fd(directory_fd)
    return modules


def _is_file_local_import(mod, ctx, importer, *, direct_script=False):
    if importer is None or not str(mod).isidentifier():
        return False

    directory = importer.parent
    cache_key = (directory.as_posix(), mod, direct_script)
    if cache_key in ctx["file_local_cache"]:
        return ctx["file_local_cache"][cache_key]

    if directory in ctx["package_context_cache"]:
        source_context, strong_package_context = ctx["package_context_cache"][directory]
    else:
        source_context = any(
            source_root in directory.parents for source_root in ctx["source_roots"]
        )
        strong_package_context = any(
            package_dir == directory or package_dir in directory.parents
            for package_dir in ctx["package_directories"]
        )
        current = directory
        while not strong_package_context:
            if _context_has_local_python_file(ctx, current / "__init__.py"):
                strong_package_context = True
                break
            if not current.parts:
                break
            current = current.parent
        ctx["package_context_cache"][directory] = (
            source_context,
            strong_package_context,
        )

    package_context = strong_package_context or (source_context and not direct_script)

    is_local = not package_context and (
        _context_has_local_python_file(ctx, directory / f"{mod}.py")
        or _context_has_local_python_file(ctx, directory / mod / "__init__.py")
    )
    ctx["file_local_cache"][cache_key] = is_local
    return is_local


def _has_direct_script_evidence(source):
    if source.startswith("#!"):
        return True
    if "__name__" not in source or "__main__" not in source:
        return False
    try:
        tree = ast.parse(source)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return False

    for statement in tree.body:
        if not isinstance(statement, ast.If):
            continue
        comparison = statement.test
        if (
            not isinstance(comparison, ast.Compare)
            or len(comparison.ops) != 1
            or not isinstance(comparison.ops[0], ast.Eq)
            or len(comparison.comparators) != 1
        ):
            continue
        left, right = comparison.left, comparison.comparators[0]
        if (
            isinstance(left, ast.Name)
            and left.id == "__name__"
            and isinstance(right, ast.Constant)
            and right.value == "__main__"
        ) or (
            isinstance(right, ast.Name)
            and right.id == "__name__"
            and isinstance(left, ast.Constant)
            and left.value == "__main__"
        ):
            return True
    return False


def _diff_file_has_direct_script_evidence(repo_root, file_label):
    if _contained_importer_path(repo_root, file_label, diff_path=True) is None:
        return False
    source = read_project_text_no_symlink(
        repo_root,
        file_label,
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    return source is not None and _has_direct_script_evidence(source)


def _parse_requirements_txt(path):
    deps = set()

    text = read_text_no_symlink(
        path,
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if text is None:
        return deps
    lines = text.splitlines()

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("-e "):
            continue

        if line.startswith("git+"):
            continue

        if line.startswith("http://") or line.startswith("https://"):
            continue

        m = REQ_LINE_RE.match(line)
        if not m:
            continue

        name = m.group(1)
        deps.add(_normalize_name(name))

    return deps


def _dependency_names(specs):
    deps = set()
    if not isinstance(specs, list):
        return deps

    for spec in specs:
        if not isinstance(spec, str):
            continue
        match = REQ_LINE_RE.match(spec.strip())
        if match:
            deps.add(_normalize_name(match.group(1)))
    return deps


def _project_dependency_metadata(data):
    project = data.get("project")
    if not isinstance(project, dict):
        return set(), None

    deps = _dependency_names(project.get("dependencies"))
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for specs in optional.values():
            deps.update(_dependency_names(specs))

    raw_name = project.get("name")
    project_name = raw_name if isinstance(raw_name, str) else None
    return deps, project_name


def _dependency_group_names(data):
    groups = data.get("dependency-groups")
    if not isinstance(groups, dict):
        return set()

    deps = set()
    for specs in groups.values():
        # PEP 735 also permits {include-group = "..."} entries. Every group
        # is considered declared here, so collecting the string entries from
        # all groups already includes the referenced group's dependencies.
        deps.update(_dependency_names(specs))
    return deps


def _poetry_dependency_names(poetry):
    deps = set()
    poetry_dependencies = poetry.get("dependencies")
    if isinstance(poetry_dependencies, dict):
        for raw_name in poetry_dependencies:
            name = _normalize_name(raw_name)
            if name and name != "python":
                deps.add(name)

    poetry_extras = poetry.get("extras")
    if isinstance(poetry_extras, dict):
        for specs in poetry_extras.values():
            deps.update(_dependency_names(specs))
    return deps


def _poetry_dependency_metadata(data):
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return set(), None

    poetry = tool.get("poetry")
    if not isinstance(poetry, dict):
        return set(), None

    raw_name = poetry.get("name")
    project_name = raw_name if isinstance(raw_name, str) else None
    return _poetry_dependency_names(poetry), project_name


def _pyproject_dependency_metadata(data):
    deps, project_name = _project_dependency_metadata(data)
    deps.update(_dependency_group_names(data))
    poetry_deps, poetry_name = _poetry_dependency_metadata(data)
    deps.update(poetry_deps)
    if project_name is None:
        project_name = poetry_name
    return deps, project_name


def _parse_pyproject_toml(path, *, project_root=None):
    if project_root is None:
        txt = read_text_no_symlink(
            path,
            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            encoding="utf-8",
        )
    else:
        txt = read_project_text_no_symlink(
            project_root,
            path,
            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            encoding="utf-8",
        )
    if txt is None:
        return set(), None

    try:
        data = tomllib.loads(txt)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        logger.debug("Failed to parse dependency metadata from %s: %s", path, exc)
        return set(), None

    return _pyproject_dependency_metadata(data)


def _parse_setup_py(path):
    deps = set()
    project_name = None

    txt = read_text_no_symlink(
        path,
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if txt is None:
        return deps, project_name

    name_match = re.search(r"""name\s*=\s*['"]([^'"]+)['"]""", txt)
    if name_match:
        project_name = name_match.group(1)

    for key in ("install_requires", "setup_requires"):
        pattern = re.compile(re.escape(key) + r"\s*=\s*\[")
        m = pattern.search(txt)
        if not m:
            continue

        start = m.end()
        depth = 1
        pos = start
        while pos < len(txt) and depth > 0:
            ch = txt[pos]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            elif ch in ('"', "'"):
                quote = ch
                pos += 1
                while pos < len(txt) and txt[pos] != quote:
                    if txt[pos] == "\\":
                        pos += 1
                    pos += 1
            pos += 1

        if depth != 0:
            continue

        block = txt[start : pos - 1]
        raw_items = re.findall(r"['\"]([^'\"]+)['\"]", block)
        for item in raw_items:
            rm = REQ_LINE_RE.match(item.strip())
            if rm:
                deps.add(_normalize_name(rm.group(1)))

    return deps, project_name


def _has_dependency_manifest_context(repo_root):
    current = repo_root

    for _ in range(5):
        try:
            for filename in DEPENDENCY_MANIFEST_FILENAMES:
                if (current / filename).exists():
                    return True

            req_dir = current / "requirements"
            if req_dir.exists() and req_dir.is_dir():
                for req_file in req_dir.glob("*.txt"):
                    if req_file.exists():
                        return True
        except OSError:
            return False

        parent = current.parent
        if parent == current:
            break
        current = parent

    return False


def _collect_declared_deps(repo_root):
    deps = set()
    project_name = None

    current = repo_root
    for _ in range(5):
        req_path = current / "requirements.txt"
        if req_path.exists():
            deps |= _parse_requirements_txt(req_path)

        pyproj_path = current / "pyproject.toml"
        if pyproj_path.exists():
            pyproj_deps, pyproj_name = _parse_pyproject_toml(pyproj_path)
            deps |= pyproj_deps
            if pyproj_name and not project_name:
                project_name = pyproj_name

        setup_path = current / "setup.py"
        if setup_path.exists():
            setup_deps, setup_name = _parse_setup_py(setup_path)
            deps |= setup_deps
            if setup_name and not project_name:
                project_name = setup_name

        req_dir = current / "requirements"
        if req_dir.exists() and req_dir.is_dir():
            for req_file in req_dir.glob("*.txt"):
                deps |= _parse_requirements_txt(req_file)

        if deps:
            break

        parent = current.parent
        if parent == current:
            break
        current = parent

    if project_name:
        deps.add(_normalize_name(project_name))

    return deps


def _nested_pyproject_metadata(repo_root, directory):
    pyproject = directory / "pyproject.toml"
    try:
        if not pyproject.exists():
            return frozenset(), False
    except OSError:
        return frozenset(), False

    deps, project_name = _parse_pyproject_toml(
        pyproject,
        project_root=repo_root,
    )
    if project_name:
        deps.add(_normalize_name(project_name))
    return frozenset(deps), True


def _dependency_scope_for_file(
    repo_root,
    file_path,
    scope_cache,
    extra_deps_by_directory=None,
):
    root = Path(os.path.abspath(repo_root))
    try:
        raw_path = os.fspath(file_path)
    except TypeError:
        return scope_cache[root]
    if not isinstance(raw_path, str) or len(raw_path) > MAX_DEPENDENCY_SCOPE_PATH_CHARS:
        return scope_cache[root]

    path = Path(raw_path)
    if not path.is_absolute():
        path = root / path
    directory = Path(os.path.abspath(path)).parent

    try:
        relative_directory = directory.relative_to(root)
    except ValueError:
        return scope_cache[root]
    if len(relative_directory.parts) > MAX_DEPENDENCY_SCOPE_COMPONENTS:
        return scope_cache[root]

    pending = []
    current = directory
    while current not in scope_cache:
        pending.append(current)
        parent = current.parent
        if parent == current:
            return scope_cache[root]
        current = parent

    declared_deps, manifest_context = scope_cache[current]
    for nested_directory in reversed(pending):
        nested_deps, has_pyproject = _nested_pyproject_metadata(root, nested_directory)
        extra_deps = (
            extra_deps_by_directory.get(nested_directory, frozenset())
            if extra_deps_by_directory
            else frozenset()
        )
        if nested_deps or extra_deps:
            declared_deps = declared_deps.union(nested_deps, extra_deps)
        manifest_context = manifest_context or has_pyproject or bool(extra_deps)
        scope_cache[nested_directory] = declared_deps, manifest_context

    return scope_cache[directory]


def _normalized_dependency_names(dependencies):
    if isinstance(dependencies, str):
        dependencies = (dependencies,)

    normalized = set()
    for dependency in dependencies or ():
        name = _normalize_name(dependency)
        if name:
            normalized.add(name)
    return frozenset(normalized)


def _split_extra_dependency_scopes(repo_root, extra_declared_deps):
    """Separate root-wide diff declarations from nested manifest scopes."""
    if not extra_declared_deps:
        return frozenset(), {}

    by_directory = getattr(extra_declared_deps, "by_directory", None)
    if not isinstance(by_directory, dict):
        return _normalized_dependency_names(extra_declared_deps), {}

    root = Path(os.path.abspath(repo_root))
    scopes = {}
    for directory_label, dependencies in by_directory.items():
        relative = Path(str(directory_label))
        if relative.is_absolute() or ".." in relative.parts:
            continue
        directory = Path(os.path.abspath(root / relative))
        try:
            directory.relative_to(root)
        except ValueError:
            continue

        names = _normalized_dependency_names(dependencies)
        if names:
            scopes[directory] = scopes.get(directory, frozenset()).union(names)

    return scopes.pop(root, frozenset()), scopes


def _find_import_line(src, mod):
    if not src:
        return 1

    try:
        lines = src.splitlines()
    except AttributeError:
        return 1

    pattern = r"^\s*(import|from)\s+{}(\.|\s|$)".format(re.escape(mod))

    for idx, ln in enumerate(lines, start=1):
        if re.search(pattern, ln):
            return idx

    return 1


def _load_private_allowlist():
    raw = os.getenv("SKYLOS_PRIVATE_DEPS_ALLOW", "")
    raw = raw.strip()

    allow = set()
    if not raw:
        return allow

    parts = raw.split(",")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        allow.add(_normalize_name(p))

    return allow


def _load_pypi_cache(repo_root, cache_path):
    return load_project_json_cache(repo_root, cache_path)


def _save_pypi_cache(repo_root, cache_path, cache):
    if not save_project_json_cache(repo_root, cache_path, cache):
        logger.debug("Failed to save PyPI cache %s", cache_path)


def _check_pypi_status(package_name, cache):
    normalized = _normalize_name(package_name)

    if normalized in cache:
        return cache[normalized]

    names_to_try = [normalized]
    if package_name:
        names_to_try.append(package_name)
        if "_" in package_name:
            names_to_try.append(package_name.replace("_", "-"))

    for name in names_to_try:
        name = str(name or "").strip()
        if not name:
            continue

        url = f"https://pypi.org/simple/{name}/"
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "skylos-dep-scanner/1.0")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if getattr(resp, "status", 200) == 200:
                    cache[normalized] = "exists"
                    return "exists"

        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            cache[normalized] = "unknown"
            return "unknown"

        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            cache[normalized] = "unknown"
            return "unknown"

    cache[normalized] = "missing"
    return "missing"


def _is_confident_hallucination_candidate(name):
    if not name:
        return False

    if name.isupper():
        return False

    if len(name) <= 2:
        return False

    return True


def _build_dependency_context(repo_root, py_files=None):
    declared_deps = _collect_declared_deps(repo_root)
    known_python_files = _known_python_files(
        repo_root, _dependency_context_python_files(repo_root, py_files)
    )
    (
        source_roots,
        marker_required_roots,
        mapped_modules,
        package_directories,
    ) = _configured_python_layout(repo_root)
    conventional_roots = {CONVENTIONAL_PYTHON_SOURCE_ROOT} - source_roots
    secure_file_access = _supports_directory_fd_access()
    secure_source_scan = _supports_directory_fd_access(require_scandir=True)
    local_modules = _collect_local_modules(repo_root) | mapped_modules
    if not secure_file_access:
        local_modules.update(_collect_known_root_modules(known_python_files))
    if secure_source_scan:
        local_modules.update(
            _collect_source_root_modules(
                repo_root,
                source_roots - marker_required_roots,
            )
        )
        local_modules.update(
            _collect_source_root_modules(
                repo_root,
                marker_required_roots,
                require_package_marker=True,
            )
        )
        local_modules.update(
            _collect_source_root_modules(
                repo_root,
                conventional_roots,
                require_package_marker=True,
            )
        )
    else:
        local_modules.update(
            _collect_known_source_root_modules(
                known_python_files,
                source_roots - marker_required_roots,
            )
        )
        local_modules.update(
            _collect_known_source_root_modules(
                known_python_files,
                marker_required_roots,
                require_package_marker=True,
            )
        )
        local_modules.update(
            _collect_known_source_root_modules(
                known_python_files,
                conventional_roots,
                require_package_marker=True,
            )
        )
    cache_path = repo_root / ".skylos" / "cache" / "pypi_exists.json"
    return {
        "repo_root": repo_root,
        "known_python_files": known_python_files,
        "source_roots": source_roots - marker_required_roots,
        "package_directories": package_directories,
        "stdlib": _get_stdlib_modules(),
        "local_modules": local_modules,
        "file_local_cache": {},
        "package_context_cache": {},
        "declared_deps": declared_deps,
        "manifest_context": bool(declared_deps)
        or _has_dependency_manifest_context(repo_root),
        "private_allow": _load_private_allowlist(),
        "installed_mapping": _build_installed_module_mapping(),
        "import_to_dist": _load_import_to_dist_mapping(),
        "cache_path": cache_path,
        "pypi_cache": _load_pypi_cache(repo_root, cache_path),
        "cache_modified": False,
        "registry_unreachable": False,
    }


def _tracked_pypi_status(name, ctx):
    old_size = len(ctx["pypi_cache"])
    status = _check_pypi_status(name, ctx["pypi_cache"])
    if len(ctx["pypi_cache"]) != old_size:
        ctx["cache_modified"] = True
    if status == "unknown":
        ctx["registry_unreachable"] = True
    return status


def _undeclared_template(mod, message):
    return {
        "rule_id": RULE_ID_UNDECLARED,
        "severity": SEV_MEDIUM,
        "message": message,
        "col": 0,
        "symbol": mod,
    }


def _hallucinated_template(mod):
    return {
        "rule_id": RULE_ID_HALLUCINATION,
        "severity": SEV_CRITICAL,
        "message": (
            f"Hallucinated dependency '{mod}'. Package does not exist on PyPI."
        ),
        "col": 0,
        "symbol": mod,
        "category": "ai_defect",
        "defect_type": "dependency_hallucination",
        "vibe_category": "dependency_hallucination",
        "ai_likelihood": "high",
    }


def _classify_import(mod, ctx, file_path=None, *, diff_path=False, direct_script=False):
    """Return a finding template (without file/line) for an import root, or None."""
    if not mod or mod.startswith("_"):
        return None

    if mod in ctx["stdlib"]:
        return None

    importer = None
    local_scope_valid = file_path is None
    if file_path is not None:
        importer = _contained_importer_path(
            ctx["repo_root"], file_path, diff_path=diff_path
        )
        local_scope_valid = (
            importer is not None
            and _contained_directory(
                ctx["repo_root"], importer.parent, allow_missing=diff_path
            )
            is not None
        )
        if local_scope_valid and not diff_path:
            local_scope_valid = _context_has_local_python_file(ctx, importer)
    if local_scope_valid and (
        mod in ctx["local_modules"]
        or _is_file_local_import(mod, ctx, importer, direct_script=direct_script)
    ):
        return None

    declared_deps = ctx["declared_deps"]
    manifest_context = ctx["manifest_context"]

    installed_result = _classify_installed_import(mod, ctx)
    if installed_result is not _NO_FINDING:
        return installed_result

    if _get_possible_packages(mod, ctx["installed_mapping"]) & declared_deps:
        return None

    normalized_mod = _normalize_name(mod)

    if normalized_mod in declared_deps:
        return None

    if normalized_mod in ctx["private_allow"]:
        return None

    mapped_result = _classify_mapped_import(mod, ctx)
    if mapped_result is not _NO_FINDING:
        return mapped_result

    return _classify_registry_import(mod, ctx, manifest_context)


_NO_FINDING = object()


def _classify_installed_import(mod, ctx):
    if mod not in ctx["installed_mapping"]:
        return _NO_FINDING

    known_dists = ctx["installed_mapping"][mod]
    if known_dists & ctx["declared_deps"]:
        return None

    if not ctx["manifest_context"]:
        return None

    dist_hint = ", ".join(sorted(known_dists))
    return _undeclared_template(
        mod,
        f"Undeclared import '{mod}' (provided by: {dist_hint}). Add to requirements.txt/pyproject.toml/setup.py.",
    )


def _classify_mapped_import(mod, ctx):
    if mod in ctx["import_to_dist"]:
        mapped_dist = ctx["import_to_dist"][mod]

        if _normalize_name(mapped_dist) in ctx["declared_deps"]:
            return None

        if not ctx["manifest_context"]:
            return None

        if _tracked_pypi_status(mapped_dist, ctx) == "exists":
            return _undeclared_template(
                mod,
                (
                    f"Undeclared import '{mod}' (provided by: "
                    f"{mapped_dist}). Add to "
                    f"requirements.txt/pyproject.toml/setup.py."
                ),
            )
    return _NO_FINDING


def _classify_registry_import(mod, ctx, manifest_context):
    pypi_status = _tracked_pypi_status(mod, ctx)

    if pypi_status == "missing" and _is_confident_hallucination_candidate(mod):
        return _hallucinated_template(mod)
    if pypi_status == "exists" and manifest_context:
        return _undeclared_template(
            mod,
            (
                f"Undeclared import '{mod}'. Not found in "
                f"requirements.txt/pyproject.toml/setup.py."
            ),
        )
    if manifest_context:
        return _undeclared_template(
            mod,
            (
                f"Undeclared import '{mod}'. Not found in "
                f"requirements.txt/pyproject.toml/setup.py "
                f"(possible import/dist name mismatch)."
            ),
        )
    return None


def scan_python_dependency_hallucinations(repo_root, py_files):
    findings = []

    if repo_root is None:
        return findings

    root = Path(os.path.abspath(repo_root))
    py_files = list(py_files)
    ctx = _build_dependency_context(root, py_files)
    scope_cache = {root: (frozenset(ctx["declared_deps"]), ctx["manifest_context"])}

    for file_path in py_files:
        declared_deps, manifest_context = _dependency_scope_for_file(
            root, file_path, scope_cache
        )
        ctx["declared_deps"] = declared_deps
        ctx["manifest_context"] = manifest_context
        try:
            src = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        direct_script = _has_direct_script_evidence(src)
        for mod in sorted(_extract_imports(src)):
            template = _classify_import(
                mod, ctx, file_path, direct_script=direct_script
            )
            if template is None:
                continue

            finding = dict(template)
            finding["file"] = str(file_path)
            finding["line"] = _find_import_line(src, mod)
            findings.append(finding)

    if ctx["cache_modified"]:
        _save_pypi_cache(repo_root, ctx["cache_path"], ctx["pypi_cache"])

    return findings


def scan_diff_added_imports(
    repo_root,
    added_imports,
    extra_local_modules=None,
    extra_declared_deps=None,
):
    """Classify import roots added by a diff against the current checkout.

    added_imports: iterable of (file_label, line_no, module_name) tuples.
    extra_local_modules: module roots created by the same diff, treated as
    local so brand-new project modules are not reported as hallucinated.
    Returns (findings, registry_unreachable).
    """
    findings = []

    if repo_root is None:
        return findings, False

    root = Path(os.path.abspath(repo_root))
    ctx = _build_dependency_context(root)
    if extra_local_modules:
        ctx["local_modules"] = set(ctx["local_modules"]) | set(extra_local_modules)
    root_extra_deps, scoped_extra_deps = _split_extra_dependency_scopes(
        root, extra_declared_deps
    )
    if root_extra_deps:
        ctx["declared_deps"] = set(ctx["declared_deps"]) | set(root_extra_deps)
        ctx["manifest_context"] = True

    scope_cache = {
        root: (
            frozenset(ctx["declared_deps"]),
            ctx["manifest_context"],
        )
    }

    seen = set()
    direct_script_cache = {}
    for file_label, line_no, module_name in added_imports:
        mod = str(module_name).split(".")[0].strip()
        if (file_label, mod) in seen:
            continue
        seen.add((file_label, mod))

        declared_deps, manifest_context = _dependency_scope_for_file(
            root,
            file_label,
            scope_cache,
            scoped_extra_deps,
        )
        ctx["declared_deps"] = declared_deps
        ctx["manifest_context"] = manifest_context

        script_key = str(file_label)
        if script_key not in direct_script_cache:
            direct_script_cache[script_key] = _diff_file_has_direct_script_evidence(
                root, file_label
            )
        template = _classify_import(
            mod,
            ctx,
            file_label,
            diff_path=True,
            direct_script=direct_script_cache[script_key],
        )
        if template is None:
            continue

        finding = dict(template)
        finding["file"] = str(file_label)
        finding["line"] = int(line_no)
        findings.append(finding)

    if ctx["cache_modified"]:
        _save_pypi_cache(root, ctx["cache_path"], ctx["pypi_cache"])

    return findings, ctx["registry_unreachable"]
