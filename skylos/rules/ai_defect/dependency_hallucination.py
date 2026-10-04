from __future__ import annotations

import ast
import csv
import io
import json
import logging
import os
import re
import site
import stat
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.rules.ai_defect import pypi_wheel_modules
from skylos.rules.ai_defect.installed_modules_cache import (
    installed_module_mapping,
    virtual_env_site_packages,
)
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
MAX_ROS_MANIFEST_BYTES = 256_000
MAX_ROS_MANIFEST_CANDIDATES = 128
MAX_ROS_PACKAGE_DIRECTORIES = 256
CONVENTIONAL_PYTHON_SOURCE_ROOT = Path("src")
MAX_DIST_MODULE_LOOKUPS = 32
DIST_MODULE_LOOKUP_WORKERS = 16
MIN_NAME_AFFINITY_TOKEN = 3
MAX_NAMESPACE_PROBES = 3
PYTHON_SOURCE_SUFFIXES = frozenset({".py", ".pyi", ".pyw"})
# These are ROS 2 Python import roots, including generated message packages.
# ROS packages are normally installed by apt/colcon, not published to PyPI.
ROS_PYTHON_IMPORT_ROOTS = frozenset(
    {
        "ament_index_python",
        "geometry_msgs",
        "launch_ros",
        "nav_msgs",
        "rclpy",
        "rosidl_runtime_py",
        "sensor_msgs",
        "sensor_msgs_py",
        "std_msgs",
        "std_srvs",
        "tf2_ros",
    }
)
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
    else:
        logger.warning(
            "Import-name mapping %s is missing (incomplete install?); "
            "dependency checks fall back to registry lookups.",
            mapping_path,
        )

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

    site_packages_dirs.extend(virtual_env_site_packages())

    for sp_dir in dict.fromkeys(site_packages_dirs):
        sp_path = Path(sp_dir)
        if not sp_path.exists():
            continue

        for index, dist_info in enumerate(sp_path.glob("*.dist-info")):
            if index >= MAX_PYTHON_LAYOUT_CANDIDATES:
                break
            metadata_file = dist_info / "METADATA"
            dist_name = None
            if metadata_file.exists():
                try:
                    metadata_text = read_project_text_no_symlink(
                        sp_path,
                        metadata_file,
                        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                        encoding="utf-8",
                        errors="ignore",
                    )
                    for line in (metadata_text or "").splitlines():
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
                    content = (
                        read_project_text_no_symlink(
                            sp_path,
                            top_level_file,
                            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                            encoding="utf-8",
                            errors="ignore",
                        )
                        or ""
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
                    content = (
                        read_project_text_no_symlink(
                            sp_path,
                            record_file,
                            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                            encoding="utf-8",
                            errors="ignore",
                        )
                        or ""
                    )
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


_IMPORT_ERROR_CATCHERS = frozenset(
    {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
)


def _catches_import_error(handler):
    caught = handler.type
    if caught is None:
        return True
    names = caught.elts if isinstance(caught, ast.Tuple) else [caught]
    return any(
        isinstance(name, ast.Name) and name.id in _IMPORT_ERROR_CATCHERS
        for name in names
    )


def _import_nodes(statements):
    """Import statements that run with ``statements`` (not in nested defs)."""
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        elif not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            pending.extend(ast.iter_child_nodes(node))


def _import_roots(node):
    if isinstance(node, ast.ImportFrom):
        if node.level or not node.module:
            return []
        return [node.module.split(".", 1)[0]]
    return [alias.name.split(".", 1)[0] for alias in node.names]


def _import_node_paths(node):
    if isinstance(node, ast.ImportFrom):
        return [node.module] if not node.level and node.module else []
    return [alias.name for alias in node.names]


def _optional_import_paths(src, *, allow_uncertain=False):
    """Paths whose imports can fail without raising or later unguarded use."""
    if not src or "except" not in src:
        return frozenset()
    try:
        tree = ast.parse(src)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return frozenset()

    # A catcher that is shadowed by project code cannot prove that a failed
    # import is handled. Be conservative across scopes rather than executing
    # or guessing which binding reaches a handler.
    shadowed = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    shadowed.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    shadowed.update(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            shadowed.update(
                alias.asname or alias.name.split(".")[0] for alias in node.names
            )

    def survives(handler):
        for node in handler.body:
            if isinstance(node, ast.Pass):
                continue
            if isinstance(node, ast.Assign) and all(
                isinstance(t, ast.Name) for t in node.targets
            ):
                if isinstance(node.value, ast.Constant):
                    continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if set(_import_roots(node)) <= _get_stdlib_modules():
                    continue
            return False
        return True

    def explicitly_fails(handler):
        for node in ast.walk(handler):
            if isinstance(node, (ast.Raise, ast.Return)):
                return True
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Name) and function.id in {"exit", "quit"}:
                    return True
                if isinstance(function, ast.Attribute) and isinstance(
                    function.value, ast.Name
                ):
                    if (function.value.id, function.attr) in {
                        ("sys", "exit"),
                        ("os", "_exit"),
                    }:
                        return True
        return False

    guarded = set()
    protected_uses = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, ast.Try):
            continue
        handler = next(
            (h for h in statement.handlers if _catches_import_error(h)), None
        )
        if handler is None or any(
            isinstance(node, ast.Name) and node.id in shadowed
            for node in (ast.walk(handler.type) if handler.type is not None else ())
        ):
            continue
        preceding = statement.handlers[: statement.handlers.index(handler)]
        disjoint = {
            "ValueError",
            "TypeError",
            "AttributeError",
            "RuntimeError",
            "NameError",
            "LookupError",
            "KeyError",
            "IndexError",
            "ArithmeticError",
            "AssertionError",
            "OSError",
            "SyntaxError",
            "UnicodeError",
            "StopIteration",
            "StopAsyncIteration",
        }
        uncertain_preceding = []
        for earlier in preceding:
            types = (
                earlier.type.elts
                if isinstance(earlier.type, ast.Tuple)
                else [earlier.type]
            )
            if not all(
                isinstance(value, ast.Name)
                and value.id in disjoint
                and value.id not in shadowed
                for value in types
            ):
                uncertain_preceding.append(earlier)
        if uncertain_preceding and (
            not allow_uncertain or any(explicitly_fails(h) for h in uncertain_preceding)
        ):
            continue
        if not survives(handler) and not (
            allow_uncertain and not explicitly_fails(handler)
        ):
            continue
        imports = list(_import_nodes(statement.body))
        guarded.update(id(node) for node in imports)
        running = list(statement.body)
        protected = set()
        while running:
            node = running.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            protected.add(id(node))
            running.extend(ast.iter_child_nodes(node))
        for node in imports:
            protected_uses.setdefault(id(node), set()).update(protected)

    if not guarded:
        return frozenset()
    statements_by_root = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for root in _import_node_paths(node):
            statements_by_root.setdefault(root, set()).add(id(node))
    optional = set()
    for root, nodes in statements_by_root.items():
        if not nodes <= guarded:
            continue
        aliases = set()
        protected = set()
        for node in ast.walk(tree):
            if id(node) not in nodes:
                continue
            aliases.update(
                alias.asname
                or (
                    alias.name.split(".")[0]
                    if isinstance(node, ast.Import)
                    else alias.name
                )
                for alias in node.names
            )
            protected.update(protected_uses[id(node)])
        if any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in aliases
            and id(node) not in protected
            for node in ast.walk(tree)
        ):
            continue
        optional.add(root)
    return frozenset(optional)


def _optional_import_roots(src, *, allow_uncertain=False):
    paths = _optional_import_paths(src, allow_uncertain=allow_uncertain)
    if not paths:
        return frozenset()
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return frozenset()
    required_roots = {
        path.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for path in _import_node_paths(node)
        if path not in paths
    }
    return frozenset(path.split(".")[0] for path in paths) - required_roots


def _local_import_fallbacks(src, ctx, importer):
    """Find absolute imports paired with a sibling relative import fallback.

    A package module can use ``from .helper`` when imported as a package and
    ``from helper`` when executed as a script. Only accept the absolute form
    when *every* absolute import of that root is in a matching ImportError
    handler and a real sibling Python module exists.
    """
    if (
        importer is None
        or "except ImportError" not in src
        or not _has_direct_script_evidence(src)
    ):
        return frozenset()
    try:
        tree = ast.parse(src)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return frozenset()

    absolute_imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            root = node.module.split(".", 1)[0]
            absolute_imports.setdefault(root, set()).add(id(node))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                absolute_imports.setdefault(root, set()).add(id(node))

    paired = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, ast.Try):
            continue
        relative_modules = {
            node.module
            for node in statement.body
            if isinstance(node, ast.ImportFrom)
            and node.level == 1
            and node.module
            and node.module.isidentifier()
        }
        for handler in statement.handlers:
            if not (
                isinstance(handler.type, ast.Name) and handler.type.id == "ImportError"
            ):
                continue
            for node in handler.body:
                if (
                    isinstance(node, ast.ImportFrom)
                    and node.level == 0
                    and node.module in relative_modules
                    and _context_has_local_python_file(
                        ctx, importer.parent / f"{node.module}.py"
                    )
                ):
                    paired.setdefault(node.module, set()).add(id(node))

    return frozenset(
        mod for mod, nodes in paired.items() if absolute_imports.get(mod) == nodes
    )


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


MAX_REQUIREMENTS_FILES_PER_DIRECTORY = 32


def _requirements_files(directory):
    """``requirements.txt`` plus variants such as ``requirements-dev.txt`` or
    ``requirements-mlx.txt`` in one directory (bounded, sorted)."""
    try:
        found = sorted(
            path
            for path in directory.glob("requirements*.txt")
            if path.name == "requirements.txt"
            or path.name[len("requirements")] in "-_."
        )
    except OSError:
        return []
    return found[:MAX_REQUIREMENTS_FILES_PER_DIRECTORY]


def _collect_declared_metadata(repo_root):
    """Declared dependency names, and the project's own normalized name."""
    deps = set()
    project_name = None

    current = repo_root
    for _ in range(5):
        for req_path in _requirements_files(current):
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

    return deps, (_normalize_name(project_name) if project_name else None)


def _collect_declared_deps(repo_root):
    deps, project_name = _collect_declared_metadata(repo_root)
    if project_name:
        deps.add(project_name)
    return deps


def _collect_project_names(repo_root):
    _, project_name = _collect_declared_metadata(repo_root)
    return {project_name} if project_name else set()


def _merge_provider_specs(target, additions):
    for name, specifier in additions.items():
        if name not in target:
            target[name] = specifier
        elif target[name] is None or specifier is None:
            target[name] = None
        else:
            target[name] = ",".join(filter(None, (target[name], specifier)))


def _add_provider_requirement(specs, raw):
    """Record a public static requirement; None means inventory is unknown."""
    if not isinstance(raw, str):
        return False
    raw = raw.split(" #", 1)[0].strip()
    raw = re.split(r"\s+--hash(?:=|\s)", raw, maxsplit=1)[0]
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        match = REQ_LINE_RE.match(raw)
        if match:
            _merge_provider_specs(specs, {_normalize_name(match.group(1)): None})
        return False
    specifier = (
        None if requirement.url or requirement.marker else str(requirement.specifier)
    )
    _merge_provider_specs(specs, {_normalize_name(requirement.name): specifier})
    return True


def _poetry_provider_specifier(value):
    if isinstance(value, dict):
        if any(
            key in value
            for key in ("git", "path", "url", "source", "markers", "python", "platform")
        ):
            return None
        value = value.get("version", "*")
    if not isinstance(value, str) or "||" in value:
        return None
    value = value.strip()
    if value in ("", "*"):
        return ""
    if value.startswith(("^", "~")) and not value.startswith("~="):
        prefix, raw = value[0], value[1:]
        try:
            version = Version(raw)
        except InvalidVersion:
            return None
        release = list(version.release)
        if not release or version.pre or version.post or version.dev:
            return None
        if prefix == "^":
            index = next(
                (i for i, part in enumerate(release) if part), len(release) - 1
            )
        else:
            index = min(1, len(release) - 1)
        upper = release[: index + 1]
        upper[index] += 1
        value = f">={version},<{'.'.join(map(str, upper))}"
    elif value[0].isdigit():
        value = f"=={value}"
    try:
        return str(SpecifierSet(value))
    except InvalidSpecifier:
        return None


def _provider_directory_metadata(directory, *, project_root=None):
    """Bounded static requirements and identity for one manifest directory."""
    specs = {}
    project_names = set()
    unknown = False

    def read(path):
        if project_root is None:
            return read_project_text_no_symlink(
                directory,
                path,
                max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                encoding="utf-8",
            )
        return read_project_text_no_symlink(
            project_root,
            path,
            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            encoding="utf-8",
        )

    requirement_files = _requirements_files(directory)
    if len(requirement_files) >= MAX_REQUIREMENTS_FILES_PER_DIRECTORY:
        unknown = True
    req_dir = directory / "requirements"
    try:
        variants = sorted(req_dir.glob("*.txt"))[:MAX_REQUIREMENTS_FILES_PER_DIRECTORY]
        if len(variants) >= MAX_REQUIREMENTS_FILES_PER_DIRECTORY:
            unknown = True
        requirement_files += variants
    except OSError:
        unknown = True
    for path in requirement_files:
        text = read(path)
        if text is None:
            unknown = True
            continue
        private_index = False
        file_specs = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line == "--require-hashes":
                continue
            if line.startswith(
                (
                    "--index-url",
                    "--extra-index-url",
                    "--find-links",
                    "--no-index",
                    "-i ",
                    "-i=",
                    "-f ",
                    "-f=",
                )
            ):
                private_index = True
                unknown = True
                continue
            if line.startswith("-"):
                unknown = True
                continue
            if not _add_provider_requirement(file_specs, line):
                unknown = True
        if private_index:
            file_specs = {name: None for name in file_specs}
        _merge_provider_specs(specs, file_specs)

    pyproject_text = read(directory / "pyproject.toml")
    if pyproject_text is not None:
        try:
            data = tomllib.loads(pyproject_text)
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            data = {}
            unknown = True
        project = data.get("project", {})
        if isinstance(project, dict):
            name = project.get("name")
            if isinstance(name, str):
                project_names.add(_normalize_name(name))
            dynamic = project.get("dynamic", [])
            if not isinstance(dynamic, list) or not all(
                isinstance(value, str) for value in dynamic
            ):
                unknown = True
            elif set(dynamic) & {"dependencies", "optional-dependencies"}:
                unknown = True
            groups = [project.get("dependencies", [])]
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                groups.extend(optional.values())
            dependency_groups = data.get("dependency-groups", {})
            if isinstance(dependency_groups, dict):
                groups.extend(dependency_groups.values())
            for group in groups:
                if not isinstance(group, list):
                    unknown = True
                    continue
                for raw in group:
                    if isinstance(raw, dict) and set(raw) == {"include-group"}:
                        continue
                    if not _add_provider_requirement(specs, raw):
                        unknown = True
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            name = poetry.get("name")
            if isinstance(name, str):
                project_names.add(_normalize_name(name))
            groups = [poetry.get("dependencies", {})]
            poetry_groups = poetry.get("group", {})
            if isinstance(poetry_groups, dict):
                groups.extend(
                    g.get("dependencies", {})
                    for g in poetry_groups.values()
                    if isinstance(g, dict)
                )
            private_sources = bool(poetry.get("source"))
            for group in groups:
                if not isinstance(group, dict):
                    unknown = True
                    continue
                for name, value in group.items():
                    normalized = _normalize_name(name)
                    if normalized == "python":
                        continue
                    specifier = (
                        None if private_sources else _poetry_provider_specifier(value)
                    )
                    _merge_provider_specs(specs, {normalized: specifier})

    setup_text = read(directory / "setup.py")
    if setup_text is not None:
        try:
            tree = ast.parse(setup_text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            tree = None
            unknown = True
        for node in ast.walk(tree) if tree is not None else ():
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not (
                (isinstance(function, ast.Name) and function.id == "setup")
                or (isinstance(function, ast.Attribute) and function.attr == "setup")
            ):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                ):
                    project_names.add(_normalize_name(keyword.value.value))
                if keyword.arg not in (
                    "install_requires",
                    "setup_requires",
                    "extras_require",
                ):
                    continue
                try:
                    value = ast.literal_eval(keyword.value)
                except (ValueError, TypeError, MemoryError, RecursionError):
                    unknown = True
                    continue
                groups = (
                    value.values()
                    if keyword.arg == "extras_require" and isinstance(value, dict)
                    else [value]
                )
                for group in groups:
                    if not isinstance(group, (list, tuple)):
                        unknown = True
                        continue
                    for raw in group:
                        if not _add_provider_requirement(specs, raw):
                            unknown = True
    return specs, project_names, unknown


def _collect_provider_metadata(repo_root):
    specs, names, unknown = {}, set(), False
    current = repo_root
    for _ in range(5):
        additions, own_names, incomplete = _provider_directory_metadata(current)
        _merge_provider_specs(specs, additions)
        if not names:
            names = own_names
        unknown = unknown or incomplete
        if additions:
            break
        if current.parent == current:
            break
        current = current.parent
    return specs, names, unknown


def _provider_scope_for_file(repo_root, file_path, cache):
    root = Path(os.path.abspath(repo_root))
    importer = _contained_importer_path(root, file_path)
    if importer is None:
        return cache[root]
    directory = root / importer.parent
    pending = []
    current = directory
    while current not in cache:
        pending.append(current)
        if current.parent == current or len(pending) > MAX_DEPENDENCY_SCOPE_COMPONENTS:
            return cache[root]
        current = current.parent
    specs, names, unknown = cache[current]
    for nested in reversed(pending):
        specs = dict(specs)
        additions, own_names, incomplete = _provider_directory_metadata(
            nested, project_root=root
        )
        _merge_provider_specs(specs, additions)
        names = names | own_names
        unknown = unknown or incomplete
        cache[nested] = specs, names, unknown
    return cache[directory]


def _nested_pyproject_metadata(repo_root, directory, project_names=None):
    deps = set()
    has_manifest = False
    for req_path in _requirements_files(directory):
        deps |= _parse_requirements_txt(req_path)
        has_manifest = True

    pyproject = directory / "pyproject.toml"
    try:
        if not pyproject.exists():
            return frozenset(deps), has_manifest
    except OSError:
        return frozenset(deps), has_manifest

    pyproject_deps, project_name = _parse_pyproject_toml(
        pyproject,
        project_root=repo_root,
    )
    deps |= pyproject_deps
    if project_name:
        deps.add(_normalize_name(project_name))
    return frozenset(deps), True


def _dependency_scope_for_file(
    repo_root,
    file_path,
    scope_cache,
    extra_deps_by_directory=None,
    project_names=None,
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
        nested_deps, has_pyproject = _nested_pyproject_metadata(
            root, nested_directory, project_names
        )
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


def _ros_manifest_candidates(repo_root, py_files):
    """Inspect conventional ROS workspace locations and analyzed file parents.

    Keep discovery bounded; a repository cannot make the dependency pass walk
    its entire tree just by adding many package directories.
    """
    candidates = [Path("package.xml")]
    seen = set(candidates)

    def add(relative):
        if relative not in seen and len(candidates) < MAX_ROS_MANIFEST_CANDIDATES:
            seen.add(relative)
            candidates.append(relative)

    for workspace in (Path("ros2"), Path("src"), Path("ros2_ws/src")):
        directory = _contained_directory(repo_root, workspace)
        if directory is None:
            continue
        try:
            children = []
            for index, child in enumerate(directory.iterdir()):
                if index >= MAX_ROS_PACKAGE_DIRECTORIES:
                    break
                children.append(child)
            for child in sorted(children, key=lambda path: path.name):
                if child.name.startswith(".") or not stat.S_ISDIR(
                    child.lstat().st_mode
                ):
                    continue
                manifest = child / "package.xml"
                try:
                    if stat.S_ISREG(manifest.lstat().st_mode):
                        add(workspace / child.name / "package.xml")
                except FileNotFoundError:
                    continue
        except OSError:
            continue

    for file_path in py_files or ():
        if len(candidates) >= MAX_ROS_MANIFEST_CANDIDATES:
            break
        relative = _contained_importer_path(repo_root, file_path)
        if relative is None:
            continue
        for parent in relative.parents:
            if not parent.parts or parent == Path("."):
                break
            add(parent / "package.xml")

    return candidates


def _parse_ros_package_manifest(repo_root, relative):
    text = read_project_text_no_symlink(
        repo_root,
        relative,
        max_bytes=MAX_ROS_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if text is None or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        return None
    try:
        package = ET.fromstring(text)
    except (ET.ParseError, RecursionError, ValueError):
        return None
    if package.tag != "package" or package.get("format") not in {"2", "3"}:
        return None
    name = package.findtext("name")
    if not name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name.strip()):
        return None
    # A package.xml alone could describe ROS 1 or unrelated XML. An ament
    # build dependency/export identifies a ROS 2 package.
    has_ament = any(
        child.tag == "buildtool_depend"
        and (child.text or "").strip().startswith("ament_")
        for child in package
    ) or any(
        child.tag == "export"
        and any(
            item.tag == "build_type" and (item.text or "").strip().startswith("ament_")
            for item in child
        )
        for child in package
    )
    if not has_ament:
        return None
    return frozenset(
        (child.text or "").strip()
        for child in package
        if child.tag in {"depend", "exec_depend"}
        and (child.text or "").strip().isidentifier()
    )


def _collect_ros_package_dependencies(repo_root, py_files):
    manifests = {}
    for relative in _ros_manifest_candidates(repo_root, py_files):
        dependencies = _parse_ros_package_manifest(repo_root, relative)
        if dependencies is not None:
            manifests[relative.parent] = dependencies
    return manifests


def _is_ros_import(mod, ctx, importer):
    manifests = ctx["ros_package_deps"]
    if not manifests or importer is None:
        return False
    package_deps = [
        manifests[parent] for parent in importer.parents if parent in manifests
    ]
    if not package_deps:
        return False
    return any(mod in dependencies for dependencies in package_deps)


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
    declared_specs, project_names, provider_unknown = _collect_provider_metadata(
        repo_root
    )
    declared_deps.update(declared_specs)
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
        "project_names": project_names,
        "declared_specs": declared_specs,
        "provider_unknown": provider_unknown,
        "ros_package_deps": _collect_ros_package_dependencies(repo_root, py_files),
        "manifest_context": bool(declared_deps)
        or _has_dependency_manifest_context(repo_root),
        "private_allow": _load_private_allowlist(),
        "installed_mapping": installed_module_mapping(
            lambda: _build_installed_module_mapping()
        ),
        "import_to_dist": _load_import_to_dist_mapping(),
        # Repository caches are untrusted input, never absence/provider proof.
        "pypi_cache": {},
        "registry_unreachable": False,
        "environment_providers": None,
        "environment_inventories": {},
        "dist_modules": {},
        "dist_lookups": 0,
        "dist_lookups_failed": False,
    }


def _tracked_pypi_status(name, ctx):
    status = _check_pypi_status(name, ctx["pypi_cache"])
    if status == "unknown":
        ctx["registry_unreachable"] = True
    return status


# ---------------------------------------------------------------------------
# Which modules the declared distributions provide.
#
# An import name is not a distribution name (django-money ships ``djmoney``),
# so a PyPI 404 for an import name proves nothing by itself. Before an import
# is reported, check what the declared distributions actually ship: installed
# metadata first, then the file list of each distribution's wheel on PyPI.
# A hallucination is only CRITICAL once every declared distribution has a
# complete compatible inventory. Unknown/private providers leave uncertainty.
# ---------------------------------------------------------------------------


def _environment_providers(ctx):
    providers = ctx["environment_providers"]
    if providers is None:
        providers = {}
        for module, dists in ctx["installed_mapping"].items():
            for dist in dists:
                providers.setdefault(dist, set()).add(module)
        ctx["environment_providers"] = providers
    return providers


def _dist_key(dist, ctx):
    return dist, ctx["declared_specs"].get(dist)


def _requirement_is_exact(specifier):
    try:
        constraints = SpecifierSet(specifier)
        pinned = [
            constraint
            for constraint in constraints
            if constraint.operator in ("==", "===") and "*" not in constraint.version
        ]
        return bool(pinned) and constraints.contains(
            Version(pinned[0].version), prereleases=True
        )
    except (TypeError, InvalidSpecifier, InvalidVersion):
        return False


def _installed_record_is_incomplete(directory, dist_info, file_names):
    # Editable RECORDs list loader machinery rather than all source modules.
    # Inspect metadata only; never execute the loader or follow its source URL.
    if any(
        PurePosixPath(name).name.startswith("__editable__")
        or (len(PurePosixPath(name).parts) == 1 and name.endswith(".pth"))
        for name in file_names
    ):
        return True
    direct_url = read_project_text_no_symlink(
        directory,
        dist_info / "direct_url.json",
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if direct_url is None:
        return f"{dist_info.name}/direct_url.json" in file_names
    try:
        metadata = json.loads(direct_url)
    except (ValueError, RecursionError):
        return True
    if not isinstance(metadata, dict):
        return True
    dir_info = metadata.get("dir_info")
    if dir_info is None:
        return False
    if not isinstance(dir_info, dict):
        return True
    editable = dir_info.get("editable", False)
    return editable is not False


def _installed_provider_inventory(dist, ctx):
    key = _dist_key(dist, ctx)
    if key in ctx["environment_inventories"]:
        return ctx["environment_inventories"][key]
    ctx["environment_inventories"][key] = None
    specifier = key[1]
    if specifier is None:
        return None
    directories = virtual_env_site_packages()
    try:
        directories.extend(site.getsitepackages())
        user_site = site.getusersitepackages()
        if isinstance(user_site, str):
            directories.append(user_site)
    except (AttributeError, OSError):
        pass
    for directory in dict.fromkeys(directories):
        try:
            candidates = Path(directory).glob("*.dist-info")
            for index, dist_info in enumerate(candidates):
                if index >= MAX_PYTHON_LAYOUT_CANDIDATES:
                    break
                distribution_name = dist_info.name.removesuffix(".dist-info").rsplit(
                    "-", 1
                )[0]
                if _normalize_name(distribution_name) != dist:
                    continue
                metadata = read_project_text_no_symlink(
                    directory,
                    dist_info / "METADATA",
                    max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                    encoding="utf-8",
                )
                if metadata is None:
                    continue
                fields = {}
                for line in metadata.splitlines():
                    if not line:
                        break
                    name, separator, value = line.partition(":")
                    if separator and name in ("Name", "Version"):
                        fields[name] = value.strip()
                if _normalize_name(fields.get("Name")) != dist:
                    continue
                try:
                    version = Version(fields.get("Version", ""))
                    if not SpecifierSet(specifier).contains(version, prereleases=True):
                        continue
                except (InvalidVersion, InvalidSpecifier):
                    continue
                record = read_project_text_no_symlink(
                    directory,
                    dist_info / "RECORD",
                    max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                    encoding="utf-8",
                )
                if record is None:
                    continue
                try:
                    file_names = [
                        row[0] for row in csv.reader(io.StringIO(record)) if row
                    ]
                except csv.Error:
                    continue
                inventory = pypi_wheel_modules.module_inventory(file_names)
                inventory["version"] = str(version)
                inventory["complete_for_requirement"] = _requirement_is_exact(
                    specifier
                ) and not _installed_record_is_incomplete(
                    directory, dist_info, file_names
                )
                ctx["environment_inventories"][key] = inventory
                return inventory
        except OSError:
            continue
    return None


def _verified_provider_inventory(dist, ctx):
    installed = _installed_provider_inventory(dist, ctx)
    if installed is not None and installed.get("complete_for_requirement") is True:
        return installed
    wheel = ctx["dist_modules"].get(_dist_key(dist, ctx))
    if not isinstance(wheel, dict) or "module_paths" not in wheel:
        return installed
    if installed is None:
        return wheel

    # Positive wheel evidence can supplement a partial installed inventory.
    # It cannot establish absence in an editable checkout, which may differ
    # from the published wheel even when both report the same version.
    inventory = dict(wheel)
    inventory["complete_for_requirement"] = False
    installed_version, wheel_version = installed.get("version"), wheel.get("version")
    installed_paths = set(installed["module_paths"])
    if installed_version and wheel_version:
        try:
            same_version = Version(installed_version) == Version(wheel_version)
        except (TypeError, InvalidVersion):
            same_version = False
        if not same_version:
            # A different release must independently cover the installed
            # paths and their shapes, including concrete from-import bases.
            # Never combine disjoint releases or invalidate earlier checks.
            for field in (
                "module_paths",
                "concrete_module_paths",
                "plain_module_paths",
                "package_paths",
            ):
                provider_paths = {
                    path
                    for path in installed.get(field, ())
                    if not path.split(".", 1)[0].startswith("__editable__")
                }
                if not provider_paths <= set(wheel.get(field, ())):
                    return installed

    installed_plain = set(installed.get("plain_module_paths", ()))
    installed_packages = set(installed.get("package_paths", ()))
    installed_parents = {
        ".".join(path.split(".")[:index])
        for path in installed_paths
        for index in range(1, len(path.split(".")))
    }
    blocked = {
        path
        for path in wheel["module_paths"]
        if any(
            ".".join(path.split(".")[:index]) in installed_plain
            for index in range(1, len(path.split(".")))
        )
    }
    # A published wheel may differ from an editable checkout. Supplement its
    # paths without replacing the module/package layout actually installed.
    conflicting_plain = set(wheel.get("plain_module_paths", ())) & (
        installed_packages | installed_parents
    )
    for field, excluded in (
        ("module_paths", blocked),
        ("concrete_module_paths", blocked | conflicting_plain | installed_plain),
        ("plain_module_paths", blocked | conflicting_plain),
        ("package_paths", blocked | installed_plain),
    ):
        inventory[field] = sorted(
            set(installed.get(field, ())) | (set(wheel.get(field, ())) - excluded)
        )
    inventory["modules"] = sorted(
        {path.split(".", 1)[0] for path in inventory["module_paths"]}
    )
    namespace_paths = set(inventory["module_paths"]) - set(
        inventory["concrete_module_paths"]
    )
    inventory["namespace_paths"] = sorted(namespace_paths)
    inventory["namespace_roots"] = sorted(
        path for path in namespace_paths if "." not in path
    )
    return inventory


def _provider_absence_proved(dist, ctx):
    inventory = _verified_provider_inventory(dist, ctx)
    return inventory is not None and inventory.get("complete_for_requirement") is True


def _known_provider_paths(ctx):
    paths, concrete, plain, packages = set(), set(), set(), set()
    for dist in set(ctx["declared_deps"]) - ctx["project_names"]:
        specifier = ctx["declared_specs"].get(dist)
        # Root metadata is positive evidence for a bare root import only.
        # It neither proves a pinned version nor completeness/namespace paths.
        if specifier == "":
            paths.update(_environment_providers(ctx).get(dist, ()))
        inventory = _verified_provider_inventory(dist, ctx)
        if inventory is not None:
            paths.update(inventory["module_paths"])
            concrete.update(inventory.get("concrete_module_paths", ()))
            plain.update(inventory.get("plain_module_paths", ()))
            packages.update(inventory.get("package_paths", ()))
    return paths, concrete, plain, packages


def _paths_covered(mod, required_paths, from_imports, ctx):
    paths, concrete, plain, _packages = _known_provider_paths(ctx)
    for path in set(required_paths or (mod,)) | {base for base, _names in from_imports}:
        if any(
            ".".join(path.split(".")[:index]) in plain
            for index in range(1, len(path.split(".")))
        ):
            return False
    if not set(required_paths or (mod,)) <= paths:
        return False
    for base, names in from_imports:
        if base not in paths:
            return False
        if base not in concrete and any(
            name != "*" and f"{base}.{name}" not in paths for name in names
        ):
            return False
    return True


def _fetch_dist_modules(dist, *, specifier=""):
    try:
        return pypi_wheel_modules.fetch_distribution_modules(dist, specifier=specifier)
    except pypi_wheel_modules.LookupUnavailable as exc:
        logger.debug("Could not read the modules of %s from PyPI: %s", dist, exc)
        return None


def _lookup_dist_modules(dists, ctx):
    """Read bounded per-analysis inventories; never trust repository caches."""
    if ctx["dist_lookups_failed"]:
        return
    pending = [
        _dist_key(dist, ctx)
        for dist in dists
        if _dist_key(dist, ctx) not in ctx["dist_modules"]
        and ctx["declared_specs"].get(dist) is not None
    ]
    pending = pending[: max(0, MAX_DIST_MODULE_LOOKUPS - ctx["dist_lookups"])]
    if not pending:
        return
    workers = min(len(pending), DIST_MODULE_LOOKUP_WORKERS)

    def fetch(key):
        dist, specifier = key
        return _fetch_dist_modules(dist, specifier=specifier)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for offset in range(0, len(pending), workers):
            batch = pending[offset : offset + workers]
            ctx["dist_lookups"] += len(batch)
            results = list(pool.map(fetch, batch))
            for key, result in zip(batch, results):
                if result is None:
                    ctx["dist_lookups_failed"] = True
                ctx["dist_modules"][key] = result
            if ctx["dist_lookups_failed"]:
                break


def _name_tokens(name):
    return [token for token in re.split(r"[^a-z0-9]+", name.lower()) if token]


def _name_affinity(module, dist):
    """How strongly the names suggest ``dist`` ships ``module``.

    Only orders and narrows the lookups; whether a distribution provides the
    module is always decided by its real file list.
    """
    module_tokens = _name_tokens(module)
    dist_tokens = _name_tokens(dist)
    if module_tokens and set(module_tokens) <= set(dist_tokens):
        return 2
    module_compact = "".join(module_tokens)
    dist_compact = "".join(dist_tokens)
    for token in dist_tokens:
        if len(token) >= MIN_NAME_AFFINITY_TOKEN and token in module_compact:
            return 1
    for token in module_tokens:
        if len(token) >= MIN_NAME_AFFINITY_TOKEN and token in dist_compact:
            return 1
    return 0


def _declared_provider(mod, ctx, *, exhaustive, required_paths=(), from_imports=()):
    """Return coverage plus every distribution whose inventory is unknown."""
    if _paths_covered(mod, required_paths, from_imports, ctx):
        return True, []
    candidates = sorted(set(ctx["declared_deps"]) - ctx["project_names"])
    unknown = [dist for dist in candidates if not _provider_absence_proved(dist, ctx)]
    likely = sorted(
        (dist for dist in unknown if _name_affinity(mod, dist)),
        key=lambda dist: (-_name_affinity(mod, dist), dist),
    )
    rounds = [likely]
    if exhaustive:
        rounds.append([dist for dist in unknown if dist not in likely])
    for batch in rounds:
        _lookup_dist_modules(batch, ctx)
        if _paths_covered(mod, required_paths, from_imports, ctx):
            return True, []
    unchecked = [dist for dist in unknown if not _provider_absence_proved(dist, ctx)]
    return False, unchecked


def _check_declared_providers(
    mod, template, ctx, *, required_paths=(), from_imports=()
):
    hallucination = template["rule_id"] == RULE_ID_HALLUCINATION
    covered, unchecked = _declared_provider(
        mod,
        ctx,
        exhaustive=hallucination,
        required_paths=required_paths,
        from_imports=from_imports,
    )
    if covered:
        return None
    _paths, _concrete, plain, packages = _known_provider_paths(ctx)
    ambiguous = plain & packages
    if any(
        path == prefix or path.startswith(prefix + ".")
        for prefix in ambiguous
        for path in set(required_paths or (mod,))
        | {base for base, _names in from_imports}
    ):
        return _undeclared_template(
            mod,
            f"Unverified import '{mod}'. Declared distributions provide overlapping module and package paths, so the effective import cannot be established safely.",
        )
    if unchecked and ctx["dist_lookups_failed"]:
        ctx["registry_unreachable"] = True
    # Distribution naming, partial installed metadata and source-only/private
    # declarations cannot disprove an arbitrary module alias.
    if unchecked or ctx["provider_unknown"]:
        return _unverified_template(mod, unchecked, registry_missing=hallucination)
    return template


def _namespace_distribution(mod, submodules, ctx):
    """A PyPI project that ships ``mod.<sub>`` as a namespace package.

    PEP 420 namespace packages are published per portion, e.g.
    ``sphinxcontrib.serializinghtml`` as sphinxcontrib-serializinghtml, so
    the namespace root itself is usually not a PyPI project.
    """
    for sub in sorted(submodules)[:MAX_NAMESPACE_PROBES]:
        dist = f"{mod}-{sub}"
        if _tracked_pypi_status(dist, ctx) == "exists":
            return dist
    return None


def _imported_submodules(src, mod):
    submodules = set()
    for pattern in (IMPORT_RE, FROM_RE):
        for match in pattern.finditer(src or ""):
            root, _, rest = match.group(1).partition(".")
            if root == mod and rest:
                submodules.add(rest.split(".")[0])
    return frozenset(submodules)


def _import_module_requirements(src, mod):
    """Paths imports require, without guessing whether imported names are classes."""
    try:
        tree = ast.parse(src or "")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return frozenset({mod}), ()
    paths = set()
    from_imports = []
    optional_paths = _optional_import_paths(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == mod and alias.name not in optional_paths:
                    paths.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            if node.module.split(".")[0] == mod and node.module not in optional_paths:
                paths.add(node.module)
                from_imports.append(
                    (node.module, tuple(alias.name for alias in node.names))
                )
    return frozenset(paths or {mod}), tuple(from_imports)


def _undeclared_template(mod, message):
    return {
        "rule_id": RULE_ID_UNDECLARED,
        "severity": SEV_MEDIUM,
        "message": message,
        "col": 0,
        "symbol": mod,
    }


def _unverified_template(mod, unchecked, *, registry_missing=True):
    if not unchecked:
        return _undeclared_template(
            mod,
            f"Unverified import '{mod}'. Dynamic or unsupported dependency declarations prevent establishing which import paths they provide.",
        )
    names = ", ".join(f"'{dist}'" for dist in unchecked[:3])
    if len(unchecked) > 3:
        names += f" and {len(unchecked) - 3} more"
    noun = "dependency" if len(unchecked) == 1 else "dependencies"
    return _undeclared_template(
        mod,
        (
            f"Unverified import '{mod}'. "
            + ("No PyPI project has this name, and " if registry_missing else "")
            + f"the declared {noun} {names} could not be checked for this import path, so it is not confirmed as an undeclared or hallucinated dependency."
        ),
    )


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


def _classify_import(
    mod,
    ctx,
    file_path=None,
    *,
    diff_path=False,
    direct_script=False,
    local_fallbacks=frozenset(),
    submodules=frozenset(),
    optional_imports=frozenset(),
    uncertain_imports=frozenset(),
    required_paths=(),
    from_imports=(),
):
    """Return a finding template (without file/line) for an import root, or None."""
    if (
        mod
        and mod not in ctx["stdlib"]
        and _paths_covered(mod, required_paths, from_imports, ctx)
    ):
        return None
    root_only = set(required_paths or (mod,)) <= {mod} and not from_imports
    template = _classify_import_names(
        mod,
        ctx,
        file_path,
        diff_path=diff_path,
        direct_script=direct_script,
        local_fallbacks=local_fallbacks,
        submodules=submodules,
        root_only=root_only,
    )
    if template is None:
        return None
    if template["rule_id"] == RULE_ID_HALLUCINATION and mod in optional_imports:
        return None
    if mod in uncertain_imports:
        return _undeclared_template(
            mod,
            f"Unverified import '{mod}'. ImportError is handled, but the fallback cannot be proven to complete safely; this is not confirmed as a required hallucinated dependency.",
        )
    return _check_declared_providers(
        mod, template, ctx, required_paths=required_paths, from_imports=from_imports
    )


def _classify_import_names(
    mod,
    ctx,
    file_path,
    *,
    diff_path,
    direct_script,
    local_fallbacks,
    submodules,
    root_only,
):
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
        or mod in local_fallbacks
    ):
        return None

    if local_scope_valid and _is_ros_import(mod, ctx, importer):
        return None

    declared_deps = ctx["declared_deps"]
    manifest_context = ctx["manifest_context"]

    installed_result = _classify_installed_import(mod, ctx, root_only=root_only)
    if installed_result is not _NO_FINDING:
        return installed_result

    normalized_mod = _normalize_name(mod)

    if root_only and normalized_mod in declared_deps:
        return None

    if normalized_mod in ctx["private_allow"]:
        return None

    mapped_result = _classify_mapped_import(mod, ctx, root_only=root_only)
    if mapped_result is not _NO_FINDING:
        return mapped_result

    ros_launch = (
        mod == "launch"
        and importer is not None
        and importer.name.endswith(".launch.py")
        and any(parent in ctx["ros_package_deps"] for parent in importer.parents)
    )
    if mod in ROS_PYTHON_IMPORT_ROOTS or ros_launch:
        # These are known ROS modules, so a missing PyPI project is not proof
        # of hallucination. A manifest must actually declare the imported
        # package; an unrelated ROS package elsewhere in a monorepo cannot.
        if manifest_context or ctx["ros_package_deps"]:
            return _undeclared_template(
                mod,
                f"Undeclared ROS import '{mod}' in package.xml or Python manifest.",
            )
        return None

    return _classify_registry_import(mod, ctx, manifest_context, submodules)


_NO_FINDING = object()


def _classify_installed_import(mod, ctx, *, root_only=True):
    if mod not in ctx["installed_mapping"]:
        return _NO_FINDING

    known_dists = ctx["installed_mapping"][mod]
    if known_dists & ctx["declared_deps"]:
        bare_provider = any(
            ctx["declared_specs"].get(dist) == ""
            for dist in known_dists & ctx["declared_deps"]
        )
        return None if root_only and bare_provider else _NO_FINDING

    if not ctx["manifest_context"]:
        return None

    dist_hint = ", ".join(sorted(known_dists))
    return _undeclared_template(
        mod,
        f"Undeclared import '{mod}' (provided by: {dist_hint}). Add to requirements.txt/pyproject.toml/setup.py.",
    )


def _classify_mapped_import(mod, ctx, *, root_only=True):
    if mod in ctx["import_to_dist"]:
        mapped_dist = ctx["import_to_dist"][mod]

        if _normalize_name(mapped_dist) in ctx["declared_deps"]:
            return (
                None
                if root_only
                and ctx["declared_specs"].get(_normalize_name(mapped_dist)) == ""
                else _NO_FINDING
            )

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


def _classify_registry_import(mod, ctx, manifest_context, submodules=frozenset()):
    pypi_status = _tracked_pypi_status(mod, ctx)

    if pypi_status == "missing":
        namespace_dist = _namespace_distribution(mod, submodules, ctx)
        if namespace_dist is not None:
            if not manifest_context:
                return None
            # Only a hint: the name exists, but nothing proves it is the
            # package the code meant, so it is not recommended outright.
            return _undeclared_template(
                mod,
                (
                    f"Undeclared import '{mod}'. No PyPI project has this "
                    f"name; namespace package '{namespace_dist}' does. Verify "
                    f"it is the intended package before declaring it."
                ),
            )

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


_SYS_PATH_EDIT_RE = re.compile(
    r"\bsys\.path\.(?:insert|append|extend)\s*\(|\bsys\.path\s*(?:\+=|=)|\bsite\.addsitedir\s*\("
)


def _repository_module_inventory(root, py_files):
    """Module names defined anywhere in the analyzed files, and root-level
    directories that hold Python files (implicit namespace packages such as
    ``examples/``). Built from the analyzer's own file list; nothing is walked."""
    modules = set()
    namespace_roots = set()
    for file_path in py_files:
        relative = _contained_importer_path(root, file_path)
        if relative is None:
            continue
        parts = relative.parts
        if relative.name != "__init__.py" and relative.stem.isidentifier():
            modules.add(relative.stem)
        for directory in parts[:-1]:
            if directory.isidentifier():
                modules.add(directory)
        if len(parts) > 1 and parts[0].isidentifier():
            namespace_roots.add(parts[0])
    return modules, namespace_roots


def _is_repository_module_import(template, mod, ctx, src):
    """A local module reached through ``sys.path`` edits, a test runner's
    rootdir or a namespace package is not a dependency."""
    if mod not in ctx.get("repo_modules", ()):
        return False
    if template.get("rule_id") == RULE_ID_HALLUCINATION:
        # "Does not exist on PyPI" but a module of that name exists here.
        return True
    return bool(_SYS_PATH_EDIT_RE.search(src))


def scan_python_dependency_hallucinations(repo_root, py_files):
    findings = []

    if repo_root is None:
        return findings

    root = Path(os.path.abspath(repo_root))
    py_files = list(py_files)
    ctx = _build_dependency_context(root, py_files)
    repo_modules, namespace_roots = _repository_module_inventory(root, py_files)
    ctx["repo_modules"] = repo_modules
    ctx["local_modules"] = set(ctx["local_modules"]) | namespace_roots
    scope_cache = {root: (frozenset(ctx["declared_deps"]), ctx["manifest_context"])}
    provider_scope_cache = {
        root: (ctx["declared_specs"], ctx["project_names"], ctx["provider_unknown"])
    }

    for file_path in py_files:
        declared_deps, manifest_context = _dependency_scope_for_file(
            root, file_path, scope_cache
        )
        specs, own_names, unknown = _provider_scope_for_file(
            root, file_path, provider_scope_cache
        )
        ctx["declared_specs"] = specs
        ctx["project_names"] = own_names
        ctx["provider_unknown"] = unknown
        ctx["declared_deps"] = declared_deps | specs.keys()
        ctx["manifest_context"] = manifest_context
        src = read_project_text_no_symlink(
            root,
            file_path,
            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if src is None:
            continue

        direct_script = _has_direct_script_evidence(src)
        importer = _contained_importer_path(root, file_path)
        local_fallbacks = _local_import_fallbacks(src, ctx, importer)
        optional_imports = _optional_import_roots(src)
        uncertain_imports = (
            _optional_import_roots(src, allow_uncertain=True) - optional_imports
        )
        for mod in sorted(_extract_imports(src)):
            required_paths, from_imports = _import_module_requirements(src, mod)
            template = _classify_import(
                mod,
                ctx,
                file_path,
                direct_script=direct_script,
                local_fallbacks=local_fallbacks,
                submodules=_imported_submodules(src, mod),
                optional_imports=optional_imports,
                uncertain_imports=uncertain_imports,
                required_paths=required_paths,
                from_imports=from_imports,
            )
            if template is None:
                continue
            if _is_repository_module_import(template, mod, ctx, src):
                continue

            finding = dict(template)
            finding["file"] = str(file_path)
            finding["line"] = _find_import_line(src, mod)
            findings.append(finding)

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
    provider_scope_cache = {
        root: (ctx["declared_specs"], ctx["project_names"], ctx["provider_unknown"])
    }

    seen = set()
    direct_script_cache = {}
    local_fallback_cache = {}
    source_cache = {}
    optional_cache = {}
    uncertain_cache = {}
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
        specs, own_names, unknown = _provider_scope_for_file(
            root, file_label, provider_scope_cache
        )
        ctx["declared_specs"] = specs
        ctx["project_names"] = own_names
        ctx["provider_unknown"] = unknown
        ctx["declared_deps"] = declared_deps | specs.keys()
        ctx["manifest_context"] = manifest_context

        script_key = str(file_label)
        if script_key not in direct_script_cache:
            direct_script_cache[script_key] = _diff_file_has_direct_script_evidence(
                root, file_label
            )
        if script_key not in local_fallback_cache:
            importer = _contained_importer_path(root, file_label, diff_path=True)
            source = read_project_text_no_symlink(
                root,
                file_label,
                max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                encoding="utf-8",
                errors="ignore",
            )
            source_cache[script_key] = source
            optional_cache[script_key] = _optional_import_roots(source)
            uncertain_cache[script_key] = (
                _optional_import_roots(source, allow_uncertain=True)
                - optional_cache[script_key]
            )
            local_fallback_cache[script_key] = (
                _local_import_fallbacks(source, ctx, importer)
                if source is not None
                else frozenset()
            )
        required_paths, from_imports = _import_module_requirements(
            source_cache[script_key], mod
        )
        if "." in str(module_name):
            required_paths |= frozenset({str(module_name)})
        template = _classify_import(
            mod,
            ctx,
            file_label,
            diff_path=True,
            direct_script=direct_script_cache[script_key],
            local_fallbacks=local_fallback_cache[script_key],
            submodules=_imported_submodules(source_cache[script_key], mod)
            | _imported_submodules(f"import {module_name}", mod),
            optional_imports=optional_cache[script_key],
            uncertain_imports=uncertain_cache[script_key],
            required_paths=required_paths,
            from_imports=from_imports,
        )
        if template is None:
            continue

        finding = dict(template)
        finding["file"] = str(file_label)
        finding["line"] = int(line_no)
        findings.append(finding)

    return findings, ctx["registry_unreachable"]
