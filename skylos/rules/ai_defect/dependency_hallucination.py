from __future__ import annotations

import logging
import os
import re
import site
import sys
import urllib.request
import urllib.error
from pathlib import Path

from skylos.core.safe_cache_io import (
    load_project_json_cache,
    read_text_no_symlink,
    save_project_json_cache,
)

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

            if p.is_file():
                if p.suffix == ".py":
                    local.add(p.stem)
                continue

            if p.is_dir():
                init_file = p / "__init__.py"
                if init_file.exists():
                    local.add(p.name)

    except OSError as exc:
        logger.debug("Failed to collect local modules from %s: %s", repo_root, exc)

    return local


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


def _extract_toml_array(txt, key):
    pattern = re.compile(r"(?m)^\s*" + re.escape(key) + r"\s*=\s*\[")
    match = pattern.search(txt)
    if not match:
        return None

    start = match.end()
    depth = 1
    pos = start
    while pos < len(txt) and depth > 0:
        ch = txt[pos]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == '"':
            pos += 1
            while pos < len(txt) and txt[pos] != '"':
                if txt[pos] == "\\":
                    pos += 1
                pos += 1
        elif ch == "'":
            pos += 1
            while pos < len(txt) and txt[pos] != "'":
                if txt[pos] == "\\":
                    pos += 1
                pos += 1
        pos += 1

    if depth != 0:
        return None

    return txt[start : pos - 1]


def _parse_pyproject_toml(path):
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

    name_match = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', txt)
    if name_match:
        project_name = name_match.group(1)

    for key in ("dependencies",):
        block = _extract_toml_array(txt, key)
        if block is None:
            continue
        raw_items = re.findall(r'"([^"]+)"', block)
        raw_items += re.findall(r"'([^']+)'", block)

        for item in raw_items:
            item = item.strip()
            m = REQ_LINE_RE.match(item)
            if not m:
                continue

            deps.add(_normalize_name(m.group(1)))

    for section_re in (
        r"\[project\.optional-dependencies\]",
        r"\[tool\.poetry\.extras\]",
    ):
        section_match = re.search(section_re, txt)
        if not section_match:
            continue
        rest = txt[section_match.end() :]
        next_section = re.search(r"(?m)^\s*\[", rest)

        if next_section:
            section_body = rest[: next_section.start()]
        else:
            section_body = rest

        for arr_match in re.finditer(r"(\w+)\s*=\s*\[", section_body):
            arr_key = arr_match.group(1)
            block = _extract_toml_array(section_body, arr_key)
            if block is None:
                continue

            raw_items = re.findall(r'"([^"]+)"', block)
            raw_items += re.findall(r"'([^']+)'", block)
            for item in raw_items:
                item = item.strip()
                m = REQ_LINE_RE.match(item)
                if m:
                    deps.add(_normalize_name(m.group(1)))

    in_poetry = False

    for raw_line in txt.splitlines():
        line = raw_line.strip()

        if line.startswith("[") and line.endswith("]"):
            if line == "[tool.poetry.dependencies]":
                in_poetry = True
            else:
                in_poetry = False
            continue

        if not in_poetry:
            continue

        if not line:
            continue

        if line.startswith("#"):
            continue

        key = line.split("=", 1)[0].strip()
        if not key:
            continue

        if key == "python":
            continue

        deps.add(_normalize_name(key))

    if not project_name:
        poetry_name = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', txt)
        if poetry_name:
            project_name = poetry_name.group(1)

    return deps, project_name


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


def _build_dependency_context(repo_root):
    declared_deps = _collect_declared_deps(repo_root)
    cache_path = repo_root / ".skylos" / "cache" / "pypi_exists.json"
    return {
        "stdlib": _get_stdlib_modules(),
        "local_modules": _collect_local_modules(repo_root),
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
            f"Hallucinated dependency '{mod}'. "
            f"Package does not exist on PyPI."
        ),
        "col": 0,
        "symbol": mod,
        "category": "ai_defect",
        "defect_type": "dependency_hallucination",
        "vibe_category": "dependency_hallucination",
        "ai_likelihood": "high",
    }


def _classify_import(mod, ctx):
    """Return a finding template (without file/line) for an import root, or None."""
    if not mod or mod.startswith("_"):
        return None

    if mod in ctx["stdlib"] or mod in ctx["local_modules"]:
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

    ctx = _build_dependency_context(repo_root)

    for file_path in py_files:
        try:
            src = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for mod in sorted(_extract_imports(src)):
            template = _classify_import(mod, ctx)
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
    """Classify import roots added by a diff without reading files from disk.

    added_imports: iterable of (file_label, line_no, module_name) tuples.
    extra_local_modules: module roots created by the same diff, treated as
    local so brand-new project modules are not reported as hallucinated.
    Returns (findings, registry_unreachable).
    """
    findings = []

    if repo_root is None:
        return findings, False

    root = Path(repo_root)
    ctx = _build_dependency_context(root)
    if extra_local_modules:
        ctx["local_modules"] = set(ctx["local_modules"]) | set(extra_local_modules)
    if extra_declared_deps:
        ctx["declared_deps"] = set(ctx["declared_deps"]) | {
            _normalize_name(dep) for dep in extra_declared_deps if _normalize_name(dep)
        }
        ctx["manifest_context"] = True

    seen = set()
    for file_label, line_no, module_name in added_imports:
        mod = str(module_name).split(".")[0].strip()
        if (file_label, mod) in seen:
            continue
        seen.add((file_label, mod))

        template = _classify_import(mod, ctx)
        if template is None:
            continue

        finding = dict(template)
        finding["file"] = str(file_label)
        finding["line"] = int(line_no)
        findings.append(finding)

    if ctx["cache_modified"]:
        _save_pypi_cache(root, ctx["cache_path"], ctx["pypi_cache"])

    return findings, ctx["registry_unreachable"]
