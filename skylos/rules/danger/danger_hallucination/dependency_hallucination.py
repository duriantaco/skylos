from __future__ import annotations

import json
import os
import re
import site
import urllib.request
import urllib.error
from pathlib import Path


RULE_ID_HALLUCINATION = "SKY-D222"
RULE_ID_UNDECLARED = "SKY-D223"

SEV_CRITICAL = "CRITICAL"
SEV_MEDIUM = "MEDIUM"

IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z_][\w\.]*)", re.MULTILINE)
FROM_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w\.]*)\s+import\b", re.MULTILINE)

REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")


def _normalize_name(name):
    if name is None:
        return ""

    cleaned = str(name).strip()
    cleaned = cleaned.lower()
    cleaned = re.sub(r"[-_.]+", "-", cleaned)
    return cleaned


def _get_stdlib_modules():
    try:
        import sys

        std = getattr(sys, "stdlib_module_names", None)
        if std:
            return set(std)
    except Exception:
        pass

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
    except ImportError:
        pass
    except Exception:
        pass

    site_packages_dirs = []

    try:
        site_packages_dirs.extend(site.getsitepackages())
    except Exception:
        pass

    try:
        user_site = site.getusersitepackages()
        if user_site:
            site_packages_dirs.append(user_site)
    except Exception:
        pass

    try:
        import sys

        if hasattr(sys, "prefix") and sys.prefix != sys.base_prefix:
            venv_site = Path(sys.prefix) / "lib"
            for pydir in venv_site.glob("python*/site-packages"):
                site_packages_dirs.append(str(pydir))
    except Exception:
        pass

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
                except Exception:
                    pass

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
                except Exception:
                    pass
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
                except Exception:
                    pass

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

    except Exception:
        pass

    return local


def _parse_requirements_txt(path):
    deps = set()

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return deps

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


def _parse_pyproject_toml(path):
    deps = set()

    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return deps

    dep_blocks = re.finditer(r"(?m)^\s*dependencies\s*=\s*\[(.*?)\]", txt, re.DOTALL)
    for block_match in dep_blocks:
        block = block_match.group(1)
        raw_items = re.findall(r'"([^"]+)"', block)

        for item in raw_items:
            item = item.strip()
            m = REQ_LINE_RE.match(item)
            if not m:
                continue

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

    return deps


def _parse_setup_py(path):
    deps = set()

    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return deps

    match = re.search(r"install_requires\s*=\s*\[(.*?)\]", txt, re.DOTALL)
    if match:
        block = match.group(1)
        raw_items = re.findall(r"['\"]([^'\"]+)['\"]", block)
        for item in raw_items:
            m = REQ_LINE_RE.match(item.strip())
            if m:
                deps.add(_normalize_name(m.group(1)))

    return deps


def _collect_declared_deps(repo_root):
    deps = set()

    current = repo_root
    for _ in range(5):
        req_path = current / "requirements.txt"
        if req_path.exists():
            deps |= _parse_requirements_txt(req_path)

        pyproj_path = current / "pyproject.toml"
        if pyproj_path.exists():
            deps |= _parse_pyproject_toml(pyproj_path)

        setup_path = current / "setup.py"
        if setup_path.exists():
            deps |= _parse_setup_py(setup_path)

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

    return deps


def _find_import_line(src, mod):
    if not src:
        return 1

    try:
        lines = src.splitlines()
    except Exception:
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


def _load_pypi_cache(cache_path):
    cache = {}
    try:
        if cache_path.exists():
            txt = cache_path.read_text(encoding="utf-8")
            cache = json.loads(txt)
    except Exception:
        pass
    return cache


def _save_pypi_cache(cache_path, cache):
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception:
        pass


def _check_pypi_status(package_name, cache):
    normalized = _normalize_name(package_name)

    if normalized in cache:
        return cache[normalized]

    names_to_try = [normalized]
    if package_name and _normalize_name(package_name) != normalized:
        names_to_try.append(_normalize_name(package_name))
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

        except Exception:
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


def scan_python_dependency_hallucinations(repo_root, py_files):
    findings = []

    if repo_root is None:
        return findings

    stdlib = _get_stdlib_modules()
    local_modules = _collect_local_modules(repo_root)
    declared_deps = _collect_declared_deps(repo_root)
    private_allow = _load_private_allowlist()

    installed_mapping = _build_installed_module_mapping()
    has_env_metadata = len(installed_mapping) > 0

    cache_path = repo_root / ".skylos" / "cache" / "pypi_exists.json"
    pypi_cache = _load_pypi_cache(cache_path)
    cache_modified = False

    for file_path in py_files:
        try:
            src = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        imported = _extract_imports(src)

        for mod in sorted(imported):
            if not mod:
                continue

            if mod.startswith("_"):
                continue

            if mod in stdlib:
                continue

            if mod in local_modules:
                continue

            if mod in installed_mapping:
                known_dists = installed_mapping[mod]
                if known_dists & declared_deps:
                    continue

                line = _find_import_line(src, mod)
                dist_hint = ", ".join(sorted(known_dists))
                findings.append(
                    {
                        "rule_id": RULE_ID_UNDECLARED,
                        "severity": SEV_MEDIUM,
                        "message": f"Undeclared import '{mod}' (provided by: {dist_hint}). Add to requirements.txt/pyproject.toml/setup.py.",
                        "file": str(file_path),
                        "line": line,
                        "col": 0,
                        "symbol": mod,
                    }
                )
                continue

            possible_packages = _get_possible_packages(mod, installed_mapping)

            if possible_packages & declared_deps:
                continue

            normalized_mod = _normalize_name(mod)

            if normalized_mod in declared_deps:
                continue

            if normalized_mod in private_allow:
                continue

            line = _find_import_line(src, mod)

            if has_env_metadata and _is_confident_hallucination_candidate(mod):
                original_cache_size = len(pypi_cache)
                exists_on_pypi = _check_pypi_status(mod, pypi_cache)
                if len(pypi_cache) != original_cache_size:
                    cache_modified = True

                if not exists_on_pypi:
                    findings.append(
                        {
                            "rule_id": RULE_ID_HALLUCINATION,
                            "severity": SEV_CRITICAL,
                            "message": f"Hallucinated dependency '{mod}'. Package does not exist on PyPI.",
                            "file": str(file_path),
                            "line": line,
                            "col": 0,
                            "symbol": mod,
                        }
                    )
                else:
                    findings.append(
                        {
                            "rule_id": RULE_ID_UNDECLARED,
                            "severity": SEV_MEDIUM,
                            "message": f"Undeclared import '{mod}'. Not found in requirements.txt/pyproject.toml/setup.py.",
                            "file": str(file_path),
                            "line": line,
                            "col": 0,
                            "symbol": mod,
                        }
                    )
            elif not has_env_metadata:
                original_cache_size = len(pypi_cache)
                exists_on_pypi = _check_pypi_status(mod, pypi_cache)
                if len(pypi_cache) != original_cache_size:
                    cache_modified = True

                if not exists_on_pypi and _is_confident_hallucination_candidate(mod):
                    findings.append(
                        {
                            "rule_id": RULE_ID_HALLUCINATION,
                            "severity": SEV_CRITICAL,
                            "message": f"Hallucinated dependency '{mod}'. Package does not exist on PyPI.",
                            "file": str(file_path),
                            "line": line,
                            "col": 0,
                            "symbol": mod,
                        }
                    )
                else:
                    findings.append(
                        {
                            "rule_id": RULE_ID_UNDECLARED,
                            "severity": SEV_MEDIUM,
                            "message": f"Undeclared import '{mod}'. Not found in requirements.txt/pyproject.toml/setup.py.",
                            "file": str(file_path),
                            "line": line,
                            "col": 0,
                            "symbol": mod,
                        }
                    )
            else:
                findings.append(
                    {
                        "rule_id": RULE_ID_UNDECLARED,
                        "severity": SEV_MEDIUM,
                        "message": f"Undeclared import '{mod}'. Not found in requirements.txt/pyproject.toml/setup.py (possible import/dist name mismatch).",
                        "file": str(file_path),
                        "line": line,
                        "col": 0,
                        "symbol": mod,
                    }
                )

    if cache_modified:
        _save_pypi_cache(cache_path, pypi_cache)

    return findings
