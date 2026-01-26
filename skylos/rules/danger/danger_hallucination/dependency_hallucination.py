from __future__ import annotations

import os
import re


RULE_ID_HALLUCINATION = "SKY-D212"
RULE_ID_UNDECLARED = "SKY-D213"

SEV_CRITICAL = "CRITICAL"
SEV_MEDIUM = "MEDIUM"

try:
    from importlib.metadata import packages_distributions

    IMPORT_TO_PACKAGES = packages_distributions()
except ImportError:
    IMPORT_TO_PACKAGES = {}


def _get_possible_packages(import_name):
    result = {import_name, _normalize_name(import_name)}
    for pkg in IMPORT_TO_PACKAGES.get(import_name, []):
        result.add(_normalize_name(pkg))
    return result


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

    req_path = repo_root / "requirements.txt"
    if req_path.exists():
        deps |= _parse_requirements_txt(req_path)

    pyproj_path = repo_root / "pyproject.toml"
    if pyproj_path.exists():
        deps |= _parse_pyproject_toml(pyproj_path)

    setup_path = repo_root / "setup.py"
    if setup_path.exists():
        deps |= _parse_setup_py(setup_path)

    req_dir = repo_root / "requirements"
    if req_dir.exists() and req_dir.is_dir():
        for req_file in req_dir.glob("*.txt"):
            deps |= _parse_requirements_txt(req_file)

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


def scan_python_dependency_hallucinations(repo_root, py_files):
    findings = []

    if repo_root is None:
        return findings

    stdlib = _get_stdlib_modules()
    local_modules = _collect_local_modules(repo_root)
    declared_deps = _collect_declared_deps(repo_root)
    private_allow = _load_private_allowlist()

    cache_path = repo_root / ".skylos" / "cache" / "pypi_exists.json"

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

            possible_packages = _get_possible_packages(mod)

            if possible_packages & declared_deps:
                continue

            normalized_mod = _normalize_name(mod)

            if normalized_mod in declared_deps:
                continue

            if normalized_mod in private_allow:
                continue

            line = _find_import_line(src, mod)

            findings.append(
                {
                    "rule_id": RULE_ID_UNDECLARED,
                    "severity": SEV_MEDIUM,
                    "message": f"Undeclared import '{mod}'. Not found in requirements.txt/pyproject.toml/setup.py.",
                    "file": str(file_path),
                    "line": line,
                    "col": 0,
                }
            )

    return findings
