from __future__ import annotations
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_text_no_symlink

RULE_ID = "SKY-U005"
MAX_DEPENDENCY_MANIFEST_BYTES = 5_000_000

CLI_ONLY_PACKAGES = {
    "black",
    "ruff",
    "mypy",
    "pytest",
    "flake8",
    "pylint",
    "isort",
    "pre-commit",
    "tox",
    "nox",
    "coverage",
    "sphinx",
    "mkdocs",
    "twine",
    "build",
    "setuptools",
    "wheel",
    "pip",
    "pipx",
    "autopep8",
    "bandit",
    "pyflakes",
    "pycodestyle",
    "pydocstyle",
    "pytest-cov",
    "pytest-xdist",
    "pytest-mock",
    "pytest-asyncio",
}

RUNTIME_PLUGIN_PACKAGES = {
    "pytest-cov",
    "pytest-xdist",
    "pytest-mock",
    "pytest-asyncio",
    "pytest-django",
    "pytest-flask",
    "pytest-celery",
    "flask-cors",
    "flask-login",
    "flask-migrate",
    "flask-sqlalchemy",
    "django-cors-headers",
    "django-filter",
    "django-extensions",
    "celery",
    "gunicorn",
    "uvicorn",
}

IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)", re.MULTILINE)
FROM_RE = re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b", re.MULTILINE)
DYNAMIC_RE = re.compile(
    r"importlib\.import_module\s*\(\s*['\"]([A-Za-z_][\w.]*)['\"]", re.MULTILINE
)
REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")


def _normalize_name(name):
    if not name:
        return ""
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def _collect_all_imports(py_files):
    imports = set()
    has_dynamic = False

    for fp in py_files:
        try:
            src = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for m in IMPORT_RE.finditer(src):
            raw = m.group(1)
            if raw:
                imports.add(raw.split(".")[0])

        for m in FROM_RE.finditer(src):
            raw = m.group(1)
            if raw:
                imports.add(raw.split(".")[0])

        for m in DYNAMIC_RE.finditer(src):
            raw = m.group(1)
            if raw:
                imports.add(raw.split(".")[0])
                has_dynamic = True

    return imports, has_dynamic


def _build_import_to_dist():
    mapping = {}

    try:
        from importlib.metadata import packages_distributions

        pkg_dist = packages_distributions()
        for module, dists in pkg_dist.items():
            for d in dists:
                norm = _normalize_name(d)
                if module not in mapping:
                    mapping[module] = set()
                mapping[module].add(norm)
    except (ImportError, Exception):
        pass

    return mapping


def _parse_pyproject_toml(path):
    text = read_text_no_symlink(
        path,
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if text is None:
        return set(), None

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set(), None

    project = data.get("project")
    if not isinstance(project, dict):
        return set(), None

    project_name = project.get("name")
    if not isinstance(project_name, str):
        project_name = None

    deps = set()
    dependencies = project.get("dependencies")
    if isinstance(dependencies, list):
        for item in dependencies:
            if not isinstance(item, str):
                continue
            match = REQ_LINE_RE.match(item.strip())
            if match:
                deps.add(_normalize_name(match.group(1)))

    return deps, project_name


def _collect_declared_deps(repo_root):
    deps = set()
    project_name = None

    current = repo_root
    for _ in range(5):
        req_path = current / "requirements.txt"
        if req_path.exists():
            try:
                for line in req_path.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = REQ_LINE_RE.match(line)
                    if m:
                        deps.add(_normalize_name(m.group(1)))
            except Exception:
                pass

        pyproj_path = current / "pyproject.toml"
        if pyproj_path.exists():
            pyproject_deps, pyproject_name = _parse_pyproject_toml(pyproj_path)
            deps.update(pyproject_deps)
            if pyproject_name and not project_name:
                project_name = pyproject_name

        setup_path = current / "setup.py"
        if setup_path.exists():
            try:
                txt = setup_path.read_text(encoding="utf-8", errors="ignore")
                name_match = re.search(r"""name\s*=\s*['"]([^'"]+)['"]""", txt)
                if name_match and not project_name:
                    project_name = name_match.group(1)

                for key in ("install_requires", "setup_requires"):
                    pattern = re.compile(re.escape(key) + r"\s*=\s*\[")
                    km = pattern.search(txt)
                    if not km:
                        continue
                    start = km.end()
                    depth = 1
                    pos = start
                    while pos < len(txt) and depth > 0:
                        if txt[pos] == "[":
                            depth += 1
                        elif txt[pos] == "]":
                            depth -= 1
                        pos += 1
                    block = txt[start : pos - 1]
                    for item in re.findall(r'["\']([^"\']+)["\']', block):
                        rm = REQ_LINE_RE.match(item.strip())
                        if rm:
                            deps.add(_normalize_name(rm.group(1)))
            except Exception:
                pass

        req_dir = current / "requirements"
        if req_dir.exists() and req_dir.is_dir():
            for req_file in req_dir.glob("*.txt"):
                try:
                    for line in req_file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("-"):
                            continue
                        m = REQ_LINE_RE.match(line)
                        if m:
                            deps.add(_normalize_name(m.group(1)))
                except Exception:
                    pass

        if deps:
            break

        parent = current.parent
        if parent == current:
            break
        current = parent

    return deps, project_name


_MANIFEST_NAMES = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")


def _is_within(path, boundary):
    try:
        Path(path).resolve().relative_to(Path(boundary).resolve())
    except (OSError, ValueError):
        return False
    return True


def _declared_dependency_location(repo_root, dep, boundary=None):
    """Return (manifest_path, line) where ``dep`` is declared, or None.

    Uses the same walk-up as ``_collect_declared_deps`` so the location is the
    manifest the dependency was read from. The finding then points at a real
    file and line instead of the repository folder. Manifests outside
    ``boundary`` (the scanned project) are not used as a location: a path
    outside the project cannot be stored or shown as part of it.
    """
    token = re.compile(
        r"(?<![A-Za-z0-9_.-])" + r"[-_.]+".join(map(re.escape, re.split(r"[-_.]+", dep))) + r"(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )
    current = repo_root
    for _ in range(5):
        if boundary is not None and not _is_within(current, boundary):
            break
        for name in _MANIFEST_NAMES:
            manifest = current / name
            if not manifest.is_file():
                continue
            text = read_text_no_symlink(
                manifest,
                max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
                encoding="utf-8",
            )
            if not text:
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if token.search(stripped):
                    return manifest, number
        if current.parent == current:
            break
        current = current.parent
    return None


def scan_unused_dependencies(repo_root, py_files, location_root=None):
    """Declared dependencies with no matching import.

    ``location_root`` is the scanned project; a dependency declared only in a
    manifest above it is reported at ``repo_root`` (no file location).
    """
    findings = []

    if not repo_root or not py_files:
        return findings

    declared_deps, project_name = _collect_declared_deps(repo_root)
    if not declared_deps:
        return findings

    all_imports, has_dynamic = _collect_all_imports(py_files)
    import_to_dist = _build_import_to_dist()

    project_norm = _normalize_name(project_name) if project_name else None

    used_dists = set()
    for imp in all_imports:
        used_dists.add(_normalize_name(imp))

        if imp in import_to_dist:
            used_dists.update(import_to_dist[imp])

    for dep in sorted(declared_deps):
        if not dep:
            continue

        if project_norm and dep == project_norm:
            continue

        if dep in CLI_ONLY_PACKAGES:
            continue

        if dep in RUNTIME_PLUGIN_PACKAGES:
            continue

        if dep in used_dists:
            continue

        dep_as_import = dep.replace("-", "_")
        if dep_as_import in all_imports:
            continue
        if _normalize_name(dep_as_import) in used_dists:
            continue

        for imp in all_imports:
            imp_norm = _normalize_name(imp)
            if imp_norm == dep:
                break
        else:
            location = _declared_dependency_location(
                repo_root, dep, location_root or repo_root
            )
            manifest, line = location if location else (repo_root, 0)
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "dependency",
                    "name": dep,
                    "simple_name": dep,
                    "value": "unused",
                    "threshold": 0,
                    "message": f"Declared dependency '{dep}' appears unused. No matching import found in any Python file.",
                    "file": str(manifest),
                    "basename": manifest.name if location else "",
                    "line": line,
                    "col": 0,
                }
            )

    return findings
