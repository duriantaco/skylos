from __future__ import annotations

import ast
import configparser
import os
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.python_distributions import (
    NAMESPACE_ROOTS,
    distribution_commands,
    distribution_import_paths,
    shared_namespace_roots,
)
from skylos.core.python_requirements import (
    SetuptoolsRequirements,
    lock_source_files,
    normalize_distribution_name,
    read_requirements_tree,
    read_setup_cfg,
    read_setup_py,
    requirement_name,
)
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
    # Database drivers are loaded by ORM backends from settings or URLs
    # (``django.db.backends.postgresql``, ``postgresql+asyncpg://``).
    "psycopg",
    "psycopg-binary",
    "psycopg-c",
    "psycopg2",
    "psycopg2-binary",
    "mysqlclient",
    "pymysql",
    "cx-oracle",
    "oracledb",
    "asyncpg",
    "aiomysql",
    "aiosqlite",
}

# Files whose commands run installed console scripts.
COMMAND_FILE_PATTERNS = (
    re.compile(r"^Procfile(\..+)?$"),
    re.compile(r"^(Dockerfile|Containerfile)([.-].+)?$"),
    re.compile(r"^.+\.(dockerfile|Dockerfile)$"),
    re.compile(r"^(docker-)?compose(\..+)?\.ya?ml$"),
    re.compile(r"^Makefile$"),
)
MAX_COMMAND_FILES = 64
MAX_COMMAND_FILE_DEPTH = 3
MAX_COMMAND_FILE_BYTES = 1_000_000
COMMAND_FILE_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
}
_INSTALL_LINE_RE = re.compile(
    r"\b(?:pip3?|uv|pipx|poetry|pdm|conda|mamba|apt-get|apt|apk|yum|dnf|npm|yarn|pnpm)\b"
    r"[^\n]*\b(?:install|add|sync)\b"
)
_COMMAND_SPLIT_RE = re.compile(r"[\s\"'`\[\],;&|()=]+")
_DOTTED_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_STRING_IMPORT_CALLS = {"import_module", "import_string", "__import__"}

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


def _is_type_stub_distribution(dep):
    """Stub-only packages are read by type checkers, never imported."""
    return dep.startswith("types-") or dep.endswith("-stubs")


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


def _requirements_entries(current):
    """Direct requirements declared in ``current``'s requirements files.

    Returns {normalized name: (manifest path, line)}. ``-r`` includes are
    followed; ``-c`` constraint files declare nothing. Compiled lock files
    (pip-compile/uv output) are mostly transitive pins, so their entries are
    never declarations; the ``.in`` inputs they name are read instead.
    """
    declared = {}
    visited = set()
    lock_inputs = []
    candidates = [current / "requirements.txt"]
    req_dir = current / "requirements"
    try:
        if req_dir.is_dir():
            candidates.extend(sorted(req_dir.glob("*.txt"))[:32])
    except OSError:
        pass

    def add(tree):
        for parsed in tree.files:
            if tree.kinds.get(parsed.path) == "constraint":
                continue
            if parsed.compiled:
                lock_inputs.extend(lock_source_files(parsed, current))
                continue
            for requirement in parsed.requirements:
                declared.setdefault(
                    requirement.normalized, (parsed.path, requirement.line)
                )

    for candidate in candidates:
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        add(read_requirements_tree(candidate, root=current, visited=visited))
    for source in dict.fromkeys(lock_inputs):
        add(read_requirements_tree(source, root=current, visited=visited))
    return declared


def _collect_declared(repo_root):
    """Declared direct dependencies with locations, and the project name."""
    deps = {}
    project_name = None

    current = repo_root
    for _ in range(5):
        deps.update(
            (name, location)
            for name, location in _requirements_entries(current).items()
            if name not in deps
        )

        pyproj_path = current / "pyproject.toml"
        if pyproj_path.exists():
            pyproject_deps, pyproject_name = _parse_pyproject_toml(pyproj_path)
            for name in pyproject_deps:
                deps.setdefault(name, None)
            if pyproject_name and not project_name:
                project_name = pyproject_name

        # Run-time requirements only, as for ``[project].dependencies``:
        # ``setup_requires``/``tests_require``/extras are not imported by
        # the package itself.
        for setup_path, reader in (
            (current / "setup.py", read_setup_py),
            (current / "setup.cfg", read_setup_cfg),
        ):
            if not setup_path.exists():
                continue
            declaration = reader(setup_path)
            if declaration is None and setup_path.name == "setup.py":
                declaration = _legacy_setup_py(setup_path)
            if declaration is None:
                continue
            if declaration.name and not project_name:
                project_name = declaration.name
            for spec, line in declaration.install:
                name = requirement_name(spec)
                if name:
                    deps.setdefault(
                        normalize_distribution_name(name),
                        (setup_path, line) if line else None,
                    )

        if deps:
            break

        parent = current.parent
        if parent == current:
            break
        current = parent

    return deps, project_name


def _legacy_setup_py(setup_path):
    """A literal ``install_requires=[...]`` in a setup.py that is not Python 3."""
    txt = read_text_no_symlink(
        setup_path,
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
        errors="ignore",
    )
    if txt is None:
        return None
    declaration = SetuptoolsRequirements(setup_path)
    name_match = re.search(r"""name\s*=\s*['"]([^'"]+)['"]""", txt)
    if name_match:
        declaration.name = name_match.group(1)
    match = re.search(r"install_requires\s*=\s*\[", txt)
    if match:
        depth, pos = 1, match.end()
        while pos < len(txt) and depth > 0:
            if txt[pos] == "[":
                depth += 1
            elif txt[pos] == "]":
                depth -= 1
            pos += 1
        block = txt[match.end() : pos - 1]
        declaration.install = [
            (item, 0) for item in re.findall(r'["\']([^"\']+)["\']', block)
        ]
    return declaration


def _collect_declared_deps(repo_root):
    deps, project_name = _collect_declared(repo_root)
    return set(deps), project_name


def _string_values(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def _module_reference(text):
    """``a.b.c`` or ``a.b:attr`` in a string, as a dotted module path."""
    text = text.strip()
    if ":" in text and " " not in text:
        text = text.split(":", 1)[0]
    if len(text) > 200 or not _DOTTED_RE.match(text):
        return None
    return text


def _string_references(tree):
    """Dotted paths named in strings that frameworks import by name.

    Django settings (``INSTALLED_APPS``, ``MIDDLEWARE``, cache/storage/
    template backends, ``REST_FRAMEWORK`` classes) are UPPER_CASE module
    assignments; ``import_module``/``import_string`` take the path directly.
    """
    references = set()
    for statement in ast.walk(tree):
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if statement.value is None or not any(
                isinstance(target, ast.Name) and target.id.isupper()
                for target in targets
            ):
                continue
            for value in _string_values(statement.value):
                reference = _module_reference(value)
                if reference:
                    references.add(reference)
        elif isinstance(statement, ast.Call) and statement.args:
            function = statement.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else getattr(function, "id", None)
            )
            first = statement.args[0]
            if (
                name in _STRING_IMPORT_CALLS
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                reference = _module_reference(first.value)
                if reference:
                    references.add(reference)
    return references


def _collect_usage(py_files):
    """Dotted import paths and string module references in Python sources."""
    paths = set()
    for fp in py_files:
        try:
            src = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pattern in (IMPORT_RE, FROM_RE, DYNAMIC_RE):
            for match in pattern.finditer(src):
                if match.group(1):
                    paths.add(match.group(1))
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        paths |= _string_references(tree)
    return paths


def _command_files(root):
    found = []
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in COMMAND_FILE_SKIP_DIRS and depth < MAX_COMMAND_FILE_DEPTH
        )
        for filename in sorted(filenames):
            if any(pattern.match(filename) for pattern in COMMAND_FILE_PATTERNS):
                found.append(Path(dirpath) / filename)
                if len(found) >= MAX_COMMAND_FILES:
                    return found
    return found


def _collect_commands(root):
    """Command words and ``python -m`` modules in Procfile/Dockerfile/etc."""
    commands, modules = set(), set()
    for path in _command_files(root):
        text = read_text_no_symlink(
            path, max_bytes=MAX_COMMAND_FILE_BYTES, encoding="utf-8", errors="ignore"
        )
        if not text:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _INSTALL_LINE_RE.search(stripped):
                # ``pip install foo`` installs foo; it does not use it.
                continue
            tokens = [token for token in _COMMAND_SPLIT_RE.split(stripped) if token]
            for index, token in enumerate(tokens):
                word = token.rsplit("/", 1)[-1]
                commands.add(word)
                if (
                    token == "-m"
                    and index
                    and tokens[index - 1].rsplit("/", 1)[-1].startswith("python")
                    and index + 1 < len(tokens)
                ):
                    reference = _module_reference(tokens[index + 1])
                    if reference:
                        modules.add(reference)
    return commands, modules


def _entry_point_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _entry_point_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _entry_point_values(item)


def _collect_configured_modules(root):
    """Modules named by entry points and plugin settings in project config.

    ``[project.scripts]``/``[project.entry-points]``, Poetry scripts/plugins,
    ``setup.cfg`` ``[options.entry_points]`` and mypy ``plugins``.
    """
    values = []
    pyproject = read_text_no_symlink(
        Path(root) / "pyproject.toml",
        max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
        encoding="utf-8",
    )
    if pyproject:
        try:
            data = tomllib.loads(pyproject)
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            data = {}
        project = data.get("project") if isinstance(data, dict) else None
        if isinstance(project, dict):
            for key in ("scripts", "gui-scripts", "entry-points"):
                values.extend(_entry_point_values(project.get(key)))
        tool = data.get("tool") if isinstance(data, dict) else None
        if isinstance(tool, dict):
            poetry = tool.get("poetry")
            if isinstance(poetry, dict):
                for key in ("scripts", "plugins"):
                    values.extend(_entry_point_values(poetry.get(key)))
            mypy = tool.get("mypy")
            if isinstance(mypy, dict):
                values.extend(_entry_point_values(mypy.get("plugins")))
    for name in ("setup.cfg", "mypy.ini", ".mypy.ini"):
        text = read_text_no_symlink(
            Path(root) / name,
            max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES,
            encoding="utf-8",
            errors="ignore",
        )
        if not text:
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error:
            continue
        for section in parser.sections():
            if section == "options.entry_points":
                values.extend(parser[section].values())
            elif section == "mypy" and parser.has_option(section, "plugins"):
                values.append(parser[section]["plugins"])
    modules = set()
    for value in values:
        for item in re.split(r"[\s,]+", value):
            if "=" in item:
                item = item.split("=", 1)[1]
            reference = _module_reference(item)
            if reference:
                modules.add(reference)
    return modules


def _path_used(used_path, provided_paths):
    """Lenient: a namespace portion like ``google.cloud.translate`` also
    covers ``google.cloud.translate_v2`` (both ship in one distribution)."""
    root = used_path.split(".", 1)[0]
    for provided in provided_paths:
        if used_path == provided or used_path.startswith(provided + "."):
            return True
        if (
            root in NAMESPACE_ROOTS
            and "." in used_path
            and "." in provided
            and (used_path.startswith(provided) or provided.startswith(used_path + "."))
        ):
            return True
    return False


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
        r"(?<![A-Za-z0-9_.-])"
        + r"[-_.]+".join(map(re.escape, re.split(r"[-_.]+", dep)))
        + r"(?![A-Za-z0-9_])",
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


def _load_import_to_dist():
    """The pipreqs import -> distribution table shared with SKY-D222/D223."""
    from skylos.rules.ai_defect.dependency_hallucination import (
        _load_import_to_dist_mapping,
    )

    return _load_import_to_dist_mapping()


def scan_unused_dependencies(repo_root, py_files, location_root=None):
    """Declared dependencies with no matching import.

    ``location_root`` is the scanned project; a dependency declared only in a
    manifest above it is reported at ``repo_root`` (no file location).
    """
    findings = []

    if not repo_root or not py_files:
        return findings

    repo_root = Path(repo_root)
    declared, project_name = _collect_declared(repo_root)
    if not declared:
        return findings

    used_paths = _collect_usage(py_files)
    commands, command_modules = _collect_commands(repo_root)
    used_paths |= command_modules
    used_paths |= _collect_configured_modules(repo_root)
    all_imports = {path.split(".", 1)[0] for path in used_paths}
    import_to_dist = _build_import_to_dist()
    pipreqs = _load_import_to_dist()
    shared = shared_namespace_roots(import_to_dist)

    project_norm = _normalize_name(project_name) if project_name else None

    used_dists = set()
    for imp in all_imports:
        used_dists.add(_normalize_name(imp))

        if imp in import_to_dist:
            used_dists.update(import_to_dist[imp])

    boundary = location_root or repo_root
    for dep in sorted(declared):
        if not dep:
            continue

        if project_norm and dep == project_norm:
            continue

        if dep in CLI_ONLY_PACKAGES:
            continue

        if dep in RUNTIME_PLUGIN_PACKAGES:
            continue

        if _is_type_stub_distribution(dep):
            continue

        if dep in used_dists:
            continue

        dep_as_import = dep.replace("-", "_")
        if dep_as_import in all_imports:
            continue
        if _normalize_name(dep_as_import) in used_dists:
            continue

        provided = distribution_import_paths(
            dep,
            installed_modules=import_to_dist,
            import_to_dist=pipreqs,
            namespace_roots=shared,
        )
        if any(_path_used(path, provided) for path in used_paths):
            continue
        if commands & distribution_commands(dep):
            continue

        location = declared.get(dep)
        if location is not None and not _is_within(location[0], boundary):
            location = None
        if location is None:
            location = _declared_dependency_location(repo_root, dep, boundary)
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
