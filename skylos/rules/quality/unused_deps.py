from __future__ import annotations

import ast
import configparser
import os
import re
import shlex
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.python_distributions import (
    NAMESPACE_ROOTS,
    distribution_commands,
    distribution_import_paths,
    path_is_provided,
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

# Plugin interfaces, not packages to exempt unconditionally. Each entry must
# have a corresponding request, marker or option in the scanned project.
# Sources: pytest-click and pytest-subtests package documentation on PyPI;
# pytest-rerunfailures.readthedocs.io/latest/configuration.html.
_PYTEST_FIXTURE_PROVIDERS = {
    "cli_runner": "pytest-click",
    "isolated_cli_runner": "pytest-click",
    "subtests": "pytest-subtests",
}
_PYTEST_MARKER_PROVIDERS = {
    "pytest.mark.timeout": "pytest-timeout",
    "pytest.mark.flaky": "pytest-rerunfailures",
}
_PYTEST_OPTION_PROVIDERS = {
    "--timeout": "pytest-timeout",
    "--timeout-method": "pytest-timeout",
    "--reruns": "pytest-rerunfailures",
    "--reruns-delay": "pytest-rerunfailures",
    "--only-rerun": "pytest-rerunfailures",
    "--rerun-except": "pytest-rerunfailures",
}
_PYTEST_INI_PROVIDERS = {
    "timeout": "pytest-timeout",
    "timeout_method": "pytest-timeout",
    "timeout_func_only": "pytest-timeout",
    "timeout_disable_debugger": "pytest-timeout",
    "reruns": "pytest-rerunfailures",
    "reruns_delay": "pytest-rerunfailures",
    "only_rerun": "pytest-rerunfailures",
    "rerun_except": "pytest-rerunfailures",
}
_PYTEST_PLUGIN_NAMES = {
    "timeout": "pytest-timeout",
    "pytest_timeout": "pytest-timeout",
    "rerunfailures": "pytest-rerunfailures",
    "pytest_rerunfailures": "pytest-rerunfailures",
    "subtests": "pytest-subtests",
    "pytest_subtests": "pytest-subtests",
    "pytest_click": "pytest-click",
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
        # A pyproject or repository root is the scanned project's boundary;
        # an enclosing project's manifest does not declare this one's deps.
        if pyproj_path.exists() or (current / ".git").exists():
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
                isinstance(target, ast.Name)
                and (target.id.isupper() or target.id == "pytest_plugins")
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


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _resolve_name(node, aliases):
    name = _qualified_name(node)
    root, separator, suffix = name.partition(".")
    return aliases.get(root, root) + (separator + suffix if separator else "")


def _module_scope_nodes(tree):
    """Statements/expressions evaluated outside nested lexical bodies."""
    pending = list(reversed(tree.body))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _pytest_aliases(tree):
    """Only borrowed pytest names whose identity is not contradicted locally."""
    bindings = {}
    ambiguous = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                target = alias.name if alias.asname else local
                if local in bindings and bindings[local] != target:
                    ambiguous.add(local)
                bindings[local] = target
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                local = alias.asname or alias.name
                target = f"{node.module}.{alias.name}"
                if local in bindings and bindings[local] != target:
                    ambiguous.add(local)
                bindings[local] = target
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            ambiguous.add(node.id)
        elif isinstance(node, ast.arg):
            ambiguous.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ambiguous.add(node.name)
    return {
        local: target
        for local, target in bindings.items()
        if local not in ambiguous
        and (target == "pytest" or target.startswith("pytest."))
    }


def _pytest_name(node, aliases):
    root = _qualified_name(node).split(".", 1)[0]
    return _resolve_name(node, aliases) if root in aliases else ""


def _pytest_fixture_evidence(tree, aliases, *, test_module):
    """Fixture requests use pytest's injection protocol, not arbitrary args.

    A locally supplied fixture is not proof that an identically named plugin
    fixture is used. Direct parametrization similarly supplies a value rather
    than requesting a fixture.
    """
    supplied, requested, delegated = set(), set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fixture = False
        fixture_name = node.name
        direct_parameters = set()
        for decorator in node.decorator_list:
            function = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _pytest_name(function, aliases)
            if name in {"pytest.fixture", "pytest.yield_fixture"}:
                fixture = True
                if isinstance(decorator, ast.Call):
                    for keyword in decorator.keywords:
                        if (
                            keyword.arg == "name"
                            and isinstance(keyword.value, ast.Constant)
                            and isinstance(keyword.value.value, str)
                        ):
                            fixture_name = keyword.value.value
            if (
                name == "pytest.mark.parametrize"
                and isinstance(decorator, ast.Call)
                and decorator.args
            ):
                argument = decorator.args[0]
                names = (
                    {part.strip() for part in argument.value.split(",")}
                    if isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                    else set(_string_values(argument))
                )
                indirect = next(
                    (kw.value for kw in decorator.keywords if kw.arg == "indirect"),
                    None,
                )
                if isinstance(indirect, ast.Constant) and indirect.value is True:
                    continue
                direct_parameters |= names - (
                    set(_string_values(indirect)) if indirect is not None else set()
                )
        if fixture:
            supplied.add(fixture_name)
        if fixture or (test_module and node.name.startswith("test")):
            parameters = {
                arg.arg
                for arg in node.args.args + node.args.kwonlyargs
                if arg.arg not in direct_parameters
            }
            requested |= parameters
            if fixture and fixture_name in parameters:
                delegated.add(fixture_name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _pytest_name(node.func, aliases) == (
            "pytest.mark.usefixtures"
        ):
            requested.update(
                arg.value
                for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            )
    return supplied - delegated, requested


def _collect_usage_evidence(py_files, *, unresolved=None):
    """Collect exact import paths without executing sources.

    A from-import names its child, not every distribution below its namespace:
    ``from zope import interface`` supplies ``zope.interface``. A failed read,
    failed parse or unresolved dynamic import leaves absence unproven.
    """
    paths = set()
    plugins = set()
    supplied_fixtures, requested_fixtures = {}, {}
    complete = True
    if unresolved is None:
        unresolved = []
    for fp in py_files:
        try:
            src = Path(fp).read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (
            OSError,
            UnicodeError,
            SyntaxError,
            ValueError,
            RecursionError,
            MemoryError,
        ) as exc:
            complete = False
            unresolved.append(
                {
                    "kind": "source_unreadable"
                    if isinstance(exc, (OSError, UnicodeError))
                    else "source_unparsed",
                    "file": str(fp),
                }
            )
            continue
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    paths.add(alias.name)
                    local = alias.asname or alias.name.split(".", 1)[0]
                    aliases[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    if alias.name == "*":
                        paths.add(node.module)
                    else:
                        full = f"{node.module}.{alias.name}"
                        paths.add(full)
                        aliases[alias.asname or alias.name] = full
        pytest_aliases = _pytest_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                provider = _PYTEST_MARKER_PROVIDERS.get(
                    _pytest_name(node, pytest_aliases)
                )
                if provider:
                    plugins.add(provider)
            elif isinstance(node, ast.Call):
                name = _resolve_name(node.func, aliases)
                if name not in {
                    "__import__",
                    "importlib.import_module",
                    "django.utils.module_loading.import_string",
                    "werkzeug.utils.import_string",
                }:
                    continue
                first = (
                    node.args[0]
                    if node.args
                    else next(
                        (
                            kw.value
                            for kw in node.keywords
                            if kw.arg
                            in {"name", "module_name", "dotted_path", "import_name"}
                        ),
                        None,
                    )
                )
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    reference = _module_reference(first.value)
                    if reference:
                        paths.add(reference)
                else:
                    complete = False
                    unresolved.append(
                        {
                            "kind": "unresolved_dynamic_import",
                            "file": str(fp),
                            "line": node.lineno,
                        }
                    )
        paths |= _string_references(tree)
        path = Path(fp)
        supplied, requested = _pytest_fixture_evidence(
            tree,
            pytest_aliases,
            test_module=path.name.startswith("test_") or path.name.endswith("_test.py"),
        )
        supplied_fixtures[path] = supplied
        requested_fixtures[path] = requested
    conftests = [
        (path, fixtures)
        for path, fixtures in supplied_fixtures.items()
        if path.name == "conftest.py"
    ]
    for path, requested in requested_fixtures.items():
        supplied = set(supplied_fixtures[path])
        for fixture_path, fixtures in conftests:
            if _is_within(path, fixture_path.parent):
                supplied |= fixtures
        plugins.update(
            _PYTEST_FIXTURE_PROVIDERS[name]
            for name in requested - supplied
            if name in _PYTEST_FIXTURE_PROVIDERS
        )
    return paths, plugins, complete


def _collect_usage(py_files):
    """Dotted imports and configured module references (compatibility helper)."""
    return _collect_usage_evidence(py_files)[0]


def _installed_pytest_plugin_names():
    """Read pytest entry-point ownership without importing any plugin."""
    from importlib.metadata import distributions

    names = {}
    try:
        installed = distributions()
        for distribution in installed:
            owner = _normalize_name(distribution.metadata.get("Name"))
            if not owner:
                continue
            for point in distribution.entry_points:
                if point.group == "pytest11":
                    names[point.name] = owner
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return names


def _pytest_token_usage(tokens, plugin_names):
    modules, distributions = set(), set()
    for index, token in enumerate(tokens):
        if not isinstance(token, str):
            continue
        provider = _PYTEST_OPTION_PROVIDERS.get(token.split("=", 1)[0])
        if provider:
            distributions.add(provider)
        plugin = (
            tokens[index + 1]
            if token == "-p" and index + 1 < len(tokens)
            else token[2:]
            if token.startswith("-p")
            else ""
        )
        if isinstance(plugin, str) and plugin and not plugin.startswith("no:"):
            provider = plugin_names.get(plugin)
            if provider:
                distributions.add(provider)
            reference = _module_reference(plugin)
            if reference:
                modules.add(reference)
    return modules, distributions


def _pytest_command_tokens(command):
    """Arguments of an explicit pytest command in a tox command declaration."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    if tokens and tokens[0].endswith(":"):
        tokens = tokens[1:]  # tox's ``py311: pytest ...`` factor prefix
    if not tokens:
        return []
    executable = tokens[0].lstrip("-").rsplit("/", 1)[-1]
    if executable in {"pytest", "py.test"}:
        return tokens[1:]
    if (executable.startswith("python") or executable == "{envpython}") and tokens[
        1:3
    ] == ["-m", "pytest"]:
        return tokens[3:]
    return []


def _collect_pytest_usage(root, *, unresolved=None):
    """Evidence of plugins explicitly selected or configured by pytest."""
    modules, distributions = set(), set()
    configurations = []
    command_options = []
    plugin_names = _PYTEST_PLUGIN_NAMES | _installed_pytest_plugin_names()
    complete = True
    if unresolved is None:
        unresolved = []
    for filename in ("pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg"):
        path = Path(root) / filename
        if not path.is_file():
            continue
        text = read_text_no_symlink(
            path, max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES, encoding="utf-8"
        )
        if text is None:
            complete = False
            unresolved.append({"kind": "configuration_unreadable", "file": str(path)})
            continue
        try:
            if filename == "pyproject.toml":
                data = tomllib.loads(text)
                pytest = data.get("tool", {}).get("pytest", {})
                configurations.append(pytest.get("ini_options", pytest))
            else:
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                parser.read_string(text)
                section = "tool:pytest" if filename == "setup.cfg" else "pytest"
                if parser.has_section(section):
                    configurations.append(dict(parser[section]))
                if filename == "tox.ini":
                    for tox_section in parser.sections():
                        if not tox_section.startswith("testenv"):
                            continue
                        for key in ("commands", "commands_pre", "commands_post"):
                            for command in parser.get(
                                tox_section, key, fallback=""
                            ).splitlines():
                                command_options.append(_pytest_command_tokens(command))
        except (
            tomllib.TOMLDecodeError,
            configparser.Error,
            AttributeError,
            TypeError,
            ValueError,
        ):
            complete = False
            unresolved.append({"kind": "configuration_unparsed", "file": str(path)})

    for options in configurations:
        if not isinstance(options, dict):
            complete = False
            unresolved.append({"kind": "pytest_options_unparsed"})
            continue
        distributions.update(
            provider
            for key, provider in _PYTEST_INI_PROVIDERS.items()
            if key in options
        )
        for value in _entry_point_values(options.get("required_plugins")):
            for spec in value.split():
                name = requirement_name(spec)
                if name:
                    distributions.add(_normalize_name(name))
        addopts = options.get("addopts", "")
        try:
            tokens = shlex.split(addopts) if isinstance(addopts, str) else list(addopts)
        except (ValueError, TypeError):
            complete = False
            unresolved.append({"kind": "pytest_options_unparsed"})
            continue
        if not all(isinstance(token, str) for token in tokens):
            complete = False
            unresolved.append({"kind": "pytest_options_unparsed"})
        command_options.append(tokens)
    for tokens in command_options:
        used_modules, used_distributions = _pytest_token_usage(tokens, plugin_names)
        modules |= used_modules
        distributions |= used_distributions
    return modules, distributions, complete


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


def _sphinx_config_modules(root, *, unresolved):
    """Read Sphinx's extension declarations, including its shared config API."""
    modules = set()
    candidates = {Path(root) / "conf.py"}
    for dirname in ("doc", "docs", "documentation"):
        directory = Path(root) / dirname
        for current, directories, files in os.walk(directory, followlinks=False):
            depth = len(Path(current).relative_to(directory).parts)
            directories[:] = [
                name
                for name in directories
                if depth < 2 and name not in COMMAND_FILE_SKIP_DIRS
            ]
            if "conf.py" in files:
                candidates.add(Path(current) / "conf.py")
    for path in sorted(candidates):
        if not path.is_file():
            continue
        source = read_text_no_symlink(
            path, max_bytes=MAX_DEPENDENCY_MANIFEST_BYTES, encoding="utf-8"
        )
        if source is None:
            unresolved.append({"kind": "configuration_unreadable", "file": str(path)})
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            unresolved.append({"kind": "configuration_unparsed", "file": str(path)})
            continue
        aliases = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0]
                    )
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        values = []
        for node in _module_scope_nodes(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if node.value is not None and any(
                    isinstance(target, ast.Name) and target.id == "extensions"
                    for target in targets
                ):
                    values.extend(_string_values(node.value))
            elif isinstance(node, ast.Call) and _resolve_name(node.func, aliases) == (
                "sphinx_celery.conf.build_config"
            ):
                for keyword in node.keywords:
                    if keyword.arg in {"extensions", "extra_extensions"}:
                        values.extend(_string_values(keyword.value))
        for value in values:
            reference = _module_reference(value)
            if reference:
                modules.add(reference)
    return modules


def _collect_configured_modules(root, *, unresolved=None):
    """Modules named by entry points and plugin settings in project config.

    ``[project.scripts]``/``[project.entry-points]``, Poetry scripts/plugins,
    ``setup.cfg`` ``[options.entry_points]`` and mypy ``plugins``.
    """
    values = []
    if unresolved is None:
        unresolved = []
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
    for name in ("setup.cfg", "mypy.ini", ".mypy.ini", ".flake8", "tox.ini"):
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
            elif section == "flake8":
                options = parser[section]
                if "docstring-convention" in options or any(
                    re.search(r"(?<![A-Za-z])D\d*(?![A-Za-z])", options.get(key, ""))
                    for key in (
                        "select",
                        "extend-select",
                        "ignore",
                        "extend-ignore",
                        "per-file-ignores",
                    )
                ):
                    values.append("flake8_docstrings")
    modules = set()
    for value in values:
        for item in re.split(r"[\s,]+", value):
            if "=" in item:
                item = item.split("=", 1)[1]
            reference = _module_reference(item)
            if reference:
                modules.add(reference)
    return modules | _sphinx_config_modules(root, unresolved=unresolved)


def _path_used(used_path, provided_paths):
    # A namespace parent alone cannot prove which child distribution is used.
    return any(
        path_is_provided(used_path, (provided,))
        and not provided.startswith(used_path + ".")
        for provided in provided_paths
    )


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


def scan_unused_dependencies(repo_root, py_files, location_root=None, *, coverage=None):
    """Declared dependencies absent from a resolved usage inventory.

    ``location_root`` is the scanned project; a dependency declared only in a
    manifest above it is reported at ``repo_root`` (no file location).
    ``coverage`` receives one rule-level receipt. An unresolved consumer is a
    limit on the absence analysis, not evidence of an unused dependency.
    """
    findings = []
    receipt = coverage if coverage is not None else {}
    receipt.update(
        rule_id=RULE_ID,
        status="complete",
        complete=True,
        reasons=[],
        abstained_count=0,
        abstained_dependencies=[],
    )

    if not repo_root or not py_files:
        receipt.update(
            status="not_run",
            complete=False,
            reasons=[{"kind": "no_python_sources"}],
        )
        return findings

    repo_root = Path(repo_root)
    declared, project_name = _collect_declared(repo_root)
    if not declared:
        return findings

    unresolved = []
    used_paths, used_plugins, _ = _collect_usage_evidence(
        py_files, unresolved=unresolved
    )
    pytest_modules, pytest_distributions, _ = _collect_pytest_usage(
        repo_root, unresolved=unresolved
    )
    used_paths |= pytest_modules
    commands, command_modules = _collect_commands(repo_root)
    used_paths |= command_modules
    used_paths |= _collect_configured_modules(repo_root, unresolved=unresolved)
    all_imports = {path.split(".", 1)[0] for path in used_paths}
    import_to_dist = _build_import_to_dist()
    pipreqs = _load_import_to_dist()
    shared = shared_namespace_roots(import_to_dist)

    project_norm = _normalize_name(project_name) if project_name else None

    used_dists = used_plugins | pytest_distributions
    for imp in all_imports:
        used_dists.add(_normalize_name(imp))

        if imp in import_to_dist and imp not in NAMESPACE_ROOTS and imp not in shared:
            used_dists.update(import_to_dist[imp])

    boundary = location_root or repo_root
    # Preserve each source/configuration limitation once, rather than turning
    # the same unresolved import into a finding for every declared package.
    for reason in unresolved:
        if reason not in receipt["reasons"]:
            receipt["reasons"].append(reason)
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
        candidate_uncertainty = list(unresolved)
        if any(
            provided_path.startswith(path + ".")
            for path in used_paths
            for provided_path in provided
        ):
            candidate_uncertainty.append({"kind": "namespace_parent_only"})
        # Installed top-level metadata alone cannot attribute an unfamiliar
        # shared namespace's children to its individual distributions.
        if any(
            dep in import_to_dist.get(root, ())
            and not any(path.split(".", 1)[0] == root for path in provided)
            for root in all_imports & shared
        ):
            candidate_uncertainty.append({"kind": "shared_namespace_unresolved"})
        if commands & distribution_commands(dep):
            continue
        if candidate_uncertainty:
            receipt["abstained_dependencies"].append(dep)
            for reason in candidate_uncertainty:
                if reason not in receipt["reasons"]:
                    receipt["reasons"].append(reason)
            continue

        location = declared.get(dep)
        if location is not None and not _is_within(location[0], boundary):
            location = None
        if location is None:
            location = _declared_dependency_location(repo_root, dep, boundary)
        manifest, line = location if location else (repo_root, 0)
        finding = {
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
        findings.append(finding)

    receipt["abstained_count"] = len(receipt["abstained_dependencies"])
    if receipt["reasons"]:
        receipt.update(status="incomplete", complete=False)
    return findings
