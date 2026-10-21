"""Repository-level proof for path findings that rest on a helper parameter.

Per-file path analysis keeps a finding when the only source is a parameter of
a non-entrypoint function: a caller elsewhere might pass it untrusted input
(see ``_PathFlowChecker._untrusted_path_evidence``). On a scan of a whole
repository this module drops such a finding only when it sits in test code
that no non-test file imports, names, configures or dynamically loads (a
loader call whose module name, path or source is computed can load any
module): test code is not deployed, so its values come from the tests.
Comments in non-test files are not evidence: a comment can mention a module or
a folder but never imports or loads one.

Every other helper-parameter finding goes to ``path_provenance``, which
resolves the helper's callers in the scanned source. It reports a finding
only when a resolved caller passes untrusted input and records the steps; a
caller it cannot resolve leaves the finding ``unknown``, which is not a claim
of an attack or of safety. Dispatch by computed name, mutable module state,
CGI request variables and process launches with untrusted arguments are
modelled there rather than assumed safe.
"""

from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from pathlib import Path

from skylos.core.file_discovery import find_git_root
from skylos.rules.quality._test_code import (
    is_python_test_file,
    looks_like_python_test_path,
)

HELPER_PARAMETER_SOURCE = "helper_parameter"
PATH_RULES = frozenset({"SKY-D215", "SKY-D324", "SKY-D325"})
TEST_MODULE_REASON = (
    "path comes from a helper parameter in test code that no non-test file "
    "imports, so its values come from the tests"
)

_SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".nox",
     ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".eggs"}
)  # fmt: skip
_CONFIG_SUFFIXES = frozenset(
    {".toml", ".cfg", ".ini", ".yaml", ".yml", ".json", ".txt", ".sh", ".env",
     ".conf", ".service", ".tf", ".hcl", ".j2", ".tpl"}
)  # fmt: skip
_CONFIG_NAMES = frozenset({"Procfile", "Makefile", "Justfile", "Pipfile"})
_CONFIG_PREFIXES = ("Dockerfile", "Containerfile", "docker-compose", "compose")
_MAX_FILES = 20000
_MAX_BYTES = 2_000_000
_MAX_TOTAL_BYTES = 200_000_000
_TEST_DIRS = frozenset({"test", "tests"})
# ``from a.b import c`` / ``import a.b, c as d``: the module part of each
# import statement (a parenthesised name list continues on later lines but
# never changes the module).
_FROM_IMPORT_RE = re.compile(r"^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import\b(.*)$", re.M)
_IMPORT_RE = re.compile(r"^[ \t]*import[ \t]+([\w., \t]+?)[ \t]*(?:#.*)?$", re.M)

_DYNAMIC_IMPORT_RE = re.compile(
    r"\b(?:import_module|__import__|spec_from_file_location|load_source|"
    r"iter_modules|walk_packages|entry_points|iter_entry_points|run_path|"
    r"run_module|load_plugins?|SourceFileLoader|exec|execfile|find_spec|"
    r"load_module|import_string|resolve_name)\s*\("
)
# Calls that load code by a module name, file path or source text, and the
# arguments that choose what they load as (position, keyword). Without the
# first one the call searches everywhere (``walk_packages()`` walks sys.path),
# except a loader object's ``load_module()``, whose file is already chosen.
_LOADER_TARGETS = {
    "import_module": ((0, "name"), (1, "package")),
    "__import__": ((0, "name"), (3, "fromlist")),
    "find_spec": ((0, "name"), (1, "path"), (1, "package")),
    "import_string": ((0, "dotted_path"),),
    "resolve_name": ((0, "name"), (1, "package")),
    "run_module": ((0, "mod_name"),),
    "run_path": ((0, "path_name"),),
    "spec_from_file_location": ((1, "location"),),
    "SourceFileLoader": ((1, "path"),),
    "load_source": ((1, "pathname"),),
    "load_module": ((0, "fullname"), (2, "pathname")),
    "walk_packages": ((0, "path"),),
    "execfile": ((0, "filename"),),
    "exec": ((0, "source"),),
    "SourcelessFileLoader": ((1, "path"),),
    # Dotted-path loaders of common libraries; their names are generic, so
    # they count only through their module (``pydoc.locate``).
    "locate": ((0, "path"),),
    "import_from_string": ((0, "import_str"),),
    "symbol_by_name": ((0, "name"),),
    "get_method": ((0, "path"),),
    "get_class": ((0, "path"),),
    "get_object": ((0, "path"),),
    "import_class": ((0, "import_str"),),
    "import_object": ((0, "import_str"),),
    "load_object": ((0, "path"),),
}
_QUALIFIED_LOADERS = {
    "locate": frozenset({"pydoc"}),
    "import_from_string": frozenset({"uvicorn.importer"}),
    "symbol_by_name": frozenset({"kombu.utils", "kombu.utils.imports", "celery.utils.imports"}),
    "get_method": frozenset({"hydra.utils"}),
    "get_class": frozenset({"hydra.utils"}),
    "get_object": frozenset({"hydra.utils"}),
    "import_class": frozenset({"oslo_utils.importutils"}),
    "import_object": frozenset({"oslo_utils.importutils"}),
    "load_object": frozenset({"scrapy.utils.misc"}),
}
_OPTIONAL_FIRST_TARGET = frozenset({"load_module"})
# Builtins only: ``session.exec(query)`` loads nothing, ``builtins.exec`` does.
_BUILTIN_LOADERS = frozenset({"exec", "execfile"})
_BUILTINS_MODULES = frozenset({"builtins", "__builtins__"})
_LOADER_MODULES = frozenset(
    {"importlib", "importlib.util", "importlib.machinery", "builtins",
     "__builtins__", "runpy", "pkgutil", "imp", "pydoc"}
)  # fmt: skip
# Unbound names that are loaders without an import.
_BUILTIN_LOADER_NAMES = frozenset({"exec", "execfile", "__import__"})
_STAR_BOUND = "<bound by a star import>"
_LOADER_WORD_RE = re.compile(
    r"\b(?:" + "|".join([*_LOADER_TARGETS, *_LOADER_MODULES]) + r")\b"
)
_LOADER_CALL_RE = re.compile(r"\b(?:" + "|".join(_LOADER_TARGETS) + r")\s*\(")
# Fixed by the loader file's own location.
_OWN_LOCATION_NAMES = frozenset({"__name__", "__package__", "__file__"})
# Path builders whose result is fixed when every input is:
# ``Path(__file__).resolve().parent / "tests" / "evaluator.py"``.
_PATH_FUNCTIONS = frozenset(
    {"Path", "PurePath", "PosixPath", "PurePosixPath", "join", "dirname",
     "abspath", "realpath", "normpath", "fspath", "str"}
)  # fmt: skip
_PATH_METHODS = frozenset({"resolve", "absolute", "joinpath", "with_name", "with_suffix", "join"})
_PATH_MODULES = frozenset({"os", "os.path", "posixpath", "pathlib"})

def is_helper_parameter_finding(finding: dict) -> bool:
    metadata = finding.get("metadata")
    return (
        finding.get("rule_id") in PATH_RULES
        and isinstance(metadata, dict)
        and metadata.get("path_source") == HELPER_PARAMETER_SOURCE
    )


def drop_closed_world_helper_findings(
    findings: list[dict], *, scan_path, suppressed: list[dict]
) -> list[dict]:
    """Findings without the helper-parameter ones the repository disproves.

    Dropped findings are appended to ``suppressed`` with the reason.
    """
    from skylos.rules.danger.danger_fs.path_provenance import (
        needs_provenance,
        resolve_helper_parameter_findings,
    )

    if not any(needs_provenance(f) for f in findings):
        return findings
    candidates = [f for f in findings if is_helper_parameter_finding(f)]
    root = _closed_world_root(scan_path)
    if root is not None and any(_in_test_code(root, f) for f in candidates):
        findings = _drop_unreferenced_test_helpers(findings, root, suppressed)
    return resolve_helper_parameter_findings(
        findings, scan_path=scan_path, project_root=root, suppressed=suppressed
    )


def _drop_unreferenced_test_helpers(
    findings: list[dict], root: Path, suppressed: list[dict]
) -> list[dict]:
    index = _ProjectIndex.build(root)
    if index is None:
        return findings

    reasons: dict[str, str | None] = {}
    kept = []
    for finding in findings:
        if is_helper_parameter_finding(finding):
            key = str(finding.get("file", ""))
            if key not in reasons:
                reasons[key] = _proof_reason(index, key)
            if reasons[key]:
                dropped = dict(finding)
                dropped["category"] = "danger"
                dropped["reason"] = reasons[key]
                suppressed.append(dropped)
                continue
        kept.append(finding)
    return kept


def _proof_reason(index, file_key: str) -> str | None:
    """Why the helper-parameter premise is false, or None when unproven."""
    try:
        path = Path(file_key).resolve(strict=True)
        relative = path.relative_to(index.root)
    except (OSError, ValueError, RuntimeError):
        return None
    if path not in index.py_texts or not index.is_test_file(path):
        return None
    return TEST_MODULE_REASON if index.test_module_unreferenced(path, relative) else None


def _in_test_code(root: Path, finding: dict) -> bool:
    """Cheap name/folder check before the project is indexed."""
    return looks_like_python_test_path(str(finding.get("file", "")), root)


def _closed_world_root(scan_path) -> Path | None:
    """The scan path when it is the whole repository, else None."""
    if isinstance(scan_path, (list, tuple)):
        return None
    try:
        path = Path(scan_path)
        if path.is_symlink() or not path.is_dir():
            return None
        path = path.resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        return None
    git_root = find_git_root(path)
    if git_root is not None:
        return path if Path(git_root).resolve() == path else None
    markers = ("pyproject.toml", "setup.py", "setup.cfg")
    return path if any((path / marker).is_file() for marker in markers) else None


def _is_config_file(path: Path) -> bool:
    name = path.name
    return (
        path.suffix in _CONFIG_SUFFIXES
        or name in _CONFIG_NAMES
        or name.startswith(_CONFIG_PREFIXES)
    )


def _is_python_source(path: Path, text: str) -> bool:
    if path.suffix in {".py", ".pyw"}:
        return True
    first_line = text.split("\n", 1)[0]
    return not path.suffix and first_line.startswith("#!") and "python" in first_line


def _without_comments(text: str) -> str:
    """``text`` with every comment blanked and the line structure kept; the
    raw text when it does not tokenize (unproven, so nothing is discounted)."""
    lines = io.StringIO(text).readlines()
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, ValueError):
        return text
    for token in tokens:
        if token.type != tokenize.COMMENT or token.start[0] != token.end[0]:
            continue
        row, start = token.start
        line = lines[row - 1]
        end = token.end[1]
        lines[row - 1] = line[:start] + " " * (end - start) + line[end:]
    return "".join(lines)


class _ProjectIndex:
    def __init__(self, root: Path, py_texts: dict[Path, str], config_texts: list[str]):
        self.root = root
        self.py_texts = py_texts
        self.config_texts = config_texts
        self.dynamic_importers = {
            path: text
            for path, text in py_texts.items()
            if _DYNAMIC_IMPORT_RE.search(text)
        }
        self.loader_mentions = [
            path for path, text in py_texts.items() if _LOADER_WORD_RE.search(text)
        ]
        self._code_texts: dict[Path, str] = {}
        self._computed_loaders: dict[Path, bool] = {}

    def code_text(self, path: Path) -> str:
        """The file without its comments, computed only for files whose raw
        text already matched a check."""
        if path not in self._code_texts:
            self._code_texts[path] = _without_comments(self.py_texts[path])
        return self._code_texts[path]

    @classmethod
    def build(cls, root: Path) -> _ProjectIndex | None:
        py_texts: dict[Path, str] = {}
        config_texts: list[str] = []
        count = 0
        total = 0
        for current, dirs, files in os.walk(root):
            dirs[:] = [
                name
                for name in dirs
                if name not in _SKIP_DIRS
                and not (Path(current) / name / "pyvenv.cfg").exists()
            ]
            for name in files:
                path = Path(current) / name
                is_py = path.suffix in {".py", ".pyw"}
                maybe_script = not path.suffix
                if not (is_py or maybe_script or _is_config_file(path)):
                    continue
                count += 1
                if count > _MAX_FILES:
                    return None
                try:
                    size = path.stat().st_size
                    if path.is_symlink() or size > _MAX_BYTES:
                        if is_py:
                            return None
                        continue
                    total += size
                    if total > _MAX_TOTAL_BYTES:
                        return None
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    if is_py:
                        return None
                    continue
                if _is_python_source(path, text):
                    py_texts[path.resolve()] = text
                elif _is_config_file(path):
                    config_texts.append(text)
        return cls(root, py_texts, config_texts)

    def test_module_unreferenced(self, path: Path, relative: Path) -> bool:
        """No non-test file imports, names or dynamically loads the module."""
        parts = list(relative.with_suffix("").parts)
        if not parts:
            return False
        # Any import of the module names its last component: ``import a.mod``,
        # ``from a import mod``, ``from .mod import x``, ``from . import mod``.
        word = re.compile(rf"(?<![\w-]){re.escape(parts[-1])}(?![\w-])")
        reachable = _test_import_names(relative)
        for other, other_text in self.py_texts.items():
            if other == path or self.is_test_file(other):
                continue
            if word.search(other_text) and word.search(self.code_text(other)):
                return False
            if reachable & self._imported_modules(other, other_text) and (
                reachable & self._imported_modules(other, self.code_text(other))
            ):
                return False
        return not self._named_in_config(relative) and not self._dynamically_loadable(path)

    def _imported_modules(self, path: Path, text: str) -> set[str]:
        """Dotted modules (and ``module.name`` for ``from`` imports) that
        ``path`` imports, relative imports resolved from its folder."""
        try:
            package = list(path.parent.relative_to(self.root).parts)
        except ValueError:
            package = []
        modules = set()
        text = text.replace("\\\n", " ")  # backslash line continuations
        for match in _IMPORT_RE.finditer(text):
            for item in match.group(1).split(","):
                name = item.split()[0] if item.split() else ""
                if name:
                    modules.add(name)
        for dots, module, names in _FROM_IMPORT_RE.findall(text):
            if dots:
                base = package[: len(package) - (len(dots) - 1)] if len(dots) > 1 else package
                module = ".".join([*base, *([module] if module else [])])
            if not module:
                continue
            modules.add(module)
            for name in re.findall(r"\w+", names.split("#", 1)[0]):
                if name != "as":
                    modules.add(f"{module}.{name}")
        return modules

    def is_test_file(self, path: Path) -> bool:
        """Test code by name or folder that holds tests (``ab_test.py`` with
        no tests in it is production code)."""
        return is_python_test_file(path, self.root, self.py_texts.get(path))

    def _named_in_config(self, relative: Path) -> bool:
        """A config file loads the module by dotted path, ``module:attr`` or
        ``module.attr`` (a script run by its file path is started by the
        operator: ``python tools/job_key.py``)."""
        parts = list(relative.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return True
        stem = parts[-1]
        dotted = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        refs = [re.compile(rf"(?<![\w.-]){re.escape(name)}(?![\w-])") for name in dotted]
        refs.append(re.compile(rf"(?<![\w.-]){re.escape(stem)}(?=[:.](?!py\b)\w)"))
        return any(ref.search(text) for text in self.config_texts for ref in refs)

    def _dynamically_loadable(self, path: Path) -> bool:
        """A non-test dynamic loader can import the module: a loader call
        whose module name, path or source is computed can load any module,
        and a fixed one (or a plugin hook) needs the loader to name every
        folder between where the two files meet and the module (none when the
        loader sits in that folder or below it). Tests that load the code
        under test with importlib pass test data."""
        for loader in self.loader_mentions:
            if loader != path and not self.is_test_file(loader):
                if loader not in self._computed_loaders:
                    self._computed_loaders[loader] = _has_computed_loader_call(
                        self.code_text(loader)
                    )
                if self._computed_loaders[loader]:
                    return True
        for loader in self.dynamic_importers:
            if loader == path or self.is_test_file(loader):
                continue
            loader_code = self.code_text(loader)
            if not _DYNAMIC_IMPORT_RE.search(loader_code):
                continue
            common = Path(os.path.commonpath([loader.parent, path.parent]))
            needed = path.parent.relative_to(common).parts
            if all(
                re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", loader_code)
                for name in needed
            ):
                return True
        return False

def _has_computed_loader_call(code: str) -> bool:
    """A loader in ``code`` can load a module chosen at run time: a call
    whose target is not written in the file, or a loader passed around as a
    value, whose calls cannot be seen. Code too deep to judge is never proven
    free of one; code that does not parse is judged by its text: a loader
    call shape there is not proven fixed."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return bool(_LOADER_CALL_RE.search(code))
    except (RecursionError, MemoryError):
        return True
    try:
        return _computed_loader(tree)
    except (RecursionError, MemoryError):
        return True


class _Names:
    """How the file binds each name: ``import m [as n]``, ``from m import x
    [as n]``, or anything else (assignment, parameter, def, loop, ...)."""

    def __init__(self, tree: ast.Module):
        self.bindings: dict[str, list[tuple]] = {}
        self.star = False  # ``from m import *`` can bind any name unseen
        self.namespace_mutated = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self._add(alias.asname, ("import", alias.name))
                    else:
                        top = alias.name.split(".")[0]
                        self._add(top, ("import", top))
            elif isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                for alias in node.names:
                    if alias.name == "*":
                        self.star = True
                    else:
                        self._add(alias.asname or alias.name, ("from", module, alias.name))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                self._add(node.id, ("other",))
            elif isinstance(node, ast.arg):
                self._add(node.arg, ("other",))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._add(node.name, ("other",))
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    self._add(name, ("other",))
            elif not isinstance(node, ast.alias):  # aliases: the imports above
                for attr in ("name", "rest"):  # except ... as e, match captures
                    value = getattr(node, attr, None)
                    if isinstance(value, str):
                        self._add(value, ("other",))

            # Attribute/dictionary writes can replace an imported callable
            # without rebinding its root Name (os.path.join = ..., for example).
            # A globals()/locals() write can replace even __file__ or str.
            target = None
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                target = node.value
            elif isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and node.args
                ):
                    target = node.args[0]
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "update", "setdefault", "pop", "popitem", "clear",
                    "__setitem__", "__delitem__",
                }:
                    target = node.func.value
            while isinstance(target, (ast.Attribute, ast.Subscript)):
                target = target.value
            if isinstance(target, ast.Name):
                self._add(target.id, ("other",))
            elif (
                isinstance(target, ast.Call)
                and isinstance(target.func, ast.Name)
                and target.func.id in {"globals", "locals", "vars"}
                and not target.args
            ):
                self.namespace_mutated = True

    def _add(self, name: str, binding: tuple) -> None:
        self.bindings.setdefault(name, []).append(binding)

    def unbound(self, name: str) -> bool:
        return name not in self.bindings and not self.star and not self.namespace_mutated

    def module(self, name: str) -> str | None:
        """The module ``name`` always refers to, when only imports bind it."""
        if self.star:
            return _STAR_BOUND
        if self.namespace_mutated:
            return None
        entries = self.bindings.get(name)
        if not entries:
            if self.star:
                return _STAR_BOUND
            return "__builtins__" if name == "__builtins__" else None
        origins = [self._module_origin(entry) for entry in entries]
        if any(origin is None for origin in origins):
            return None
        modules = set(origins)
        return modules.pop() if len(modules) == 1 else None

    @staticmethod
    def _module_origin(entry: tuple) -> str | None:
        if entry[0] == "import":
            return entry[1]
        if entry[0] == "from":
            module = f"{entry[1]}.{entry[2]}"
            return module
        return None

    def dotted(self, node: ast.AST) -> str:
        """``a.b.c`` with ``a`` resolved through imports; "" when unknown."""
        if isinstance(node, ast.Name):
            return self.module(node.id) or ""
        if isinstance(node, ast.Attribute):
            owner = self.dotted(node.value)
            if owner == _STAR_BOUND:
                return owner
            return f"{owner}.{node.attr}" if owner else ""
        return ""

    def may_be(self, node: ast.AST, modules) -> bool:
        """``node`` is, or (bound by a star import) may be, one of ``modules``."""
        possible = self.possible_dotted(node)
        return bool(possible & modules) or _STAR_BOUND in possible

    def possible_dotted(self, node: ast.AST) -> set[str]:
        """Possible import origins, including a binding another branch replaces.

        These origins can retain a finding; they never prove a path fixed.
        """
        if isinstance(node, ast.Name):
            origins = {
                origin for entry in self.bindings.get(node.id, ())
                if (origin := self._module_origin(entry)) is not None
            }
            if node.id == "__builtins__":
                origins.add("__builtins__")
            if self.star:
                origins.add(_STAR_BOUND)
            return origins
        if isinstance(node, ast.Attribute):
            return {
                origin if origin == _STAR_BOUND else f"{origin}.{node.attr}"
                for origin in self.possible_dotted(node.value)
            }
        return set()

    def imported(self, name: str, modules, original: str) -> bool:
        """Only ``from <one of modules> import original [as name]`` binds it."""
        entries = self.bindings.get(name)
        return not self.star and not self.namespace_mutated and bool(entries) and all(
            entry[0] == "from" and entry[1] in modules and entry[2] == original
            for entry in entries
        )


def _computed_loader(tree: ast.Module) -> bool:
    names = _Names(tree)
    ambiguous_aliases = set()
    for local, entries in names.bindings.items():
        loaders = {
            entry[2] for entry in entries
            if entry[0] == "from" and entry[2] in _LOADER_TARGETS
            and (entry[2] not in _QUALIFIED_LOADERS or entry[1] in _QUALIFIED_LOADERS[entry[2]])
        }
        if loaders and (
            len(loaders) != 1 or names.star or names.namespace_mutated
            or any(entry[0] != "from" or entry[2] not in loaders for entry in entries)
        ):
            ambiguous_aliases.add(local)
    called = set()
    owners = set()
    benign_module_refs = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            owners.add(id(node.value))
        if not isinstance(node, ast.Call):
            continue
        called.add(id(node.func))
        if isinstance(node.func, ast.Name) and node.args:
            if node.func.id == "getattr":
                # _getattr_of_a_loader judges the chosen attribute below.
                benign_module_refs.add(id(node.args[0]))
            elif (
                node.func.id in {"setattr", "delattr"} and len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and node.args[1].value not in _LOADER_TARGETS
                and node.args[1].value != "__dict__"
            ):
                # Setting builtins._ for gettext does not escape its loaders.
                benign_module_refs.add(id(node.args[0]))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in ambiguous_aliases:
                return True
            if (
                id(node) not in owners and id(node) not in benign_module_refs
                and names.possible_dotted(node) & _LOADER_MODULES
            ):
                return True
        name = _loader_name(node, names)
        if name is not None and id(node) not in called:
            if isinstance(node, ast.Name) or names.may_be(node.value, _LOADER_MODULES):
                return True
        if not isinstance(node, ast.Call):
            continue
        if _getattr_of_a_loader(node, names):
            return True
        name = _loader_name(node.func, names)
        if name is not None:
            if (
                isinstance(node.func, ast.Attribute)
                and names.may_be(node.func.value, _LOADER_MODULES)
                and names.dotted(node.func.value) not in _LOADER_MODULES
            ):
                return True
            if _computed_target(node, name, names):
                return True
    return False


def _loader_name(node: ast.AST, names: _Names) -> str | None:
    """The loader ``node`` refers to: a name imported as one (``from
    importlib import import_module as load``), an unbound builtin loader, or
    an attribute named like one (on its own module when the name is
    generic). A local variable or function that shares the name is not."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        entries = names.bindings.get(node.id)
        if not entries:
            if node.id in _BUILTIN_LOADER_NAMES or (names.star and node.id in _LOADER_TARGETS):
                return node.id
            return None
        if not all(entry[0] == "from" and entry[2] in _LOADER_TARGETS for entry in entries):
            return None
        loader = entries[0][2]
        qualified = _QUALIFIED_LOADERS.get(loader)
        if qualified and not all(entry[1] in qualified for entry in entries):
            return None
        return loader
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        loader = node.attr
        if loader in _BUILTIN_LOADERS:
            return loader if names.may_be(node.value, _BUILTINS_MODULES) else None
        if loader in _QUALIFIED_LOADERS:
            return loader if names.may_be(node.value, _QUALIFIED_LOADERS[loader]) else None
        return loader if loader in _LOADER_TARGETS else None
    return None


def _getattr_of_a_loader(node: ast.Call, names: _Names) -> bool:
    """``getattr(importlib, "import_module")`` or ``getattr(importlib, name)``."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
        return False
    if len(node.args) < 2:
        return False
    attribute = node.args[1]
    if isinstance(attribute, ast.Constant):
        return attribute.value in _LOADER_TARGETS
    return names.may_be(node.args[0], _LOADER_MODULES)


def _computed_target(node: ast.Call, name: str, names: _Names) -> bool:
    for index, (position, keyword) in enumerate(_LOADER_TARGETS[name]):
        argument = _call_argument(node, position, keyword)
        if argument is None:
            if index == 0 and name not in _OPTIONAL_FIRST_TARGET:
                return True
            continue
        if not _is_fixed(argument, names):
            return True
    return False


def _call_argument(node: ast.Call, position: int, keyword: str) -> ast.AST | None:
    if any(isinstance(arg, ast.Starred) for arg in node.args[: position + 1]):
        return node  # ``f(*args)``: unknown, and a call is never fixed text
    if position < len(node.args):
        return node.args[position]
    for item in node.keywords:
        if item.arg == keyword or item.arg is None:  # ``**kwargs`` is unknown
            return item.value
    return None


def _is_fixed(node: ast.AST, names: _Names) -> bool:
    """What ``node`` evaluates to is written in the file: literals, names
    fixed by the file's location, and paths joined from them with the real
    ``str``/``pathlib``/``os.path`` (not a same-named local). Any other name
    is not: another module, ``globals()`` or a star import can rebind it."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in _OWN_LOCATION_NAMES and names.unbound(node.id)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        return _is_fixed(node.left, names) and _is_fixed(node.right, names)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_fixed(element, names) for element in node.elts)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _is_fixed(node.value, names)
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "parents"
        and isinstance(node.slice, ast.Constant)
    ):
        return _is_fixed(node.value.value, names)
    if not isinstance(node, ast.Call) or not all(_is_fixed(arg, names) for arg in node.args):
        return False
    if not all(item.arg and _is_fixed(item.value, names) for item in node.keywords):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        if func.id == "str":
            return names.unbound("str")
        return func.id in _PATH_FUNCTIONS and names.imported(func.id, _PATH_MODULES, func.id)
    if not isinstance(func, ast.Attribute):
        return False
    if names.dotted(func.value) in _PATH_MODULES:
        return func.attr in _PATH_FUNCTIONS
    return func.attr in _PATH_METHODS and _is_fixed(func.value, names)


def _test_import_names(relative: Path) -> set[str]:
    """Dotted names whose import can reach the module: the module and the
    test packages above it (a package ``__init__`` can re-export it), from
    the project root and from every folder below it (a source root)."""
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    names = set()
    for start in range(len(parts)):
        tail = parts[start:]
        names.add(".".join(tail))
        for end in range(1, len(tail)):
            if _TEST_DIRS & set(tail[:end]):
                names.add(".".join(tail[:end]))
    return names
