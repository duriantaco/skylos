"""Bounded source-only pytest binding evidence; never imports target modules.

Collection settings alone are not a safety proof. The fixture evaluator also
requires a real provider, rejects explicit callers and checks path operations.
Unknown plugins, collection hooks, incomplete reads and budgets fail closed.
"""

from __future__ import annotations

import ast
import configparser
import os
import re
import shlex
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from skylos.analysis.ast_cache import run_memo
from skylos.core.file_discovery import find_git_root
from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.danger.danger_fs.pytest_paths import _PYTEST_CALLS, _resolved

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}
_CONFIGS = ("pytest.ini", ".pytest.ini", "pyproject.toml", "tox.ini", "setup.cfg")
_HOOKS = {
    "pytest_generate_tests",
    "pytest_fixture_setup",
    "pytest_collection_modifyitems",
    "pytest_pyfunc_call",
    "pytest_runtest_call",
    "pytest_runtest_setup",
    "pytest_runtest_protocol",
    "pytest_itemcollected",
    "pytest_collection_finish",
}
_MAX_FILES = 4096
_MAX_BYTES = 64_000_000


@dataclass
class FixtureContext:
    root: Path
    trees: dict[Path, ast.Module]
    sources: dict[Path, str]
    file_patterns: tuple[str, ...]
    function_patterns: tuple[str, ...]
    class_patterns: tuple[str, ...]
    testpaths: tuple[str, ...]
    explicit_files: set[Path]
    references: object = None
    unknown_loader: bool | None = None

    def tree_for(self, path):
        if path in self.trees:
            return self.trees[path]
        source = self.sources.get(path)
        if source is None:
            return None
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError):
            tree = None
        self.trees[path] = tree
        return tree

    def collected(self, path):
        if path in self.explicit_files:
            return True
        matched = False
        for pattern in self.file_patterns:
            if fnmatchcase(path.name, pattern):
                matched = True
                break
        if not matched:
            return False
        if not self.testpaths:
            return True
        relative = path.relative_to(self.root).as_posix()
        for selected in self.testpaths:
            prefix = selected.rstrip("/")
            if relative == prefix or relative.startswith(prefix + "/"):
                return True
        return False


def _root_for(path):
    if not path.is_file() or path.is_symlink():
        return None
    root = find_git_root(path)
    if root is not None:
        return root
    for directory in path.parents:
        for name in _CONFIGS:
            if (directory / name).is_file():
                return directory
    return None


def _words(value, default):
    if isinstance(value, str):
        return tuple(shlex.split(value))
    if isinstance(value, list):
        values = []
        for item in value:
            if not isinstance(item, str):
                return None
            values.append(item)
        return tuple(values)
    if value is None:
        return default
    return None


def _collection_options(root):
    for name in _CONFIGS:
        path = root / name
        if not path.exists():
            continue
        text = read_project_text_no_symlink(root, path, max_bytes=1_000_000)
        if text is None:
            return None
        if name == "pyproject.toml":
            options = (
                tomllib.loads(text).get("tool", {}).get("pytest", {}).get("ini_options")
            )
            if options is None:
                continue
        else:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
            section = "pytest"
            if name == "setup.cfg":
                section = "tool:pytest"
            if not parser.has_section(section):
                if name in {"pytest.ini", ".pytest.ini"}:
                    return None
                continue
            options = dict(parser[section])
        if not isinstance(options, dict):
            return None
        # Local collection hooks and explicit plugins can replace providers.
        addopts = _words(options.get("addopts"), ())
        if addopts is None:
            return None
        for option in addopts:
            if not option.startswith("-") or option.startswith(
                ("-o", "--override-ini")
            ):
                return None
            if option.startswith(
                (
                    "-p",
                    "--ignore",
                    "--deselect",
                    "--pyargs",
                    "--import-mode",
                    "--rootdir",
                    "--confcutdir",
                    "--noconftest",
                )
            ) or option in {"-k", "-m", "-c"}:
                return None
        files = _words(options.get("python_files"), ("test_*.py", "*_test.py"))
        functions = _words(options.get("python_functions"), ("test",))
        classes = _words(options.get("python_classes"), ("Test",))
        paths = _words(options.get("testpaths"), ())
        if files is None or functions is None or classes is None or paths is None:
            return None
        return files, functions, classes, paths
    return ("test_*.py", "*_test.py"), ("test",), ("Test",), ()


def _pytest_commands(root):
    """Only direct shell-step pytest invocations from the repository root."""
    import yaml

    selected = set()
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return selected
    paths = sorted(workflow_dir.iterdir())
    if len(paths) > 128:
        return None
    for path in paths:
        if path.suffix not in {".yml", ".yaml"}:
            continue
        text = read_project_text_no_symlink(root, path, max_bytes=1_000_000)
        if text is None:
            return None
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            continue
        defaults = document.get("defaults", {}).get("run", {})
        jobs = document.get("jobs", {})
        if not isinstance(defaults, dict) or not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            job_defaults = job.get("defaults", {}).get("run", defaults)
            steps = job.get("steps", [])
            if (
                not isinstance(job_defaults, dict)
                or not isinstance(steps, list)
                or len(steps) > 2048
            ):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                command = step.get("run")
                workdir = step.get(
                    "working-directory", job_defaults.get("working-directory")
                )
                if not isinstance(command, str):
                    # CodSpeedHQ/action action.yml defines run as the command
                    # and working-directory as its cwd. Other action inputs
                    # have no such inferred execution contract.
                    action = step.get("uses", "")
                    if not isinstance(action, str) or not re.fullmatch(
                        r"CodSpeedHQ/action@[0-9a-fA-F]{40}", action
                    ):
                        continue
                    inputs = step.get("with", {})
                    if not isinstance(inputs, dict):
                        continue
                    command = inputs.get("run")
                    workdir = inputs.get("working-directory", ".")
                    if not isinstance(command, str):
                        continue
                if workdir is not None and workdir not in (".", "./"):
                    continue
                selected.update(_shell_pytest_files(root, command))
    return selected


def _shell_pytest_files(root, script):
    selected = set()
    lines = script.replace("\\\n", " ").splitlines()
    for line in lines:
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError:
            return set()
        if not words:
            continue
        if any(
            word in {"cd", "pushd", "popd", ";", "&&", "||", "|", "&"} for word in words
        ):
            return set()
        if len(words) > 2 and words[:2] in (
            ["uv", "run"],
            ["poetry", "run"],
            ["pdm", "run"],
        ):
            words = words[2:]
        if (
            len(words) >= 3
            and re.fullmatch(r"python(?:3(?:\.\d+)?)?", words[0])
            and words[1:3] == ["-m", "pytest"]
        ):
            words = ["pytest", *words[3:]]
        if words[0] not in {"pytest", "py.test"}:
            continue
        for word in words[1:]:
            if word.startswith("-"):
                if word not in {
                    "-q",
                    "--quiet",
                    "-v",
                    "--verbose",
                    "-x",
                    "--exitfirst",
                    "-s",
                    "--codspeed",
                }:
                    return set()
                continue
            filename = word.split("::", 1)[0]
            candidate = root / filename
            if filename.endswith(".py") and candidate.is_file():
                selected.add(candidate.absolute())
    return selected


def _build_context(root):
    trees = {}
    sources = {}
    total = 0
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        for name in list(subdirs):
            child = Path(directory) / name
            if name in _SKIP or child.is_symlink():
                subdirs.remove(name)
        if "pytest.py" in filenames or "pytest" in subdirs:
            return None
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = Path(directory) / filename
            text = read_project_text_no_symlink(root, path, max_bytes=2_000_000)
            if text is None:
                return None
            total += len(text)
            if len(sources) >= _MAX_FILES or total > _MAX_BYTES:
                return None
            sources[path] = text
    options = _collection_options(root)
    explicit = _pytest_commands(root)
    if options is None or explicit is None:
        return None
    return FixtureContext(root, trees, sources, *options, explicit)


def fixture_context(file_path):
    try:
        path = Path(file_path).absolute()
        root = _root_for(path)
        if root is None:
            return None
        return run_memo(
            ("pytest-fixture-path-context", str(root)), lambda: _build_context(root)
        )
    except (OSError, ValueError, RuntimeError, SyntaxError, configparser.Error):
        return None


def fixture_definitions(tree):
    """Only unshadowed pytest fixture imports and literal names are supported."""
    imports = pytest_imports(tree)
    fixtures = {}
    for function in tree.body:
        if not isinstance(function, _FUNCTIONS):
            continue
        for decorator in function.decorator_list:
            target = decorator
            name = function.name
            if isinstance(decorator, ast.Call):
                target = decorator.func
            if _resolved(target, imports) not in {
                "pytest.fixture",
                "pytest.yield_fixture",
            }:
                continue
            unknown = False
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg == "name":
                        if not isinstance(
                            keyword.value, ast.Constant
                        ) or not isinstance(keyword.value.value, str):
                            return None
                        name = keyword.value.value
                    if keyword.arg == "params":
                        unknown = True
            if _resolved(target, imports) in {"pytest.fixture", "pytest.yield_fixture"}:
                if name in fixtures:
                    return None
                if unknown:
                    fixtures[name] = None
                else:
                    fixtures[name] = function
    return fixtures


def fixture_scope_supported(tree):
    from skylos.rules.danger.danger_fs.closed_world import _Names
    from skylos.rules.danger.danger_fs.pytest_fixture_bindings import binding_escapes

    names = _Names(tree)
    if names.namespace_mutated:
        return False
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "pytest" and not pytest_imports(tree):
                    if binding_escapes(
                        tree, alias.asname or alias.name, allow_decorators=True
                    ):
                        return False
        elif isinstance(statement, ast.ImportFrom):
            if statement.module == "pytest":
                for alias in statement.names:
                    if binding_escapes(
                        tree, alias.asname or alias.name, allow_decorators=True
                    ):
                        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"exec", "eval"} and names.unbound(node.func.id):
                return False
    for statement in tree.body:
        if isinstance(statement, _FUNCTIONS) and statement.name in _HOOKS:
            return False
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                if (alias.asname or alias.name) in _HOOKS:
                    return False
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(statement, ast.Assign):
                hook_targets = statement.targets
            else:
                hook_targets = [statement.target]
            for target in hook_targets:
                for node in ast.walk(target):
                    if isinstance(node, ast.Name) and node.id in _HOOKS:
                        return False
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name == "*":
                    return False
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            else:
                targets = [statement.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == "pytest_plugins":
                    if (
                        not isinstance(statement.value, (ast.List, ast.Tuple))
                        or statement.value.elts
                    ):
                        return False
                    for node in ast.walk(tree):
                        if (
                            isinstance(node, ast.Name)
                            and node.id == "pytest_plugins"
                            and isinstance(node.ctx, ast.Load)
                        ):
                            return False
    return True


def pytest_imports(tree):
    """Resolve pytest aliases without mistaking annotations for module escapes."""
    imports = {}
    definitions = {}
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "pytest":
                    name = alias.asname or alias.name
                    imports[name] = "pytest"
                    definitions[name] = alias
        elif (
            isinstance(statement, ast.ImportFrom)
            and statement.module == "pytest"
            and not statement.level
        ):
            for alias in statement.names:
                if alias.name == "*":
                    return {}
                name = alias.asname or alias.name
                imports[name] = "pytest." + alias.name
                definitions[name] = alias
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                if name in imports and definitions[name] is not alias:
                    return {}
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in imports:
                return {}
        elif isinstance(node, ast.arg) and node.arg in imports:
            return {}
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)) and node.name in imports:
            return {}
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id in imports:
                return {}
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "exec",
                "eval",
                "setattr",
                "delattr",
                "globals",
                "locals",
                "vars",
            }:
                return {}
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in imports
        ):
            expression = node
            parent = parents.get(expression)
            while isinstance(parent, ast.Attribute) and parent.value is expression:
                expression = parent
                parent = parents.get(expression)
            qualified = _resolved(expression, imports)
            known = qualified in _PYTEST_CALLS or qualified.startswith("pytest.mark.")
            if known and isinstance(parent, ast.Call) and parent.func is expression:
                continue
            if (
                known
                and isinstance(parent, (*_FUNCTIONS, ast.ClassDef))
                and expression in parent.decorator_list
            ):
                continue
            current = expression
            in_annotation = False
            while current in parents:
                owner = parents[current]
                if isinstance(owner, ast.arg) and current is owner.annotation:
                    in_annotation = True
                    break
                if isinstance(owner, ast.AnnAssign) and current is owner.annotation:
                    in_annotation = True
                    break
                if isinstance(owner, _FUNCTIONS) and current is owner.returns:
                    in_annotation = True
                    break
                if isinstance(owner, (ast.stmt, ast.Call)):
                    break
                current = owner
            if not in_annotation:
                return {}
    return imports


def externally_referenced(context, path, function, *, complete_loader_proof=True):
    """Do not reinterpret application calls, callbacks or dynamic dispatch as pytest."""
    from skylos.rules.danger.danger_fs.pytest_fixture_loaders import (
        has_unknown_fixture_loader,
    )

    from skylos.rules.danger.danger_fs.closed_world import _LOADER_WORD_RE

    if context.references is None:
        context.references = {}
    key = str(path), function.name
    if key not in context.references:
        context.references[key] = _candidate_referenced(context, path, function)
    if context.references[key]:
        return True
    if not complete_loader_proof:
        return False
    if context.unknown_loader is None:
        context.unknown_loader = False
        for source_path, source in context.sources.items():
            if context.collected(source_path) or source_path.name == "conftest.py":
                continue
            if not _LOADER_WORD_RE.search(source):
                continue
            source_tree = context.tree_for(source_path)
            if source_tree is not None and has_unknown_fixture_loader(
                source_tree, source
            ):
                context.unknown_loader = True
                break
    return context.unknown_loader


def _candidate_referenced(context, path, function):
    from skylos.rules.danger.danger_fs.closed_world import _Names, _loader_name

    relative = path.relative_to(context.root).with_suffix("")
    module = ".".join(relative.parts)
    for source_path, source in context.sources.items():
        if function.name not in source and path.stem not in source:
            continue
        tree = context.tree_for(source_path)
        if tree is None:
            continue
        if function.name in _free_loaded_names(tree):
            return True
        names = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if names is None:
                    names = _Names(tree)
                loader = _loader_name(node.func, names)
                if loader is not None:
                    for argument in [
                        *node.args,
                        *[keyword.value for keyword in node.keywords],
                    ]:
                        for value in ast.walk(argument):
                            if isinstance(value, ast.Constant) and isinstance(
                                value.value, str
                            ):
                                if (
                                    module in value.value
                                    or path.stem in value.value
                                    or function.name in value.value
                                ):
                                    return True
            if source_path == path:
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == module or module.startswith(alias.name + "."):
                        return True
            elif isinstance(node, ast.ImportFrom):
                imported = node.module or ""
                if node.level:
                    package = list(source_path.relative_to(context.root).parent.parts)
                    remove = node.level - 1
                    if remove:
                        package = package[:-remove]
                    if imported:
                        package.extend(imported.split("."))
                    imported = ".".join(package)
                if imported == module:
                    return True
                for alias in node.names:
                    if imported + "." + alias.name == module:
                        return True
    return False


def _free_loaded_names(tree):
    """Fixture dependency parameters shadow same-named provider definitions."""
    names = set()

    class References(ast.NodeVisitor):
        def __init__(self):
            self.parameters = []

        def visit_Name(self, node):
            if not isinstance(node.ctx, ast.Load):
                return
            for parameters in self.parameters:
                if node.id in parameters:
                    return
            names.add(node.id)

        def visit_FunctionDef(self, node):
            for decorator in node.decorator_list:
                self.visit(decorator)
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                if default is not None:
                    self.visit(default)
            parameters = set()
            for argument in [
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            ]:
                parameters.add(argument.arg)
            if node.args.vararg:
                parameters.add(node.args.vararg.arg)
            if node.args.kwarg:
                parameters.add(node.args.kwarg.arg)

            class Locals(ast.NodeVisitor):
                def visit_Name(self, child):
                    if isinstance(child.ctx, (ast.Store, ast.Del)):
                        parameters.add(child.id)

                def visit_FunctionDef(self, child):
                    parameters.add(child.name)

                visit_AsyncFunctionDef = visit_FunctionDef
                visit_ClassDef = visit_FunctionDef

            bindings = Locals()
            for statement in node.body:
                bindings.visit(statement)
            self.parameters.append(parameters)
            for statement in node.body:
                self.visit(statement)
            self.parameters.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

    References().visit(tree)
    return names
