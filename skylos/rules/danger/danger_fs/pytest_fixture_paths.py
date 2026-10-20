"""Source-bound pytest providers and per-expression temporary path evidence.

No target code is executed. Unknown providers keep ordinary path findings.
"""

from __future__ import annotations

import ast
from fnmatch import fnmatchcase
from pathlib import Path

from skylos.rules.danger.danger_fs.pytest_paths import _name, _resolved
from skylos.rules.danger.danger_fs.pytest_fixture_values import (
    FixturePathEvidence,
    _FunctionPaths,
)
from skylos.rules.danger.danger_fs.pytest_fixture_context import (
    externally_referenced,
    fixture_context,
    fixture_definitions,
    fixture_scope_supported,
    pytest_imports,
)

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BUILTINS = {
    "tmp_path": "path",
    "tmpdir": "path",
    "tmp_path_factory": "factory",
    "tmpdir_factory": "factory",
}
_MAX_DEPTH = 12


def _fixture_parameters(function):
    """Pytest injects required positional-or-keyword and keyword-only names."""
    if function.args.posonlyargs:
        return []
    arguments = function.args.args
    required = len(arguments) - len(function.args.defaults)
    result = list(arguments[:required])
    for argument, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
        if default is None:
            result.append(argument)
    return result


def _providers(context, path):
    result = {}
    chain = []
    directory = path.parent
    while True:
        chain.append(directory)
        if directory == context.root:
            break
        directory = directory.parent
    for directory in reversed(chain):
        conftest = directory / "conftest.py"
        if conftest in context.sources:
            scope_tree = context.tree_for(conftest)
            if scope_tree is None or not fixture_scope_supported(scope_tree):
                return None
            fixtures = fixture_definitions(scope_tree)
            if fixtures is None:
                return None
            for statement in context.trees[conftest].body:
                if (
                    isinstance(statement, (*_FUNCTIONS, ast.ClassDef))
                    and statement.name in _BUILTINS
                ):
                    result[statement.name] = None
                elif isinstance(statement, (ast.Import, ast.ImportFrom)):
                    for alias in statement.names:
                        result[alias.asname or alias.name] = None
                elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    if isinstance(statement, ast.Assign):
                        targets = statement.targets
                    else:
                        targets = [statement.target]
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name):
                                result[name.id] = None
            for name, function in fixtures.items():
                if function is None:
                    result[name] = None
                else:
                    result[name] = (conftest, function)
    fixtures = fixture_definitions(context.trees[path])
    if fixtures is None:
        return None
    for statement in context.trees[path].body:
        if (
            isinstance(statement, (*_FUNCTIONS, ast.ClassDef))
            and statement.name in _BUILTINS
        ):
            result[statement.name] = None
        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            for alias in statement.names:
                result[alias.asname or alias.name] = None
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            else:
                targets = [statement.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        result[name.id] = None
    for name, function in fixtures.items():
        if function is None:
            result[name] = None
        else:
            result[name] = (path, function)
    return result


def _collected_functions(tree, context, imports):
    functions = []
    for statement in tree.body:
        if isinstance(statement, _FUNCTIONS):
            functions.append((statement, None))
        elif isinstance(statement, ast.ClassDef):
            if statement.bases or statement.keywords or statement.decorator_list:
                continue
            matched = False
            for pattern in context.class_patterns:
                if fnmatchcase(statement.name, pattern) or (
                    not any(character in pattern for character in "*?[")
                    and statement.name.startswith(pattern)
                ):
                    matched = True
            if not matched:
                continue
            supported = True
            methods = []
            for member in statement.body:
                if isinstance(member, _FUNCTIONS):
                    if member.name.startswith("__"):
                        supported = False
                    for decorator in member.decorator_list:
                        target = decorator
                        if isinstance(decorator, ast.Call):
                            target = decorator.func
                        if not _resolved(target, imports).startswith("pytest.mark."):
                            supported = False
                    methods.append(member)
                elif not (
                    isinstance(member, ast.Pass)
                    or (
                        isinstance(member, ast.Expr)
                        and isinstance(member.value, ast.Constant)
                        and isinstance(member.value.value, str)
                    )
                ):
                    supported = False
            if supported:
                for method in methods:
                    functions.append((method, statement))
    return functions


def fixture_path_evidence(tree, file_path, literal_parameters=None):
    evidence = FixturePathEvidence()
    context = fixture_context(file_path)
    path = Path(file_path).absolute()
    if context is None or path not in context.sources or not context.collected(path):
        return evidence
    source_tree = context.tree_for(path)
    if (
        source_tree is None
        or not fixture_scope_supported(source_tree)
        or ast.dump(tree) != ast.dump(source_tree)
    ):
        return evidence
    providers = _providers(context, path)
    if providers is None:
        return evidence
    # A shared function-scoped temp fixture can be changed before the test by
    # an autouse provider. Do not infer a fresh leaf without modeling that setup.
    for provider in providers.values():
        if provider is None:
            continue
        _provider_path, provider_function = provider
        autouse = False
        for decorator in provider_function.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if keyword.arg == "autouse":
                    if (
                        not isinstance(keyword.value, ast.Constant)
                        or keyword.value.value
                    ):
                        autouse = True
        if autouse:
            for argument in _fixture_parameters(provider_function):
                if argument.arg in {"tmp_path", "tmpdir"}:
                    return evidence
    fixtures = fixture_definitions(tree)
    imports = pytest_imports(tree)
    if fixtures is None:
        return evidence
    literals = literal_parameters or {}

    def resolve(name, trail, *, complete_proof=True):
        if name in trail or len(trail) >= _MAX_DEPTH:
            return None
        if name not in providers:
            return _BUILTINS.get(name)
        if providers[name] is None:
            return None
        provider_path, provider = providers[name]
        provider_imports = pytest_imports(context.trees[provider_path])
        for decorator in provider.decorator_list:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            qualified = _resolved(target, provider_imports)
            if qualified not in {"pytest.fixture", "pytest.yield_fixture"}:
                return None
        if externally_referenced(
            context, provider_path, provider, complete_loader_proof=False
        ):
            return None
        parameters = {}
        for argument in _fixture_parameters(provider):
            kind = resolve(argument.arg, (*trail, name), complete_proof=complete_proof)
            if kind is not None:
                parameters[argument.arg] = kind
        model = _FunctionPaths(
            context.trees[provider_path],
            provider,
            parameters,
            FixturePathEvidence(),
            file_path=provider_path,
            project_root=context.root,
        )
        returned = model.run()
        if complete_proof and returned in {"path", "factory"}:
            if externally_referenced(context, provider_path, provider):
                return None
        return returned

    for provider in providers.values():
        if provider is None:
            continue
        _provider_path, provider_function = provider
        autouse = False
        for decorator in provider_function.decorator_list:
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg == "autouse":
                        if (
                            not isinstance(keyword.value, ast.Constant)
                            or keyword.value.value
                        ):
                            autouse = True
        if not autouse:
            continue
        for argument in _fixture_parameters(provider_function):
            if resolve(argument.arg, (), complete_proof=False) == "path":
                return evidence
        for node in ast.walk(provider_function):
            if isinstance(node, ast.Attribute) and node.attr == "getfixturevalue":
                return evidence

    for function, owner_class in _collected_functions(tree, context, imports):
        is_fixture = function in fixtures.values()
        collected_name = False
        for pattern in context.function_patterns:
            if fnmatchcase(function.name, pattern):
                collected_name = True
            elif not any(
                character in pattern for character in "*?["
            ) and function.name.startswith(pattern):
                collected_name = True
        if not is_fixture and not collected_name:
            continue
        # Unknown function decorators may replace pytest binding or execution.
        valid_decorators = True
        parameterized = set()
        for decorator in function.decorator_list:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            name = _resolved(target, imports)
            if name == "pytest.mark.usefixtures":
                valid_decorators = False
            if name == "pytest.mark.parametrize":
                argument_names = None
                if isinstance(decorator, ast.Call):
                    if decorator.args:
                        argument_names = decorator.args[0]
                    for keyword in decorator.keywords:
                        if keyword.arg == "argnames":
                            argument_names = keyword.value
                if isinstance(argument_names, ast.Constant) and isinstance(
                    argument_names.value, str
                ):
                    for argument_name in argument_names.value.split(","):
                        parameterized.add(argument_name.strip())
                elif isinstance(argument_names, (ast.List, ast.Tuple)):
                    for argument_name in argument_names.elts:
                        if not isinstance(
                            argument_name, ast.Constant
                        ) or not isinstance(argument_name.value, str):
                            valid_decorators = False
                            break
                        parameterized.add(argument_name.value)
                else:
                    valid_decorators = False
            if name not in {
                "pytest.fixture",
                "pytest.yield_fixture",
            } and not name.startswith("pytest.mark."):
                valid_decorators = False
        if not valid_decorators:
            continue
        parameters = {}
        for argument in _fixture_parameters(function):
            if argument.arg in parameterized:
                continue
            kind = resolve(argument.arg, ())
            if kind in {"path", "factory"}:
                parameters[argument.arg] = kind
        if not parameters:
            continue
        builtin_names = set()
        old_test_path = path.name.startswith("test_") or path.name.endswith("_test.py")
        for part in path.relative_to(context.root).parts[:-1]:
            if part in {"test", "tests"}:
                old_test_path = True
        legacy_fixture = False
        for decorator in function.decorator_list:
            target = decorator
            if isinstance(decorator, ast.Call):
                target = decorator.func
            if _name(target) in {"pytest.fixture", "fixture"}:
                legacy_fixture = True
        if old_test_path and (function.name.startswith("test_") or legacy_fixture):
            for name in parameters:
                if name in {"tmp_path", "tmpdir"} and name not in providers:
                    builtin_names.add(name)
        if externally_referenced(
            context, path, function, complete_loader_proof=not bool(builtin_names)
        ):
            continue
        if owner_class is not None and externally_referenced(
            context, path, owner_class, complete_loader_proof=False
        ):
            continue
        extension_names = set(parameters) - builtin_names
        if (
            builtin_names
            and extension_names
            and externally_referenced(context, path, function)
        ):
            for name in extension_names:
                parameters.pop(name, None)
        evidence.parameters[function] = set(parameters)
        # Ordinary, positively bound builtins retain the existing opaque-call
        # policy. New providers and layouts require complete expression proof.
        # This is compatibility, not a claim that unknown callbacks are safe.
        for compatible in (False, True):
            selected = {}
            for name, kind in parameters.items():
                if (name in builtin_names) == compatible:
                    selected[name] = kind
            if not selected:
                continue
            function_evidence = FixturePathEvidence()
            model = _FunctionPaths(
                tree,
                function,
                selected,
                function_evidence,
                literals.get(function, ()),
                file_path=path,
                project_root=context.root,
                preserve_opaque_calls=compatible,
            )
            model.run()
            evidence.paths.update(function_evidence.paths)
            evidence.unsafe.update(function_evidence.unsafe)
    return evidence
