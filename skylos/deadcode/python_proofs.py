"""Small source-only proofs for deprecated APIs and PEP 562 exports.

Names and string mentions are hints, not evidence that a provider or an export
is used. Unsupported assignments and control flow deliberately fail closed.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path

from skylos.analysis.ast_cache import MODE_STRICT, load_python_module
from skylos.deadcode._reachability_bindings import argument_nodes, bound_names


_WARNING_TYPES = {"DeprecationWarning", "PendingDeprecationWarning", "FutureWarning"}
_DEPRECATED_PROVIDERS = {"warnings.deprecated", "typing_extensions.deprecated"}
_DEPRECATED_DOCSTRING = re.compile(
    r"\A\s*(?:soft[- ]?)?deprecated\b|^\s*\.\.\s+deprecated::|"
    r"\b(?:kept|retained|provided)\s+(?:only\s+)?for\s+backwards?[- ]compatib",
    re.IGNORECASE | re.MULTILINE,
)
_RETIRED_COMPATIBILITY_DOCSTRING = re.compile(
    r"\A\s*(?:old|legacy)\s+(?:function|method|class|api|entry\s+point)\b"
    r"[\s\S]{0,240}\bbackwards?[- ]compatib[\s\S]{0,240}"
    r"\b(?:do\s+not\s+use|use\s+[^.\n]{1,160}\s+instead)\b",
    re.IGNORECASE,
)


def qualified_name(node: ast.AST, bindings: dict[str, str | None]) -> str | None:
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        parent = qualified_name(node.value, bindings)
        if parent:
            return parent + "." + node.attr
    return None


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def scope_bindings(body, inherited=(), arguments=None) -> dict[str, str | None]:
    """Resolve singly bound, unconditional imports; retain shadowed names."""
    result = dict(inherited)
    counts = bound_names(body).counts
    for name in counts:
        result[name] = None
    if arguments is not None:
        for argument in argument_nodes(arguments):
            result[argument.arg] = None
            counts[argument.arg] += 1
    for statement in body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                name = alias.asname or alias.name.split(".", 1)[0]
                if counts[name] == 1:
                    result[name] = alias.name if alias.asname else name
        elif isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for alias in statement.names:
                name = alias.asname or alias.name
                if alias.name != "*" and counts[name] == 1:
                    result[name] = f"{statement.module}.{alias.name}"
    for statement in body:
        for child in ast.walk(statement):
            if isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                name = _root_name(child)
                if name:
                    result[name] = None
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in {"setattr", "delattr"}
                and child.args
            ):
                name = _root_name(child.args[0])
                if name:
                    result[name] = None
    return result


def _provider_available(provider: str, filename: str) -> bool:
    root = provider.split(".", 1)[0]
    if root == "builtins":
        return True
    # An absolute spelling need not be the standard provider: local modules
    # can shadow warnings or typing_extensions without running target code.
    for directory in Path(filename).resolve().parents:
        if (directory / f"{root}.py").is_file() or (
            directory / root / "__init__.py"
        ).is_file():
            return False
    return True


def _warning_call(node, bindings, filename) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if any(keyword.arg is None for keyword in node.keywords):
        return False
    provider = qualified_name(node.func, bindings)
    if provider != "warnings.warn" or not _provider_available(provider, filename):
        return False
    category = node.args[1] if len(node.args) > 1 else None
    for keyword in node.keywords:
        if keyword.arg == "category":
            category = keyword.value
    if isinstance(category, ast.Name) and category.id not in bindings:
        return category.id in _WARNING_TYPES
    resolved = qualified_name(category, bindings)
    for name in _WARNING_TYPES:
        if resolved == f"builtins.{name}":
            return True
    return False


def _leading_warning(body, bindings, filename, *, allow_metadata=False) -> bool:
    for index, statement in enumerate(body):
        if (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            continue
        if allow_metadata and isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if (
                all(isinstance(target, ast.Name) for target in targets)
                and value is not None
                and sum(1 for _ in ast.walk(value)) <= 128
            ):
                try:
                    ast.literal_eval(value)
                except (ValueError, TypeError, SyntaxError, RecursionError):
                    pass
                else:
                    continue
        return isinstance(statement, ast.Expr) and _warning_call(
            statement.value, bindings, filename
        )
    return False


@lru_cache(maxsize=256)
def _deprecation_facts(filename: str, source: str, provider_state):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return False, frozenset()
    module_bindings = scope_bindings(tree.body)
    deprecated = set()

    def visit(body, inherited, function_globals=None):
        for statement in body:
            if not isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            document = ast.get_docstring(statement, clean=False)
            marked = bool(
                document
                and (
                    _DEPRECATED_DOCSTRING.search(document)
                    or _RETIRED_COMPATIBILITY_DOCSTRING.search(document)
                )
            )
            for decorator in statement.decorator_list:
                target = (
                    decorator.func if isinstance(decorator, ast.Call) else decorator
                )
                provider = qualified_name(target, inherited)
                if provider in _DEPRECATED_PROVIDERS and _provider_available(
                    provider, filename
                ):
                    marked = True
            arguments = None
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = statement.args
            body_bindings = inherited
            if arguments is not None and function_globals is not None:
                # A method does not capture its class body's namespace.
                body_bindings = function_globals
            local = scope_bindings(statement.body, body_bindings, arguments)
            if arguments is not None and _leading_warning(
                statement.body, local, filename
            ):
                marked = True
            if marked:
                deprecated.add((statement.lineno, statement.name))
            if isinstance(statement, ast.ClassDef):
                enclosing = inherited if function_globals is None else function_globals
                visit(statement.body, local, enclosing)
            else:
                visit(statement.body, local)

    visit(tree.body, module_bindings)
    return _leading_warning(
        tree.body, module_bindings, filename, allow_metadata=True
    ), frozenset(deprecated)


def deprecation_facts(filename: str):
    source, tree = load_python_module(Path(filename), MODE_STRICT)
    if tree is None or not source:
        return False, frozenset()
    provider_state = (
        _provider_available("warnings", filename),
        _provider_available("typing_extensions", filename),
    )
    return _deprecation_facts(filename, source, provider_state)


def _literal_strings(node) -> set[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result = set()
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str
            ):
                return None
            result.add(element.value)
        return result
    return None


def _lazy_tables(tree):
    tables = {}
    counts = bound_names(tree.body).counts
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or counts[target.id] != 1:
            continue
        if not isinstance(statement.value, ast.Dict):
            continue
        entries = {}
        for key, value in zip(statement.value.keys, statement.value.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                break
            if not isinstance(value, (ast.Tuple, ast.List)) or len(value.elts) != 2:
                break
            module, attribute = value.elts
            if not all(
                isinstance(part, ast.Constant) and isinstance(part.value, str)
                for part in (module, attribute)
            ):
                break
            entries[key.value] = (module.value, attribute.value)
        else:
            tables[target.id] = entries
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            tables.pop(_root_name(node), None)
        elif isinstance(node, ast.Call):
            # A table passed to unknown code, or one of its methods, may be
            # mutated. There is no proof that its original entries survive.
            if isinstance(node.func, ast.Attribute):
                tables.pop(_root_name(node.func.value), None)
            for argument in [*node.args, *(kw.value for kw in node.keywords)]:
                if isinstance(argument, ast.Name):
                    tables.pop(argument.id, None)
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in tables
        ):
            parent = parents.get(id(node))
            if not (isinstance(parent, ast.Subscript) and parent.value is node):
                tables.pop(node.id, None)
    return tables


def _has_fromlist(node):
    value = node.args[3] if len(node.args) > 3 else None
    for keyword in node.keywords:
        if keyword.arg is None:
            return False
        if keyword.arg == "fromlist":
            value = keyword.value
    return isinstance(value, (ast.List, ast.Tuple)) and bool(value.elts)


def proven_lazy_exports(tree: ast.Module, filename: str) -> dict[str, str]:
    from skylos.deadcode.lazy_export_proofs import proven_lazy_exports as prove

    return prove(tree, filename)
