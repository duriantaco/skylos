"""Module bindings handed to dynamically executed code.

``exec(code, globals())`` and ``eval(expr, globals())`` give the executed code
the calling module's namespace, so every module-level binding of that module is
reachable by name: its imports, functions, classes and variables, and the names
a ``from X import *`` copied in (``X.__all__`` when declared, otherwise every
public module-level name of ``X``, imports included). A fresh or restricted
namespace such as ``exec(code, {})`` exposes nothing.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Sequence

from skylos.deadcode._registration_common import _package_base
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode._reachability_bindings import argument_nodes, bound_names

_EXECUTORS = frozenset({"exec", "eval"})
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_MAX_STAR_DEPTH = 8


def _is_globals_call(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "globals"
        and not node.args
        and not node.keywords
    )


def _namespace_owners(tree: ast.Module, *, safe_star=False):
    """Executable builtin namespace escapes, with their deferred owner.

    A same-spelled function or parameter does not expose the module namespace.
    Class bindings affect their body, but are not closure bindings of methods.
    """

    def walk(node, bindings, owner, enclosing):
        if isinstance(node, (ast.Module, *_SCOPES)):
            body = node.body if isinstance(node.body, list) else [node.body]
            local = set(bound_names(body).counts)
            if node is tree and safe_star:
                local.discard("*")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                local.update(arg.arg for arg in argument_nodes(node.args))
                owner = node
            visible = bindings | local
            method_bindings = bindings if isinstance(node, ast.ClassDef) else visible
            for child in body:
                child_bindings = (
                    method_bindings
                    if isinstance(
                        child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                    )
                    else visible
                )
                yield from walk(child, child_bindings, owner, method_bindings)
            return
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _EXECUTORS and not bindings.intersection(
                {node.func.id, "globals", "*"}
            ):
                namespace = node.args[1] if len(node.args) > 1 else None
                for keyword in node.keywords:
                    if keyword.arg == "globals":
                        namespace = keyword.value
                if _is_globals_call(namespace):
                    yield owner
        for child in ast.iter_child_nodes(node):
            child_bindings = (
                enclosing
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                )
                else bindings
            )
            yield from walk(child, child_bindings, owner, enclosing)

    yield from walk(tree, set(), None, set())


def _module_scope_statements(tree: ast.Module):
    pending = list(reversed(tree.body))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, _SCOPES):
            continue
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                pending.append(child)


def _declared_all(tree: ast.Module) -> set[str] | None:
    for stmt in tree.body:
        targets = []
        value = None
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            targets, value = [stmt.target], stmt.value
        for target in targets:
            if not isinstance(target, ast.Name) or target.id != "__all__":
                continue
            names = set()
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                for element in value.elts:
                    if isinstance(element, ast.Constant) and isinstance(
                        element.value, str
                    ):
                        names.add(element.value)
            return names
    return None


def _star_sources(tree: ast.Module, module: str, path: Path) -> list[str]:
    sources = []
    for stmt in _module_scope_statements(tree):
        if not isinstance(stmt, ast.ImportFrom):
            continue
        if not any(alias.name == "*" for alias in stmt.names):
            continue
        source = stmt.module or ""
        if stmt.level:
            base = _package_base(module, path, stmt.level)
            if base is None:
                continue
            if base and source:
                source = f"{base}.{source}"
            elif base:
                source = base
        if source:
            sources.append(source)
    return sources


def _import_lines(tree: ast.Module) -> dict[int, set[str]]:
    lines: dict[int, set[str]] = {}
    for stmt in _module_scope_statements(tree):
        if not isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        for alias in stmt.names:
            if alias.name == "*":
                continue
            bound = alias.asname
            if not bound:
                bound = alias.name
                if isinstance(stmt, ast.Import):
                    bound = alias.name.split(".", 1)[0]
            for line in {stmt.lineno, getattr(alias, "lineno", stmt.lineno)}:
                lines.setdefault(line, set()).add(bound)
    return lines


def _star_preserves_builtins(module, by_module, seen=()):
    """A known project star source cannot replace exec/eval/globals.

    Unknown providers, dynamic exports and executable module effects do not
    establish that proof. Ordinary project re-exports of unrelated names do.
    """
    if module in seen or len(seen) >= _MAX_STAR_DEPTH or module not in by_module:
        return False
    parsed, _key = by_module[module]
    counts = bound_names(parsed.tree.body).counts
    declared = None
    for stmt in parsed.tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.decorator_list or stmt.args.defaults or any(stmt.args.kw_defaults):
                return False
            if (
                any(arg.annotation is not None for arg in argument_nodes(stmt.args))
                or stmt.returns is not None
            ):
                return False
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if not all(isinstance(target, ast.Name) for target in targets):
                return False
            if any(target.id == "__all__" for target in targets):
                value = stmt.value
                if counts["__all__"] != 1 or not isinstance(
                    value, (ast.List, ast.Tuple, ast.Set)
                ):
                    return False
                if not all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                    for item in value.elts
                ):
                    return False
                declared = {item.value for item in value.elts}
            elif stmt.value is not None and any(
                isinstance(node, (ast.Call, ast.Await, ast.Yield, ast.NamedExpr))
                for node in ast.walk(stmt.value)
            ):
                return False
            continue
        return False
    exposed = set(counts) if declared is None else declared
    if exposed.intersection({"exec", "eval", "globals"}):
        return False
    sources = _star_sources(parsed.tree, module, parsed.path)
    return len(sources) == counts["*"] and all(
        _star_preserves_builtins(source, by_module, (*seen, module))
        for source in sources
    )


def find_exec_namespace_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
    module_names: dict[str, str] | None,
    project_root: Path,
) -> list[Any]:
    if not module_names:
        return []
    resolved: dict[str, str] = {}

    def file_key(path: Any) -> str:
        text = str(path)
        key = resolved.get(text)
        if key is None:
            try:
                key = str(Path(text).resolve())
            except OSError:
                key = text
            resolved[text] = key
        return key

    modules_by_file = {file_key(path): name for path, name in module_names.items()}
    by_module = {}
    escapes = []
    for parsed in parsed_files:
        key = file_key(parsed.path)
        module = modules_by_file.get(key)
        if not module:
            continue
        by_module[module] = (parsed, key)
    for module, (parsed, key) in by_module.items():
        star_sources = _star_sources(parsed.tree, module, parsed.path)
        safe_star = len(star_sources) == bound_names(parsed.tree.body).counts[
            "*"
        ] and all(
            _star_preserves_builtins(source, by_module) for source in star_sources
        )
        for owner in _namespace_owners(parsed.tree, safe_star=safe_star):
            escapes.append((module, key, owner))
    if not escapes:
        return []

    # Build this before marking any namespace targets live: an exec in an
    # unreachable helper must not manufacture its own caller. The source graph
    # already records namespace reads as edges owned by the calling function.
    from skylos.deadcode.reachability import analyze_python_reachability

    reachability = analyze_python_reachability(
        definitions,
        [parsed.path for parsed in parsed_files],
        project_root,
        module_names=module_names,
    )
    reached = reachability.reachable_keys | reachability.protected_keys
    live_locations = {
        (file_key(definitions[key].filename), definitions[key].line)
        for key in reached
        if key in definitions
    }
    exposing = {
        module
        for module, key, owner in escapes
        if owner is None or (key, owner.lineno) in live_locations
    }
    if not exposing:
        return []

    exposed: dict[str, bool] = {}
    pending = [(module, True, 0) for module in exposing]
    while pending:
        module, everything, depth = pending.pop()
        if module not in by_module or depth > _MAX_STAR_DEPTH:
            continue
        if exposed.get(module) or (module in exposed and not everything):
            continue
        exposed[module] = everything
        parsed, _key = by_module[module]
        for source in _star_sources(parsed.tree, module, parsed.path):
            pending.append((source, False, depth + 1))

    visible: dict[str, tuple[bool, set[str] | None, dict[int, set[str]], str]] = {}
    for module, everything in exposed.items():
        parsed, key = by_module[module]
        declared = None
        if not everything:
            declared = _declared_all(parsed.tree)
        visible[key] = (everything, declared, _import_lines(parsed.tree), module)

    def shown(name: str, everything: bool, declared: set[str] | None) -> bool:
        if everything:
            return True
        if declared is not None:
            return name in declared
        return not name.startswith("_")

    imported_by_name: dict[str, list[Any]] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) in {"function", "class", "variable"}:
            imported_by_name.setdefault(str(getattr(defn, "name", "")), []).append(defn)

    targets = []
    for defn in definitions.values():
        entry = visible.get(file_key(getattr(defn, "filename", "")))
        if entry is None:
            continue
        everything, declared, import_lines, module = entry
        kind = getattr(defn, "type", None)
        if kind == "import":
            bound = import_lines.get(getattr(defn, "line", 0), set())
            binding = getattr(defn, "binding_name", None) or defn.simple_name
            if binding in bound and shown(binding, everything, declared):
                targets.append(defn)
                targets.extend(imported_by_name.get(str(getattr(defn, "name", "")), ()))
        elif kind in {"function", "class", "variable"}:
            simple = getattr(defn, "simple_name", "")
            if getattr(defn, "name", "") != f"{module}.{simple}":
                continue
            if shown(simple, everything, declared):
                targets.append(defn)
    return targets
