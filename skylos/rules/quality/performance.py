from __future__ import annotations
import ast
import os
import stat
from importlib.machinery import all_suffixes
from pathlib import Path
from skylos.rules.base import SkylosRule
from skylos.rules.quality._receivers import (
    class_method_nodes,
    context_method_kinds,
    method_receiver,
)
from skylos.rules.quality._ast_visit import IterativeNodeVisitor
from skylos.rules.quality._scope import is_non_production_python
from skylos.rules.quality._provider_context import project_local_provider


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in target.elts))
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return set()


class _ScopeBindings(IterativeNodeVisitor):
    """Bindings in one lexical scope, optionally before a source location."""

    def __init__(
        self,
        before_line: int | None = None,
        *,
        track_mutations=False,
        ignored_calls=(),
        ignored_stores=(),
    ):
        self.names: set[str] = set()
        self.mutated_names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self.before_line = before_line
        self.track_mutations = track_mutations
        self.ignored_calls = ignored_calls
        self.ignored_stores = ignored_stores

    def _add(self, node: ast.AST, name: str):
        if self.before_line is None or getattr(node, "lineno", 0) < self.before_line:
            self.names.add(name)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._add(node, node.id)

    def visit_Global(self, node):
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocal_names.update(node.names)

    def _mutated_receiver(self, node):
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        if isinstance(node, ast.Name):
            self._add(node, node.id)
            if self.before_line is None or node.lineno < self.before_line:
                self.mutated_names.add(node.id)

    def visit_Call(self, node):
        if self.track_mutations and node not in self.ignored_calls:
            # Unknown methods and callees can resize a mutable literal alias.
            # A prior list initializer alone cannot establish a fixed count.
            if isinstance(node.func, ast.Attribute):
                self._mutated_receiver(node.func.value)
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                self._mutated_receiver(arg)
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if (
            self.track_mutations
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node not in self.ignored_stores
        ):
            self._mutated_receiver(node.value)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if self.track_mutations and isinstance(node.ctx, (ast.Store, ast.Del)):
            self._mutated_receiver(node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._add(node, node.name)
        # Function creation evaluates these in the enclosing scope. A walrus
        # in a default/decorator can replace an outer item or a builtin name.
        for expression in [
            *node.decorator_list,
            *node.args.defaults,
            *node.args.kw_defaults,
        ]:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._add(node, node.name)
        for expression in [*node.bases, *node.keywords, *node.decorator_list]:
            self.visit(expression)

    def visit_Lambda(self, node):
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_ListComp(self, node):
        # Comprehension targets have their own scope. Walrus expressions can
        # bind in the surrounding scope, so retain those bindings.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.visit(child.target)
            elif self.track_mutations and isinstance(
                child, (ast.Call, ast.Attribute, ast.Subscript)
            ):
                # Comprehension-local targets do not leak, but evaluated
                # callbacks and writes can grow an enclosing mutable source.
                self.visit(child)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Import(self, node):
        for alias in node.names:
            self._add(node, alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self._add(node, alias.asname or alias.name)

    def visit_ExceptHandler(self, node):
        if node.name:
            self._add(node, node.name)
        self.generic_visit(node)


def _os_walk_partition_names(outer: ast.For) -> set[str]:
    """Names bound to the per-directory children returned by ``os.walk``."""
    iterator = outer.iter
    target = outer.target
    if not (
        isinstance(iterator, ast.Call)
        and isinstance(iterator.func, ast.Attribute)
        and isinstance(iterator.func.value, ast.Name)
        and iterator.func.value.id == "os"
        and iterator.func.attr == "walk"
        and isinstance(target, (ast.Tuple, ast.List))
        and len(target.elts) == 3
    ):
        return set()
    return {element.id for element in target.elts[1:] if isinstance(element, ast.Name)}


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _call_chain_has_limiter(node: ast.AST) -> bool:
    current = node
    while isinstance(current, ast.Call):
        func = current.func
        if isinstance(func, ast.Attribute) and func.attr in {
            "first",
            "get",
            "head",
            "limit",
            "one",
            "one_or_none",
            "paginate",
            "take",
        }:
            return True
        current = func.value if isinstance(func, ast.Attribute) else func
    if isinstance(current, ast.Attribute):
        return _call_chain_has_limiter(current.value)
    return False


def _looks_like_orm_query(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        if node.attr == "query":
            return True
        return _looks_like_orm_query(node.value)
    if isinstance(node, ast.Call):
        func_name = _qualified_name(node.func)
        if func_name.endswith((".query", ".select")):
            return True
        if isinstance(node.func, ast.Attribute):
            return _looks_like_orm_query(node.func.value)
    return False


def _is_unbounded_orm_all(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "all":
        return False
    if node.args or node.keywords:
        return False
    receiver = node.func.value
    return _looks_like_orm_query(receiver) and not _call_chain_has_limiter(receiver)


_UNKNOWN_READ_SIZE = object()


_VIEW_METHODS = frozenset({"items", "keys", "values"})
_MUTATING_METHODS = frozenset(
    {
        "append",
        "appendleft",
        "extend",
        "extendleft",
        "insert",
        "update",
        "setdefault",
        "pop",
        "popitem",
        "popleft",
        "clear",
        "remove",
        "discard",
        "add",
        "sort",
        "reverse",
        "__setitem__",
        "__delitem__",
        "__iadd__",
    }
)
_LIST_SHRINKING_METHODS = frozenset({"sort", "reverse", "remove", "pop", "clear"})
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_COPYING_BUILTINS = frozenset(
    {
        "list",
        "tuple",
        "set",
        "frozenset",
        "dict",
        "sorted",
        "len",
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "repr",
        "min",
        "max",
        "sum",
        "any",
        "all",
    }
)


def _is_literal(node: ast.AST) -> bool:
    """A constant, or a display of constants (``[]``, ``{}``, ``("a", 1)``)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(element) for element in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_literal(key) and _is_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    return False


def _item_view_root(node: ast.AST) -> str | None:
    """``T`` for ``T[CONST]``, ``T.get(CONST)`` or ``T.get(CONST, LITERAL)``."""
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and isinstance(node.slice, ast.Constant)
    ):
        return node.value.id
    if (
        isinstance(node, ast.Call)
        and not node.keywords
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Name)
        and 1 <= len(node.args) <= 2
        and isinstance(node.args[0], ast.Constant)
        and all(_is_literal(arg) for arg in node.args[1:])
    ):
        return node.func.value.id
    return None


def _view_root(node: ast.AST) -> str | None:
    """The name a strict per-item view reads from, or None."""
    if (
        isinstance(node, ast.BoolOp)
        and isinstance(node.op, ast.Or)
        and len(node.values) == 2
        and _is_literal(node.values[1])
    ):
        # ``item.get("words") or []``: the fallback is a fixed literal.
        return _view_root(node.values[0])
    if (
        isinstance(node, ast.Call)
        and not node.args
        and not node.keywords
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _VIEW_METHODS
    ):
        receiver = node.func.value
        if isinstance(receiver, ast.Name):
            return receiver.id
        return _item_view_root(receiver)
    return _item_view_root(node)


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _parameters(args: ast.arguments) -> list[ast.arg]:
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if args.vararg:
        parameters.append(args.vararg)
    if args.kwarg:
        parameters.append(args.kwarg)
    return parameters


def _carried_names(node: ast.AST) -> set[str]:
    """Names whose object (or a part of it) ``node`` may evaluate to:
    ``row``, ``row[k]``, ``row.attr``, ``(row, x)``, ``row or x``,
    ``row.get(k)``, ``helper(row)``. A builtin copy carries nothing."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred)):
        return _carried_names(node.value)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return set().union(*(_carried_names(item) for item in node.elts))
    if isinstance(node, ast.BoolOp):
        return set().union(*(_carried_names(value) for value in node.values))
    if isinstance(node, ast.IfExp):
        return _carried_names(node.body) | _carried_names(node.orelse)
    if isinstance(node, ast.NamedExpr):
        return _carried_names(node.value)
    if isinstance(node, ast.Await):
        return _carried_names(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _COPYING_BUILTINS:
            return set()
        carried = set().union(
            *(_carried_names(arg) for arg in node.args),
            *(_carried_names(keyword.value) for keyword in node.keywords),
        )
        if isinstance(node.func, ast.Attribute):
            carried |= _carried_names(node.func.value)
        return carried
    return set()


class _ScopeSummary:
    """Every binding, store and in-place call of one function (or module),
    nested scopes included: a strict proof must hold for all of them."""

    def __init__(self, scope: ast.AST):
        # name -> binding nodes (the Name, arg, alias or statement that binds)
        self.bindings: dict[str, list[ast.AST]] = {}
        # name -> Subscript/Attribute stores, AugAssigns and dels rooted at it
        self.stores: dict[str, list[ast.AST]] = {}
        # name -> in-place method calls on a receiver rooted at it
        self.mutating_calls: dict[str, list[ast.Call]] = {}
        # names declared global or nonlocal anywhere inside the scope
        self.escaped: set[str] = set()
        # names the scope itself binds (not only a nested function or class)
        self.own_names: set[str] = set()
        comprehension_targets = set()
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for parameter in _parameters(scope.args):
                self.bindings.setdefault(parameter.arg, []).append(parameter)
                self.own_names.add(parameter.arg)
        body = scope.body if isinstance(scope.body, list) else [scope.body]
        nodes = [node for statement in body for node in ast.walk(statement)]
        nested = set()
        for node in nodes:
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                nested.update(child for child in ast.walk(node) if child is not node)
        for node in nodes:
            if isinstance(node, _COMPREHENSIONS):
                for generator in node.generators:
                    comprehension_targets.update(
                        child
                        for child in ast.walk(generator.target)
                        if isinstance(child, ast.Name)
                    )
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if node not in comprehension_targets:
                    self.bindings.setdefault(node.id, []).append(node)
            elif isinstance(node, ast.arg):
                self.bindings.setdefault(node.arg, []).append(node)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                self.bindings.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                self.bindings.setdefault(node.name, []).append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    self.bindings.setdefault(name, []).append(node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                self.escaped.update(node.names)
        for name, binding_nodes in self.bindings.items():
            if any(node not in nested for node in binding_nodes):
                self.own_names.add(name)
        for node in nodes:
            if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                root = _root_name(node.value)
                if root is not None:
                    self.stores.setdefault(root, []).append(node)
            elif isinstance(node, ast.AugAssign):
                root = _root_name(node.target)
                if root is not None:
                    self.stores.setdefault(root, []).append(node)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _MUTATING_METHODS
            ):
                root = _root_name(node.func.value)
                if root is not None:
                    self.mutating_calls.setdefault(root, []).append(node)
        # name -> Load uses (to prove a name is only ever iterated)
        self.loads: dict[str, list[ast.Name]] = {}
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.loads.setdefault(node.id, []).append(node)
        # (bound names, names the bound value may carry) per assignment
        self.assign_carriers: list[tuple[set[str], set[str]]] = []
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                bound = set().union(*(_target_names(target) for target in targets))
            elif isinstance(node, ast.NamedExpr):
                bound = _target_names(node.target)
            else:
                continue
            carried = _carried_names(node.value)
            if bound and carried:
                self.assign_carriers.append((bound, carried))
        # Locals bound only from strict views: name -> the names they read.
        self.view_sources: dict[str, set[str]] = {}
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                root = _view_root(node.value)
                for target in targets:
                    if isinstance(target, ast.Name) and root is not None:
                        self.view_sources.setdefault(target.id, set()).add(root)


class PerformanceRule(SkylosRule):
    rule_id = "SKY-P401"
    name = "Performance Checks"

    def __init__(self, ignore_list=None):
        self.ignore_list = ignore_list or []
        self._parents: dict[ast.AST, ast.AST] = {}
        self._global_writes: set[str] = set()
        self._read_nonlocal_writes: set[str] = set()
        self._read_method_kinds = {}
        self._read_dynamic_namespace = False
        self._read_project_root = None
        self._read_filename = None
        self._read_non_library = False
        self._read_source_reader = None
        self._read_project_providers = {}

        self._reset_scope_caches()

    def _reset_scope_caches(self) -> None:
        # Keyed by node identity; valid for the module being visited.
        self._scope_names_cache: dict[ast.AST, frozenset[str]] = {}
        self._scope_imports_cache: dict[
            ast.AST, tuple[dict[str, list[str]], frozenset[str]]
        ] = {}
        self._scope_summary_cache: dict[ast.AST, _ScopeSummary] = {}
        self._binding_kinds_cache: dict[ast.AST, dict[str, str]] = {}
        self._walk_preserving_cache: dict[ast.AST, tuple[set, set]] = {}

    def _scope_names(self, scope: ast.AST) -> frozenset[str]:
        """Names bound by the statements of ``scope`` (see ``_ScopeBindings``)."""
        cached = self._scope_names_cache.get(scope)
        if cached is None:
            bindings = _ScopeBindings()
            for statement in scope.body:
                bindings.visit(statement)
            cached = self._scope_names_cache[scope] = frozenset(bindings.names)
        return cached

    def _scope_imports(
        self, scope: ast.AST
    ) -> tuple[dict[str, list[str]], frozenset[str]]:
        """Top-level absolute imports of ``scope`` by bound name, one entry per
        statement, and the names its other statements bind."""
        cached = self._scope_imports_cache.get(scope)
        if cached is not None:
            return cached
        matches: dict[str, list[str]] = {}
        other = _ScopeBindings()
        for statement in scope.body:
            resolved: dict[str, str] = {}
            if isinstance(statement, ast.ImportFrom) and not statement.level:
                for alias in statement.names:
                    resolved[alias.asname or alias.name] = (
                        f"{statement.module}.{alias.name}"
                    )
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    resolved[alias.asname or alias.name.split(".")[0]] = alias.name
            else:
                other.visit(statement)
            for name, target in resolved.items():
                matches.setdefault(name, []).append(target)
        cached = self._scope_imports_cache[scope] = (matches, frozenset(other.names))
        return cached

    def _enclosing_scope(self, node: ast.AST) -> ast.AST:
        current = node
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, _SCOPES):
                return current
        return current

    def _scope_summary(self, scope: ast.AST) -> _ScopeSummary:
        cached = self._scope_summary_cache.get(scope)
        if cached is None:
            cached = self._scope_summary_cache[scope] = _ScopeSummary(scope)
        return cached

    def _fixed_display_name(self, node: ast.AST) -> bool:
        """A name bound only to list/tuple/set displays without ``*`` and only
        ever used as a loop's iterable: nothing can alias, grow or pass it
        on, so each loop over it runs a fixed number of times. Reassigning it
        inside the outer loop (``patterns = [r"a", r"b"]``) keeps the count."""
        if not isinstance(node, ast.Name):
            return False
        summary = self._scope_summary(self._enclosing_scope(node))
        name = node.id
        bindings = summary.bindings.get(name)
        if not bindings or name in summary.escaped or name not in summary.own_names:
            return False
        for binding in bindings:
            parent = self._parents.get(binding)
            if not (
                isinstance(binding, ast.Name)
                and isinstance(parent, (ast.Assign, ast.AnnAssign))
                and (
                    parent.targets == [binding]
                    if isinstance(parent, ast.Assign)
                    else parent.target is binding
                )
                and isinstance(parent.value, (ast.List, ast.Tuple, ast.Set))
                and not any(isinstance(item, ast.Starred) for item in parent.value.elts)
            ):
                return False
        for load in summary.loads.get(name, ()):
            parent = self._parents.get(load)
            if not (
                isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension))
                and parent.iter is load
            ):
                return False
        return True

    def _strict_inner_names(self, iterator: ast.AST, names: set[str]) -> set | None:
        """Names an inner iterable reads when it is a strict per-item form:
        a view of an item name, ``zip`` of item names or views, or a list or
        tuple display of them (``[segment, *words]``). None otherwise."""
        root = _view_root(iterator)
        if root is not None:
            return {root} if root in names else None
        if isinstance(iterator, (ast.List, ast.Tuple)) and iterator.elts:
            parts = [
                element.value if isinstance(element, ast.Starred) else element
                for element in iterator.elts
            ]
        elif (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id == "zip"
            and self._is_builtin(iterator, "zip")
            and iterator.args
            and all(keyword.arg == "strict" for keyword in iterator.keywords)
            and not any(isinstance(arg, ast.Starred) for arg in iterator.args)
        ):
            parts = iterator.args
        else:
            return None
        used = set()
        for part in parts:
            if isinstance(part, ast.Name) and part.id in names:
                used.add(part.id)
                continue
            root = _view_root(part)
            if root is None or root not in names:
                return None
            used.add(root)
        return used

    def _view_closure(self, outer: ast.For, names: set[str]) -> set[str]:
        """``names`` plus every name they were read from through strict views
        (``words = segment.get("words") or []`` adds ``segment``)."""
        summary = self._scope_summary(self._enclosing_scope(outer))
        closure = set(names)
        pending = list(names)
        while pending:
            for source in summary.view_sources.get(pending.pop(), ()):
                if source not in closure:
                    closure.add(source)
                    pending.append(source)
        return closure

    def _outer_sources_repeat(self, outer: ast.For) -> bool:
        """Whether an outer ``zip``/``enumerate`` argument repeats one shared
        object (``zip(keys, [shared] * n)``); base already checks the plain
        outer iterable."""
        iterator = outer.iter
        if (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id in {"zip", "enumerate"}
            and self._is_builtin(iterator, iterator.func.id)
        ):
            return any(
                isinstance(arg, ast.Starred) or self._repeats_shared_elements(arg)
                for arg in iterator.args
            )
        return False

    def _strict_per_item(self, outer: ast.For, roots: set[str]) -> bool:
        """Every name in ``roots`` holds this outer item's own data.

        Across the whole function: an outer target is bound only by the outer
        ``for``; a local read from a view is bound only from views of
        ``roots``; nothing stores into, deletes from or calls an in-place
        method on any of them (other than ``os.walk``'s list pruning); the
        outer iterable repeats no shared object; and the loop body does not
        pass them to unknown callees.
        """
        if self._outer_sources_repeat(outer):
            return False
        scope = self._enclosing_scope(outer)
        summary = self._scope_summary(scope)
        targets = _target_names(outer.target)
        target_nodes = {
            node for node in ast.walk(outer.target) if isinstance(node, ast.Name)
        }
        walk_calls, walk_stores = self._walk_list_preserving(outer)
        for name in roots:
            if name in summary.escaped:
                return False
            for binding in summary.bindings.get(name, ()):
                if name in targets:
                    if binding not in target_nodes:
                        return False
                    continue
                parent = self._parents.get(binding)
                if not (
                    isinstance(parent, (ast.Assign, ast.AnnAssign))
                    and parent.value is not None
                    and _view_root(parent.value) in roots
                ):
                    return False
            if name not in targets and not summary.bindings.get(name):
                return False
            if any(store not in walk_stores for store in summary.stores.get(name, ())):
                return False
            if any(
                call not in walk_calls for call in summary.mutating_calls.get(name, ())
            ):
                return False
        # Locals that may hold the item or a part of it (``alias = row``,
        # ``child = row[key]``): changing them changes the item.
        aliases = set(roots)
        changed = True
        while changed:
            changed = False
            for bound, carried in summary.assign_carriers:
                if carried & aliases and not bound <= aliases:
                    aliases |= bound
                    changed = True
        for name in aliases - roots:
            if (
                name in summary.escaped
                or any(
                    store not in walk_stores for store in summary.stores.get(name, ())
                )
                or any(
                    call not in walk_calls
                    for call in summary.mutating_calls.get(name, ())
                )
            ):
                return False
        return not self._iteration_sources_mutated(outer, roots)

    def _os_walk_names(self, outer: ast.For) -> set[str]:
        """``dirnames``/``filenames`` of ``for top, dirnames, filenames in os.walk(...)``."""
        names = _os_walk_partition_names(outer)
        if names:
            return names
        iterator, target = outer.iter, outer.target
        if (
            isinstance(iterator, ast.Call)
            and self._is_stdlib_callable(iterator.func, "os", "walk")
            and isinstance(target, (ast.Tuple, ast.List))
            and len(target.elts) == 3
        ):
            return {
                element.id
                for element in target.elts[1:]
                if isinstance(element, ast.Name)
            }
        return set()

    def _walk_list_preserving(self, outer: ast.For) -> tuple[set, set]:
        """Calls and stores that only reorder or shrink ``os.walk``'s lists:
        ``dirnames.sort()``, ``.remove(x)``, ``del dirnames[i]`` and
        ``dirnames[:] = <filter of dirnames>``."""
        cached = self._walk_preserving_cache.get(outer)
        if cached is not None:
            return cached
        walk_names = self._os_walk_names(outer)
        calls, stores = set(), set()
        self._walk_preserving_cache[outer] = (calls, stores)
        if not walk_names:
            return calls, stores
        for node in ast.walk(outer):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _LIST_SHRINKING_METHODS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in walk_names
            ):
                calls.add(node)
            elif isinstance(node, ast.Delete):
                stores.update(
                    target
                    for target in node.targets
                    if isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in walk_names
                )
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name)
                and node.targets[0].value.id in walk_names
                and isinstance(node.targets[0].slice, ast.Slice)
                and node.targets[0].slice.lower is None
                and node.targets[0].slice.upper is None
                and node.targets[0].slice.step is None
                and self._is_partition_expression(
                    node.value, {node.targets[0].value.id}
                )
            ):
                stores.add(node.targets[0])
        return calls, stores

    def _read_binding(self, node: ast.AST, name: str) -> ast.AST | None:
        """Resolve a preceding value on this lexical path, without executing it.

        A conditional write, parameter, mutation or global write is unknown.
        Unlike receiver spelling, a resolved ``with open(...) as x`` provides
        file evidence. These facts are private to P401's materialization check.
        """
        if (
            name in self._global_writes
            or name in self._read_nonlocal_writes
            or self._read_dynamic_namespace
        ):
            return None
        enclosing = node
        while enclosing in self._parents:
            enclosing = self._parents[enclosing]
            if isinstance(
                enclosing, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                break
            if isinstance(enclosing, (ast.For, ast.AsyncFor, ast.While)):
                bindings = _ScopeBindings()
                bindings.visit(enclosing)
                if name in bindings.names:
                    return None
        current = node
        in_function = False
        while current in self._parents:
            parent = self._parents[current]
            if isinstance(parent, ast.ClassDef) and in_function:
                current = parent
                continue
            for field in ("body", "orelse", "finalbody"):
                statements = getattr(parent, field, None)
                if not isinstance(statements, list) or current not in statements:
                    continue
                for statement in reversed(statements[: statements.index(current)]):
                    bindings = _ScopeBindings()
                    bindings.visit(statement)
                    if name not in bindings.names and "*" not in bindings.names:
                        continue
                    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        targets = (
                            statement.targets
                            if isinstance(statement, ast.Assign)
                            else [statement.target]
                        )
                        if any(
                            isinstance(target, ast.Name) and target.id == name
                            for target in targets
                        ):
                            return statement.value
                    return None
            if isinstance(parent, (ast.With, ast.AsyncWith)) and current in parent.body:
                for item in reversed(parent.items):
                    if (
                        isinstance(item.optional_vars, ast.Name)
                        and item.optional_vars.id == name
                    ):
                        return item.context_expr
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = parent.args
                parameters = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(arg is not None and arg.arg == name for arg in parameters):
                    return None
                # A local assigned later shadows any outer binding throughout
                # the function; it is not an initialized outer constant.
                bindings = _ScopeBindings()
                # Lambda bodies are expressions, but their walrus bindings
                # still shadow captured names throughout the lambda scope.
                body = [parent.body] if isinstance(parent, ast.Lambda) else parent.body
                for statement in body:
                    bindings.visit(statement)
                if name in bindings.names or "*" in bindings.names:
                    return None
            current = parent
        return None

    def _read_size_value(self, node: ast.AST, seen=()):
        """Small, bounded integer evaluation; unknown is never proof of a cap."""
        if len(seen) >= 12:
            return _UNKNOWN_READ_SIZE
        if isinstance(node, ast.Constant):
            return (
                node.value
                if node.value is None or type(node.value) is int
                else _UNKNOWN_READ_SIZE
            )
        if isinstance(node, ast.Name) and node.id not in seen:
            value = self._read_binding(node, node.id)
            if value is not None:
                return self._read_size_value(value, (*seen, node.id))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # A literal class chunk-size default is useful source evidence.
            # Reject visible instance/class writes and competing definitions;
            # the spelling "chunk_size" alone is never a bound.
            method = node
            while method in self._parents:
                method = self._parents[method]
                if isinstance(
                    method, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    break
            owner = self._parents.get(method)
            receiver = (
                method_receiver(
                    method, instance_only=True, kinds=self._read_method_kinds
                )
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                else None
            )
            if isinstance(owner, ast.ClassDef) and receiver == node.value.id:
                bindings = _ScopeBindings()
                for statement in method.body:
                    bindings.visit(statement)
                if node.value.id in bindings.names:
                    return _UNKNOWN_READ_SIZE
                root = owner
                while root in self._parents:
                    root = self._parents[root]
                if not self._plain_read_class(owner, root):
                    return _UNKNOWN_READ_SIZE
                candidates = []
                for statement in owner.body:
                    bindings = _ScopeBindings()
                    bindings.visit(statement)
                    if node.attr not in bindings.names and "*" not in bindings.names:
                        continue
                    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        return _UNKNOWN_READ_SIZE
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    if not any(
                        isinstance(target, ast.Name) and target.id == node.attr
                        for target in targets
                    ):
                        return _UNKNOWN_READ_SIZE
                    candidates.append(statement.value)
                if len(candidates) != 1 or candidates[0] is None:
                    return _UNKNOWN_READ_SIZE
                for child in ast.walk(root):
                    if isinstance(child, ast.ClassDef) and child is not owner:
                        inherited = {owner.name}
                        for _ in range(12):
                            previous = set(inherited)
                            for declaration in root.body:
                                if isinstance(declaration, ast.ClassDef) and any(
                                    isinstance(base, ast.Name) and base.id in inherited
                                    for base in declaration.bases
                                ):
                                    inherited.add(declaration.name)
                            if inherited == previous:
                                break
                        if child.name in inherited:
                            if not self._plain_read_class(child, root):
                                return _UNKNOWN_READ_SIZE
                            bindings = _ScopeBindings()
                            for statement in child.body:
                                bindings.visit(statement)
                            if node.attr in bindings.names or "*" in bindings.names:
                                return _UNKNOWN_READ_SIZE
                    if (
                        isinstance(child, ast.Attribute)
                        and child.attr == node.attr
                        and isinstance(child.ctx, (ast.Store, ast.Del))
                    ):
                        return _UNKNOWN_READ_SIZE
                    if isinstance(child, ast.Call):
                        function = _qualified_name(child.func)
                        if (
                            function.rsplit(".", 1)[-1]
                            in {"setattr", "delattr", "__setattr__", "__delattr__"}
                            and len(child.args) > 1
                            and (
                                not isinstance(child.args[1], ast.Constant)
                                or child.args[1].value == node.attr
                            )
                        ):
                            return _UNKNOWN_READ_SIZE
                    if (
                        isinstance(child, ast.Subscript)
                        and isinstance(child.ctx, (ast.Store, ast.Del))
                        and (
                            not isinstance(child.slice, ast.Constant)
                            or child.slice.value == node.attr
                        )
                    ):
                        return _UNKNOWN_READ_SIZE
                    if isinstance(child, (ast.Assign, ast.AnnAssign)):
                        targets = (
                            child.targets
                            if isinstance(child, ast.Assign)
                            else [child.target]
                        )
                        if any(
                            isinstance(target, ast.Name) and target.id == node.attr
                            for target in targets
                        ):
                            if child not in owner.body:
                                return _UNKNOWN_READ_SIZE
                return self._read_size_value(candidates[0], (*seen, node.attr))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            value = self._read_size_value(node.operand, (*seen, "unary"))
            if type(value) is int:
                return -value if isinstance(node.op, ast.USub) else value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult)
        ):
            left = self._read_size_value(node.left, (*seen, "left"))
            right = self._read_size_value(node.right, (*seen, "right"))
            if type(left) is int and type(right) is int:
                if max(left.bit_length(), right.bit_length()) > 128:
                    return _UNKNOWN_READ_SIZE
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                return left * right
        return _UNKNOWN_READ_SIZE

    def _plain_read_class(self, owner, root, seen=()):
        """Only locally resolved, ordinary class lookup supports a size default.

        Imported/dynamic bases, metaclasses, decorators and custom attribute
        lookup do not establish the scalar value observed by a method read.
        """
        if (
            not isinstance(root, ast.Module)
            or self._parents.get(owner) is not root
            or owner in seen
            or len(seen) >= 12
            or owner.decorator_list
            or owner.keywords
            or self._read_dynamic_namespace
        ):
            return False
        definitions = []
        for statement in root.body:
            bindings = _ScopeBindings()
            bindings.visit(statement)
            if owner.name in bindings.names or "*" in bindings.names:
                definitions.append(statement)
        if definitions != [owner]:
            return False
        for statement in owner.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass)):
                continue
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                return False
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            if not all(isinstance(target, ast.Name) for target in targets):
                return False
            value = statement.value
            if value is None:
                continue
            # Class-body expressions may install descriptors or execute code
            # against the class namespace. Only literal metadata or a proved
            # scalar alias supports this ordinary-state proof.
            literal_nodes = (
                ast.Constant,
                ast.Tuple,
                ast.List,
                ast.Set,
                ast.Dict,
                ast.UnaryOp,
                ast.USub,
                ast.UAdd,
                ast.Load,
            )
            if not all(isinstance(child, literal_nodes) for child in ast.walk(value)):
                if self._read_size_value(value) is _UNKNOWN_READ_SIZE:
                    return False
        bindings = _ScopeBindings()
        for statement in owner.body:
            bindings.visit(statement)
        if bindings.names & {
            "__getattribute__",
            "__getattr__",
            "__setattr__",
            "__delattr__",
        } or not self._local_read_receiver_state(owner):
            return False
        if any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in {"eval", "exec", "locals", "vars", "globals"}
            and self._is_builtin(child, child.id)
            for child in ast.walk(owner)
        ):
            return False
        for base in owner.bases:
            if (
                isinstance(base, ast.Name)
                and base.id == "object"
                and self._is_builtin(base, "object")
            ):
                continue
            if not isinstance(base, ast.Name):
                return False
            matches = [
                child
                for child in root.body
                if isinstance(child, ast.ClassDef)
                and child.name == base.id
                and child.lineno < owner.lineno
            ]
            if len(matches) != 1 or not self._plain_read_class(
                matches[0], root, (*seen, owner)
            ):
                return False
        return True

    def _local_read_receiver_state(self, owner):
        """A class default is useful only while its receiver state stays local.

        Permit ordinary attribute access on the bound receiver. Passing the
        receiver as a value, exposing its protocol namespace, or an unresolved
        decorator leaves object state unknown. The surrounding class check
        separately establishes ordinary lookup and the scalar field binding.
        """
        methods = list(class_method_nodes(owner))
        for method in methods:
            if self._read_method_kinds.get(method) == "unknown":
                return False
            receiver = method_receiver(method, kinds=self._read_method_kinds)
            if receiver is None:
                continue
            for child in ast.walk(method):
                if not (
                    isinstance(child, ast.Name)
                    and isinstance(child.ctx, ast.Load)
                    and child.id == receiver
                ):
                    continue
                parent = self._parents.get(child)
                if not (
                    isinstance(parent, ast.Attribute)
                    and parent.value is child
                    and not parent.attr.startswith("__")
                ):
                    return False
        return True

    def _read_bound(self, node: ast.Call) -> str:
        # A caller-chosen size bounds the call by construction; chunked reads
        # are the remedy this rule recommends. Only an omitted size or one
        # that resolves to None, a negative number, or readlines(0) reads all.
        size = node.args[0] if node.args else None
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            return "bounded"
        if size is None:
            size = next(
                (kw.value for kw in node.keywords if kw.arg in {"size", "n", "hint"}),
                None,
            )
        if size is None:
            return "unbounded"
        value = self._read_size_value(size)
        if value is _UNKNOWN_READ_SIZE:
            return "bounded"
        if value is None or value < 0 or (node.func.attr == "readlines" and value == 0):
            return "unbounded"
        return "bounded"

    def _is_memory_buffer(self, origin: ast.AST | None) -> bool:
        return (
            isinstance(origin, ast.Call)
            and self._stdlib_read_module_unshadowed("io")
            and any(
                self._read_stdlib_callable(origin.func, "io", constructor)
                for constructor in ("BytesIO", "StringIO")
            )
        )

    def _local_memory_buffer_read(self, node, origin, *, fixed_contents=False):
        """Keep constructor provenance only while a local buffer stays local.

        Writes and seeks do not turn a genuine buffer into an external stream.
        Replacing a method, exposing the object/namespace, or capturing it in
        another scope does invalidate that fact. For a fixed-content proof,
        writes and writable views additionally invalidate the size bound.
        """
        scope = node
        while scope in self._parents and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            scope = self._parents[scope]
        constructor_scope = origin
        while constructor_scope in self._parents and not isinstance(
            constructor_scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            constructor_scope = self._parents[constructor_scope]
        if constructor_scope is not scope:
            return False
        if node.func.value is origin:
            return True
        nodes = list(ast.walk(scope))
        aliases = set()
        for _ in range(12):
            previous = set(aliases)
            for child in nodes:
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and (
                    child.value is origin
                    or isinstance(child.value, ast.Name)
                    and child.value.id in aliases
                ):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target]
                    )
                    if not all(isinstance(target, ast.Name) for target in targets):
                        return False
                    aliases.update(target.id for target in targets)
                elif (
                    isinstance(child, ast.withitem)
                    and isinstance(self._parents.get(child), ast.With)
                    and (
                        child.context_expr is origin
                        or isinstance(child.context_expr, ast.Name)
                        and child.context_expr.id in aliases
                    )
                ):
                    # This helper is reached only for a proven stdlib buffer;
                    # its synchronous __enter__ returns that same object.
                    # Preserve this normal binding form, then apply identical
                    # escape and method-integrity checks to every alias.
                    if isinstance(child.optional_vars, ast.Name):
                        aliases.add(child.optional_vars.id)
                    elif child.optional_vars is not None:
                        return False
            if aliases == previous:
                break
        else:
            return False
        if not aliases:
            return False
        safe_methods = {
            "read",
            "readline",
            "readlines",
            "write",
            "writelines",
            "seek",
            "tell",
            "truncate",
            "getvalue",
            "getbuffer",
            "close",
            "flush",
            "isatty",
            "readable",
            "seekable",
            "writable",
        }
        if fixed_contents:
            safe_methods -= {"write", "writelines", "truncate", "getbuffer"}
        for child in nodes:
            if not (
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load)
                and child.id in aliases
            ):
                continue
            # An otherwise harmless-looking read in a nested scope can run
            # after the surrounding scope has exposed or replaced the object.
            enclosing = child
            while enclosing in self._parents and enclosing is not scope:
                enclosing = self._parents[enclosing]
                if (
                    isinstance(
                        enclosing,
                        (
                            ast.FunctionDef,
                            ast.AsyncFunctionDef,
                            ast.Lambda,
                            ast.ClassDef,
                        ),
                    )
                    and enclosing is not scope
                ):
                    return False
            parent = self._parents.get(child)
            if (
                isinstance(parent, ast.withitem)
                and parent.context_expr is child
                and isinstance(self._parents.get(parent), ast.With)
                and (
                    parent.optional_vars is None
                    or isinstance(parent.optional_vars, ast.Name)
                    and parent.optional_vars.id in aliases
                )
            ):
                continue
            if (
                isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                and parent.value is child
            ):
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                if all(isinstance(target, ast.Name) for target in targets):
                    continue
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is child
                and isinstance(parent.ctx, ast.Load)
                and parent.attr in safe_methods
            ):
                call = self._parents.get(parent)
                if isinstance(call, ast.Call) and call.func is parent:
                    continue
            return False
        return True

    def _fixed_memory_buffer(self, node, origin):
        # Literal content establishes an input-independent upper bound;
        # arbitrary constructor arguments and subsequent growth do not.
        if origin.keywords or len(origin.args) > 1:
            return False
        if origin.args:
            value = origin.args[0]
            if not (
                isinstance(value, ast.Constant)
                and isinstance(value.value, (bytes, str))
            ):
                return False
        return self._local_memory_buffer_read(node, origin, fixed_contents=True)

    def _memory_buffer_attribute(self, receiver: ast.AST) -> bool:
        """Require ordinary receiver lookup and no competing field writes.

        A buffer initializer in __init__ does not establish what an arbitrary
        later attribute read observes. Aliases, callers, subclasses, reflection
        and method replacement must not turn that initializer into an exemption.
        """
        if not (
            isinstance(receiver, ast.Attribute) and isinstance(receiver.value, ast.Name)
        ):
            return False
        method = receiver
        while method in self._parents and not isinstance(
            method, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            method = self._parents[method]
        owner = self._parents.get(method)
        if not isinstance(owner, ast.ClassDef) or receiver.value.id != method_receiver(
            method, instance_only=True, kinds=self._read_method_kinds
        ):
            return False
        root = owner
        while root in self._parents:
            root = self._parents[root]
        if not self._plain_read_class(owner, root):
            return False
        bindings = _ScopeBindings()
        for statement in method.body:
            bindings.visit(statement)
        if receiver.value.id in bindings.names:
            return False
        initializers = {}
        for item in class_method_nodes(owner):
            name = method_receiver(
                item, instance_only=True, kinds=self._read_method_kinds
            )
            if name is None:
                continue
            for child in ast.walk(item):
                if not isinstance(child, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = (
                    child.targets if isinstance(child, ast.Assign) else [child.target]
                )
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == receiver.attr
                        and isinstance(target.value, ast.Name)
                        and target.value.id == name
                    ):
                        if not self._is_memory_buffer(child.value):
                            return False
                        initializers[target] = child.value
        if not initializers:
            return False
        for child in ast.walk(root):
            if (
                isinstance(child, ast.Attribute)
                and child.attr == receiver.attr
                and isinstance(child.ctx, ast.Load)
            ):
                # Exposing the field itself lets aliases or unknown callees
                # replace its read method without another field assignment.
                access = self._parents.get(child)
                call = self._parents.get(access)
                if not (
                    isinstance(access, ast.Attribute)
                    and access.value is child
                    and access.attr
                    in {
                        "read",
                        "readline",
                        "readlines",
                        "write",
                        "writelines",
                        "seek",
                        "tell",
                        "truncate",
                        "getvalue",
                        "getbuffer",
                        "close",
                        "flush",
                        "isatty",
                        "readable",
                        "seekable",
                        "writable",
                    }
                    and isinstance(call, ast.Call)
                    and call.func is access
                ):
                    return False
            if isinstance(child, ast.ClassDef):
                bindings = _ScopeBindings()
                for statement in child.body:
                    bindings.visit(statement)
                if receiver.attr in bindings.names or "*" in bindings.names:
                    return False
            if isinstance(child, ast.Attribute) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                if child.attr == receiver.attr and child not in initializers:
                    return False
                if any(
                    isinstance(part, ast.Attribute) and part.attr == receiver.attr
                    for part in ast.walk(child.value)
                ):
                    return False
            if (
                isinstance(child, ast.Subscript)
                and isinstance(child.ctx, (ast.Store, ast.Del))
                and (
                    not isinstance(child.slice, ast.Constant)
                    or child.slice.value == receiver.attr
                )
            ):
                return False
            if (
                isinstance(child, ast.Call)
                and _qualified_name(child.func).rsplit(".", 1)[-1]
                in {"setattr", "delattr", "__setattr__", "__delattr__"}
                and len(child.args) > 1
                and (
                    not isinstance(child.args[1], ast.Constant)
                    or child.args[1].value in {receiver.attr, "read", "readlines"}
                )
            ):
                return False
        return True

    def _read_origin(self, node: ast.AST, seen=()) -> ast.AST | None:
        if isinstance(node, ast.Name):
            if node.id in seen or len(seen) >= 12:
                return None
            value = self._read_binding(node, node.id)
            return (
                self._read_origin(value, (*seen, node.id))
                if value is not None
                else None
            )
        return node

    def _read_stdlib_callable(self, node: ast.AST, module: str, symbol: str) -> bool:
        if not self._is_stdlib_callable(node, module, symbol):
            return False
        # An imported module can be monkeypatched without rebinding its name.
        # The generic import resolver is shared with P403, so keep this stricter
        # constructor proof local to P401.
        root = node
        while root in self._parents:
            root = self._parents[root]
        nodes = list(ast.walk(root))
        if any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in {"eval", "exec", "locals", "vars", "globals"}
            and self._is_builtin(child, child.id)
            for child in nodes
        ):
            return False
        if not isinstance(node, ast.Attribute):
            return True
        module_names = {node.value.id}
        for _ in range(12):
            previous = set(module_names)
            for child in nodes:
                if (
                    isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                    and isinstance(child.value, ast.Name)
                    and child.value.id in module_names
                ):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target]
                    )
                    module_names.update(
                        name for target in targets for name in _target_names(target)
                    )
            if previous == module_names:
                break
        for child in nodes:
            if (
                isinstance(child, ast.Attribute)
                and child.attr == "__dict__"
                and isinstance(child.value, ast.Name)
                and child.value.id in module_names
            ):
                return False
            if isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
                child.ctx, (ast.Store, ast.Del)
            ):
                receiver = child.value
                while isinstance(receiver, (ast.Attribute, ast.Subscript)):
                    receiver = receiver.value
                if isinstance(receiver, ast.Name) and receiver.id in module_names:
                    return False
            if isinstance(child, ast.Call) and any(
                isinstance(arg, ast.Name) and arg.id in module_names
                for arg in [*child.args, *(kw.value for kw in child.keywords)]
            ):
                return False
        return True

    def _stdlib_read_module_unshadowed(self, module: str) -> bool:
        """Require project metadata before trusting a shadowable stdlib API."""
        if (
            self._read_project_root is None
            or self._read_filename is None
            or self._read_source_reader is not None
        ):
            # Historical readers return None for both absent and unavailable
            # blobs. They cannot establish shadow-module absence, and HEAD's
            # filesystem must never substitute for that snapshot evidence.
            return False
        root = Path(os.path.abspath(self._read_project_root))
        filename = Path(os.path.abspath(self._read_filename))
        try:
            filename.relative_to(root)
        except ValueError:
            return False
        directories = {root, root / "src", filename.parent}
        for directory in directories:
            try:
                mode = os.lstat(directory).st_mode
            except FileNotFoundError:
                if directory == root / "src":
                    continue
                return False
            except OSError:
                return False
            if not stat.S_ISDIR(mode):
                return False
            for name in [module, *(module + suffix for suffix in all_suffixes())]:
                try:
                    os.lstat(directory / name)
                except FileNotFoundError:
                    continue
                except OSError:
                    return False
                return False
        return True

    def _non_stream_read_api(self, node: ast.Call) -> bool:
        """Prove a stdlib API whose first argument is filenames, not read size.

        Constructor spelling is insufficient. Require an explicit, unshadowed
        import and a local instance whose read method has not escaped or been
        replaced before this call. Unknown receivers retain their warning.
        """
        if node.func.attr != "read" or not self._stdlib_read_module_unshadowed(
            "configparser"
        ):
            return False
        origin = self._read_origin(node.func.value)
        if not isinstance(origin, ast.Call) or not any(
            self._read_stdlib_callable(origin.func, "configparser", constructor)
            for constructor in ("ConfigParser", "RawConfigParser")
        ):
            return False
        root = origin
        while root in self._parents:
            root = self._parents[root]
        constructor_names = (
            {origin.func.id} if isinstance(origin.func, ast.Name) else set()
        )
        nodes = list(ast.walk(root))
        for _ in range(12):
            previous = set(constructor_names)
            for child in nodes:
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and (
                    isinstance(child.value, ast.Name)
                    and child.value.id in constructor_names
                    or _qualified_name(child.value) == _qualified_name(origin.func)
                ):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target]
                    )
                    constructor_names.update(
                        name for target in targets for name in _target_names(target)
                    )
            if previous == constructor_names:
                break
        else:
            return False
        for child in nodes:
            if (
                isinstance(child, (ast.Name, ast.Attribute))
                and isinstance(child.ctx, ast.Load)
                and (
                    isinstance(child, ast.Name)
                    and child.id in constructor_names
                    or _qualified_name(child) == _qualified_name(origin.func)
                )
            ):
                parent = self._parents.get(child)
                if isinstance(parent, ast.Call) and parent.func is child:
                    continue
                if (
                    isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
                    and parent.value is child
                ):
                    targets = (
                        parent.targets
                        if isinstance(parent, ast.Assign)
                        else [parent.target]
                    )
                    if all(isinstance(target, ast.Name) for target in targets):
                        continue
                if (
                    isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and parent.returns is child
                    or isinstance(parent, ast.arg)
                    and parent.annotation is child
                    or isinstance(parent, ast.AnnAssign)
                    and parent.annotation is child
                ):
                    continue
                return False
            if (
                isinstance(child, ast.Attribute)
                and child.attr == "read"
                and isinstance(child.ctx, (ast.Store, ast.Del))
            ):
                return False
            if (
                isinstance(child, ast.Call)
                and _qualified_name(child.func).rsplit(".", 1)[-1]
                in {"setattr", "delattr", "__setattr__", "__delattr__"}
                and len(child.args) > 1
                and (
                    not isinstance(child.args[1], ast.Constant)
                    or child.args[1].value == "read"
                )
            ):
                return False
        scope = node
        while scope in self._parents:
            scope = self._parents[scope]
            if isinstance(scope, (ast.For, ast.AsyncFor, ast.While)):
                return False
            if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                break
        aliases = set()
        nodes = list(ast.walk(scope))
        for _ in range(12):
            previous = set(aliases)
            for child in nodes:
                if isinstance(child, (ast.Assign, ast.AnnAssign)) and (
                    child.value is origin
                    or (isinstance(child.value, ast.Name) and child.value.id in aliases)
                ):
                    targets = (
                        child.targets
                        if isinstance(child, ast.Assign)
                        else [child.target]
                    )
                    if not all(isinstance(target, ast.Name) for target in targets):
                        return False
                    aliases.update(target.id for target in targets)
            if previous == aliases:
                break
        else:
            return False
        if any(
            child is not scope
            and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            )
            and any(
                isinstance(name, ast.Name) and name.id in aliases
                for name in ast.walk(child)
            )
            for child in nodes
        ):
            return False
        if origin is node.func.value:
            return True
        for child in nodes:
            if not (
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load)
                and child.id in aliases
                and origin.lineno <= child.lineno <= node.lineno
            ):
                continue
            parent = self._parents.get(child)
            if parent is node.func:
                continue
            if (
                isinstance(parent, (ast.Assign, ast.AnnAssign))
                and parent.value is child
            ):
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                if all(isinstance(target, ast.Name) for target in targets):
                    continue
            return False
        return True

    def _materialized_return_types(self, annotation, seen=()):
        """Resolve only stable, built-in scalar return contracts."""
        if annotation is None or len(seen) >= 12 or self._read_dynamic_namespace:
            return None
        if isinstance(annotation, ast.Constant):
            if annotation.value is None:
                return frozenset({None})
            if annotation.value in {"str", "bytes"} and self._is_builtin(annotation, annotation.value):
                current = annotation
                while current in self._parents:
                    current = self._parents[current]
                    if isinstance(current, ast.ClassDef) and annotation.value in self._scope_names(current):
                        return None
                return frozenset({annotation.value})
            return None
        if isinstance(annotation, ast.Name):
            name = annotation.id
            current = annotation
            while current in self._parents:
                current = self._parents[current]
                # Function annotations can resolve a class namespace even
                # though a method's runtime body skips that namespace.
                if isinstance(current, ast.ClassDef) and name in self._scope_names(current):
                    return None
            if name in {"str", "bytes"} and self._is_builtin(annotation, name):
                return frozenset({name})
            if name in seen:
                return None
            value = self._read_binding(annotation, name)
            if value is None:
                return None
            root = annotation
            while root in self._parents:
                root = self._parents[root]
            bindings = [child for child in ast.walk(root) if (
                isinstance(child, ast.Name) and child.id == name and not isinstance(child.ctx, ast.Load)
            ) or (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == name
            ) or (
                isinstance(child, ast.alias) and (child.asname or child.name.split(".")[0]) == name
            )]
            if len(bindings) != 1:
                return None
            return self._materialized_return_types(value, (*seen, name))
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            left = self._materialized_return_types(annotation.left, seen)
            right = self._materialized_return_types(annotation.right, seen)
            return left | right if left is not None and right is not None else None
        if isinstance(annotation, ast.Subscript) and self._stdlib_read_module_unshadowed("typing"):
            if self._read_stdlib_callable(annotation.value, "typing", "Optional"):
                inner = self._materialized_return_types(annotation.slice, seen)
                return inner | {None} if inner is not None else None
            if self._read_stdlib_callable(annotation.value, "typing", "Union") and isinstance(annotation.slice, ast.Tuple):
                result = frozenset()
                for item in annotation.slice.elts:
                    inner = self._materialized_return_types(item, seen)
                    if inner is None:
                        return None
                    result |= inner
                return result
        return None

    def _returned_materialized_read(self, node):
        value = node
        parent = self._parents.get(value)
        if isinstance(parent, ast.Await) and parent.value is value:
            value, parent = parent, self._parents.get(parent)
        if isinstance(parent, ast.Attribute) and parent.value is value and parent.attr == "decode":
            call = self._parents.get(parent)
            if not isinstance(call, ast.Call) or call.func is not parent:
                return False
            value, parent = call, self._parents.get(call)
        if not isinstance(parent, ast.Return) or parent.value is not value:
            return False
        function = self._enclosing_scope(parent)
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or function.decorator_list:
            return False
        kinds = self._materialized_return_types(function.returns)
        return bool(kinds and kinds <= {"str", "bytes", None} and kinds & {"str", "bytes"})

    def _whole_buffer_consumer(self, node: ast.Call) -> bool:
        """Known consumers need a complete value, so chunking breaks the API.

        Resolve imports and local shadow modules instead of trusting a parser
        spelling. This deliberately excludes unknown helpers and return/read
        wrappers: those alone do not establish a complete-buffer contract.
        """
        parent = self._parents.get(node)
        if not isinstance(parent, ast.Call):
            return False
        # The argument is the buffer itself, not a later computation that
        # happens to include a read (e.g. hashing or joining several chunks).
        positional = bool(parent.args) and parent.args[0] is node
        if not positional and not any(keyword.value is node for keyword in parent.keywords):
            return False
        if isinstance(parent.func, ast.Name) and parent.func.id == "compile":
            return self._is_builtin(parent, "compile") and (
                positional or any(keyword.arg == "source" and keyword.value is node for keyword in parent.keywords)
            )
        contracts = (
            ("ast", "parse", "source"),
            ("json", "loads", "s"),
            ("tomllib", "loads", "s"),
            ("pickle", "loads", "data"),
            ("marshal", "loads", "bytes"),
            ("gzip", "decompress", "data"),
            ("zlib", "decompress", "data"),
        )
        for module, symbol, argument in contracts:
            if not positional and not any(
                keyword.arg == argument and keyword.value is node for keyword in parent.keywords
            ):
                continue
            if self._stdlib_read_module_unshadowed(module) and self._read_stdlib_callable(
                parent.func, module, symbol
            ):
                return True
        return False

    def _read_message(self, node: ast.Call) -> str | None:
        origin = self._read_origin(node.func.value)
        archive_member = (
            node.func.attr == "read"
            and isinstance(origin, ast.Call)
            and self._stdlib_read_module_unshadowed("zipfile")
            and self._read_stdlib_callable(origin.func, "zipfile", "ZipFile")
        )
        # ZipFile.read(name, pwd=None) names a member; its first argument is
        # not a byte bound as it is on file.read(size). Keep that API's whole
        # member materialization visible instead of treating a name as a size.
        if not archive_member and self._read_bound(node) == "bounded":
            return None
        if self._non_stream_read_api(node):
            return None
        if node.func.attr == "read" and (
            self._whole_buffer_consumer(node) or self._returned_materialized_read(node)
        ):
            return None
        if archive_member:
            return (
                "Potential Memory Risk: 'read()' loads an entire archive member. "
                "For large members, open the member and use bounded reads."
            )
        local_buffer = self._is_memory_buffer(
            origin
        ) and self._local_memory_buffer_read(node, origin)
        attribute_buffer = self._memory_buffer_attribute(node.func.value)
        if local_buffer or attribute_buffer:
            if node.func.attr == "read":
                return None
            if local_buffer and self._fixed_memory_buffer(node, origin):
                return None
            return (
                "Potential Memory Risk: 'readlines()' allocates a new list containing "
                "all remaining lines, even when the source is an in-memory buffer. "
                "For large inputs, iterate over lines instead."
            )
        disk_file = isinstance(origin, ast.Call) and (
            (
                isinstance(origin.func, ast.Name)
                and origin.func.id == "open"
                and self._is_builtin(origin, "open")
            )
            or self._read_stdlib_callable(origin.func, "io", "open")
        )
        if disk_file:
            return (
                f"Potential Memory Risk: '{node.func.attr}()' requests the entire remaining file. "
                "For large files, use chunked reads or iterate over lines."
            )
        return (
            f"Potential Memory Risk: '{node.func.attr}()' has no size limit and may materialize "
            "the entire source if this API implements stream reads. Establish the source size "
            "or use bounded reads for large inputs."
        )

    def _is_builtin(self, node: ast.AST, name: str) -> bool:
        if name in self._global_writes:
            return False
        current = node
        in_function = False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = current.args
                parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
                if args.vararg:
                    parameters.append(args.vararg)
                if args.kwarg:
                    parameters.append(args.kwarg)
                if any(arg.arg == name for arg in parameters):
                    return False
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                names = self._scope_names(current)
                if name in names or "*" in names:
                    return False
        return True

    def _constant_iteration_count(self, node: ast.AST, seen=None) -> bool:
        """Whether iteration count is independent of runtime input sizes."""
        if seen is None:
            seen = set()
        if isinstance(node, ast.Name):
            if node.id in seen or len(seen) >= 8:
                return False
            if self._may_change_in_enclosing_loop(node, node.id):
                return False
            value = self._preceding_value(node, node.id)
            if value is None:
                return False
            return self._constant_iteration_count(value, seen | {node.id})
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return not any(isinstance(item, ast.Starred) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(key is not None for key in node.keys)
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bytes))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            for sequence, count in ((node.left, node.right), (node.right, node.left)):
                if isinstance(count, ast.Constant) and type(count.value) is int:
                    return self._constant_iteration_count(sequence, seen)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"items", "keys", "values"}
            and not node.args
            and not node.keywords
        ):
            receiver = node.func.value
            if isinstance(receiver, ast.Name):
                if self._may_change_in_enclosing_loop(
                    receiver, receiver.id, ignore_call=node
                ):
                    return False
                receiver = self._preceding_value(receiver, receiver.id)
            # These builtin dictionary views preserve its known upper bound.
            # An arbitrary object's similarly named method proves nothing.
            return isinstance(receiver, ast.Dict) and all(
                key is not None for key in receiver.keys
            )
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            return False
        if not self._is_builtin(node, node.func.id) or node.keywords:
            return False
        if node.func.id == "range" and 1 <= len(node.args) <= 3:
            for arg in node.args:
                if isinstance(arg, ast.UnaryOp) and isinstance(
                    arg.op, (ast.USub, ast.UAdd)
                ):
                    arg = arg.operand
                if not isinstance(arg, ast.Constant) or type(arg.value) is not int:
                    return False
            return True
        if node.func.id in {
            "list",
            "tuple",
            "set",
            "iter",
            "reversed",
            "sorted",
            "enumerate",
        }:
            return len(node.args) == 1 and self._constant_iteration_count(
                node.args[0], seen
            )
        return False

    def _may_change_in_enclosing_loop(
        self, node: ast.AST, name: str, *, ignore_call=None
    ) -> bool:
        """Later mutations can affect the next iteration despite source order."""
        current = node
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
            if isinstance(current, (ast.For, ast.AsyncFor, ast.While)):
                bindings = _ScopeBindings(
                    track_mutations=True, ignored_calls={ignore_call}
                )
                for statement in current.body:
                    bindings.visit(statement)
                if name in bindings.names:
                    return True
        return False

    def _preceding_value(self, node: ast.AST, name: str) -> ast.AST | None:
        """Resolve only direct, unambiguously bound preceding assignments."""
        current = node
        in_function = False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if not isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            if isinstance(current, ast.Module) and name in self._global_writes:
                return None
            in_function |= isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef))
            found = False
            value = None
            for stmt in current.body:
                bindings = _ScopeBindings(before_line=node.lineno, track_mutations=True)
                bindings.visit(stmt)
                if name not in bindings.names:
                    continue
                found, value = True, None
                targets = (
                    stmt.targets
                    if isinstance(stmt, ast.Assign)
                    else ([stmt.target] if isinstance(stmt, ast.AnnAssign) else [])
                )
                if any(
                    isinstance(target, ast.Name) and target.id == name
                    for target in targets
                ):
                    value = stmt.value
            if found:
                return value
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = current.args
                params = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(param is not None and param.arg == name for param in params):
                    return None
                bindings = _ScopeBindings()
                for stmt in current.body:
                    bindings.visit(stmt)
                if name in bindings.names:
                    return None
        return None

    def _repeats_shared_elements(self, iterator: ast.AST) -> bool:
        """Sequence multiplication repeats references, not child collections."""
        seen = set()
        for _ in range(8):
            if isinstance(iterator, ast.Name) and iterator.id not in seen:
                seen.add(iterator.id)
                value = self._preceding_value(iterator, iterator.id)
                if value is None:
                    break
                iterator = value
            elif (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Attribute)
                and iterator.func.attr in {"items", "keys", "values"}
                and not iterator.args
                and not iterator.keywords
            ):
                iterator = iterator.func.value
            elif (
                isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Name)
                and iterator.func.id
                in {"list", "tuple", "set", "iter", "reversed", "sorted"}
                and self._is_builtin(iterator, iterator.func.id)
                and len(iterator.args) == 1
                and not iterator.keywords
            ):
                iterator = iterator.args[0]
            else:
                break
        if isinstance(
            iterator, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            produced = (
                iterator.value if isinstance(iterator, ast.DictComp) else iterator.elt
            )
            targets = set().union(
                *(_target_names(generator.target) for generator in iterator.generators)
            )
            # Reading the index does not prove disjointness: overlapping
            # slices and ``items if index else items`` still repeat input.
            # Only identity forwarding preserves the source's row structure.
            if isinstance(produced, ast.Name) and produced.id in targets:
                return any(
                    self._repeats_shared_elements(generator.iter)
                    for generator in iterator.generators
                )
            return not self._constant_iteration_count(produced)
        return (
            not self._constant_iteration_count(iterator)
            and isinstance(iterator, ast.BinOp)
            and isinstance(iterator.op, ast.Mult)
            and (
                isinstance(iterator.left, (ast.List, ast.Tuple))
                or isinstance(iterator.right, (ast.List, ast.Tuple))
            )
        )

    def _walks_outer_partition(self, outer: ast.For, inner: ast.For) -> bool:
        if self._repeats_shared_elements(outer.iter):
            return False
        names = self._partition_names_before(outer, inner)
        iterator = inner.iter
        while isinstance(iterator, ast.Call):
            if isinstance(iterator.func, ast.Name):
                if (
                    iterator.func.id
                    not in {
                        "list",
                        "tuple",
                        "set",
                        "iter",
                        "reversed",
                        "sorted",
                        "enumerate",
                    }
                    or not self._is_builtin(iterator, iterator.func.id)
                    or len(iterator.args) != 1
                    or iterator.keywords
                ):
                    break
                iterator = iterator.args[0]
            else:
                break
        # Properties, subscriptions and arbitrary methods may expose a shared
        # global collection. Only the yielded binding itself is evidence here,
        # plus the strict views below.
        if isinstance(iterator, ast.Name) and iterator.id in names:
            roots = self._view_closure(outer, {iterator.id})
            if roots == {iterator.id}:
                return not self._iteration_sources_mutated(outer, {iterator.id})
            return self._strict_per_item(outer, roots)
        used = self._strict_inner_names(iterator, names)
        if used is not None:
            return self._strict_per_item(outer, self._view_closure(outer, used))
        if (
            isinstance(iterator, ast.Call)
            and self._is_stdlib_callable(iterator.func, "itertools", "chain")
            and iterator.args
            and not iterator.keywords
            and all(
                isinstance(arg, ast.Name) and arg.id in names for arg in iterator.args
            )
        ):
            return not self._iteration_sources_mutated(
                outer, {arg.id for arg in iterator.args}
            )
        # An arbitrary mapping protocol can yield the same backing collection
        # for every key. Forwarding __iter__/__getitem__ alone proves no bound.
        return False

    def _iteration_sources_mutated(self, outer, names: set[str]) -> bool:
        """Reject consumption proofs when a source escapes or is replenished.

        Follow shared aliases through the whole scan, including aliases created
        inside it. Rebinding an alias is not itself a mutation; method calls and
        passing the collection to an unknown callee can change its contents.
        """
        names = set(names)
        body = outer.body
        nodes = [child for statement in body for child in ast.walk(statement)]
        aliases = []

        class Aliases(_ScopeBindings):
            def visit_Assign(visitor, node):
                value = node.value
                if isinstance(value, ast.Call) and (
                    isinstance(value.func, ast.Name)
                    and value.func.id in {"iter", "enumerate", "reversed"}
                    and self._is_builtin(value, value.func.id)
                    and len(value.args) == 1
                    and not value.keywords
                ):
                    value = value.args[0]
                if isinstance(value, ast.Name):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    aliases.extend(
                        (target.id, value.id)
                        for target in targets
                        if isinstance(target, ast.Name)
                    )
                visitor.generic_visit(node)

            visit_AnnAssign = visit_Assign

        scope = outer
        while scope in self._parents:
            scope = self._parents[scope]
            if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
                break
        visitor = Aliases()
        for statement in scope.body:
            visitor.visit(statement)
        while True:
            expanded = names | {
                right if left in names else left
                for left, right in aliases
                if left in names or right in names
            }
            if expanded == names:
                break
            names = expanded
        walk_calls, walk_stores = self._walk_list_preserving(outer)
        pure_calls = {
            node
            for node in nodes
            if isinstance(node, ast.Call)
            and (
                self._is_partition_expression(node, names)
                or self._is_builtin_type_check(node)
            )
        } | walk_calls
        effects = _ScopeBindings(
            track_mutations=True, ignored_calls=pure_calls, ignored_stores=walk_stores
        )
        for statement in body:
            effects.visit(statement)
        # Comprehension targets are local, but evaluated calls can still
        # mutate an outer source; the ordinary scope visitor skips those calls.
        for node in nodes:
            if isinstance(node, ast.Call):
                effects.visit(node)
        return bool(names & effects.mutated_names)

    def _is_partition_expression(self, node: ast.AST, names: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return node.id in names
        root = _view_root(node)
        if root is not None:
            return root in names
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and self._is_builtin(node, "zip")
            and node.args
            and all(keyword.arg == "strict" for keyword in node.keywords)
        ):
            # Pairing partitions yields at most the shortest one's items.
            return all(
                not isinstance(arg, ast.Starred)
                and self._is_partition_expression(arg, names)
                for arg in node.args
            )
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            # Filtering or mapping one source produces at most one output per
            # source item. Additional generators can multiply the work.
            return (
                len(node.generators) == 1
                and not node.generators[0].is_async
                and self._is_partition_expression(node.generators[0].iter, names)
            )
        if isinstance(node, ast.IfExp):
            return self._is_partition_expression(
                node.body, names
            ) and self._is_partition_expression(node.orelse, names)
        if not isinstance(node, ast.Call) or node.keywords:
            return False
        if (
            isinstance(node.func, ast.Name)
            and node.func.id
            in {"list", "tuple", "set", "iter", "reversed", "sorted", "enumerate"}
            and self._is_builtin(node, node.func.id)
            and len(node.args) == 1
        ):
            return self._is_partition_expression(node.args[0], names)
        return (
            self._is_stdlib_callable(node.func, "itertools", "chain")
            and bool(node.args)
            and all(self._is_partition_expression(arg, names) for arg in node.args)
        )

    def _partition_effects(
        self, node: ast.AST, names: set[str], walk_preserving=(set(), set())
    ) -> set[str]:
        # Proven wrappers read their source rather than extending it. Other
        # calls may mutate passed collections, including a callback supplied
        # by the caller; an escaped mutable alias loses its partition proof.
        walk_calls, walk_stores = walk_preserving
        pure_calls = {
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and (
                self._is_partition_expression(child, names)
                or self._is_builtin_type_check(child)
            )
        } | walk_calls
        bindings = _ScopeBindings(
            track_mutations=True, ignored_calls=pure_calls, ignored_stores=walk_stores
        )
        bindings.visit(node)
        # _ScopeBindings omits comprehension-local bindings. Calls in their
        # evaluated expressions still matter to the enclosing collections.
        for expression in ast.walk(node):
            if isinstance(
                expression, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                for child in ast.walk(expression):
                    if isinstance(child, ast.Call):
                        bindings.visit(child)
        return names - bindings.names

    def _is_builtin_type_check(self, node: ast.Call) -> bool:
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and self._is_builtin(node, "isinstance")
            and len(node.args) == 2
            and not node.keywords
        ):
            return False
        classes = (
            node.args[1].elts if isinstance(node.args[1], ast.Tuple) else [node.args[1]]
        )
        return all(
            isinstance(cls, ast.Name)
            and cls.id
            in {
                "list",
                "tuple",
                "dict",
                "set",
                "frozenset",
                "str",
                "bytes",
                "int",
                "float",
                "bool",
            }
            and self._is_builtin(cls, cls.id)
            for cls in classes
        )

    def _partition_names_before(self, outer: ast.For, inner: ast.For) -> set[str]:
        """Propagate bounded aliases and intersect alternative control paths."""
        ancestors = set()
        current = inner
        while current in self._parents and current is not outer:
            current = self._parents[current]
            ancestors.add(current)

        # Track explicit shared-object aliases. Mutating a mapping key does
        # not invalidate a separately yielded value, while passing a direct
        # alias to a callback invalidates both names for that object.
        aliases = []
        for statement in ast.walk(outer):
            if getattr(statement, "lineno", inner.lineno) >= inner.lineno:
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                sources = [value] if isinstance(value, ast.Name) else []
                if isinstance(value, ast.GeneratorExp) and len(value.generators) == 1:
                    sources = [value.generators[0].iter]
                elif isinstance(value, ast.Call) and (
                    (
                        isinstance(value.func, ast.Name)
                        and value.func.id in {"iter", "enumerate", "reversed"}
                        and self._is_builtin(value, value.func.id)
                    )
                    or self._is_stdlib_callable(value.func, "itertools", "chain")
                ):
                    sources = value.args
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                aliases.extend(
                    (target.id, source.id)
                    for target in targets
                    if isinstance(target, ast.Name)
                    for source in sources
                    if isinstance(source, ast.Name)
                )

        walk_preserving = self._walk_list_preserving(outer)

        def effects(expression, names):
            changed = names - self._partition_effects(
                expression, names, walk_preserving
            )
            while True:
                expanded = changed | {
                    right if left in changed else left
                    for left, right in aliases
                    if left in changed or right in changed
                }
                if expanded == changed:
                    return names - changed
                changed = expanded

        def transfer(body, names):
            names = set(names)
            for statement in body:
                if statement is inner:
                    return names
                if isinstance(statement, ast.If):
                    names = effects(statement.test, names)
                    if statement in ancestors:
                        branch = (
                            statement.body
                            if any(
                                child is inner or child in ancestors
                                for child in statement.body
                            )
                            else statement.orelse
                        )
                        return transfer(branch, names)
                    names = transfer(statement.body, names) & transfer(
                        statement.orelse, names
                    )
                    continue
                if statement in ancestors:
                    if isinstance(statement, (ast.With, ast.AsyncWith)):
                        for item in statement.items:
                            names = effects(item.context_expr, names)
                            if item.optional_vars is not None:
                                names -= _target_names(item.optional_vars)
                        return transfer(statement.body, names)
                    # Try/finally and intervening loops need their own flow
                    # model; they do not inherit an unproven alias fact.
                    return set()
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    value = statement.value
                    if value is None:
                        continue
                    names = effects(value, names)
                    partition = self._is_partition_expression(value, names)
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    for target in targets:
                        names -= _target_names(target)
                    if partition:
                        names.update(
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        )
                else:
                    names = effects(statement, names)
            return names

        return transfer(
            outer.body, self._os_walk_names(outer) or _target_names(outer.target)
        )

    def _is_stdlib_callable(self, node: ast.AST, module: str, symbol: str) -> bool:
        """Resolve an explicit import, rejecting shadowing and unknown bindings."""
        if isinstance(node, ast.Name):
            name, expected = node.id, f"{module}.{symbol}"
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.attr == symbol
        ):
            name, expected = node.value.id, module
        else:
            return False
        if name in self._global_writes:
            return False
        current, in_function = node, False
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_function = True
                args = current.args
                parameters = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(arg is not None and arg.arg == name for arg in parameters):
                    return False
            if isinstance(current, ast.ClassDef) and in_function:
                continue
            if not isinstance(
                current,
                (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            imports, other_names = self._scope_imports(current)
            if name in other_names or "*" in other_names:
                return False
            matches = imports.get(name)
            if matches:
                return matches == [expected]
        return False

    def _iterator_origin(self, node: ast.AST, seen=None) -> ast.AST | None:
        """Find an explicitly created single-pass iterator, following aliases.

        Merely iterating the same collection twice is not evidence: lists,
        ranges and mappings restart. Builtin iterator producers and generator
        expressions instead retain their position between the two loops.
        """
        seen = set() if seen is None else seen
        if isinstance(node, ast.Name):
            if node.id in seen or len(seen) >= 8:
                return None
            value = self._preceding_value(node, node.id)
            if value is not None:
                return self._iterator_origin(value, seen | {node.id})
            return None
        if isinstance(node, ast.GeneratorExp):
            return node
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and self._is_builtin(node, node.func.id)
            and node.func.id
            in {"iter", "enumerate", "reversed", "zip", "map", "filter"}
        ):
            return node
        return None

    def _consumes_shared_iterator(self, outer: ast.For, inner: ast.For) -> bool:
        origin = self._iterator_origin(outer.iter)
        if origin is None:
            return False
        iterator = inner.iter
        # A materializing wrapper also consumes the remaining iterator once.
        while (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id
            in {"list", "tuple", "set", "sorted", "iter", "enumerate"}
            and self._is_builtin(iterator, iterator.func.id)
            and len(iterator.args) == 1
            and not iterator.keywords
        ):
            iterator = iterator.args[0]
        if self._iterator_origin(iterator) is not origin:
            return False
        source_names = {
            node.id
            for node in ast.walk(origin)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        if isinstance(outer.iter, ast.Name):
            source_names.add(outer.iter.id)
        # A list iterator has retained position but can still run forever if
        # the body grows its backing list. Single-pass is not a bound then.
        return not self._iteration_sources_mutated(outer, source_names)

    def _nearest_loop(self, node: ast.AST) -> ast.AST | None:
        while node in self._parents:
            node = self._parents[node]
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                return node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                break
        return None

    def _block_outcomes(self, body: list[ast.stmt], loop: ast.For) -> set[str]:
        """Normal control-flow outcomes, with break/continue relative to a loop."""
        outcomes = {"normal"}
        for statement in body:
            if "normal" not in outcomes:
                break
            outcomes.remove("normal")
            outcomes.update(self._statement_outcomes(statement, loop))
        return outcomes

    def _statement_outcomes(self, node: ast.stmt, loop: ast.For) -> set[str]:
        if isinstance(node, ast.Return):
            return {"return"}
        if isinstance(node, ast.Raise):
            return {"raise"}
        if isinstance(node, (ast.Break, ast.Continue)):
            if self._nearest_loop(node) is loop:
                return {"break" if isinstance(node, ast.Break) else "continue"}
            return {"normal"}
        if isinstance(node, ast.If):
            return self._block_outcomes(node.body, loop) | self._block_outcomes(
                node.orelse, loop
            )
        if isinstance(node, (ast.With, ast.AsyncWith)):
            outcomes = self._block_outcomes(node.body, loop)
            if "raise" in outcomes:
                outcomes.add("normal")  # __exit__ may suppress the exception.
            return outcomes
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            # A nested loop may execute zero times or run to completion.
            return (
                {"normal"}
                | self._block_outcomes(node.body, loop)
                | self._block_outcomes(node.orelse, loop)
            )
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            outcomes = self._block_outcomes(node.body, loop)
            if "normal" in outcomes:
                outcomes.remove("normal")
                outcomes.update(self._block_outcomes(node.orelse, loop))
            # Calls in the try body may enter any handler, even without an
            # explicit raise. Do not prove an exit from its happy path alone.
            for handler in node.handlers:
                outcomes.update(self._block_outcomes(handler.body, loop))
            final = self._block_outcomes(node.finalbody, loop)
            return (outcomes if "normal" in final else set()) | (final - {"normal"})
        if isinstance(node, ast.Match):
            outcomes = {"normal"}
            for case in node.cases:
                outcomes.update(self._block_outcomes(case.body, loop))
            return outcomes
        return {"normal"}

    def _leaves_outer_after_scan(self, outer: ast.For, inner: ast.For) -> bool:
        """The nested scan can complete only once before the outer loop exits."""
        path = []
        current = inner
        while current in self._parents:
            parent = self._parents[current]
            path.append((current, parent))
            if parent is outer:
                break
            # A handler/finally can retry or replace an exit. An intervening
            # input-dependent loop can repeat the scan before its own exit.
            if isinstance(parent, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                # The try's handlers do not catch exceptions from one another,
                # and without finally they cannot replace a handler's break.
                if parent.finalbody or not (
                    isinstance(current, ast.ExceptHandler) or current in parent.orelse
                ):
                    return False
            if isinstance(parent, ast.While):
                return False
            if isinstance(
                parent, (ast.For, ast.AsyncFor)
            ) and not self._constant_iteration_count(parent.iter):
                return False
            current = parent
        else:
            return False
        outcomes = {"normal"}
        for current, parent in path:
            for field in ("body", "orelse", "finalbody"):
                body = getattr(parent, field, None)
                if isinstance(body, list) and current in body and "normal" in outcomes:
                    outcomes.remove("normal")
                    outcomes.update(
                        self._block_outcomes(body[body.index(current) + 1 :], outer)
                    )
                    break
            if outcomes and outcomes <= {"return", "break"}:
                return True
        return False

    def _scan_source_value(self, node: ast.AST, name: str) -> ast.AST | None:
        """Find a dominating direct assignment, including loop-local aliases."""
        current = node
        while current in self._parents:
            parent = self._parents[current]
            for field in ("body", "orelse", "finalbody"):
                body = getattr(parent, field, ())
                if not isinstance(body, list) or current not in body:
                    continue
                for statement in reversed(body[: body.index(current)]):
                    bindings = _ScopeBindings(track_mutations=True)
                    bindings.visit(statement)
                    if name not in bindings.names:
                        continue
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                        if isinstance(statement, ast.AnnAssign)
                        else []
                    )
                    if any(
                        isinstance(target, ast.Name) and target.id == name
                        for target in targets
                    ):
                        return statement.value
                    return None
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                return None
            current = parent
        return None

    def _scan_alias_identity(self, node: ast.AST, seen=()):
        """Canonicalize direct name aliases to their lexical object binding."""
        if (
            not isinstance(node, ast.Name)
            or node in seen
            or len(seen) >= 12
            or node.id in self._global_writes
            or node.id in self._read_nonlocal_writes
        ):
            return None
        value = self._scan_source_value(node, node.id)
        if isinstance(value, ast.Name):
            return self._scan_alias_identity(value, (*seen, node))
        if value is not None:
            return ("initializer", id(value))
        scope = node
        while scope in self._parents and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            scope = self._parents[scope]
        return ("binding", id(scope), node.id)

    def _scan_stored_value(self, expression: ast.Subscript):
        """Resolve a dominating dictionary-cell write through direct aliases.

        Only an immediately preceding assignment establishes the cell observed
        by the iterator; callbacks or conditional writes cannot substitute for
        that fact. The receiver must originate in a builtin dict allocation.
        """
        identity = self._scan_alias_identity(expression.value)
        if identity is None or identity[0] != "initializer":
            return None
        root = expression
        while root in self._parents:
            root = self._parents[root]
        origin = next(
            (node for node in ast.walk(root) if id(node) == identity[1]), None
        )
        builtin_mapping = isinstance(origin, (ast.Dict, ast.DictComp)) or (
            isinstance(origin, ast.Call)
            and isinstance(origin.func, ast.Attribute)
            and isinstance(origin.func.value, ast.Name)
            and origin.func.value.id == "dict"
            and origin.func.attr == "fromkeys"
            and self._is_builtin(origin, "dict")
        )
        if not builtin_mapping:
            return None
        current = expression
        while current in self._parents:
            parent = self._parents[current]
            body = getattr(parent, "body", ())
            if isinstance(body, list) and current in body:
                if body.index(current) == 0:
                    return None
                prior = body[body.index(current) - 1]
                if not isinstance(prior, ast.Assign) or len(prior.targets) != 1:
                    return None
                target = prior.targets[0]
                if (
                    isinstance(target, ast.Subscript)
                    and self._scan_alias_identity(target.value) == identity
                    and ast.dump(target.slice, include_attributes=False)
                    == ast.dump(expression.slice, include_attributes=False)
                ):
                    return prior.value
                return None
            current = parent
        return None

    def _recurring_name_scan(self, outer: ast.For, inner: ast.For) -> bool | None:
        """Track cardinality provenance across rebindings and loop backedges.

        Inspect recurring states rather than joining the initial collection
        into every iteration. An unconditional bounded reset can make only the
        first scan expensive; aliases and sequence copies can retain its size.
        Unsupported effects leave the existing source checks in charge.
        """
        if not isinstance(inner.iter, ast.Name):
            return None
        scope = self._parents.get(outer)
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return None
        source_name = inner.iter.id
        bindings = _ScopeBindings()
        for statement in outer.body:
            bindings.visit(statement)
        if (
            source_name not in bindings.names
            or source_name in self._global_writes
            or source_name in self._read_nonlocal_writes
        ):
            return None

        unknown = frozenset({("unknown", None)})
        outer_value = frozenset({("outer", None)})
        names = {node.id for node in ast.walk(scope) if isinstance(node, ast.Name)}
        outer_targets = _target_names(outer.target)
        # This closure only detects possible escapes; it never establishes
        # identity. An alias can be captured before it gets the scan's name.
        pairs = []
        for node in ast.walk(scope):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name) and isinstance(
                        node.value, ast.Name
                    ):
                        pairs.append((target.id, node.value.id))
                    elif (
                        isinstance(target, (ast.Tuple, ast.List))
                        and isinstance(node.value, (ast.Tuple, ast.List))
                        and len(target.elts) == len(node.value.elts)
                    ):
                        pairs.extend(
                            (left.id, right.id)
                            for left, right in zip(target.elts, node.value.elts)
                            if isinstance(left, ast.Name)
                            and isinstance(right, ast.Name)
                        )
        aliases = {source_name}
        while True:
            expanded = aliases | {
                right if left in aliases else left
                for left, right in pairs
                if left in aliases or right in aliases
            }
            if expanded == aliases:
                break
            aliases = expanded
        entry = {name: unknown for name in names}
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = scope.args
            for argument in [
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
                arguments.vararg,
                arguments.kwarg,
            ]:
                if argument is not None:
                    entry[argument.arg] = frozenset({("shared", argument.arg)})

        class Unsupported(Exception):
            pass

        conditions = []

        def control_tests(body):
            for statement in body:
                if statement is inner:
                    continue
                if isinstance(statement, (ast.Break, ast.Return, ast.Raise)):
                    raise Unsupported
                if isinstance(statement, ast.If):
                    conditions.append(self._load_names(statement.test))
                    control_tests(statement.body)
                    control_tests(statement.orelse)

        dependencies = []
        for node in ast.walk(scope):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                if node.value is None:
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                dependencies.extend(
                    (name, source)
                    for target in targets
                    for name in _target_names(target)
                    for source in self._load_names(node.value)
                )

        def condition_dependencies(names):
            names = set(names)
            while True:
                expanded = names | {
                    right if left in names else left
                    for left, right in dependencies
                    if left in names or right in names
                }
                if expanded == names:
                    return names
                names = expanded

        def merge(states):
            result = {}
            for state in states:
                for name, values in state.items():
                    result[name] = result.get(name, frozenset()) | values
            return result

        def invalidate(state, values):
            for name, current in list(state.items()):
                if current & values:
                    state[name] = unknown

        def effects(node, state, *, unpack=False):
            source_values = {
                fact
                for name in aliases
                for fact in state.get(name, unknown)
                if fact[0] in {"bounded", "shared"}
            }
            for child in ast.walk(node):
                if isinstance(
                    child, (ast.NamedExpr, ast.Yield, ast.YieldFrom, ast.Lambda)
                ):
                    raise Unsupported
                if (
                    isinstance(
                        child,
                        (
                            ast.List,
                            ast.Tuple,
                            ast.Set,
                            ast.Dict,
                            ast.ListComp,
                            ast.SetComp,
                            ast.DictComp,
                            ast.GeneratorExp,
                        ),
                    )
                    and not (unpack and child is node)
                    and any(
                        state.get(reference.id, unknown) & source_values
                        for reference in ast.walk(child)
                        if isinstance(reference, ast.Name)
                    )
                ):
                    # A container can carry the source to an opaque callback.
                    # This analysis deliberately has no heap/closure graph.
                    raise Unsupported
                if (
                    isinstance(child, ast.Attribute)
                    and isinstance(child.ctx, ast.Load)
                    and any(
                        state.get(name, unknown) & source_values
                        for name in self._load_names(child.value)
                    )
                ):
                    # Bound methods may escape and resize the source later.
                    raise Unsupported
            copies = {
                child
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in {"list", "tuple"}
                and self._is_builtin(child, child.func.id)
                and len(child.args) == 1
                and not child.keywords
            }
            changed = _ScopeBindings(track_mutations=True, ignored_calls=copies)
            changed.visit(node)
            for name in changed.mutated_names:
                invalidate(state, state.get(name, unknown))
            return changed

        def value(node, state):
            if isinstance(node, ast.Name):
                return state.get(node.id, unknown)
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and not any(
                isinstance(item, ast.Starred) for item in node.elts
            ):
                return frozenset({("bounded", id(node))})
            if isinstance(node, ast.Dict) and all(key is not None for key in node.keys):
                return frozenset({("bounded", id(node))})
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"list", "tuple"}
                and self._is_builtin(node, node.func.id)
                and len(node.args) == 1
                and not node.keywords
            ):
                return value(node.args[0], state)
            if self._constant_iteration_count(node):
                return frozenset({("bounded", id(node))})
            return unknown

        def evaluate(node, state, *, unpack=False):
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                result = evaluate(node.value, state)
                state[node.target.id] = result
                return result
            effects(node, state, unpack=unpack)
            return value(node, state)

        def bind(target, expression, state, previous, supplied=None):
            if isinstance(target, ast.Name):
                state[target.id] = (
                    value(expression, previous) if supplied is None else supplied
                )
            elif (
                isinstance(target, (ast.Tuple, ast.List))
                and isinstance(expression, (ast.Tuple, ast.List))
                and len(target.elts) == len(expression.elts)
            ):
                for item, supplied in zip(target.elts, expression.elts):
                    bind(item, supplied, state, previous)
            else:
                # Attribute/subscript stores can mutate the source or expose
                # it through an object. They need a separate alias proof.
                raise Unsupported

        def block(body, state, scans):
            paths = {"normal": state}
            for statement in body:
                if "normal" not in paths:
                    break
                current = dict(paths.pop("normal"))
                if statement is inner:
                    scans.append(current.get(source_name, unknown))
                    changed = _ScopeBindings(track_mutations=True)
                    for child in inner.body:
                        effects(child, dict(current))
                        changed.visit(child)
                    # A changing live iterator can grow during its very first
                    # scan. A later reset cannot establish a bound for that work.
                    if source_name in changed.names or any(
                        current.get(name, unknown) & current.get(source_name, unknown)
                        for name in changed.mutated_names
                    ):
                        raise Unsupported
                    for name in changed.names:
                        current[name] = unknown
                    next_paths = {"normal": current}
                elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    if statement.value is not None:
                        targets = (
                            statement.targets
                            if isinstance(statement, ast.Assign)
                            else [statement.target]
                        )
                        unpack = (
                            len(targets) == 1
                            and isinstance(targets[0], (ast.Tuple, ast.List))
                            and isinstance(statement.value, (ast.Tuple, ast.List))
                            and len(targets[0].elts) == len(statement.value.elts)
                        )
                        supplied = evaluate(statement.value, current, unpack=unpack)
                        previous = dict(current)
                        for target in targets:
                            bind(target, statement.value, current, previous, supplied)
                    next_paths = {"normal": current}
                elif isinstance(statement, ast.If):
                    effects(statement.test, current)
                    branches = [statement.body, statement.orelse]
                    if isinstance(statement.test, ast.Constant):
                        branches = [branches[not bool(statement.test.value)]]
                    alternatives = [
                        block(branch, dict(current), scans) for branch in branches
                    ]
                    next_paths = {
                        outcome: merge(
                            [path[outcome] for path in alternatives if outcome in path]
                        )
                        for outcome in {key for path in alternatives for key in path}
                    }
                elif isinstance(statement, ast.Continue):
                    next_paths = {"continue": current}
                elif isinstance(statement, (ast.Break, ast.Return, ast.Raise)):
                    next_paths = {}
                elif isinstance(statement, (ast.Expr, ast.Pass, ast.Assert)):
                    changed = effects(statement, current)
                    for name in changed.names - changed.mutated_names:
                        current[name] = unknown
                    next_paths = {"normal": current}
                else:
                    # Loop/exception/context-manager flow needs a separate
                    # proof; never infer a bounded reset by skipping it.
                    raise Unsupported
                for outcome, state in next_paths.items():
                    paths[outcome] = (
                        merge([paths[outcome], state]) if outcome in paths else state
                    )
            return paths

        seen = {}
        scan_states = []
        try:
            prefix_body = scope.body[: scope.body.index(outer)]
            control_tests(prefix_body)
            control_tests(outer.body)
            prior_dependencies = set()
            for condition in conditions:
                # Independent branch joins cannot model phase flags or
                # correlations between a source choice and a later exit.
                if condition & (bindings.names - outer_targets):
                    raise Unsupported
                related = condition_dependencies(condition)
                if related & prior_dependencies:
                    raise Unsupported
                prior_dependencies.update(related)
            # Execute the actual prefix once: saved=catalog must retain its
            # old object/cardinality when catalog is subsequently replaced.
            prefix = block(prefix_body, entry, [])
            if "normal" not in prefix:
                return False
            entry = prefix["normal"]
            if any(condition & outer_targets for condition in conditions) and not (
                isinstance(outer.iter, ast.Name)
                and all(
                    kind == "shared" for kind, _ in entry.get(outer.iter.id, unknown)
                )
            ):
                # Index ranges and derived iterators can select a catalog
                # only once; their order needs a separate recurrence proof.
                raise Unsupported
            # A finite analysis budget is not a finding threshold: unresolved
            # cycles fall back to the existing checks without an exemption.
            for _ in range(32):
                key = frozenset((name, values) for name, values in entry.items())
                if key in seen:
                    recurring = [
                        item for group in scan_states[seen[key] :] for item in group
                    ]
                    if not recurring:
                        return False
                    if any(
                        kind == "shared" for group in recurring for kind, _ in group
                    ):
                        return True
                    if all(
                        kind == "bounded" for group in recurring for kind, _ in group
                    ):
                        return False
                    return None
                seen[key] = len(scan_states)
                current = dict(entry)
                for name in outer_targets:
                    current[name] = outer_value
                scans = []
                paths = block(outer.body, current, scans)
                scan_states.append(scans)
                backedges = [
                    paths[key] for key in ("normal", "continue") if key in paths
                ]
                if not backedges:
                    return False
                entry = merge(backedges)
        except Unsupported:
            return None
        return None

    def _shared_scan_source(
        self,
        outer: ast.For,
        inner: ast.For,
        outer_names: set[str],
        source_override=None,
    ) -> bool:
        """Require source evidence before calling an outer-dependent scan shared.

        Plain independent sources remain candidates. Subscriptions, receiver
        properties and arbitrary calls involving the current item do not prove
        reuse. Recognize only explicit shared-value mappings, direct aliases,
        transparent return-argument helpers and indexed tails of the same list.
        """

        def untouched_mapping(node, name, value):
            initializer = self._parents.get(value)
            scope = node
            while scope in self._parents and not isinstance(
                scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
            ):
                scope = self._parents[scope]
            nested_scopes = (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.Lambda,
                ast.ClassDef,
                ast.GeneratorExp,
            )
            for child in ast.walk(scope):
                if child is scope or not isinstance(child, nested_scopes):
                    continue
                if any(
                    isinstance(reference, ast.Name)
                    and reference.id == name
                    or isinstance(reference, (ast.Global, ast.Nonlocal))
                    and name in reference.names
                    for reference in ast.walk(child)
                ):
                    return False
            for child in ast.walk(scope):
                if not isinstance(child, ast.Name) or child.id != name:
                    continue
                if getattr(child, "lineno", 0) <= getattr(initializer, "end_lineno", 0):
                    continue
                parent = self._parents.get(child)
                if not (
                    isinstance(child.ctx, ast.Load)
                    and isinstance(parent, ast.Subscript)
                    and parent.value is child
                    and isinstance(parent.ctx, ast.Load)
                ):
                    return False
            return True

        def helper_argument(call):
            if (
                not isinstance(call.func, ast.Name)
                or call.func.id in self._global_writes
            ):
                return None
            name = call.func.id
            scope = call
            while scope in self._parents:
                scope = self._parents[scope]
                if not isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
                ):
                    continue
                if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = scope.args
                    if name in {
                        arg.arg
                        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
                    }:
                        return None
                matches = [
                    statement
                    for statement in scope.body
                    if isinstance(statement, ast.FunctionDef) and statement.name == name
                ]
                if not matches:
                    bindings = _ScopeBindings()
                    for statement in scope.body:
                        bindings.visit(statement)
                    if name in bindings.names:
                        return None
                    continue
                if len(matches) != 1:
                    return None
                function = matches[0]
                bindings = _ScopeBindings()
                for statement in scope.body:
                    if statement is not function:
                        bindings.visit(statement)
                args = function.args
                if (
                    name in bindings.names
                    or function.decorator_list
                    or len(function.body) != 1
                    or not isinstance(function.body[0], ast.Return)
                    or not isinstance(function.body[0].value, ast.Name)
                    or args.vararg
                    or args.kwarg
                    or args.kwonlyargs
                    or args.defaults
                ):
                    return None
                parameters = [arg.arg for arg in [*args.posonlyargs, *args.args]]
                if len(call.args) > len(parameters) or any(
                    isinstance(arg, ast.Starred) for arg in call.args
                ):
                    return None
                bound = dict(zip(parameters, call.args))
                for keyword in call.keywords:
                    if keyword.arg not in parameters or keyword.arg in bound:
                        return None
                    bound[keyword.arg] = keyword.value
                return bound.get(function.body[0].value.id)
            return None

        def shared(expression, seen):
            if id(expression) in seen or len(seen) >= 12:
                return False
            seen = seen | {id(expression)}
            if not self._load_names(expression) & outer_names:
                return True
            if isinstance(expression, ast.Name):
                value = self._scan_source_value(expression, expression.id)
                if value is None:
                    return False
                if (
                    not isinstance(value, (ast.Name, ast.Subscript))
                    and not self._load_names(value) & outer_names
                ):
                    current = value
                    while current in self._parents:
                        current = self._parents[current]
                        if current is outer:
                            # A fresh allocation/call evaluated inside the
                            # outer loop is not a stable catalog identity.
                            return False
                return shared(value, seen)
            if isinstance(expression, ast.Subscript) and isinstance(
                expression.value, ast.Name
            ):
                stored = self._scan_stored_value(expression)
                if stored is not None:
                    return shared(stored, seen)
                mapping = expression.value
                value = self._scan_source_value(mapping, mapping.id)
                if value is None or not untouched_mapping(mapping, mapping.id, value):
                    return False
                if isinstance(value, ast.DictComp):
                    targets = set().union(
                        *(
                            _target_names(generator.target)
                            for generator in value.generators
                        )
                    )
                    return (
                        isinstance(value.value, ast.Name)
                        and value.value.id not in targets
                        and shared(value.value, seen)
                    )
                if (
                    isinstance(value, ast.Dict)
                    and value.values
                    and all(key is not None for key in value.keys)
                    and all(isinstance(item, ast.Name) for item in value.values)
                ):
                    identity = ast.dump(value.values[0], include_attributes=False)
                    return all(
                        ast.dump(item, include_attributes=False) == identity
                        for item in value.values
                    ) and shared(value.values[0], seen)
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and isinstance(value.func.value, ast.Name)
                    and value.func.value.id == "dict"
                    and value.func.attr == "fromkeys"
                    and self._is_builtin(value, "dict")
                    and len(value.args) == 2
                    and not value.keywords
                ):
                    fixed = value.args[1]
                    if isinstance(fixed, (ast.List, ast.Tuple)) and not any(
                        isinstance(element, ast.Starred) for element in fixed.elts
                    ):
                        # This fresh literal has no other owner. A fixed-size
                        # bucket stays bounded only when it is merely iterated.
                        scope = mapping
                        while scope in self._parents and not isinstance(
                            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
                        ):
                            scope = self._parents[scope]
                        reads = [
                            child
                            for child in ast.walk(scope)
                            if isinstance(child, ast.Name)
                            and child.id == mapping.id
                            and isinstance(child.ctx, ast.Load)
                        ]
                        if all(
                            isinstance(self._parents.get(child), ast.Subscript)
                            and isinstance(
                                self._parents.get(self._parents[child]), ast.For
                            )
                            and self._parents[self._parents[child]].iter
                            is self._parents[child]
                            for child in reads
                        ):
                            return False
                    return shared(value.args[1], seen)
                return False
            if isinstance(expression, ast.Call):
                argument = helper_argument(expression)
                if isinstance(argument, ast.Name):
                    return shared(argument, seen)
            return False

        # Explicit growth of the very builtin list consumed by the inner
        # loop is a separate positive source fact, even if freshly allocated
        # for each outer item. Follow direct aliases, never opaque callbacks.
        if isinstance(inner.iter, ast.Name):
            aliases = {inner.iter.id}
            pairs = []
            for statement in outer.body:
                if statement is inner:
                    break
                if isinstance(statement, ast.Assign) and isinstance(
                    statement.value, ast.Name
                ):
                    pairs.extend(
                        (target.id, statement.value.id)
                        for target in statement.targets
                        if isinstance(target, ast.Name)
                    )
            while True:
                expanded = aliases | {
                    right if left in aliases else left
                    for left, right in pairs
                    if left in aliases or right in aliases
                }
                if expanded == aliases:
                    break
                aliases = expanded
            nodes = [child for statement in inner.body for child in ast.walk(statement)]
            if not any(
                isinstance(child, ast.Name)
                and isinstance(child.ctx, (ast.Store, ast.Del))
                and child.id in aliases
                for child in nodes
            ):
                fresh_list = any(
                    isinstance(value := self._scan_source_value(inner, name), ast.List)
                    and any(
                        not isinstance(element, ast.Starred) for element in value.elts
                    )
                    for name in aliases
                )
                if fresh_list and any(
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in aliases
                    and child.func.attr in {"append", "extend", "insert"}
                    for child in nodes
                ):
                    return True

        # A file handle is single-pass, but reopening one stable path for
        # each outer item repeats the file search. A finite literal path map
        # also establishes shared sources; arbitrary per-item filenames do not.
        def stable_path(expression, seen=()):
            if id(expression) in seen or len(seen) >= 12:
                return False
            seen = (*seen, id(expression))
            if isinstance(expression, ast.Constant):
                return isinstance(expression.value, (str, bytes))
            if isinstance(expression, ast.Name):
                if expression.id in self._global_writes | self._read_nonlocal_writes:
                    return False
                value = self._read_binding(expression, expression.id)
                if value is None:
                    return expression.id not in outer_names
                return stable_path(value, seen)
            if isinstance(expression, ast.IfExp):
                return stable_path(expression.body, seen) and stable_path(
                    expression.orelse, seen
                )
            if isinstance(expression, ast.Subscript) and isinstance(
                expression.value, ast.Name
            ):
                mapping = expression.value
                value = self._read_binding(mapping, mapping.id)
                if not (
                    isinstance(value, ast.Dict)
                    and value.values
                    and all(key is not None for key in value.keys)
                    and all(stable_path(item, seen) for item in value.values)
                ):
                    return False
                root = mapping
                while root in self._parents:
                    root = self._parents[root]
                # The literal map must not escape or acquire other filenames.
                initializer = self._parents.get(value)
                allowed_targets = set(
                    target
                    for target in getattr(initializer, "targets", ())
                    if isinstance(target, ast.Name)
                )
                return all(
                    reference in allowed_targets
                    or isinstance(reference.ctx, ast.Load)
                    and isinstance(
                        parent := self._parents.get(reference), ast.Subscript
                    )
                    and parent.value is reference
                    and isinstance(parent.ctx, ast.Load)
                    for reference in ast.walk(root)
                    if isinstance(reference, ast.Name) and reference.id == mapping.id
                )
            return False

        if isinstance(inner.iter, ast.Name):
            current = inner
            while current in self._parents and current is not outer:
                parent = self._parents[current]
                if isinstance(parent, ast.With):
                    before = _ScopeBindings()
                    for statement in parent.body:
                        if statement is current:
                            break
                        before.visit(statement)
                    for item in parent.items:
                        call = item.context_expr
                        if (
                            isinstance(item.optional_vars, ast.Name)
                            and item.optional_vars.id == inner.iter.id
                            and inner.iter.id not in before.names
                            and isinstance(call, ast.Call)
                            and isinstance(call.func, ast.Name)
                            and call.func.id == "open"
                            and self._is_builtin(call, "open")
                            and call.args
                            and stable_path(call.args[0])
                        ):
                            return True
                current = parent
        if shared(
            source_override if source_override is not None else inner.iter, set()
        ):
            return True
        # A tail range still scans the same catalog when the range index is
        # used to load catalog[index], as in pairwise DFA state unification.
        iterator = inner.iter
        if not (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id == "range"
            and self._is_builtin(iterator, "range")
            and 1 <= len(iterator.args) <= 3
            and not iterator.keywords
        ):
            return False
        stop = iterator.args[0 if len(iterator.args) == 1 else 1]
        if not (
            isinstance(stop, ast.Call)
            and isinstance(stop.func, ast.Name)
            and stop.func.id == "len"
            and self._is_builtin(stop, "len")
            and len(stop.args) == 1
            and not stop.keywords
        ):
            return False
        source = stop.args[0]
        outer_source = outer.iter
        if (
            isinstance(outer_source, ast.Call)
            and isinstance(outer_source.func, ast.Name)
            and outer_source.func.id == "enumerate"
            and self._is_builtin(outer_source, "enumerate")
            and len(outer_source.args) == 1
            and not outer_source.keywords
        ):
            outer_source = outer_source.args[0]
        identity = self._scan_alias_identity(source)
        if identity is None or self._scan_alias_identity(outer_source) != identity:
            return False
        indices = _target_names(inner.target)
        return any(
            isinstance(child, ast.Subscript)
            and isinstance(child.ctx, ast.Load)
            and self._scan_alias_identity(child.value) == identity
            and isinstance(child.slice, ast.Name)
            and child.slice.id in indices
            for statement in inner.body
            for child in ast.walk(statement)
        )

    def _is_repeated_scan(self, outer: ast.For, inner: ast.For) -> bool:
        if (
            self._constant_iteration_count(outer.iter)
            or self._constant_iteration_count(inner.iter)
            or self._fixed_display_name(inner.iter)
            or self._walks_outer_partition(outer, inner)
            or self._consumes_shared_iterator(outer, inner)
            or self._leaves_outer_after_scan(outer, inner)
            or self._block_outcomes(inner.body, inner) <= {"break", "return"}
        ):
            return False
        outer_names = set(_target_names(outer.target))
        inner_names = set(_target_names(inner.target))
        for statement in outer.body:
            bindings = _ScopeBindings()
            bindings.visit(statement)
            if statement is inner or inner in set(ast.walk(statement)):
                # Bindings inside the inner loop derive from its elements.
                for child in inner.body:
                    inner_bindings = _ScopeBindings()
                    inner_bindings.visit(child)
                    inner_names |= inner_bindings.names
            outer_names |= bindings.names
        outer_names -= inner_names
        # Selection can happen before the loop body: builtin filter and a
        # one-source generator both test catalog members before yielding them.
        iterator = inner.iter
        if isinstance(iterator, ast.Name):
            value = self._scan_source_value(iterator, iterator.id)
            if value is not None:
                iterator = value
        selection_tests = []
        selection_source = None
        selection_names = set(inner_names)
        if (
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id == "filter"
            and self._is_builtin(iterator, "filter")
            and len(iterator.args) == 2
            and not iterator.keywords
            and isinstance(predicate := iterator.args[0], ast.Lambda)
            and len(parameters := _parameters(predicate.args)) == 1
            and not predicate.args.vararg
            and not predicate.args.kwarg
            and not predicate.args.kwonlyargs
        ):
            selection_names.add(parameters[0].arg)
            selection_tests = [predicate.body]
            selection_source = iterator.args[1]
        elif (
            isinstance(iterator, ast.GeneratorExp)
            and len(iterator.generators) == 1
            and not iterator.generators[0].is_async
            and isinstance(iterator.elt, ast.Name)
            and iterator.elt.id in _target_names(iterator.generators[0].target)
        ):
            generator = iterator.generators[0]
            selection_names |= _target_names(generator.target)
            selection_tests = generator.ifs
            selection_source = generator.iter
        iterator_search = bool(selection_tests) and self._relates_items(
            (),
            outer_names - (selection_names - inner_names),
            selection_names,
            extra_tests=selection_tests,
        )
        # An outer-derived source needs positive shared-source evidence.
        # It is not enough for a comparison in its body to mention both loops.
        recurring_source = self._recurring_name_scan(outer, inner)
        # The new pass adds positive provenance only. It cannot suppress a
        # source already recognized by the existing mapping/partition checks.
        if recurring_source is not True and not self._shared_scan_source(
            outer, inner, outer_names, selection_source
        ):
            return False
        if self._required_pair_outputs(inner) and not iterator_search:
            return False
        # Re-scanning the same collection is replaceable by an index only
        # when the inner body searches it for the outer item. All-pairs work
        # (products, matrices, reports) has no shorter equivalent.
        return iterator_search or self._relates_items(
            inner.body, outer_names, inner_names
        )

    def _matrix_cell_result(self, node: ast.AST) -> bool:
        """Recognize direct writes to distinct cells of a fresh builtin grid.

        The grid must be allocated immediately before two range loops with
        matching dimensions. No alias, custom subscription protocol, callback
        or intervening statement participates in this bounded recipe.
        """
        if not isinstance(node, ast.IfExp):
            return False
        statement = self._parents.get(node)
        inner = self._parents.get(statement)
        outer = self._parents.get(inner)
        if not (
            isinstance(statement, ast.Assign)
            and statement.value is node
            and len(statement.targets) == 1
            and isinstance(inner, ast.For)
            and isinstance(outer, ast.For)
            and inner.body == [statement]
            and outer.body == [inner]
            and isinstance(inner.target, ast.Name)
            and isinstance(outer.target, ast.Name)
            and inner.target.id != outer.target.id
        ):
            return False
        target = statement.targets[0]
        if not (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Subscript)
            and isinstance(target.value.value, ast.Name)
            and isinstance(target.slice, ast.Name)
            and target.slice.id == inner.target.id
            and isinstance(target.value.slice, ast.Name)
            and target.value.slice.id == outer.target.id
        ):
            return False
        name = target.value.value.id
        indices = {outer.target.id, inner.target.id}
        if name in indices:
            return False
        # Range indices are builtin ints; direct equality/order tests and
        # passive scalar results cannot invoke a custom sink or predicate.
        allowed = (
            ast.Compare,
            ast.BoolOp,
            ast.UnaryOp,
            ast.Name,
            ast.Constant,
            ast.Load,
            ast.Eq,
            ast.NotEq,
            ast.Lt,
            ast.LtE,
            ast.Gt,
            ast.GtE,
            ast.And,
            ast.Or,
            ast.Not,
        )
        if any(not isinstance(child, allowed) for child in ast.walk(node.test)):
            return False
        if not self._load_names(node.test) <= indices:
            return False
        if any(
            not isinstance(value, (ast.Constant, ast.Name))
            or isinstance(value, ast.Name)
            and value.id not in indices
            for value in (node.body, node.orelse)
        ):
            return False
        parent = self._parents.get(outer)
        body = getattr(parent, "body", ())
        if not isinstance(body, list) or outer not in body or body.index(outer) == 0:
            return False
        initializer = body[body.index(outer) - 1]
        if not (
            isinstance(initializer, ast.Assign)
            and len(initializer.targets) == 1
            and isinstance(initializer.targets[0], ast.Name)
            and initializer.targets[0].id == name
            and isinstance(initializer.value, ast.ListComp)
        ):
            return False
        grid = initializer.value
        if len(grid.generators) != 1:
            return False
        generator = grid.generators[0]
        if generator.is_async or generator.ifs:
            return False
        iterators = (outer.iter, inner.iter, generator.iter)
        if not all(
            isinstance(iterator, ast.Call)
            and isinstance(iterator.func, ast.Name)
            and iterator.func.id == "range"
            and self._is_builtin(iterator, "range")
            and len(iterator.args) == 1
            and isinstance(iterator.args[0], (ast.Name, ast.Constant))
            and not iterator.keywords
            for iterator in iterators
        ):
            return False
        bound = ast.dump(outer.iter.args[0], include_attributes=False)
        if any(
            ast.dump(iterator.args[0], include_attributes=False) != bound
            for iterator in iterators
        ):
            return False
        row = grid.elt
        if isinstance(row, ast.ListComp):
            if len(row.generators) != 1 or not isinstance(row.elt, ast.Constant):
                return False
            row_generator = row.generators[0]
            iterator = row_generator.iter
            if not (
                not row_generator.is_async
                and not row_generator.ifs
                and isinstance(iterator, ast.Call)
                and isinstance(iterator.func, ast.Name)
                and iterator.func.id == "range"
                and self._is_builtin(iterator, "range")
                and len(iterator.args) == 1
                and not iterator.keywords
                and ast.dump(iterator.args[0], include_attributes=False) == bound
            ):
                return False
        elif not (
            isinstance(row, ast.BinOp)
            and isinstance(row.op, ast.Mult)
            and isinstance(row.left, ast.List)
            and len(row.left.elts) == 1
            and isinstance(row.left.elts[0], ast.Constant)
            # A parameter may implement __rmul__ and produce a custom row;
            # range(parameter) only proves __index__, not builtin int type.
            and isinstance(row.right, ast.Constant)
            and type(row.right.value) is int
            and ast.dump(row.right, include_attributes=False) == bound
        ):
            return False
        scope = parent
        while scope in self._parents and not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            scope = self._parents[scope]
        bindings = _ScopeBindings()
        for child in scope.body:
            bindings.visit(child)
        return name not in bindings.global_names | bindings.nonlocal_names

    def _pair_result_condition(self, node: ast.AST) -> bool:
        """A scalar choice produces a result for every pair, not a lookup.

        Keep this structural: a matrix's sole if/else appends one passive
        value to the same fresh local list on either branch. Additional work,
        different sinks, callbacks, and selective outputs are not proofs.
        """

        def passive_value(value):
            if isinstance(value, (ast.Constant, ast.Name)):
                return True
            return isinstance(value, (ast.Tuple, ast.List)) and all(
                passive_value(element) for element in value.elts
            )

        if self._matrix_cell_result(node):
            return True
        outputs = []
        if isinstance(node, ast.IfExp):
            if not (passive_value(node.body) and passive_value(node.orelse)):
                return False
            call = self._parents.get(node)
            statement = self._parents.get(call)
            loop = self._parents.get(statement)
            if not (
                isinstance(call, ast.Call)
                and call.args == [node]
                and not call.keywords
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.attr == "append"
                and isinstance(statement, ast.Expr)
                and isinstance(loop, ast.For)
                and loop.body == [statement]
            ):
                return False
            outputs = [call.func.value.id, call.func.value.id]
        elif isinstance(node, ast.If):
            loop = self._parents.get(node)
            if not isinstance(loop, ast.For) or loop.body != [node]:
                return False
            for body in (node.body, node.orelse):
                if len(body) != 1 or not isinstance(body[0], ast.Expr):
                    return False
                call = body[0].value
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.attr == "append"
                    and len(call.args) == 1
                    and passive_value(call.args[0])
                    and not call.keywords
                ):
                    return False
                outputs.append(call.func.value.id)
        else:
            return False
        if outputs[0] != outputs[1]:
            return False
        return isinstance(
            self._pair_sink_value(outputs[0], loop, [node.test]), ast.List
        )

    def _pair_sink_value(self, name, loop, conditions):
        """Resolve a local output object while rejecting captures and escapes."""
        # A condition can replace or expose the sink before either append.
        # Opaque calls are not a proof that its local identity survives.
        if any(
            isinstance(child, (ast.Call, ast.NamedExpr))
            for test in conditions
            for child in ast.walk(test)
        ) or any(name in self._load_names(test) for test in conditions):
            return None
        # Appending to the iterated list can replenish it indefinitely. An
        # output that aliases an iteration source is not a finite matrix.
        if name in self._load_names(loop.iter):
            return None
        scope = loop
        while scope in self._parents:
            scope = self._parents[scope]
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                break
        bindings = _ScopeBindings()
        for statement in scope.body:
            bindings.visit(statement)
        if name in bindings.global_names | bindings.nonlocal_names:
            return None
        # A closure can capture this binding before the list initializer and
        # replace it from an item comparison during the loop. Initialization
        # does not remove that capture, so inspect the whole enclosing scope.
        nested_scopes = (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
            ast.ClassDef,
            ast.GeneratorExp,
        )
        for child in ast.walk(scope):
            if child is scope or not isinstance(child, nested_scopes):
                continue
            if any(
                isinstance(reference, ast.Name)
                and reference.id == name
                or isinstance(reference, (ast.Global, ast.Nonlocal))
                and name in reference.names
                for reference in ast.walk(child)
            ):
                return None
        current = loop
        while current in self._parents:
            parent = self._parents[current]
            body = getattr(parent, "body", ())
            if isinstance(body, list) and current in body:
                for statement in reversed(body[: body.index(current)]):
                    # A read since initialization can create an alias or
                    # expose the list to an unknown callback. Abstain rather
                    # than guessing that the output stays independent.
                    if name in self._load_names(statement):
                        return None
                    bindings = _ScopeBindings(track_mutations=True)
                    bindings.visit(statement)
                    if name not in bindings.names:
                        continue
                    if (
                        isinstance(statement, ast.Assign)
                        and len(statement.targets) == 1
                        and isinstance(statement.targets[0], ast.Name)
                        and statement.targets[0].id == name
                    ):
                        return statement.value
                    return None
            if parent is scope:
                break
            # Unmodelled conditional paths cannot establish initialization.
            if not isinstance(parent, ast.For):
                return None
            current = parent
        return None

    @staticmethod
    def _passive_pair_value(value, names=None):
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, ast.Name):
            return names is None or value.id in names
        return isinstance(value, (ast.Tuple, ast.List)) and all(
            PerformanceRule._passive_pair_value(element, names)
            for element in value.elts
        )

    def _pair_constructor_class(self, node, seen=()):
        """Resolve lexical construction bindings; spelling never proves a type."""
        if (
            not isinstance(node, ast.Name)
            or node in seen
            or len(seen) >= 12
            or node.id in self._global_writes
            or node.id in self._read_nonlocal_writes
        ):
            return None
        name = node.id
        scope = node
        while scope in self._parents:
            scope = self._parents[scope]
            if not isinstance(
                scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            if not isinstance(scope, ast.Module):
                args = scope.args
                parameters = [
                    *args.posonlyargs,
                    *args.args,
                    *args.kwonlyargs,
                    args.vararg,
                    args.kwarg,
                ]
                if any(
                    parameter is not None and parameter.arg == name
                    for parameter in parameters
                ):
                    return None
            statements = []
            for statement in (
                getattr(scope, "body", ()) if not isinstance(scope, ast.Lambda) else ()
            ):
                bindings = _ScopeBindings()
                bindings.visit(statement)
                if name in bindings.names or "*" in bindings.names:
                    statements.append(statement)
            if not statements:
                continue
            if len(statements) != 1:
                return None
            binding = statements[0]
            if isinstance(binding, ast.ClassDef) and binding.name == name:
                return binding
            if (
                isinstance(binding, ast.Assign)
                and len(binding.targets) == 1
                and isinstance(binding.targets[0], ast.Name)
                and binding.targets[0].id == name
                and isinstance(binding.value, ast.Name)
                and binding.lineno < node.lineno
            ):
                return self._pair_constructor_class(binding.value, (*seen, node))
            return None
        return None

    def _pair_output_call(self, call, loop):
        """Resolve one unconditional output, including a transparent local method."""
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and all(
                self._passive_pair_value(value)
                for value in [*call.args, *(keyword.value for keyword in call.keywords)]
            )
        ):
            return None
        name = call.func.value.id
        value = self._pair_sink_value(name, loop, [])
        if isinstance(value, ast.List):
            return (
                (name, None)
                if call.func.attr == "append"
                and len(call.args) == 1
                and not call.keywords
                else None
            )
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and not value.args
            and not value.keywords
        ):
            return None
        root = loop
        while root in self._parents:
            root = self._parents[root]
        owner = self._pair_constructor_class(value.func)
        if owner is None or not self._plain_read_class(owner, root):
            return None
        if owner.bases or any(
            isinstance(child, ast.FunctionDef) and child.name == "__new__"
            for child in owner.body
        ):
            return None
        # The class object must remain local to ordinary construction. Passing
        # it elsewhere or writing one of its members invalidates method lookup.
        for reference in ast.walk(root):
            if (
                isinstance(reference, ast.Name)
                and isinstance(reference.ctx, ast.Load)
                and reference.id == owner.name
            ):
                parent = self._parents.get(reference)
                if not isinstance(parent, ast.Call) or parent.func is not reference:
                    return None
        methods = {
            statement.name: statement
            for statement in owner.body
            if isinstance(statement, ast.FunctionDef)
        }
        constructor, method = methods.get("__init__"), methods.get(call.func.attr)
        if (
            constructor is None
            or method is None
            or constructor.decorator_list
            or method.decorator_list
        ):
            return None
        constructor_args = constructor.args
        if (
            constructor_args.vararg
            or constructor_args.kwarg
            or constructor_args.kwonlyargs
            or constructor_args.defaults
            or len([*constructor_args.posonlyargs, *constructor_args.args]) != 1
            or len(constructor.body) != 1
        ):
            return None
        initialization = constructor.body[0]
        if not (
            isinstance(initialization, ast.Assign)
            and len(initialization.targets) == 1
            and isinstance(initialization.value, ast.List)
            and self._passive_pair_value(initialization.value)
        ):
            return None
        target = initialization.targets[0]
        constructor_receiver = [*constructor_args.posonlyargs, *constructor_args.args][
            0
        ].arg
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == constructor_receiver
        ):
            return None
        args = method.args
        parameters = [arg.arg for arg in [*args.posonlyargs, *args.args]]
        if (
            args.vararg
            or args.kwarg
            or args.kwonlyargs
            or args.defaults
            or not parameters
            or len(method.body) != 1
        ):
            return None
        statement = method.body[0]
        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, ast.Call
        ):
            return None
        emission = statement.value
        if not (
            isinstance(emission.func, ast.Attribute)
            and emission.func.attr == "append"
            and isinstance(emission.func.value, ast.Attribute)
            and emission.func.value.attr == target.attr
            and isinstance(emission.func.value.value, ast.Name)
            and emission.func.value.value.id == parameters[0]
            and len(emission.args) == 1
            and not emission.keywords
            and self._passive_pair_value(emission.args[0], set(parameters[1:]))
        ):
            return None
        bound = dict(zip(parameters[1:], call.args))
        if len(call.args) > len(parameters) - 1:
            return None
        for keyword in call.keywords:
            if keyword.arg not in parameters[1:] or keyword.arg in bound:
                return None
            bound[keyword.arg] = keyword.value
        if set(bound) != set(parameters[1:]):
            return None
        return name, target.attr

    def _required_pair_outputs(self, loop):
        """Summarize normal/continue paths; every pair must emit one result.

        A branch that emits nothing remains a selective search. Unknown calls,
        exits and side effects do not establish an output-size lower bound.
        """
        tests = []

        def block(body):
            outcomes = [(None, 0, "normal")]
            for statement in body:
                updated = []
                for sink, count, outcome in outcomes:
                    if outcome != "normal":
                        updated.append((sink, count, outcome))
                        continue
                    if isinstance(statement, ast.If):
                        tests.append(statement.test)
                        branch = block(statement.body)
                        alternative = block(statement.orelse)
                        if branch is None or alternative is None:
                            return None
                        for emitted, total, ending in [*branch, *alternative]:
                            if (
                                sink is not None
                                and emitted is not None
                                and sink != emitted
                            ):
                                return None
                            updated.append((sink or emitted, count + total, ending))
                    elif isinstance(statement, ast.Expr):
                        emitted = self._pair_output_call(statement.value, loop)
                        if emitted is None or sink is not None and sink != emitted:
                            return None
                        updated.append((emitted, count + 1, "normal"))
                    elif (
                        isinstance(statement, ast.Continue)
                        and self._nearest_loop(statement) is loop
                    ):
                        updated.append((sink, count, "continue"))
                    elif isinstance(statement, ast.Pass):
                        updated.append((sink, count, "normal"))
                    else:
                        return None
                outcomes = list(set(updated))
                if len(outcomes) > 16 or any(count > 1 for _, count, _ in outcomes):
                    return None
            return outcomes

        outcomes = block(loop.body)
        if not outcomes or any(
            count != 1 or sink is None for sink, count, _ in outcomes
        ):
            return False
        sinks = {sink for sink, _, _ in outcomes}
        return (
            len(sinks) == 1
            and self._pair_sink_value(next(iter(sinks))[0], loop, tests) is not None
        )

    @staticmethod
    def _load_names(node: ast.AST) -> set[str]:
        return {
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
        }

    def _sequence_item_annotation(self, annotation):
        if not isinstance(annotation, ast.Subscript):
            return None
        base = annotation.value
        if isinstance(base, ast.Name) and base.id in {"list", "tuple"} and self._is_builtin(base, base.id):
            if base.id == "tuple":
                parts = annotation.slice
                if not (
                    isinstance(parts, ast.Tuple) and len(parts.elts) == 2
                    and isinstance(parts.elts[1], ast.Constant) and parts.elts[1].value is Ellipsis
                ):
                    return None
                return parts.elts[0]
            return annotation.slice
        if any(self._read_stdlib_callable(base, module, symbol) for module, symbol in (
            ("typing", "List"), ("typing", "Sequence"), ("typing", "Iterable"),
            ("collections.abc", "Sequence"), ("collections.abc", "Iterable"),
        )):
            return annotation.slice
        return None

    def _loop_source_annotation(self, loop):
        scope = self._enclosing_scope(loop)
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        source = loop.iter
        if isinstance(source, ast.Name):
            if source.id in self._scope_names(scope):
                return None
            return next((arg.annotation for arg in _parameters(scope.args) if arg.arg == source.id), None)
        owner = self._parents.get(scope)
        if not (
            isinstance(source, ast.Attribute) and isinstance(source.value, ast.Name)
            and isinstance(owner, ast.ClassDef)
            and source.value.id == method_receiver(scope, instance_only=True, kinds=self._read_method_kinds)
        ):
            return None
        annotations = []
        for method in class_method_nodes(owner):
            receiver = method_receiver(method, instance_only=True, kinds=self._read_method_kinds)
            for statement in ast.walk(method):
                targets = statement.targets if isinstance(statement, ast.Assign) else (
                    [statement.target] if isinstance(statement, (ast.AnnAssign, ast.AugAssign)) else []
                )
                for target in targets:
                    if not (
                        isinstance(target, ast.Attribute) and target.attr == source.attr
                        and isinstance(target.value, ast.Name) and target.value.id == receiver
                    ):
                        continue
                    if not isinstance(statement, ast.AnnAssign):
                        return None
                    annotations.append(statement.annotation)
        return annotations[0] if len(annotations) == 1 else None

    def _regex_loop_item(self, receiver):
        current = receiver
        while current in self._parents:
            current = self._parents[current]
            if isinstance(current, _SCOPES):
                return False
            if not isinstance(current, ast.For) or receiver.id not in _target_names(current.target):
                continue
            annotation = self._sequence_item_annotation(self._loop_source_annotation(current))
            target = current.target
            while isinstance(target, (ast.Tuple, ast.List)):
                if not (
                    isinstance(annotation, ast.Subscript)
                    and isinstance(annotation.value, ast.Name) and annotation.value.id == "tuple"
                    and self._is_builtin(annotation.value, "tuple")
                    and isinstance(annotation.slice, ast.Tuple)
                    and len(annotation.slice.elts) == len(target.elts)
                ):
                    return False
                position = next((index for index, item in enumerate(target.elts) if receiver.id in _target_names(item)), None)
                if position is None:
                    return False
                target, annotation = target.elts[position], annotation.slice.elts[position]
            base = annotation.value if isinstance(annotation, ast.Subscript) else annotation
            return base is not None and self._stdlib_read_module_unshadowed("re") and self._read_stdlib_callable(base, "re", "Pattern")
        return False

    def _regex_predicate(self, call):
        """Regex dispatch is a predicate search, not an indexable equality join."""
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in {"match", "search", "fullmatch"}:
            return False
        if self._stdlib_read_module_unshadowed("re") and self._read_stdlib_callable(call.func, "re", call.func.attr):
            return True
        return isinstance(call.func.value, ast.Name) and self._regex_loop_item(call.func.value)

    def _relates_items(
        self, body, outer_names: set[str], inner_names: set[str], *, extra_tests=()
    ):
        def side(expression):
            names = self._load_names(expression)
            if names & outer_names and not names & inner_names:
                return "outer"
            if names & inner_names and not names & outer_names:
                return "inner"
            return None

        def joins(test, seen=frozenset()):
            if id(test) in seen or len(seen) >= 12:
                return False
            seen = seen | {id(test)}
            for node in ast.walk(test):
                # A comparison assigned to a local Boolean still controls a
                # search when that binding is later used as the condition.
                # Resolve the dominating definition rather than guessing from
                # the variable's spelling or marking every computed flag.
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    value = self._scan_source_value(node, node.id)
                    condition = isinstance(
                        value, (ast.Compare, ast.BoolOp, ast.Name)
                    ) or (
                        isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not)
                    )
                    if condition and joins(value, seen):
                        return True
                if isinstance(node, ast.Compare) and all(
                    isinstance(
                        op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn, ast.Is, ast.IsNot)
                    )
                    for op in node.ops
                ):
                    parts = [node.left, *node.comparators]
                elif isinstance(node, ast.Call):
                    if self._regex_predicate(node):
                        continue
                    callee = (
                        node.func.value
                        if isinstance(node.func, ast.Attribute)
                        else node.func
                    )
                    parts = [callee, *node.args, *(kw.value for kw in node.keywords)]
                else:
                    continue
                sides = {side(part) for part in parts}
                if {"outer", "inner"} <= sides:
                    return True
            return False

        if any(joins(test) for test in extra_tests):
            return True
        pending = list(body)
        while pending:
            node = pending.pop()
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                continue
            if self._pair_result_condition(node):
                # Each branch still emits an output; the comparison chooses
                # its scalar value rather than selecting matching pairs.
                continue
            tests = []
            if isinstance(node, (ast.If, ast.While, ast.IfExp)):
                tests.append(node.test)
            elif isinstance(node, ast.comprehension):
                tests.extend(node.ifs)
            elif isinstance(node, ast.Assert):
                tests.append(node.test)
            if any(joins(test) for test in tests):
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    def _is_pandas_read(self, node):
        # A parser or project-specific object's read_csv method is not
        # necessarily pandas and need not accept chunksize at all.
        if not self._read_stdlib_callable(node.func, "pandas", "read_csv"):
            return False
        if self._read_source_reader is not None:
            # Historical source readers cannot establish provider absence.
            # Preserve their AST-only contract instead of applying HEAD's
            # local modules to a different revision.
            return True
        local = self._read_project_providers.get("pandas")
        if local is None:
            local = self._read_project_providers["pandas"] = project_local_provider(
                "pandas", self._read_filename, self._read_project_root
            )
        return not local

    def _pandas_row_bound(self, node):
        for keyword in node.keywords:
            if keyword.arg not in {"chunksize", "nrows"}:
                continue
            value = self._read_size_value(keyword.value)
            if value is _UNKNOWN_READ_SIZE:
                # A caller-supplied row budget is a bound, as for read(size).
                return True
            if value is not None and (
                value > 0 or keyword.arg == "nrows" and value == 0
            ):
                return True
        return False

    @staticmethod
    def _pandas_lazy_iterator(node):
        # read_csv(iterator=True) returns a TextFileReader instead of eagerly
        # constructing the complete DataFrame. Unknown flags are not proof.
        return any(
            keyword.arg == "iterator"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    def _find_nested_loops(self, outer: ast.For, body: list[ast.stmt]) -> list[ast.For]:
        findings_list = []
        for child in body:
            if isinstance(child, ast.For):
                if self._is_repeated_scan(outer, child):
                    findings_list.append(child)
                elif self._constant_iteration_count(child.iter):
                    # A fixed wrapper does not hide a repeated scan further
                    # inside: rows -> range(2) -> rows is still quadratic.
                    findings_list.extend(self._find_nested_loops(outer, child.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
            elif isinstance(child, ast.If):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
            elif isinstance(child, ast.With):
                findings_list.extend(self._find_nested_loops(outer, child.body))
            elif isinstance(child, ast.Try):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                for handler in child.handlers:
                    findings_list.extend(self._find_nested_loops(outer, handler.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
                if child.finalbody:
                    findings_list.extend(
                        self._find_nested_loops(outer, child.finalbody)
                    )
        return findings_list

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.Module):
            self._read_project_root = context.get("project_root")
            self._read_filename = context.get("filename")
            self._read_project_providers = {}
            # Tests, examples and benchmarks read inputs whose size they set
            # themselves; whole reads there are not a production memory risk.
            self._read_non_library = is_non_production_python(
                context.get("filename"), context.get("project_root")
            )
            self._read_source_reader = context.get("receiver_source_reader")
            self._read_method_kinds = context_method_kinds(node, context)
            self._read_nonlocal_writes = set()
            self._parents = {
                child: parent
                for parent in ast.walk(node)
                for child in ast.iter_child_nodes(parent)
            }
            self._global_writes = set()
            self._reset_scope_caches()
            for scope in ast.walk(node):
                if isinstance(
                    scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    bindings = _ScopeBindings()
                    for statement in scope.body:
                        bindings.visit(statement)
                    self._global_writes.update(bindings.global_names & bindings.names)
                    self._read_nonlocal_writes.update(
                        bindings.nonlocal_names & bindings.names
                    )
            self._read_dynamic_namespace = any(
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load)
                and child.id in {"eval", "exec", "locals", "vars", "globals"}
                and self._is_builtin(child, child.id)
                for child in ast.walk(node)
            )
            return None

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "read",
                "readlines",
            ):
                if "SKY-P401" not in self.ignore_list and not self._read_non_library:
                    message = self._read_message(node)
                    if message is not None:
                        findings.append(
                            {
                                "rule_id": "SKY-P401",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": node.func.attr,
                                "simple_name": node.func.attr,
                                "value": "memory_load",
                                "threshold": 0,
                                "message": message,
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

            if self._is_pandas_read(node):
                if "SKY-P402" not in self.ignore_list:
                    if not self._pandas_row_bound(node) and not self._pandas_lazy_iterator(node):
                        findings.append(
                            {
                                "rule_id": "SKY-P402",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": "read_csv",
                                "simple_name": "read_csv",
                                "value": "no_chunk",
                                "threshold": 0,
                                "message": (
                                    "Pandas Memory Risk: read_csv has no row bound. "
                                    "For large inputs, use chunksize or nrows."
                                ),
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

            if _is_unbounded_orm_all(node):
                if "SKY-P404" not in self.ignore_list:
                    findings.append(
                        {
                            "rule_id": "SKY-P404",
                            "kind": "performance",
                            "severity": "MEDIUM",
                            "type": "function",
                            "name": "all",
                            "simple_name": "all",
                            "value": "unbounded_query",
                            "threshold": 0,
                            "message": "Unbounded ORM .all() call may load an entire table. Add a limit, pagination, or streaming boundary.",
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

        if isinstance(node, ast.For):
            if "SKY-P403" not in self.ignore_list:
                suspect_loops = self._find_nested_loops(node, node.body)
                for inner_loop in suspect_loops:
                    findings.append(
                        {
                            "rule_id": "SKY-P403",
                            "kind": "performance",
                            "severity": "LOW",
                            "type": "loop",
                            "name": "nested_loop",
                            "simple_name": "for",
                            "value": "repeated_scan",
                            "threshold": 0,
                            "message": (
                                "Input-dependent nested iteration can repeat work for "
                                "each outer item. Work may scale with both iteration "
                                "counts; review whether all pairs are required."
                            ),
                            "evidence": {
                                "outer_iterable": ast.unparse(node.iter),
                                "inner_iterable": ast.unparse(inner_loop.iter),
                                "outer_line": node.lineno,
                                "bounded_iteration_proven": False,
                                "single_pass_consumption_proven": False,
                            },
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": inner_loop.lineno,
                            "col": inner_loop.col_offset,
                        }
                    )

        return findings if findings else None
