"""Receiver isolation for XSS API-write checks under the normal data-input model.

Unknown external inputs retain the analyzer's native-data/API assumptions.
Visible constructors, callbacks, protocol changes and capability escapes do not.
This is deliberately not a general Python object-effect interpreter.
"""

from __future__ import annotations

import ast
from copy import copy
from pathlib import Path

from ..builtin_bindings import builtin_references
from ..module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_name_for,
    module_rebinding,
)
from ..project_source import project_source_snapshot
from ..untrusted_sources import UntrustedSourceIndex

_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_NATIVE_MODULES = {"argparse", "html", "markupsafe", "bleach"}
_UNKNOWN_IMPORT = "<unresolved-import-capability>"
_REFLECTION = {
    "__class__",
    "__dict__",
    "__globals__",
    "__closure__",
    "__code__",
    "__wrapped__",
    "__annotations__",
    "__annotate__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__getattribute__",
    "__getattr__",
    "f_globals",
    "f_locals",
    "f_builtins",
    "f_back",
    "gi_frame",
    "cr_frame",
    "ag_frame",
    "tb_frame",
}
_PROTOCOLS = _REFLECTION | {
    "__setattr__",
    "__delattr__",
    "__new__",
    "__init__",
    "__hash__",
    "__eq__",
}
_DYNAMIC = {
    "globals",
    "locals",
    "vars",
    "getattr",
    "exec",
    "eval",
    "compile",
    "__import__",
}
_LOADERS = {
    "importlib",
    "importlib.import_module",
    "importlib.util",
    "importlib.machinery",
}
_MAX_STEPS = 50_000


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        if prefix:
            return prefix + "." + node.attr
    return None


def _generator_function(function):
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            stack.extend(ast.iter_child_nodes(node))
    return False


class _Unit:
    def __init__(self, tree, nodes):
        self.tree = tree
        self.nodes = nodes
        self.parents = {
            id(child): node
            for node in self.nodes
            for child in ast.iter_child_nodes(node)
        }
        self.imports = UntrustedSourceIndex(tree)
        self.bindings = {}
        self.raw_bindings = {}
        self.comprehension_names = {
            id(node): {
                part.id
                for generator in node.generators
                for part in ast.walk(generator.target)
                if isinstance(part, ast.Name)
            }
            for node in self.nodes
            if isinstance(node, _COMPREHENSIONS)
        }
        self.import_origins = {}
        self.import_origin_cache = {}
        self.possible_origin_cache = {}
        self.native_module_cache = {}
        self.origin_expansions = _MAX_STEPS
        self.rebound_events = {}
        self.rebound_limits = {}
        self.builtin_type_refs = frozenset()
        self.local_functions = {}
        self.parameters = {}
        self.annotation_declarations = {}
        self.annotation_only_locals = set()
        self.unevaluated_annotations = set()
        self.mutable_bindings = set()
        self.types_sensitive = False
        self.proof_rebound = frozenset()
        self.proof_event_ids = {}
        self.declarations = {}
        self.literal_cache = {}
        self.mutable_names = {
            name
            for node in self.nodes
            if isinstance(node, (ast.Global, ast.Nonlocal))
            for name in node.names
        }
        self.annotations = set()
        self.builtins = builtin_references(
            tree,
            {"setattr", "delattr", "staticmethod", "classmethod", "property", "type"}
            | _DYNAMIC,
        )
        self.definitions = {
            node.name: node
            for node in self.nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.unsupported_calls = {
            node.name
            for node in self.nodes
            if isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef))
            or isinstance(node, ast.FunctionDef)
            and _generator_function(node)
        }
        for node in self.nodes:
            bound = []
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                bound = [
                    alias.asname or alias.name.split(".")[0] for alias in node.names
                ]
                for alias, name in zip(node.names, bound):
                    if isinstance(node, ast.Import):
                        origin = alias.name if alias.asname else name
                    else:
                        origin = (
                            "." * node.level + (node.module or "") + "." + alias.name
                        )
                    self.import_origins.setdefault(
                        (id(self.scope(node)), name), []
                    ).append((origin, node))
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bound = [node.name]
                if isinstance(node, ast.FunctionDef):
                    self.local_functions.setdefault(
                        (id(self.scope(node)), node.name), []
                    ).append(node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                bound = node.names
                for name in bound:
                    self.declarations[id(self.scope(node)), name] = type(node)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bound = [node.name]
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                bound = [node.name]
            elif isinstance(node, ast.MatchMapping) and node.rest:
                bound = [node.rest]
            for name in bound:
                self.bindings.setdefault((id(self.scope(node)), name), []).append(None)
                self.raw_bindings.setdefault((id(self.scope(node)), name), []).append(
                    None
                )
            if isinstance(node, ast.arg):
                self.parameters[id(self.scope(node)), node.arg] = node
                self.bindings.setdefault((id(self.scope(node)), node.arg), []).append(
                    None
                )
                self.raw_bindings.setdefault(
                    (id(self.scope(node)), node.arg), []
                ).append(None)
                if isinstance(node.annotation, (ast.Name, ast.Attribute)):
                    self.annotations.update(
                        id(part) for part in ast.walk(node.annotation)
                    )
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and isinstance(node.returns, (ast.Name, ast.Attribute)):
                self.annotations.update(id(part) for part in ast.walk(node.returns))
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                parent = self.parents.get(id(node))
                value = (
                    parent.value
                    if isinstance(parent, (ast.Assign, ast.AnnAssign))
                    else None
                )
                self.bindings.setdefault((id(self.scope(node)), node.id), []).append(
                    value
                )
                marker = (id(self.scope(node)), node.id)
                if (
                    isinstance(parent, ast.AnnAssign)
                    and parent.target is node
                    and parent.value is None
                ):
                    self.annotation_declarations.setdefault(marker, []).append(parent)
                    continue
                child, owner = node, parent
                while isinstance(owner, (ast.Tuple, ast.List, ast.Starred)):
                    child, owner = owner, self.parents.get(id(owner))
                if not (isinstance(owner, ast.comprehension) and owner.target is child):
                    binding_scope = self.scope(node)
                    if isinstance(parent, ast.NamedExpr) and parent.target is node:
                        binding_scope = self.evaluation_scope(node)
                        while isinstance(binding_scope, _COMPREHENSIONS):
                            binding_scope = self.evaluation_scope(binding_scope)
                        if id(node) in self.unevaluated_annotations:
                            annotation = parent
                            while annotation is not None and not isinstance(
                                annotation, ast.AnnAssign
                            ):
                                annotation = self.parents.get(id(annotation))
                            if annotation is not None:
                                self.annotation_declarations.setdefault(
                                    (id(binding_scope), node.id), []
                                ).append(annotation)
                            continue
                    self.raw_bindings.setdefault(
                        (id(binding_scope), node.id), []
                    ).append(
                        parent.value if isinstance(parent, ast.NamedExpr) else value
                    )
            if isinstance(node, ast.AnnAssign) and isinstance(
                self.scope(node), (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                self.unevaluated_annotations.update(
                    id(part) for part in ast.walk(node.annotation)
                )
        function_scopes = {
            id(node)
            for node in self.nodes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        }
        for marker in self.annotation_declarations:
            if marker[0] in function_scopes and marker not in self.raw_bindings:
                self.raw_bindings[marker] = [None]
                self.annotation_only_locals.add(marker)
        for node in self.nodes:
            if isinstance(node, ast.Global):
                self.mutable_bindings.update(
                    (id(self.tree), name) for name in node.names
                )
            elif isinstance(node, ast.Nonlocal):
                for name in node.names:
                    outer = self.evaluation_scope(self.scope(node))
                    while outer is not None and outer is not self.tree:
                        marker = (id(outer), name)
                        if (
                            not isinstance(outer, ast.ClassDef)
                            and marker in self.raw_bindings
                            and marker not in self.declarations
                        ):
                            self.mutable_bindings.add(marker)
                            break
                        outer = self.evaluation_scope(outer)

    def mutable_binding(self, scope, name):
        return (id(scope), name) in self.mutable_bindings

    def proof_binding(self, node):
        binding = self.lexical_binding(node)
        if binding is None:
            return None, []
        name, _, _, scope, values = binding
        if self.mutable_binding(scope, name) or (
            scope is self.tree
            and name in self.proof_rebound
            and not self.before_rebinding(node, name)
        ):
            return None, []
        return scope, values

    def builtin_binding(self, node, rebound):
        if not isinstance(node, ast.Name):
            return False
        if self.lexical_binding(node) is None:
            return not self.mutable_binding(self.tree, node.id) and (
                node.id not in rebound or self.before_rebinding(node, node.id)
            )
        return self.proven_import_origin(node, rebound) == "builtins." + node.id

    def actual_builtin(self, node, rebound):
        return id(node) in self.builtins and self.builtin_binding(node, rebound)

    def scope(self, node):
        current = self.parents.get(id(node))
        while current is not None and not isinstance(current, _SCOPES):
            current = self.parents.get(id(current))
        return current or self.tree

    def origin(self, node):
        name = _dotted(node)
        if not name:
            return None
        scope = self.scope(node)
        return self.imports.resolved_import(
            scope
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            else None,
            name,
        )

    def binding(self, node):
        scope = self.scope(node)
        inside_function = False
        while scope is not None:
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inside_function = True
            if inside_function and isinstance(scope, ast.ClassDef):
                scope = self.scope(scope)
                continue
            values = self.bindings.get((id(scope), node.id))
            if values is not None:
                return scope, values
            scope = self.scope(scope) if scope is not self.tree else None
        return None, []

    def evaluation_scope(self, node):
        child = node
        current = self.parents.get(id(child))
        while current is not None:
            if isinstance(current, ast.comprehension):
                owner = self.parents.get(id(current))
                if (
                    isinstance(owner, _COMPREHENSIONS)
                    and current is owner.generators[0]
                    and child is current.iter
                ):
                    child, current = owner, self.parents.get(id(owner))
                    continue
            if isinstance(current, _SCOPES + _COMPREHENSIONS):
                if (
                    isinstance(
                        current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    )
                    and child not in current.body
                ):
                    child, current = current, self.parents.get(id(current))
                    continue
                if isinstance(current, ast.Lambda) and child is current.args:
                    child, current = current, self.parents.get(id(current))
                    continue
                return current
            child, current = current, self.parents.get(id(current))
        return self.tree

    def lexical_binding(self, node):
        dotted = _dotted(node)
        if not dotted:
            return None
        name, separator, rest = dotted.partition(".")
        scope = self.evaluation_scope(node)
        inside_function = False
        while scope is not None:
            if isinstance(
                scope,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda) + _COMPREHENSIONS,
            ):
                inside_function = True
            if inside_function and isinstance(scope, ast.ClassDef):
                scope = self.evaluation_scope(scope)
                continue
            if isinstance(scope, _COMPREHENSIONS):
                if name in self.comprehension_names[id(scope)]:
                    return name, separator, rest, scope, [None]
                scope = self.evaluation_scope(scope)
                continue
            marker = (id(scope), name)
            declaration = self.declarations.get(marker)
            if scope is not self.tree and declaration is ast.Global:
                scope = self.tree
                continue
            if declaration is ast.Nonlocal:
                scope = self.evaluation_scope(scope) if scope is not self.tree else None
                continue
            values = self.raw_bindings.get(marker)
            if values is None:
                scope = self.evaluation_scope(scope) if scope is not self.tree else None
                continue
            return name, separator, rest, scope, values
        return None

    def qualified_origins(self, origins, rest):
        if not rest or not origins:
            return origins
        self.origin_expansions -= len(origins)
        if self.origin_expansions < 0:
            return frozenset({_UNKNOWN_IMPORT})
        return frozenset(
            origin if origin == _UNKNOWN_IMPORT else origin + "." + rest
            for origin in origins
        )

    def possible_import_origins(self, node, rebound):
        """Resolve Name links iteratively; possible imports only reject hazards."""
        pending = []
        seen = set()
        current = node
        result = frozenset({_UNKNOWN_IMPORT})
        for _ in range(_MAX_STEPS):
            key = (id(current), rebound)
            if key in self.possible_origin_cache:
                result = self.possible_origin_cache[key]
                break
            binding = self.lexical_binding(current)
            if binding is None:
                result = frozenset()
                self.possible_origin_cache[key] = result
                break
            name, _separator, rest, scope, values = binding
            marker = (id(scope), name)
            if marker in seen:
                break
            seen.add(marker)
            if marker in self.import_origins:
                result = self.direct_import_origins(current, rebound, binding)
                self.possible_origin_cache[key] = result
                break
            if len(values) != 1 or not isinstance(values[0], ast.Name):
                result = frozenset()
                self.possible_origin_cache[key] = result
                break
            pending.append((key, rest))
            current = values[0]
        for key, rest in reversed(pending):
            result = self.qualified_origins(result, rest)
            self.possible_origin_cache[key] = result
        return result

    def direct_import_origins(self, node, rebound, binding):
        name, _separator, rest, scope, values = binding
        marker = (id(scope), name)
        records = self.import_origins[marker]
        if marker not in self.import_origin_cache:
            overwritten_after = None
            assigned = [value for value in values if value is not None]
            if len(assigned) == 1 and len(values) == len(records) + 1:
                value = assigned[0]
                assignment = self.parents.get(id(value))
                if (
                    isinstance(value, ast.Constant)
                    and type(value.value)
                    in {str, bytes, int, float, complex, bool, type(None)}
                    and isinstance(assignment, (ast.Assign, ast.AnnAssign))
                    and self.parents.get(id(assignment)) is scope
                    and name not in self.mutable_names
                    and all(
                        (imported.end_lineno, imported.end_col_offset)
                        < (assignment.lineno, assignment.col_offset)
                        for _, imported in records
                    )
                ):
                    overwritten_after = (
                        assignment.end_lineno,
                        assignment.end_col_offset,
                    )
            self.import_origin_cache[marker] = (
                frozenset(origin for origin, _ in records),
                overwritten_after,
            )
        origins, overwritten_after = self.import_origin_cache[marker]
        if (
            overwritten_after is not None
            and (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
            > overwritten_after
            and name not in rebound
        ):
            return frozenset()
        return self.qualified_origins(origins, rest)

    def before_rebinding(self, node, name):
        """A simple module statement runs before every recorded literal write."""
        if name not in self.rebound_limits:
            sites = self.rebound_events.get(name, ())
            positions = []
            complete = bool(sites)
            for site in sites:
                parent = self.parents.get(id(site))
                if id(site) in self.unevaluated_annotations or (
                    isinstance(site, ast.Attribute)
                    and isinstance(parent, ast.AnnAssign)
                    and parent.target is site
                    and parent.value is None
                ):
                    continue
                stmt = site
                while stmt is not None and not isinstance(stmt, ast.stmt):
                    stmt = self.parents.get(id(stmt))
                if (
                    not isinstance(
                        stmt, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Delete)
                    )
                    or self.parents.get(id(stmt)) is not self.tree
                ):
                    complete = False
                    break
                positions.append((stmt.lineno, stmt.col_offset))
            self.rebound_limits[name] = (
                (min(positions) if positions else ()) if complete else None
            )
        limit = self.rebound_limits[name]
        if limit == ():
            return True
        stmt = node
        while stmt is not None and not isinstance(stmt, ast.stmt):
            stmt = self.parents.get(id(stmt))
        return (
            limit is not None
            and isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign, ast.Delete))
            and self.parents.get(id(stmt)) is self.tree
            and (stmt.end_lineno, stmt.end_col_offset) < limit
        )

    def proven_import_origin(self, node, rebound):
        pending = []
        seen = set()
        current = node
        result = None
        for _ in range(_MAX_STEPS):
            key = (id(current), rebound)
            if key in self.native_module_cache:
                result = self.native_module_cache[key]
                break
            if not isinstance(current, (ast.Name, ast.Attribute)):
                break
            binding = self.lexical_binding(current)
            if binding is None:
                pending.append((key, ""))
                if (
                    isinstance(current, ast.Name)
                    and id(current) in self.builtin_type_refs
                    and not self.mutable_binding(self.tree, current.id)
                    and (
                        current.id not in rebound
                        or self.before_rebinding(current, current.id)
                    )
                ):
                    result = "builtins." + current.id
                break
            name, _separator, rest, scope, values = binding
            pending.append((key, rest))
            marker = (id(scope), name)
            if (
                marker in seen
                or self.mutable_binding(scope, name)
                or (
                    scope is self.tree
                    and name in rebound
                    and not self.before_rebinding(current, name)
                )
            ):
                break
            seen.add(marker)
            records = self.import_origins.get(marker, ())
            origins = {origin for origin, _ in records}
            if (
                records
                and len(values) == len(records)
                and all(value is None for value in values)
                and len(origins) == 1
            ):
                origin = next(iter(origins))
                result = origin
                break
            if (
                records
                or len(values) != 1
                or not isinstance(values[0], (ast.Name, ast.Attribute))
            ):
                break
            current = values[0]
        for key, rest in reversed(pending):
            if result is not None and rest:
                result += "." + rest
            self.native_module_cache[key] = result
        return result

    def native_module_origin(self, node, rebound):
        if not isinstance(node, ast.Name):
            return None
        origin = self.proven_import_origin(node, rebound)
        modules = _NATIVE_MODULES | ({"types"} if self.types_sensitive else set())
        return origin if origin in modules else None


def _hazardous_imports(origins):
    return any(
        origin
        in _LOADERS
        | {
            _UNKNOWN_IMPORT,
            "operator.attrgetter",
            "operator.methodcaller",
            "types.new_class",
        }
        or origin
        and origin.startswith(
            (
                _UNKNOWN_IMPORT,
                "importlib.",
                "sys.path",
                "sys.meta_path",
                "sys.modules",
                "builtins.",
            )
        )
        for origin in origins
    )


_MODULE_READERS = {
    "getattr",
    "hasattr",
    "dir",
    "isinstance",
    "issubclass",
    "id",
    "repr",
    "str",
    "type",
    "print",
    "callable",
    "hash",
    "bool",
}
_BUILTIN_TYPES = {
    "bool",
    "bytes",
    "bytearray",
    "complex",
    "dict",
    "float",
    "frozenset",
    "int",
    "list",
    "memoryview",
    "object",
    "range",
    "set",
    "slice",
    "str",
    "tuple",
    "type",
    "BaseException",
    "Exception",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BufferError",
    "EOFError",
    "ImportError",
    "LookupError",
    "MemoryError",
    "NameError",
    "OSError",
    "ReferenceError",
    "RuntimeError",
    "StopIteration",
    "SyntaxError",
    "SystemError",
    "TypeError",
    "ValueError",
    "Warning",
}
_READER_FIELDS = {
    "dir": {"__dir__"},
    "getattr": {"__getattr__"},
    "hasattr": {"__getattr__"},
    "print": {"__spec__", "__loader__", "__getattr__", "__name__", "__file__"},
    "repr": {"__spec__", "__loader__", "__getattr__", "__name__", "__file__"},
    "str": {"__spec__", "__loader__", "__getattr__", "__name__", "__file__"},
}
_READER_PROTOCOLS = set().union(*_READER_FIELDS.values())
_READER_CAPABILITIES = {"__spec__", "__loader__", "__dir__", "__getattr__"}
_NO_PROTOCOL_VALUE = object()
_UNKNOWN_PROTOCOL = object()


def _literal_data(expr):
    """Only freshly expressed builtin data; never a type hint or opaque value."""
    pending = [expr]
    for _ in range(_MAX_STEPS):
        if not pending:
            return True
        node = pending.pop()
        if isinstance(node, ast.Constant):
            if type(node.value) not in {
                str,
                bytes,
                int,
                float,
                complex,
                bool,
                type(None),
                type(Ellipsis),
            }:
                return False
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            pending.extend(node.elts)
        elif isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                return False
            pending.extend(node.keys)
            pending.extend(node.values)
        elif isinstance(node, ast.UnaryOp) and isinstance(
            node.op, (ast.UAdd, ast.USub, ast.Invert)
        ):
            pending.append(node.operand)
        else:
            return False
    return False


def _statement(unit, node):
    while node is not None and not isinstance(node, ast.stmt):
        node = unit.parents.get(id(node))
    return node


def _definitely_later(unit, site, use):
    site_stmt, use_stmt = _statement(unit, site), _statement(unit, use)
    return (
        site_stmt is not None
        and use_stmt is not None
        and unit.parents.get(id(site_stmt)) is unit.tree
        and unit.parents.get(id(use_stmt)) is unit.tree
        and (use_stmt.end_lineno, use_stmt.end_col_offset)
        < (site_stmt.lineno, site_stmt.col_offset)
    )


def _stable_binding(unit, scope, name, expr, rebound):
    return not unit.mutable_binding(scope, name) and (
        scope is not unit.tree
        or name not in rebound
        or unit.before_rebinding(expr, name)
    )


def _parameter_default(function, argument):
    positional = function.args.posonlyargs + function.args.args
    defaults = [None] * (len(positional) - len(function.args.defaults))
    defaults += list(function.args.defaults)
    for parameter, default in zip(positional, defaults):
        if parameter is argument:
            return default
    for parameter, default in zip(function.args.kwonlyargs, function.args.kw_defaults):
        if parameter is argument:
            return default
    return None


def _ordinary_receiver(unit, expr, rebound):
    """Refute an overapproximated module alias using the normal data-input model.

    This proof is for receivers only. ClassInfo and installed hooks never gain
    safety from an ordinary parameter or its annotation.
    """
    current = expr
    seen = set()
    for _ in range(_MAX_STEPS):
        if _literal_data(current):
            return True
        if not isinstance(current, ast.Name):
            return False
        binding = unit.lexical_binding(current)
        if binding is None:
            return False
        name, _, _, scope, values = binding
        marker = (id(scope), name)
        if marker in seen or not _stable_binding(unit, scope, name, current, rebound):
            return False
        seen.add(marker)
        if marker in unit.annotation_only_locals:
            return True  # definitely unbound; it cannot expose this module
        argument = unit.parameters.get(marker)
        if argument is not None and values == [None]:
            default = _parameter_default(scope, argument)
            return default is None or _literal_data(default)
        assigned = [value for value in values if value is not None]
        records = unit.import_origins.get(marker, ())
        if len(assigned) != 1 or len(values) != len(records) + 1:
            return False
        value = assigned[0]
        assignment = unit.parents.get(id(value))
        if not (
            isinstance(assignment, (ast.Assign, ast.AnnAssign))
            and unit.parents.get(id(assignment)) is scope
            and (assignment.end_lineno, assignment.end_col_offset)
            < (current.lineno, current.col_offset)
            and all(
                (site.end_lineno, site.end_col_offset)
                < (assignment.lineno, assignment.col_offset)
                for _, site in records
            )
        ):
            return False
        current = value
    return False


def _reader_index_tree(unit):
    """Preserve reference IDs while removing annotation-only fake writes."""

    def visit(node):
        if not isinstance(node, ast.AST):
            return node
        if isinstance(node, ast.AnnAssign):
            scope = unit.evaluation_scope(node)
            if node.value is None and isinstance(scope, (ast.Module, ast.ClassDef)):
                values = [node.annotation]
                if isinstance(node.target, ast.Attribute):
                    values.insert(0, node.target.value)
                elif isinstance(node.target, ast.Subscript):
                    values.insert(0, node.target.value)
                    values.insert(1, node.target.slice)
                return ast.Expr(value=ast.Tuple(elts=values, ctx=ast.Load()))
        changed = {}
        for field, value in ast.iter_fields(node):
            if (
                isinstance(node, ast.AnnAssign)
                and field == "annotation"
                and id(value) in unit.unevaluated_annotations
            ):
                replacement = ast.Constant(value=None)
            elif isinstance(value, ast.AST):
                replacement = visit(value)
            elif isinstance(value, list):
                replacement = [visit(item) for item in value]
                if all(a is b for a, b in zip(value, replacement)):
                    replacement = value
            else:
                replacement = value
            if replacement is not value:
                changed[field] = replacement
        if not changed:
            return node
        result = copy(node)
        for field, value in changed.items():
            setattr(result, field, value)
        return result

    return visit(unit.tree)


def _owned_inert_function(unit, function, scope, name, use, rebound, protect=True):
    marker = (id(scope), name)
    if (
        not isinstance(function, ast.FunctionDef)
        or unit.parents.get(id(function)) is not scope
        or unit.local_functions.get(marker) != [function]
        or unit.raw_bindings.get(marker) != [None]
        or unit.import_origins.get(marker)
        or not _stable_binding(unit, scope, name, use, rebound)
        or scope is unit.tree
        and (function.end_lineno, function.end_col_offset)
        >= (use.lineno, use.col_offset)
        or function.decorator_list
        or any(not _literal_data(value) for value in function.args.defaults)
        or any(
            value is not None and not _literal_data(value)
            for value in function.args.kw_defaults
        )
    ):
        return False
    for statement in function.body:
        if isinstance(statement, ast.Pass):
            continue
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if isinstance(statement, ast.Return) and (
            statement.value is None or _literal_data(statement.value)
        ):
            continue
        return False
    if protect and scope is unit.tree:
        unit.reader_protected_names.add(name)
    return True


def _inert_reader_callee(unit, expr, rebound):
    if not isinstance(expr, ast.Name):
        return False
    binding = unit.lexical_binding(expr)
    if binding is None:
        return False
    name, _, _, scope, _ = binding
    functions = unit.local_functions.get((id(scope), name), ())
    return len(functions) == 1 and _owned_inert_function(
        unit, functions[0], scope, name, expr, rebound
    )


def _class_info_safe(unit, expr, rebound):
    pending = [(expr, False)]
    active = set()
    done = set()
    for _ in range(_MAX_STEPS):
        if not pending:
            return True
        current, exiting = pending.pop()
        marker = id(current)
        if exiting:
            active.remove(marker)
            done.add(marker)
            continue
        if marker in done:
            continue
        if marker in active:
            return False
        binding = unit.lexical_binding(current)
        if binding is not None and binding[3] is unit.tree:
            unit.reader_protected_names.add(binding[0])
        origin = unit.proven_import_origin(current, rebound)
        if origin in {"builtins." + name for name in _BUILTIN_TYPES}:
            done.add(marker)
            continue
        if origin == "types.ModuleType":
            unit.types_sensitive = True
            done.add(marker)
            continue
        if isinstance(current, ast.Tuple):
            children = current.elts
        elif isinstance(current, ast.BinOp) and isinstance(current.op, ast.BitOr):
            children = [current.left, current.right]
        elif (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "type"
            and id(current.func) in unit.reader_builtin_refs
            and unit.builtin_binding(current.func, rebound)
            and len(current.args) == 1
            and not current.keywords
            and _literal_data(current.args[0])
        ):
            done.add(marker)
            continue
        elif isinstance(current, ast.Name):
            binding = unit.lexical_binding(current)
            if binding is None:
                return False
            name, _, _, scope, values = binding
            if (
                len(values) != 1
                or values[0] is None
                or not _stable_binding(unit, scope, name, current, rebound)
            ):
                return False
            if scope is unit.tree:
                unit.reader_protected_names.add(name)
            children = [values[0]]
        else:
            return False
        active.add(marker)
        pending.append((current, True))
        pending.extend((child, False) for child in children)
    return False


def _module_owner(unit, expr, rebound):
    if _ordinary_receiver(unit, expr, rebound):
        return None
    # A source attribute with the same spelling as a module is not that module.
    # Only a lexical Name chain ending at a unique whole-module import proves
    # this ownership; imported objects and arbitrary attribute projections do not.
    current, seen = expr, set()
    for _ in range(_MAX_STEPS):
        if not isinstance(current, ast.Name):
            break
        binding = unit.lexical_binding(current)
        if binding is None:
            break
        name, _, _, scope, values = binding
        marker = (id(scope), name)
        if marker in seen or not _stable_binding(unit, scope, name, current, rebound):
            break
        seen.add(marker)
        records = unit.import_origins.get(marker, ())
        if (
            records
            and len(values) == len(records)
            and all(value is None for value in values)
        ):
            origins = {origin for origin, _ in records}
            if len(origins) != 1 or not all(
                isinstance(site, ast.Import) for _, site in records
            ):
                break
            origin = next(iter(origins))
            if origin == "__main__":
                return unit.reader_module_name
            module = origin.rsplit(".", 1)[-1]
            if module in unit.reader_module_names or origin in _NATIVE_MODULES | {
                "types"
            }:
                return module
            break
        if records or len(values) != 1 or not isinstance(values[0], ast.Name):
            break
        current = values[0]
    return _UNKNOWN_PROTOCOL


def _protocol_projection(unit, expr, rebound):
    """Follow only lexical Name aliases and metadata attribute projections."""
    pending = []
    seen = set()
    current = expr
    result = None
    for _ in range(_MAX_STEPS):
        key = (id(current), rebound)
        if key in unit.reader_projection_cache:
            result = unit.reader_projection_cache[key]
            break
        if isinstance(current, ast.Attribute):
            if current.attr in _READER_CAPABILITIES:
                owner = _module_owner(unit, current.value, rebound)
                if owner is not None:
                    result = (owner, current.attr, ())
                    break
            pending.append((key, current.attr))
            current = current.value
            continue
        if not isinstance(current, ast.Name):
            break
        binding = unit.lexical_binding(current)
        if current.id in _READER_CAPABILITIES and (
            binding is None or binding[3] is unit.tree
        ):
            result = (unit.reader_module_name, current.id, ())
            break
        if binding is None:
            break
        name, _, _, scope, values = binding
        marker = (id(scope), name)
        if marker in seen:
            result = _UNKNOWN_PROTOCOL
            break
        seen.add(marker)
        if len(values) != 1:
            result = _ambiguous_protocol(unit, values, rebound)
            break
        if not isinstance(values[0], (ast.Name, ast.Attribute)):
            result = _ambiguous_protocol(unit, values, rebound)
            break
        pending.append((key, None))
        current = values[0]
    else:
        result = _UNKNOWN_PROTOCOL
    for key, suffix in reversed(pending):
        if (
            suffix is not None
            and result is not None
            and result is not _UNKNOWN_PROTOCOL
        ):
            result = (result[0], result[1], result[2] + (suffix,))
        unit.reader_projection_cache[key] = result
    unit.reader_projection_cache[(id(expr), rebound)] = result
    return result


def _ambiguous_protocol(unit, values, rebound):
    """Ambiguous bindings cannot erase a visible metadata capability."""
    pending, seen, roots = list(values), set(), set()
    for _ in range(_MAX_STEPS):
        if not pending:
            if not roots:
                return None
            if len(roots) == 1:
                owner, field = next(iter(roots))
                return owner, field, ()
            return _UNKNOWN_PROTOCOL
        node = pending.pop()
        if not isinstance(node, ast.AST) or id(node) in seen:
            continue
        seen.add(id(node))
        if not isinstance(node, (ast.Name, ast.Attribute)):
            pending.extend(ast.iter_child_nodes(node))
            continue
        if isinstance(node, ast.Attribute):
            if node.attr in _READER_CAPABILITIES:
                owner = _module_owner(unit, node.value, rebound)
                if owner is not None:
                    roots.add((owner, node.attr))
                    continue
            pending.append(node.value)
            continue
        binding = unit.lexical_binding(node)
        if node.id in _READER_CAPABILITIES and (
            binding is None or binding[3] is unit.tree
        ):
            roots.add((unit.reader_module_name, node.id))
            continue
        if binding is not None:
            pending.extend(binding[4])
    return _UNKNOWN_PROTOCOL


def _module_field_binding(unit, scope, name):
    return scope is unit.tree or unit.declarations.get((id(scope), name)) is ast.Global


def _protocol_fact(unit, field, site, value, owner=None):
    owner = unit.reader_module_name if owner is None else owner
    unit.reader_protocol_facts.setdefault((owner, field), []).append(
        (unit, site, value)
    )


def _protocol_escape(unit, projection, site):
    unit.reader_protocol_escapes.append(site)
    if projection is _UNKNOWN_PROTOCOL:
        for field in _READER_CAPABILITIES:
            _protocol_fact(unit, field, site, _NO_PROTOCOL_VALUE, _UNKNOWN_PROTOCOL)
    else:
        _protocol_fact(unit, projection[1], site, _NO_PROTOCOL_VALUE, projection[0])


def _protocol_facts(units):
    """Record metadata installations and bounded projections, never target effects."""
    facts = {}
    for unit in units:
        unit.reader_protocol_facts = facts
        unit.reader_projection_cache = {}
        unit.reader_protocol_escapes = []
        rebound = unit.module_read_state[1]
        for node in unit.nodes:
            if id(node) in unit.unevaluated_annotations:
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is None:
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in _READER_PROTOCOLS:
                        binding = unit.lexical_binding(target)
                        if binding is not None and _module_field_binding(
                            unit, binding[3], target.id
                        ):
                            _protocol_fact(unit, target.id, node, node.value)
                    elif isinstance(target, ast.Attribute):
                        projection = _protocol_projection(unit, target, rebound)
                        if projection is _UNKNOWN_PROTOCOL:
                            _protocol_escape(unit, projection, node)
                        elif projection is not None:
                            _protocol_fact(
                                unit, projection[1], node, node.value, projection[0]
                            )
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in _READER_PROTOCOLS:
                        binding = unit.lexical_binding(target)
                        if binding is not None and _module_field_binding(
                            unit, binding[3], target.id
                        ):
                            _protocol_fact(
                                unit, target.id, node, ast.Constant(value=None)
                            )
                    elif isinstance(target, ast.Attribute):
                        projection = _protocol_projection(unit, target, rebound)
                        if (
                            projection is not None
                            and projection is not _UNKNOWN_PROTOCOL
                        ):
                            _protocol_fact(
                                unit,
                                projection[1],
                                node,
                                ast.Constant(value=None),
                                projection[0],
                            )
            elif isinstance(node, ast.FunctionDef) and node.name in _READER_PROTOCOLS:
                scope = unit.scope(node)
                if _module_field_binding(unit, scope, node.name):
                    _protocol_fact(unit, node.name, node, node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                scope = unit.scope(node)
                for alias in node.names:
                    name = alias.asname or alias.name.split(".", 1)[0]
                    if name in _READER_PROTOCOLS and _module_field_binding(
                        unit, scope, name
                    ):
                        _protocol_fact(unit, name, node, _NO_PROTOCOL_VALUE)
            elif isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and len(node.args) >= 2
                ):
                    key = _literal_key(node.args[1], unit, [_MAX_STEPS])
                    if key is not None:
                        receiver = node.args[0]
                        if key[0] in _READER_PROTOCOLS:
                            owner = _module_owner(unit, receiver, rebound)
                            if owner is not None:
                                value = (
                                    node.args[2]
                                    if len(node.args) == 3
                                    else ast.Constant(value=None)
                                )
                                _protocol_fact(unit, key[0], node, value, owner)
                        projection = _protocol_projection(unit, receiver, rebound)
                        if (
                            projection is not None
                            and projection is not _UNKNOWN_PROTOCOL
                        ):
                            value = (
                                node.args[2]
                                if len(node.args) == 3
                                else ast.Constant(value=None)
                            )
                            _protocol_fact(
                                unit, projection[1], node, value, projection[0]
                            )
    # Metadata objects are capabilities. Passing a projection to opaque code,
    # returning it or storing it in a container cannot establish reader safety.
    for unit in units:
        rebound = unit.module_read_state[1]
        for node in unit.nodes:
            if (
                not isinstance(node, (ast.Name, ast.Attribute))
                or not isinstance(node.ctx, ast.Load)
                or id(node) in unit.unevaluated_annotations
            ):
                continue
            if _ordinary_receiver(unit, node, rebound):
                continue
            projection = _protocol_projection(unit, node, rebound)
            if projection is None:
                continue
            parent = unit.parents.get(id(node))
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue
            if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
                targets = (
                    parent.targets
                    if isinstance(parent, ast.Assign)
                    else [parent.target]
                )
                if all(isinstance(target, ast.Name) for target in targets):
                    continue
            if isinstance(parent, ast.Call) and parent.func is node:
                # Even a method on a projected metadata object can invoke
                # source-installed hooks; this is not an object interpreter.
                _protocol_escape(unit, projection, node)
            elif isinstance(parent, ast.Call) and (
                _inert_reader_callee(unit, parent.func, rebound)
                or _projection_read_inert(unit, parent, node, projection, rebound)
            ):
                continue
            elif isinstance(
                parent,
                (
                    ast.Call,
                    ast.keyword,
                    ast.Return,
                    ast.List,
                    ast.Tuple,
                    ast.Set,
                    ast.Dict,
                    ast.Subscript,
                ),
            ):
                _protocol_escape(unit, projection, node)


def _projection_read_inert(unit, call, receiver, projection, rebound):
    if _ordinary_receiver(unit, receiver, rebound):
        return True
    if (
        projection is _UNKNOWN_PROTOCOL
        or not isinstance(call.func, ast.Name)
        or id(call.func) not in unit.reader_builtin_refs
        or not unit.builtin_binding(call.func, rebound)
    ):
        return False
    name = call.func.id
    if name in {"id", "type", "callable"}:
        return True
    if name in {"isinstance", "issubclass"}:
        return (
            len(call.args) == 2
            and not call.keywords
            and _class_info_safe(unit, call.args[1], rebound)
        )
    if name not in _MODULE_READERS:
        return False
    owner, field, _path = projection
    if owner is _UNKNOWN_PROTOCOL:
        return False
    return _protocols_inert(unit, owner, {field}, call, rebound)


def _protocols_inert(unit, owner, fields, use, rebound):
    for field in fields:
        for key in ((owner, field), (_UNKNOWN_PROTOCOL, field)):
            for source, site, value in unit.reader_protocol_facts.get(key, ()):
                if source is unit and _definitely_later(unit, site, use):
                    continue
                if isinstance(value, ast.AST) and _literal_data(value):
                    continue
                if (
                    isinstance(value, ast.FunctionDef)
                    and source is unit
                    and _owned_inert_function(
                        unit, value, unit.tree, field, use, rebound, protect=False
                    )
                ):
                    continue
                return False
    return True


def _reader_is_inert(unit, call, receiver, rebound):
    if id(call) in unit.unevaluated_annotations or _ordinary_receiver(
        unit, receiver, rebound
    ):
        return True
    if _inert_reader_callee(unit, call.func, rebound):
        return True
    if (
        not isinstance(call.func, ast.Name)
        or id(call.func) not in unit.reader_builtin_refs
        or not unit.builtin_binding(call.func, rebound)
    ):
        return False
    name = call.func.id
    if name in {"id", "type", "callable"}:
        return True
    owner = _module_owner(unit, receiver, rebound)
    if owner is None:
        return True
    if owner is _UNKNOWN_PROTOCOL:
        return False
    if name in {"isinstance", "issubclass"}:
        return (
            len(call.args) == 2
            and not call.keywords
            and _class_info_safe(unit, call.args[1], rebound)
        )
    return _protocols_inert(unit, owner, _READER_FIELDS.get(name, ()), call, rebound)


def _prepare_reader_facts(units, paths, reads):
    module_names = {module_name_for(path) for path in paths}
    for unit, path in zip(units, paths):
        unit.reader_module_name = module_name_for(path)
        unit.reader_module_names = module_names
        unit.reader_protected_names = set()
        unit.types_sensitive = False
        index_tree = _reader_index_tree(unit)
        unit.reader_builtin_refs = builtin_references(
            index_tree, _MODULE_READERS | _BUILTIN_TYPES
        )
        unit.builtin_type_refs = builtin_references(index_tree, _BUILTIN_TYPES)
        unit.native_module_cache.clear()
        events, consumers = {}, []
        unit.module_read_state = module_rebinding(
            unit.tree,
            module_name_for(path),
            isolated_namespace_reads=reads,
            rebound_events=events,
            module_reads=consumers,
        )
        unit.module_reads = consumers
        unit.rebound_events = events
        unit.rebound_limits.clear()
        unit.native_module_cache.clear()
    _protocol_facts(units)
    for unit in units:
        rebound = unit.module_read_state[1]
        unit.reader_calls_safe = all(
            _reader_is_inert(unit, call, receiver, rebound)
            for call, receiver in unit.module_reads
        )
    sensitive = any(unit.types_sensitive for unit in units)
    if sensitive:
        for unit in units:
            unit.types_sensitive = True
            unit.native_module_cache.clear()
    return sensitive


def _types_reference_inert(unit, node, parent, rebound):
    origins = unit.possible_import_origins(node, rebound)
    if "types" not in origins:
        return True
    if (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and isinstance(parent.ctx, ast.Load)
    ):
        return True
    if _native_module_metadata(unit, node, parent, rebound) or _native_module_alias(
        unit, node, parent, rebound
    ):
        return True
    if isinstance(parent, ast.Call) and node in parent.args:
        return _reader_is_inert(unit, parent, node, rebound)
    return False


def _project_capability_facts(units):
    """Index visible native exports for rejection, never constructor identity."""
    exports, owners = {}, {}
    for unit in units:
        owners.setdefault(unit.reader_module_name, []).append(unit.tree)
        members = exports.setdefault(unit.reader_module_name, {})
        rebound = unit.module_read_state[1]
        for node in unit.nodes:
            if not isinstance(node, ast.Name):
                continue
            binding = unit.lexical_binding(node)
            if binding is None or binding[3] is not unit.tree:
                continue
            origin = unit.proven_import_origin(node, rebound)
            if origin and origin.split(".")[0] in _NATIVE_MODULES:
                members.setdefault(binding[0], set()).add(origin)
        for (scope, name), records in unit.import_origins.items():
            values = unit.raw_bindings.get((scope, name), ())
            if (
                scope != id(unit.tree)
                or name in rebound
                or unit.mutable_binding(unit.tree, name)
                or len(values) != len(records)
                or any(value is not None for value in values)
            ):
                continue
            for origin, _ in records:
                if origin.split(".")[0] in _NATIVE_MODULES:
                    members.setdefault(name, set()).add(origin)
    for unit in units:
        unit.project_native_exports = exports
        unit.project_native_owners = owners


def _project_capability(unit, node, rebound):
    origin = unit.proven_import_origin(node, rebound)
    if not origin:
        return None
    parts = origin.split(".")
    for index, name in enumerate(parts):
        if name not in unit.project_native_exports:
            continue
        if index == len(parts) - 1:
            return name, None
        exports = unit.project_native_exports[name].get(parts[index + 1], ())
        if not exports:
            continue
        suffix = ".".join(parts[index + 2 :])
        origins = {value + ("." + suffix if suffix else "") for value in exports}
        capabilities = _NATIVE_MODULES | {
            "html.escape",
            "markupsafe.escape",
            "bleach.clean",
            "argparse.Namespace",
        }
        if origins & capabilities:
            return name, origins
    return None


def _project_capability_is_inert(unit, node, parent, capability, rebound):
    owner, origins = capability
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return True
    if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
        targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
        for target in targets:
            binding = unit.lexical_binding(target)
            if (
                not isinstance(target, ast.Name)
                or binding is None
                or binding[4] != [node]
                or not _stable_binding(unit, binding[3], binding[0], target, rebound)
            ):
                return False
        return True
    if not isinstance(parent, ast.Call):
        return False
    if parent.func is node:
        return origins is not None and not origins & _NATIVE_MODULES
    if node not in parent.args:
        return False
    if (
        parent.args[0] is node
        and isinstance(parent.func, ast.Name)
        and parent.func.id in {"setattr", "delattr"}
        and unit.actual_builtin(parent.func, rebound)
        and len(parent.args) >= 2
    ):
        key = _literal_key(parent.args[1], unit, [_MAX_STEPS])
        return (
            key is not None
            and key[0] not in _PROTOCOLS | {"escape", "clean", "Namespace"}
            and (
                origins is not None
                or key[0] not in unit.project_native_exports[owner]
                or unit.project_native_owners[owner] == [unit.tree]
            )
        )
    if origins is None:
        return _reader_is_inert(unit, parent, node, rebound)
    if _inert_reader_callee(unit, parent.func, rebound):
        return True
    if not (
        isinstance(parent.func, ast.Name)
        and id(parent.func) in unit.reader_builtin_refs
        and unit.builtin_binding(parent.func, rebound)
    ):
        return False
    name = parent.func.id
    if name not in _MODULE_READERS:
        return False
    if name in {"isinstance", "issubclass"}:
        return (
            len(parent.args) == 2
            and not parent.keywords
            and _class_info_safe(unit, parent.args[1], rebound)
        )
    return all(
        _protocols_inert(unit, origin, _READER_FIELDS.get(name, ()), parent, rebound)
        for origin in origins
        if origin in _NATIVE_MODULES
    )


def _native_module_metadata(unit, node, parent, rebound):
    if unit.native_module_origin(node, rebound) is None:
        return False
    key = None
    if (
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and isinstance(parent.ctx, (ast.Store, ast.Del))
    ):
        key = parent.attr
    elif (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Name)
        and parent.func.id in {"setattr", "delattr"}
        and unit.actual_builtin(parent.func, rebound)
        and len(parent.args) == (3 if parent.func.id == "setattr" else 2)
        and not parent.keywords
        and parent.args[0] is node
    ):
        resolved = _literal_key(parent.args[1], unit, [_MAX_STEPS])
        key = resolved[0] if resolved is not None else None
    return key is not None and key not in _PROTOCOLS | {"escape", "clean", "Namespace"}


def _native_module_alias(unit, node, parent, rebound):
    if (
        not isinstance(parent, (ast.Assign, ast.AnnAssign))
        or parent.value is not node
        or unit.native_module_origin(node, rebound) is None
    ):
        return False
    targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
    for target in targets:
        binding = unit.lexical_binding(target)
        if (
            not isinstance(target, ast.Name)
            or binding is None
            or binding[4] != [node]
            or target.id in unit.mutable_names
            or target.id in rebound
        ):
            return False
    return True


def _barrier(unit, path, reads=frozenset(), constructors=frozenset()):
    dynamic, rebound = unit.module_read_state
    if has_mock_api_patching(unit.tree) or dynamic or not unit.reader_calls_safe:
        return True
    if any(
        isinstance(site, ast.Call)
        and id(site) not in unit.unevaluated_annotations
        and not (site.args and _ordinary_receiver(unit, site.args[0], rebound))
        and not unit.actual_builtin(site.func, rebound)
        for sites in unit.rebound_events.values()
        for site in sites
    ):
        return True
    for node in unit.nodes:
        if isinstance(node, (ast.Name, ast.Attribute)):
            capability = _project_capability(unit, node, rebound)
            if capability is not None:
                if isinstance(node, ast.Attribute) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    parent = unit.parents.get(id(node))
                    annotation_only = (
                        isinstance(parent, ast.AnnAssign)
                        and parent.target is node
                        and parent.value is None
                    )
                    if not annotation_only and unit.project_native_owners[
                        capability[0]
                    ] != [unit.tree]:
                        return True
                if isinstance(node.ctx, ast.Load) and not _project_capability_is_inert(
                    unit, node, unit.parents.get(id(node)), capability, rebound
                ):
                    return True
        if isinstance(node, ast.Call):
            if not isinstance(node.func, (ast.Name, ast.Attribute)) or _factory_result(
                unit, node.func
            ):
                return True
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                and unit.actual_builtin(node.func, rebound)
                and len(node.args) >= 2
            ):
                key = _literal_key(node.args[1], unit, [_MAX_STEPS])
                if key is not None:
                    receivers = unit.possible_import_origins(node.args[0], rebound) | {
                        unit.origin(node.args[0])
                    }
                    if _hazardous_imports(
                        {origin + "." + key[0] for origin in receivers if origin}
                    ):
                        return True
        if isinstance(node, ast.GeneratorExp):
            return True
        if isinstance(node, ast.Lambda):
            parent = unit.parents.get(id(node))
            if not isinstance(parent, ast.Call) or parent.func is not node:
                return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if any(
                not isinstance(decorator, ast.Name)
                or not unit.actual_builtin(decorator, rebound)
                or decorator.id not in {"staticmethod", "classmethod", "property"}
                for decorator in node.decorator_list
            ):
                return True
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value in _PROTOCOLS
        ):
            return True
        if isinstance(node, ast.Attribute) and node.attr in _PROTOCOLS:
            return True
        if isinstance(node, ast.Name) and node.id in _PROTOCOLS:
            return True
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and _hazardous_imports(
                unit.possible_import_origins(node, rebound) | {unit.origin(node)}
            )
        ):
            return True
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in _DYNAMIC
            and id(node) in unit.builtins
        ):
            parent = unit.parents.get(id(node))
            if not (
                isinstance(parent, ast.Call)
                and parent.func is node
                and id(parent) in reads
            ):
                return True
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        if (
            isinstance(node, ast.Name)
            and node.id == "type"
            and (id(node) in unit.builtins or unit.binding(node)[0] is None)
        ):
            parent = unit.parents.get(id(node))
            if (
                id(node) not in unit.builtins
                or not isinstance(parent, ast.Call)
                or parent.func is not node
                or len(parent.args) != 1
                or parent.keywords
                or isinstance(parent.args[0], ast.Starred)
            ):
                return True
        referenced = node.id if isinstance(node, ast.Name) else node.attr
        parent = unit.parents.get(id(node))
        if (
            referenced in unit.unsupported_calls
            and isinstance(parent, ast.Call)
            and parent.func is node
        ):
            return True
        if referenced in unit.definitions:
            parent = unit.parents.get(id(node))
            if not (isinstance(parent, ast.Call) and parent.func is node):
                if id(node) not in unit.annotations or not isinstance(
                    unit.definitions[referenced], ast.ClassDef
                ):
                    return True
        origin = unit.origin(node)
        possible_origins = unit.possible_import_origins(node, rebound) | {origin}
        if _hazardous_imports(possible_origins):
            return True
        parent = unit.parents.get(id(node))
        if (
            unit.types_sensitive
            and id(node) not in unit.unevaluated_annotations
            and not _types_reference_inert(unit, node, parent, rebound)
        ):
            return True
        if _native_module_metadata(unit, node, parent, rebound) or _native_module_alias(
            unit, node, parent, rebound
        ):
            continue
        for possible in possible_origins:
            if not possible or possible.split(".")[0] not in _NATIVE_MODULES:
                continue
            if (
                possible in {"argparse", "argparse.Namespace"}
                and id(node) in unit.annotations
            ):
                scope = unit.scope(node)
                if (
                    isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and scope.decorator_list
                ):
                    return True
                continue
            if possible == "argparse.Namespace":
                if (
                    isinstance(parent, ast.Call)
                    and parent.func is node
                    and id(parent) in constructors
                    and unit.proven_import_origin(node, rebound) == "argparse.Namespace"
                ):
                    continue
                return True
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and isinstance(parent.ctx, ast.Load)
            ):
                if possible == "argparse" and parent.attr != "Namespace":
                    return True
                continue
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            return True
    return False


def _factory_result(unit, node, seen=None):
    if isinstance(node, ast.Attribute):
        return _factory_result(unit, node.value, seen)
    if isinstance(node, ast.Call):
        return True
    if not isinstance(node, ast.Name):
        return False
    owner, values = unit.binding(node)
    marker = (id(owner), node.id)
    seen = set() if seen is None else set(seen)
    if marker in seen or len(seen) >= 16:
        return True
    if len(values) > 1:
        return True
    if not values or values[0] is None:
        return False
    seen.add(marker)
    return _factory_result(unit, values[0], seen)


def _helper_reference(unit, node, function):
    if not isinstance(node, ast.Name) or node.id != function.name:
        return False
    owner, values = unit.proof_binding(node)
    return (
        owner is unit.scope(function)
        and values == [None]
        and unit.local_functions.get((id(owner), node.id)) == [function]
    )


def _literal_key(expr, unit, budget, seen=frozenset()):
    """Resolve a lexical literal, without trusting a name or an annotation."""
    budget[0] -= 1
    if budget[0] < 0 or len(seen) >= 16:
        return None
    if isinstance(expr, ast.Constant) and type(expr.value) is str:
        return expr.value, frozenset()
    if not isinstance(expr, ast.Name) or expr.id in unit.mutable_names:
        return None
    binding = unit.lexical_binding(expr)
    if binding is None:
        return None
    _name, _separator, _rest, owner, values = binding
    marker = (id(owner), expr.id)
    if marker in seen:
        return None
    if id(expr) in unit.literal_cache:
        return unit.literal_cache[id(expr)]
    result = None
    if len(values) == 1 and values[0] is not None:
        assignment = unit.parents.get(id(values[0]))
        if (
            isinstance(assignment, (ast.Assign, ast.AnnAssign))
            and unit.parents.get(id(assignment)) is owner
            and (assignment.end_lineno, assignment.end_col_offset)
            < (expr.lineno, expr.col_offset)
        ):
            resolved = _literal_key(values[0], unit, budget, seen | {marker})
            if resolved is not None:
                result = resolved[0], resolved[1] | {expr.id}
    unit.literal_cache[id(expr)] = result
    return result


def _literal_writes(unit, budget):
    resolved = {}
    protected = set()
    for node in unit.nodes:
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and unit.actual_builtin(node.func, unit.proof_rebound)
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Name)
        ):
            continue
        key = _literal_key(node.args[1], unit, budget)
        if key is not None:
            resolved[id(node.args[1])] = key[0]
            protected.update(key[1])
    return resolved, protected


def _input_data(expr, unit, function, parameters, reads, budget):
    """Normal input data copied directly into a fresh native Namespace."""
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if isinstance(expr, ast.Name) and expr.id in parameters:
        owner, values = unit.proof_binding(expr)
        return owner is function and values == [None]
    if isinstance(expr, ast.Dict):
        return all(
            (key is None or _input_data(key, unit, function, parameters, reads, budget))
            and _input_data(value, unit, function, parameters, reads, budget)
            for key, value in zip(expr.keys, expr.values)
        )
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "vars"
        and unit.actual_builtin(expr.func, unit.proof_rebound)
        and len(expr.args) == 1
        and not expr.keywords
        and isinstance(expr.args[0], ast.Name)
        and expr.args[0].id in parameters
    ):
        owner, values = unit.proof_binding(expr.args[0])
        if owner is function and values == [None]:
            reads.add(id(expr))
            return True
        return False
    return _data(expr, unit, function, budget)


def _constructor_data(node, unit, function, parameters, reads, budget):
    return (
        isinstance(node, ast.Call)
        and not node.args
        and unit.proven_import_origin(node.func, unit.proof_rebound)
        == "argparse.Namespace"
        and all(
            keyword.arg not in _PROTOCOLS
            and _input_data(keyword.value, unit, function, parameters, reads, budget)
            for keyword in node.keywords
        )
    )


def _data(expr, unit, function, budget, seen=None):
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, str):
            return expr.value not in _PROTOCOLS
        return type(expr.value) in {bytes, int, float, complex, bool, type(None)}
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return all(_data(item, unit, function, budget, seen) for item in expr.elts)
    if isinstance(expr, ast.Dict):
        return all(
            key is not None
            and _data(key, unit, function, budget, seen)
            and _data(value, unit, function, budget, seen)
            for key, value in zip(expr.keys, expr.values)
        )
    if not isinstance(expr, ast.Name):
        return False
    owner, values = unit.proof_binding(expr)
    marker = (id(owner), expr.id)
    seen = set() if seen is None else set(seen)
    if marker in seen or len(values) != 1 or values[0] is None:
        return False
    seen.add(marker)
    aliases = {expr.id}
    for _ in range(16):
        before = len(aliases)
        for node in unit.nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                parent = unit.parents.get(id(node))
                if (
                    unit.scope(node) is owner
                    and isinstance(parent, (ast.Assign, ast.AnnAssign))
                    and isinstance(parent.value, ast.Name)
                    and parent.value.id in aliases
                ):
                    aliases.add(node.id)
        if len(aliases) == before:
            break
    else:
        return False
    for node in unit.nodes:
        if (
            not isinstance(node, ast.Name)
            or node.id not in aliases
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        binding_owner, _values = unit.proof_binding(node)
        if binding_owner is not owner:
            continue
        parent = unit.parents.get(id(node))
        if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
            targets = (
                parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            )
            if all(
                isinstance(target, ast.Name) and target.id in aliases
                for target in targets
            ):
                continue
        if (
            isinstance(parent, ast.Call)
            and _helper_reference(unit, parent.func, function)
            and node in parent.args
        ):
            continue
        return False
    return _data(values[0], unit, function, budget, seen)


def _callers_are_data(function, units, budget):
    names = {function.name}
    for unit in units:
        for node in unit.nodes:
            if isinstance(node, ast.ImportFrom):
                names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == function.name
                )
    for unit in units:
        for node in unit.nodes:
            budget[0] -= 1
            if budget[0] < 0:
                return False
            if not (
                (
                    isinstance(node, ast.Name)
                    and node.id in names
                    and isinstance(node.ctx, ast.Load)
                )
                or (isinstance(node, ast.Attribute) and node.attr == function.name)
            ):
                continue
            parent = unit.parents.get(id(node))
            if (
                unit is not units[0]
                or not _helper_reference(unit, node, function)
                or not isinstance(parent, ast.Call)
                or parent.func is not node
                or not isinstance(unit.parents.get(id(parent)), ast.Expr)
            ):
                return False
            parameters = function.args.posonlyargs + function.args.args
            if len(parent.args) > len(parameters):
                return False
            arguments = dict(zip((arg.arg for arg in parameters), parent.args))
            for keyword in parent.keywords:
                if (
                    keyword.arg not in {arg.arg for arg in parameters}
                    or keyword.arg in arguments
                ):
                    return False
                arguments[keyword.arg] = keyword.value
            if len(arguments) != len(parameters) or not all(
                _data(value, unit, function, budget) for value in arguments.values()
            ):
                return False
    return True


def _function_effects(function, unit, units, budget):
    """Prove a fresh native copy/merge and its read/write call identities."""
    if (
        function.decorator_list
        or function.args.defaults
        or any(default is not None for default in function.args.kw_defaults)
        or function.args.vararg
        or function.args.kwarg
        or function.args.kwonlyargs
        or isinstance(unit.scope(function), ast.ClassDef)
    ):
        return None
    arguments = function.args.posonlyargs + function.args.args
    if not 1 <= len(arguments) <= 2:
        return None
    parameters = {argument.arg for argument in arguments}
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body:
        return None
    reads = set()
    if len(body) == 1 and isinstance(body[0], ast.Return):
        constructor = body[0].value
        if _constructor_data(
            constructor, unit, function, parameters, reads, budget
        ) and _callers_are_data(function, units, budget):
            return set(), reads, {id(constructor)}
        return None
    first = body.pop(0)
    if not isinstance(first, (ast.Assign, ast.AnnAssign)):
        return None
    targets = first.targets if isinstance(first, ast.Assign) else [first.target]
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return None
    constructor = first.value
    if not _constructor_data(constructor, unit, function, parameters, reads, budget):
        return None
    names = {targets[0].id}
    while len(body) > 1 and isinstance(body[0], ast.Assign):
        alias = body.pop(0)
        if (
            len(alias.targets) != 1
            or not isinstance(alias.targets[0], ast.Name)
            or not isinstance(alias.value, ast.Name)
            or alias.value.id not in names
            or alias.targets[0].id in names
        ):
            return None
        names.add(alias.targets[0].id)
    if names & parameters or not body:
        return None
    returned = body[-1]
    if (
        not isinstance(returned, ast.Return)
        or not isinstance(returned.value, ast.Name)
        or returned.value.id not in names
    ):
        return None
    if len(body) == 1:
        if _callers_are_data(function, units, budget):
            return set(), reads, {id(constructor)}
        return None
    if len(body) != 2:
        return None
    loop = body[0]
    if (
        not isinstance(loop, ast.For)
        or loop.orelse
        or not isinstance(loop.target, (ast.Tuple, ast.List))
        or len(loop.target.elts) != 2
        or not all(isinstance(item, ast.Name) for item in loop.target.elts)
    ):
        return None
    key, value = (item.id for item in loop.target.elts)
    if key == value or {key, value} & (names | parameters):
        return None
    iterable = loop.iter
    if (
        not isinstance(iterable, ast.Call)
        or iterable.args
        or iterable.keywords
        or not isinstance(iterable.func, ast.Attribute)
        or iterable.func.attr != "items"
        or not isinstance(iterable.func.value, ast.Name)
        or iterable.func.value.id not in parameters
    ):
        return None
    if len(loop.body) != 1 or not isinstance(loop.body[0], ast.Expr):
        return None
    writer = loop.body[0].value
    if (
        not isinstance(writer, ast.Call)
        or not isinstance(writer.func, ast.Name)
        or writer.func.id != "setattr"
        or not unit.actual_builtin(writer.func, unit.proof_rebound)
        or len(writer.args) != 3
        or writer.keywords
        or not all(isinstance(arg, ast.Name) for arg in writer.args)
        or writer.args[0].id not in names
        or writer.args[1].id != key
        or writer.args[2].id != value
        or not _callers_are_data(function, units, budget)
    ):
        return None
    return {id(writer)}, reads, {id(constructor)}


def sanitizer_namespace_effects(tree, file_path, project_root):
    """Return source-proven writes, reads and literal keys; uncertainty proves none."""
    if (
        not isinstance(project_root, (str, Path))
        or not project_root
        or not isinstance(tree, ast.Module)
    ):
        return None
    try:
        current_nodes = []
        for node in ast.walk(tree):
            current_nodes.append(node)
            if len(current_nodes) > _MAX_STEPS:
                return None
        current = _Unit(tree, current_nodes)
        constructors = [
            node
            for node in current.nodes
            if isinstance(node, ast.Call)
            and current.origin(node.func) == "argparse.Namespace"
        ]
        initial_keys, _protected = _literal_writes(current, [_MAX_STEPS])
        if not constructors and not initial_keys:
            return None
        path = Path(file_path).resolve()
        trees, complete = project_source_snapshot(project_root)
        if not complete or path not in trees or ast.dump(trees[path]) != ast.dump(tree):
            return None
        if any(
            member.name in {"argparse.py", "html.py", "markupsafe.py", "bleach.py"}
            or member.name == "__init__.py"
            and member.parent.name in {"argparse", "html", "markupsafe", "bleach"}
            for member in trees
        ):
            return None
        protected = {"argparse", "html", "markupsafe", "bleach"}
        root = Path(project_root).resolve()
        directories = {root}
        for member in trees:
            directories.update(
                parent
                for parent in member.parents
                if parent == root or root in parent.parents
            )
        metadata_steps = 0
        for directory in directories:
            for entry in directory.iterdir():
                metadata_steps += 1
                if (
                    metadata_steps > _MAX_STEPS
                    or entry.name.split(".", 1)[0].casefold() in protected
                ):
                    return None
        units = [current]
        count = len(current.nodes)
        for member, source in trees.items():
            if member == path:
                continue
            nodes = []
            for node in ast.walk(source):
                count += 1
                if count > _MAX_STEPS:
                    return None
                nodes.append(node)
            units.append(_Unit(source, nodes))
        definitions = {}
        unsupported_calls = set()
        for unit in units:
            definitions.update(unit.definitions)
            unsupported_calls.update(unit.unsupported_calls)
        for _ in range(16):
            before = (len(definitions), len(unsupported_calls))
            for unit in units:
                for node in unit.nodes:
                    if isinstance(node, ast.ImportFrom):
                        for alias in node.names:
                            if alias.name in definitions:
                                definitions[alias.asname or alias.name] = definitions[
                                    alias.name
                                ]
                            if alias.name in unsupported_calls:
                                unsupported_calls.add(alias.asname or alias.name)
            if (len(definitions), len(unsupported_calls)) == before:
                break
        else:
            return None
        for unit in units:
            unit.definitions = definitions
            unit.unsupported_calls = unsupported_calls
        paths = [path] + [member for member in trees if member != path]
        # Function auditing needs actual module bindings before it can identify
        # isolated vars() reads. Temporarily allow every syntactic builtin vars
        # call, then require the final model with only audited reads to agree.
        # No provisional result by itself grants an exemption.
        for unit, member in zip(units, paths):
            unit.builtin_type_refs = builtin_references(
                _reader_index_tree(unit), _BUILTIN_TYPES
            )
            unit.native_module_cache.clear()
            provisional_reads = frozenset(
                id(node)
                for node in unit.nodes
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "vars"
                and unit.actual_builtin(node.func, frozenset())
            )
            events = {}
            dynamic, rebound = module_rebinding(
                unit.tree,
                module_name_for(member),
                isolated_namespace_reads=provisional_reads,
                rebound_events=events,
            )
            if dynamic:
                return None
            unit.proof_rebound = rebound
            unit.proof_event_ids = {
                name: frozenset(map(id, sites)) for name, sites in events.items()
            }
            unit.rebound_events = events
            unit.rebound_limits.clear()
            unit.native_module_cache.clear()
        budget = [_MAX_STEPS]
        ignored = set()
        reads = set()
        audited_constructors = set()
        for node in current.nodes:
            if isinstance(node, ast.FunctionDef):
                effects = _function_effects(node, current, units, budget)
                if effects is not None:
                    ignored.update(effects[0])
                    reads.update(effects[1])
                    audited_constructors.update(effects[2])
        resolved_keys = {}
        protected_keys = set()
        for unit in units:
            keys, protected = _literal_writes(unit, budget)
            resolved_keys.update(keys)
            protected_keys.update(protected)
        if budget[0] < 0:
            return None
        types_sensitive = _prepare_reader_facts(units, paths, frozenset(reads))
        _project_capability_facts(units)
        if any(
            unit.module_read_state[0]
            or unit.module_read_state[1] != unit.proof_rebound
            or {
                name: frozenset(map(id, sites))
                for name, sites in unit.rebound_events.items()
            }
            != unit.proof_event_ids
            for unit in units
        ):
            return None
        if types_sensitive:
            for directory in directories:
                for entry in directory.iterdir():
                    metadata_steps += 1
                    if (
                        metadata_steps > _MAX_STEPS
                        or entry.name.split(".", 1)[0].casefold() == "types"
                    ):
                        return None
        if any(
            _barrier(unit, member, frozenset(reads), frozenset(audited_constructors))
            for unit, member in zip(units, paths)
        ):
            return None
        protected_readers = set().union(
            *(unit.reader_protected_names for unit in units)
        )
        protected_apis = {"escape", "clean", "Namespace"}
        if types_sensitive:
            protected_apis.add("ModuleType")
        for unit in units:
            names, computed = attribute_write_names(
                unit.tree,
                isolated_writes=frozenset(ignored) if unit is current else frozenset(),
                resolved_attribute_names=resolved_keys,
            )
            if computed or names & (protected_apis | protected_keys):
                return None
            reader_ignored = set(ignored) if unit is current else set()
            rebound = unit.module_read_state[1]
            for node in unit.nodes:
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and _ordinary_receiver(unit, node.value, rebound)
                ) or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and unit.actual_builtin(node.func, rebound)
                    and node.args
                    and _ordinary_receiver(unit, node.args[0], rebound)
                ):
                    reader_ignored.add(id(node))
            reader_names, _computed = attribute_write_names(
                unit.tree,
                isolated_writes=frozenset(reader_ignored),
                resolved_attribute_names=resolved_keys,
            )
            if reader_names & protected_readers:
                return None
        return frozenset(ignored), frozenset(reads), resolved_keys
    except (OSError, TypeError, ValueError, RecursionError, RuntimeError):
        return None


def isolated_namespace_writes(tree, file_path, project_root):
    """Compatibility wrapper for source-proven receiver writes only."""
    effects = sanitizer_namespace_effects(tree, file_path, project_root)
    return effects[0] if effects is not None else frozenset()
