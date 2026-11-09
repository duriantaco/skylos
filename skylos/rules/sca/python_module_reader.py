"""What one Python source file binds at module level, read with ``ast``.

Nothing here imports or runs the file. What the source cannot show statically
(module ``__getattr__``, a computed ``__all__``, writes to ``globals()`` or
``sys.modules``) is recorded as a reason, never as a missing name.
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_NAMESPACE_CALLS = frozenset({"globals", "vars", "locals"})
_GLOBALS_ONLY = frozenset({"globals"})
_NAMESPACE_WRITES = frozenset({"update", "setdefault", "pop", "clear"})
_WRITES_GLOBALS = "the module writes names through globals()"
_SETS_ATTRIBUTES = "the module sets its own attributes at import time"
_DEFINES_GETATTR = "the module defines __getattr__"
_ALL_COPIES = frozenset({"list", "tuple", "set", "sorted"})


@dataclass
class Binding:
    kind: str
    node: ast.AST | None = None
    module: str | None = None
    member: str | None = None
    expression: ast.expr | None = None


@dataclass
class ModuleSurface:
    name: str
    bindings: dict[str, list[Binding]] = field(default_factory=dict)
    all_names: set[str] | None = None
    all_sources: list[str] = field(default_factory=list)
    star_sources: list[str] = field(default_factory=list)
    lazy_names: set[str] = field(default_factory=set)
    opaque: str = ""
    open_reason: str = ""


def call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def first_parameter(node: ast.AST | None) -> str:
    if node is None or not node.args.args:
        return ""
    return node.args.args[0].arg


def _is_sys_modules(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def is_namespace_call(node: ast.AST, names: frozenset[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in names
        and not node.args
    )


def assigned_names(target: ast.AST) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            yield from assigned_names(item)
    elif isinstance(target, ast.Starred):
        yield from assigned_names(target.value)


def _subscript_write(node: ast.Subscript, names: frozenset[str]) -> tuple[str, str]:
    if not isinstance(node.ctx, (ast.Store, ast.Del)):
        return "", ""
    if is_namespace_call(node.value, names):
        return "", _WRITES_GLOBALS
    if not _is_sys_modules(node.value):
        return "", ""
    if isinstance(node.slice, ast.Name) and node.slice.id == "__name__":
        return "the module replaces itself in sys.modules", ""
    return "", "the module adds modules through sys.modules"


def _call_write(node: ast.Call, names: frozenset[str]) -> tuple[str, str]:
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr in _NAMESPACE_WRITES
        and is_namespace_call(func.value, names)
    ):
        return "", _WRITES_GLOBALS
    if call_name(func) == "setattr" and node.args:
        first = node.args[0]
        if isinstance(first, ast.Subscript) and _is_sys_modules(first.value):
            return "", _SETS_ATTRIBUTES
    return "", ""


def _attribute_write(node: ast.Attribute) -> tuple[str, str]:
    if not isinstance(node.ctx, ast.Store):
        return "", ""
    value = node.value
    if isinstance(value, ast.Subscript) and _is_sys_modules(value.value):
        return "", _SETS_ATTRIBUTES
    return "", ""


def _write_reason(node: ast.AST, names: frozenset[str]) -> tuple[str, str]:
    if isinstance(node, ast.Subscript):
        return _subscript_write(node, names)
    if isinstance(node, ast.Call):
        return _call_write(node, names)
    if isinstance(node, ast.Attribute):
        return _attribute_write(node)
    return "", ""


def _dynamic_reason(tree: ast.AST) -> tuple[str, str]:
    """(opaque reason, open reason) for writes the namespace cannot show.

    ``globals()`` writes count anywhere; ``locals()`` and ``vars()`` only in the
    module's own scope, where they are its namespace."""
    opaque = ""
    open_reason = ""
    pending = [(tree, True)]
    while pending:
        node, module_scope = pending.pop()
        names = _GLOBALS_ONLY
        if module_scope:
            names = _NAMESPACE_CALLS
        found_opaque, found_open = _write_reason(node, names)
        opaque = opaque or found_opaque
        open_reason = open_reason or found_open
        inner = module_scope and not isinstance(node, SCOPE_NODES)
        pending.extend((child, inner) for child in ast.iter_child_nodes(node))
    return opaque, open_reason


def _compared_literals(test: ast.expr, parameter: str) -> set[str] | None:
    if (
        not isinstance(test, ast.Compare)
        or not isinstance(test.left, ast.Name)
        or test.left.id != parameter
        or len(test.ops) != 1
    ):
        return None
    right = test.comparators[0]
    if isinstance(test.ops[0], ast.Eq):
        return _string_values([right])
    if isinstance(test.ops[0], ast.In) and isinstance(
        right, (ast.Tuple, ast.List, ast.Set)
    ):
        return _string_values(right.elts)
    return None


def _string_values(items: Iterable[ast.expr]) -> set[str] | None:
    values = set()
    for item in items:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        values.add(item.value)
    return values


def _if_chain_literals(statement: ast.stmt, parameter: str) -> set[str] | None:
    names: set[str] = set()
    current = statement
    while True:
        if not isinstance(current, ast.If):
            return None
        literal = _compared_literals(current.test, parameter)
        if literal is None:
            return None
        names |= literal
        if not current.orelse:
            return names
        if len(current.orelse) != 1:
            return None
        current = current.orelse[0]


def _literal_getattr_names(node: ast.AST) -> set[str] | None:
    """Names a module ``__getattr__`` handles when its body only compares the
    argument with literals and then raises AttributeError; None otherwise."""
    parameter = first_parameter(node)
    if not parameter:
        return None
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    if not body or not isinstance(body[-1], ast.Raise):
        return None
    if call_name(getattr(body[-1].exc, "func", body[-1].exc)) != "AttributeError":
        return None
    names: set[str] = set()
    for statement in body[:-1]:
        literal = _if_chain_literals(statement, parameter)
        if literal is None:
            return None
        names |= literal
    return names


class _ModuleReader:
    def __init__(self, name: str, is_package: bool, is_stub: bool):
        self.surface = ModuleSurface(name)
        self.is_package = is_package
        self.is_stub = is_stub
        self.all_dynamic = False
        self._handlers = {
            ast.FunctionDef: self._function,
            ast.AsyncFunctionDef: self._function,
            ast.ClassDef: self._class,
            ast.Import: self._import,
            ast.ImportFrom: self._import_from,
            ast.Assign: self._assign_statement,
            ast.AnnAssign: self._annotated,
            ast.AugAssign: self._augmented,
            ast.Expr: self._expression,
            ast.If: self._if,
            ast.Try: self._try,
            ast.TryStar: self._try,
            ast.With: self._with,
            ast.AsyncWith: self._with,
            ast.For: self._for,
            ast.AsyncFor: self._for,
            ast.While: self._while,
            ast.Match: self._match,
        }
        type_alias = getattr(ast, "TypeAlias", None)
        if type_alias is not None:
            self._handlers[type_alias] = self._type_alias

    def read(self, tree: ast.Module) -> ModuleSurface:
        for statement in tree.body:
            if isinstance(statement, ast.Delete):
                self._delete(statement)
            else:
                self._statement(statement)
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                for name in node.names:
                    self.surface.bindings.setdefault(name, [Binding("value")])
        opaque, open_reason = _dynamic_reason(tree)
        if self.all_dynamic:
            opaque = opaque or "the module computes __all__ at import time"
        self.surface.opaque = opaque
        if open_reason and not self.surface.open_reason:
            self.surface.open_reason = open_reason
        return self.surface

    def _bind(self, name: str, binding: Binding) -> None:
        self.surface.bindings.setdefault(name, []).append(binding)

    def _body(self, statements: Iterable[ast.stmt]) -> None:
        for statement in statements:
            self._statement(statement)

    def _statement(self, node: ast.stmt) -> None:
        handler = self._handlers.get(type(node))
        if handler is not None:
            handler(node)

    def _function(self, node: ast.AST) -> None:
        self._bind(node.name, Binding("function", node=node))
        if node.name != "__getattr__":
            return
        literal = _literal_getattr_names(node)
        if literal is None:
            self.surface.open_reason = _DEFINES_GETATTR
        else:
            self.surface.lazy_names |= literal

    def _class(self, node: ast.ClassDef) -> None:
        self._bind(node.name, Binding("class", node=node))

    def _type_alias(self, node: ast.AST) -> None:
        self._bind(node.name.id, Binding("value"))

    def _annotated(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._assign(node.target, node.value)
        elif self.is_stub and isinstance(node.target, ast.Name):
            self._bind(node.target.id, Binding("value"))

    def _assign_statement(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._assign(target, node.value)

    def _expression(self, node: ast.Expr) -> None:
        self._all_call(node.value)

    def _if(self, node: ast.If) -> None:
        if self.is_stub or call_name(node.test) != "TYPE_CHECKING":
            self._body(node.body)
        self._body(node.orelse)

    def _try(self, node: ast.Try) -> None:
        self._body(node.body)
        for handler in node.handlers:
            self._body(handler.body)
        self._body(node.orelse)
        self._body(node.finalbody)

    def _with(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._bind_values(item.optional_vars)
        self._body(node.body)

    def _for(self, node: ast.For) -> None:
        self._bind_values(node.target)
        self._body(node.body)
        self._body(node.orelse)

    def _while(self, node: ast.While) -> None:
        self._body(node.body)
        self._body(node.orelse)

    def _match(self, node: ast.Match) -> None:
        for case in node.cases:
            self._body(case.body)

    def _bind_values(self, target: ast.AST) -> None:
        for name in assigned_names(target):
            self._bind(name, Binding("value"))

    def _import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._bind(alias.asname, Binding("import", module=alias.name))
            else:
                root = alias.name.split(".", 1)[0]
                self._bind(root, Binding("import", module=root))

    def _absolute(self, module: str | None, level: int) -> str | None:
        if not level:
            return module
        parts = self.surface.name.split(".")
        if not self.is_package:
            parts = parts[:-1]
        drop = level - 1
        if drop >= len(parts):
            return None
        base = parts[: len(parts) - drop]
        if module:
            base = base + module.split(".")
        return ".".join(base)

    def _import_from(self, node: ast.ImportFrom) -> None:
        module = self._absolute(node.module, node.level)
        if module is None:
            self.surface.open_reason = "the module has an unresolved relative import"
            return
        for alias in node.names:
            if alias.name == "*":
                self.surface.star_sources.append(module)
            else:
                self._bind(
                    alias.asname or alias.name,
                    Binding("import", module=module, member=alias.name),
                )

    def _assign(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self._assign_name(target.id, value)
            return
        for name in assigned_names(target):
            if name == "__all__":
                self.all_dynamic = True
                continue
            if name == "__getattr__":
                self.surface.open_reason = _DEFINES_GETATTR
            self._bind(name, Binding("value"))

    def _assign_name(self, name: str, value: ast.expr) -> None:
        if name == "__all__":
            self._set_all(value)
            return
        if name == "__getattr__":
            self.surface.open_reason = _DEFINES_GETATTR
        expression = None
        if isinstance(value, (ast.Name, ast.Attribute)):
            expression = value
        self._bind(name, Binding("value", expression=expression))

    def _augmented(self, node: ast.AugAssign) -> None:
        if not isinstance(node.target, ast.Name):
            return
        if node.target.id == "__all__":
            self._add_all(node.value)
        else:
            self._bind(node.target.id, Binding("value"))

    def _delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            for name in assigned_names(target):
                self.surface.bindings.pop(name, None)

    def _set_all(self, value: ast.expr) -> None:
        self.surface.all_names = set()
        self.surface.all_sources = []
        self._add_all(value)

    def _add_all(self, value: ast.expr) -> None:
        parts = self._all_parts(value)
        if parts is None:
            self.all_dynamic = True
            return
        names, sources = parts
        if self.surface.all_names is None:
            self.surface.all_names = set()
        self.surface.all_names |= names
        self.surface.all_sources.extend(sources)

    def _all_call(self, value: ast.expr) -> None:
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
            return
        func = value.func
        if not isinstance(func.value, ast.Name) or func.value.id != "__all__":
            return
        first = None
        if value.args:
            first = value.args[0]
        if func.attr == "extend" and first is not None:
            self._add_all(first)
            return
        names = None
        if first is not None:
            names = _string_values([first])
        if names is None or func.attr not in {"append", "remove"}:
            self.all_dynamic = True
            return
        if self.surface.all_names is None:
            self.surface.all_names = set()
        if func.attr == "append":
            self.surface.all_names |= names
        else:
            self.surface.all_names -= names

    def _all_parts(self, node: ast.expr) -> tuple[set[str], list[str]] | None:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._all_sequence(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._all_sum(node)
        if isinstance(node, ast.Call):
            if len(node.args) == 1 and call_name(node.func) in _ALL_COPIES:
                return self._all_parts(node.args[0])
            return None
        if isinstance(node, ast.Attribute):
            return self._all_of_module(node)
        return None

    def _all_sequence(self, node: ast.expr) -> tuple[set[str], list[str]] | None:
        names: set[str] = set()
        sources: list[str] = []
        for item in node.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                names.add(item.value)
                continue
            if not isinstance(item, ast.Starred):
                return None
            nested = self._all_parts(item.value)
            if nested is None:
                return None
            names |= nested[0]
            sources.extend(nested[1])
        return names, sources

    def _all_sum(self, node: ast.BinOp) -> tuple[set[str], list[str]] | None:
        left = self._all_parts(node.left)
        right = self._all_parts(node.right)
        if left is None or right is None:
            return None
        return left[0] | right[0], left[1] + right[1]

    def _all_of_module(self, node: ast.Attribute) -> tuple[set[str], list[str]] | None:
        if node.attr != "__all__" or not isinstance(node.value, ast.Name):
            return None
        source = self._bound_module(node.value.id)
        if source is None:
            return None
        return set(), [source]

    def _bound_module(self, name: str) -> str | None:
        for binding in self.surface.bindings.get(name, ()):
            if binding.kind != "import" or not binding.module:
                continue
            if binding.member is None:
                return binding.module
            return f"{binding.module}.{binding.member}"
        return None


def read_module(
    name: str, source: str, *, is_package: bool = False, is_stub: bool = False
) -> ModuleSurface:
    """Bindings of one module; a file that does not parse is opaque."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source)
        return _ModuleReader(name, is_package, is_stub).read(tree)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ModuleSurface(name, opaque="the module could not be parsed")
