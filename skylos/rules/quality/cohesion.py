import ast
from pathlib import Path
from typing import Any, Optional

from skylos.rules.base import SkylosRule
from skylos.analysis.metric_imports import MetricImports
from skylos.rules.quality._cohesion_declarations import (
    declaration_method_ids as _declaration_method_ids,
)
from skylos.rules.quality._receivers import (
    FUNCTION_NODES,
    _ReceiverVisitor,
    _scope_bindings,
    class_method_nodes,
    context_method_kinds,
    method_kind,
    method_receiver,
    resolve_method_kinds,
)
from skylos.rules.quality._scope import is_non_production_python

DATACLASS_DECORATORS = frozenset(
    {
        "dataclass",
        "dataclasses.dataclass",
        "attrs",
        "attr.s",
        "attr.attrs",
        "define",
        "attrs.define",
    }
)

DATACLASS_BASES = frozenset(
    {
        "BaseModel",
        "BaseSettings",
        "TypedDict",
        "NamedTuple",
    }
)

INIT_METHODS = frozenset({"__init__", "__post_init__", "__init_subclass__"})

INTERFACE_DUNDERS = frozenset(
    {
        "__str__",
        "__repr__",
        "__format__",
        "__bytes__",
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__hash__",
        "__bool__",
        "__len__",
        "__iter__",
        "__next__",
        "__contains__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__enter__",
        "__exit__",
        "__aenter__",
        "__aexit__",
        "__call__",
        "__add__",
        "__sub__",
        "__mul__",
    }
)

ABSTRACT_DECORATORS = frozenset(
    {
        "abstractmethod",
        "abstractproperty",
        "abstractclassmethod",
        "abstractstaticmethod",
    }
)

# The receiver's type and namespace are not fields of the class.
_RECEIVER_META_ATTRS = frozenset({"__class__", "__dict__"})

# Implicit protocol dispatch: each tuple is a fallback chain, and the first
# name the class defines receives the edge (e.g. str() falls back to __repr__).
_ITER = ("__iter__", "__getitem__")
_BOOL = ("__bool__", "__len__")
_STR = ("__str__", "__repr__")
_REPR = ("__repr__",)
_FORMAT = ("__format__", "__str__", "__repr__")
_CONTAINS = ("__contains__", "__iter__", "__getitem__")
_MAPPING = (("keys",), ("__getitem__",))
_CONSTRUCT = (("__new__",), ("__init__", "__post_init__"))

# Builtins that dispatch to a dunder of their first positional argument.
_PROTOCOL_BUILTINS = {
    "len": (("__len__",),),
    "iter": (_ITER,),
    "next": (("__next__",),),
    "reversed": (("__reversed__", "__len__"), ("__reversed__", "__getitem__")),
    "str": (_STR,),
    "repr": (_REPR,),
    "ascii": (_REPR,),
    "format": (_FORMAT,),
    "bool": (_BOOL,),
    "hash": (("__hash__",),),
    "abs": (("__abs__",),),
    "int": (("__int__", "__index__"),),
    "float": (("__float__", "__index__"),),
    "complex": (("__complex__", "__float__", "__index__"),),
    "bytes": (("__bytes__",),),
    "round": (("__round__",),),
    "dir": (("__dir__",),),
    **{
        name: (_ITER,)
        for name in (
            "list",
            "tuple",
            "set",
            "frozenset",
            "sorted",
            "enumerate",
            "sum",
            "any",
            "all",
        )
    },
}
# Builtins that inspect the receiver's identity or type without exposing it.
_IDENTITY_BUILTINS = frozenset(
    {"isinstance", "issubclass", "type", "id", "callable", "super"}
)
_NAMESPACE_WRITES = frozenset(
    {"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"}
)
_COMPARE_DUNDERS = {
    ast.Eq: (("__eq__",), ("__eq__",)),
    ast.NotEq: (("__ne__", "__eq__"), ("__ne__", "__eq__")),
    ast.Lt: (("__lt__",), ("__gt__",)),
    ast.LtE: (("__le__",), ("__ge__",)),
    ast.Gt: (("__gt__",), ("__lt__",)),
    ast.GtE: (("__ge__",), ("__le__",)),
}
_BINOP_NAMES = {
    ast.Add: "add",
    ast.Sub: "sub",
    ast.Mult: "mul",
    ast.MatMult: "matmul",
    ast.Div: "truediv",
    ast.FloorDiv: "floordiv",
    ast.Mod: "mod",
    ast.Pow: "pow",
    ast.LShift: "lshift",
    ast.RShift: "rshift",
    ast.BitOr: "or",
    ast.BitXor: "xor",
    ast.BitAnd: "and",
}
_UNARY_DUNDERS = {
    ast.USub: ("__neg__",),
    ast.UAdd: ("__pos__",),
    ast.Invert: ("__invert__",),
}


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


class _CohesionVisitor(_ReceiverVisitor):
    """Receiver facts beyond named attributes, with the same alias flow.

    Records implicit protocol use (``len(self)``, ``self[k]``, ``for x in
    self``), construction through the receiver's type, and receiver uses that
    hide edges: a bare receiver escaping into other code, or writes to an
    unnamed attribute.
    """

    def __init__(self, receiver, node, *, class_receiver=False):
        super().__init__(receiver, node)
        self.class_receiver = class_receiver
        self.links: list[tuple[str, ...]] = []
        self.escapes = False
        self.dynamic_writes = False
        self._consumed: set[int] = set()
        self._handled: set[int] = set()

    def _alias(self, expr) -> bool:
        return isinstance(expr, ast.Name) and expr.id in self.aliases

    def _consume(self, expr) -> bool:
        if self._alias(expr):
            self._consumed.add(id(expr))
            return True
        return False

    def _type_of_alias(self, expr) -> bool:
        if isinstance(expr, ast.Attribute):
            return expr.attr == "__class__" and self._alias(expr.value)
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "type"
            and len(expr.args) == 1
            and not expr.keywords
            and self._alias(expr.args[0])
        )

    def _namespace_of_alias(self, expr) -> bool:
        """``self.__dict__`` or ``vars(self)``."""
        if isinstance(expr, ast.Attribute):
            if expr.attr == "__dict__" and self._consume(expr.value):
                self._handled.add(id(expr))
                return True
            return False
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "vars"
            and len(expr.args) == 1
            and self._consume(expr.args[0])
        )

    def _truth(self, expr):
        if self._consume(expr):
            self.links.append(_BOOL)
        elif isinstance(expr, ast.BoolOp):
            for value in expr.values:
                self._truth(value)
        elif isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            self._truth(expr.operand)

    def _named_access(self, node, *, write):
        args = node.args
        name = args[1] if len(args) > 1 else None
        if isinstance(name, ast.Constant) and isinstance(name.value, str):
            self._consume(args[0])
            self.usage.attributes.add(name.value)
            if write:
                self.usage.writes.add(name.value)
        elif write:
            self._consume(args[0])
            self.dynamic_writes = True
        # A dynamic read stays unconsumed and counts as an escape.

    def visit_Name(self, node):
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in self.aliases
            and id(node) not in self._consumed
        ):
            self.escapes = True

    def visit_Attribute(self, node):
        if self._consume(node.value):
            if node.attr == "__dict__" and id(node) not in self._handled:
                # Reading the whole namespace touches every field.
                self.escapes = True
        elif self._type_of_alias(node.value) and not _is_dunder(node.attr):
            self.usage.attributes.add(node.attr)
            if isinstance(node.ctx, ast.Store):
                self.usage.writes.add(node.attr)
        super().visit_Attribute(node)

    def visit_Call(self, node):
        func = node.func
        args = node.args
        if self._consume(func):
            self.links.extend(_CONSTRUCT if self.class_receiver else (("__call__",),))
        elif self._type_of_alias(func):
            self.links.extend(_CONSTRUCT)
        elif isinstance(func, ast.Name):
            name = func.id
            if name in _PROTOCOL_BUILTINS and args and self._consume(args[0]):
                self.links.extend(_PROTOCOL_BUILTINS[name])
            elif name == "print":
                for arg in args:
                    if self._consume(arg):
                        self.links.append(_STR)
            elif name in _IDENTITY_BUILTINS:
                for arg in args:
                    self._consume(arg)
            elif name in {"getattr", "hasattr"} and args and self._alias(args[0]):
                self._named_access(node, write=False)
            elif name in {"setattr", "delattr"} and args and self._alias(args[0]):
                self._named_access(node, write=True)
        elif isinstance(func, ast.Attribute):
            if func.attr in _NAMESPACE_WRITES and self._namespace_of_alias(func.value):
                self.dynamic_writes = True
            elif args and self._alias(args[0]):
                if func.attr in {"__setattr__", "__delattr__"}:
                    self._named_access(node, write=True)
                elif func.attr in {"__getattribute__", "__getattr__"}:
                    self._named_access(node, write=False)
                elif func.attr == "__new__":
                    # ``object.__new__(cls)`` allocates; it does not expose cls.
                    self._consume(args[0])
        for keyword in node.keywords:
            if keyword.arg is None and self._consume(keyword.value):
                self.links.extend(_MAPPING)
        super().visit_Call(node)

    def visit_Subscript(self, node):
        if self._consume(node.value):
            if isinstance(node.ctx, ast.Store):
                self.links.append(("__setitem__",))
            elif isinstance(node.ctx, ast.Del):
                self.links.append(("__delitem__",))
            else:
                self.links.append(("__getitem__",))
        elif isinstance(node.ctx, (ast.Store, ast.Del)) and self._namespace_of_alias(
            node.value
        ):
            self.dynamic_writes = True
        self.generic_visit(node)

    def visit_Compare(self, node):
        operands = [node.left, *node.comparators]
        for index, op in enumerate(node.ops):
            left, right = operands[index], operands[index + 1]
            if isinstance(op, (ast.Is, ast.IsNot)):
                self._consume(left)
                self._consume(right)
            elif isinstance(op, (ast.In, ast.NotIn)):
                if self._consume(right):
                    self.links.append(_CONTAINS)
                self._consume(left)
            else:
                forward, reflected = _COMPARE_DUNDERS[type(op)]
                if self._consume(left):
                    self.links.append(forward)
                if self._consume(right):
                    self.links.append(reflected)
        self.generic_visit(node)

    def visit_BinOp(self, node):
        name = _BINOP_NAMES.get(type(node.op))
        if name:
            if self._consume(node.left):
                self.links.append((f"__{name}__",))
            if self._consume(node.right):
                left = node.left
                formats = []
                if (
                    name == "mod"
                    and isinstance(left, ast.Constant)
                    and isinstance(left.value, str)
                ):
                    # ``"%s" % self`` formats the receiver.
                    if "%r" in left.value or "%a" in left.value:
                        formats.append(_REPR)
                    if "%s" in left.value:
                        formats.append(_STR)
                self.links.extend(formats or [(f"__r{name}__",)])
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if isinstance(node.op, ast.Not):
            self._truth(node.operand)
        elif self._consume(node.operand):
            self.links.append(_UNARY_DUNDERS[type(node.op)])
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        name = _BINOP_NAMES.get(type(node.op))
        target = node.target
        if isinstance(target, ast.Subscript) and self._alias(target.value):
            self.links.append(("__getitem__",))
        if name and self._alias(target):
            self.links.append((f"__i{name}__", f"__{name}__"))
        if name and self._consume(node.value):
            self.links.append((f"__r{name}__",))
        super().visit_AugAssign(node)

    def visit_Assign(self, node):
        value = node.value
        if self._alias(value):
            if all(isinstance(target, ast.Name) for target in node.targets):
                self._consume(value)  # Aliasing, tracked by the receiver flow.
            elif all(
                isinstance(target, (ast.Tuple, ast.List)) for target in node.targets
            ):
                self._consume(value)
                self.links.append(_ITER)
        elif (
            len(node.targets) == 1
            and isinstance(node.targets[0], (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(node.targets[0].elts) == len(value.elts)
        ):
            for target, element in zip(node.targets[0].elts, value.elts):
                if isinstance(target, ast.Name):
                    self._consume(element)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            self._consume(node.value)
        super().visit_AnnAssign(node)

    def visit_NamedExpr(self, node):
        self._consume(node.value)
        super().visit_NamedExpr(node)

    def visit_If(self, node):
        self._truth(node.test)
        super().visit_If(node)

    def visit_While(self, node):
        self._truth(node.test)
        super().visit_While(node)

    def visit_IfExp(self, node):
        self._truth(node.test)
        super().visit_IfExp(node)

    def visit_Assert(self, node):
        self._truth(node.test)
        self.generic_visit(node)

    def visit_For(self, node):
        if self._consume(node.iter):
            self.links.append(
                ("__aiter__",) if isinstance(node, ast.AsyncFor) else _ITER
            )
        super().visit_For(node)

    visit_AsyncFor = visit_For

    def _comprehension_protocols(self, node):
        for generator in node.generators:
            if self._consume(generator.iter):
                self.links.append(("__aiter__",) if generator.is_async else _ITER)
            for condition in generator.ifs:
                self._truth(condition)

    def visit_ListComp(self, node):
        self._comprehension_protocols(node)
        super().visit_ListComp(node)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_GeneratorExp(self, node):
        self._comprehension_protocols(node)
        super().visit_GeneratorExp(node)

    def visit_With(self, node):
        asynchronous = isinstance(node, ast.AsyncWith)
        for item in node.items:
            if self._consume(item.context_expr):
                if asynchronous:
                    self.links.extend((("__aenter__",), ("__aexit__",)))
                else:
                    self.links.extend((("__enter__",), ("__exit__",)))
        super().visit_With(node)

    visit_AsyncWith = visit_With

    def visit_Await(self, node):
        if self._consume(node.value):
            self.links.append(("__await__",))
        self.generic_visit(node)

    def visit_YieldFrom(self, node):
        if self._consume(node.value):
            self.links.append(_ITER)
        self.generic_visit(node)

    def visit_Starred(self, node):
        if isinstance(node.ctx, ast.Load) and self._consume(node.value):
            self.links.append(_ITER)
        self.generic_visit(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if key is None and self._consume(value):
                self.links.extend(_MAPPING)
        self.generic_visit(node)

    def visit_FormattedValue(self, node):
        if self._consume(node.value):
            if node.conversion == ord("s"):
                self.links.append(_STR)
            elif node.conversion in (ord("r"), ord("a")):
                self.links.append(_REPR)
            else:
                self.links.append(_FORMAT)
        self.generic_visit(node)


def _receiver_facts(func_node, kinds, *, class_receiver) -> _CohesionVisitor | None:
    receiver = method_receiver(func_node, kinds=kinds)
    if receiver is None:
        return None
    visitor = _CohesionVisitor(receiver, func_node, class_receiver=class_receiver)
    for statement in func_node.body:
        visitor.visit(statement)
    return visitor


class _UnionFind:
    __slots__ = ("parent", "rank")

    def __init__(self):
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def make_set(self, x: str):
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str):
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for x in self.parent:
            root = self.find(x)
            groups.setdefault(root, []).append(x)
        return groups


class _MethodInfo:
    __slots__ = (
        "name",
        "lineno",
        "is_static",
        "is_classmethod",
        "is_property",
        "is_init",
        "is_dunder",
        "self_attrs",
        "cls_attrs",
        "self_calls",
        "writes",
        "links",
        "escapes",
        "dynamic_writes",
        "property_backing",
    )

    def __init__(self, name: str, lineno: int):
        self.name = name
        self.lineno = lineno
        self.is_static = False
        self.is_classmethod = False
        self.is_property = False
        self.is_init = False
        self.is_dunder = name.startswith("__") and name.endswith("__")
        self.self_attrs: set[str] = set()
        self.cls_attrs: set[str] = set()
        self.self_calls: set[str] = set()
        self.writes: set[str] = set()
        self.links: list[tuple[str, ...]] = []
        self.escapes = False
        self.dynamic_writes = False
        self.property_backing: str | None = None

    @property
    def uses_receiver(self) -> bool:
        return bool(
            self.self_attrs
            or self.cls_attrs
            or self.self_calls
            or self.links
            or self.escapes
            or self.dynamic_writes
        )

    def merge(self, other: "_MethodInfo"):
        """One name, several definitions (property getter/setter/deleter)."""
        self.is_property |= other.is_property
        self.self_attrs |= other.self_attrs
        self.cls_attrs |= other.cls_attrs
        self.self_calls |= other.self_calls
        self.writes |= other.writes
        self.links.extend(other.links)
        self.escapes |= other.escapes
        self.dynamic_writes |= other.dynamic_writes
        self.property_backing = self.property_backing or other.property_backing


def _get_decorator_names(decorators: list[ast.expr]) -> set[str]:
    names = set()
    for dec in decorators:
        if isinstance(dec, ast.Name):
            names.add(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.add(dec.attr)
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                names.add(dec.func.id)
            elif isinstance(dec.func, ast.Attribute):
                names.add(dec.func.attr)
    return names


def _is_dataclass_or_container(node: ast.ClassDef) -> bool:
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id in DATACLASS_DECORATORS:
            return True
        if isinstance(dec, ast.Attribute):
            full = f"{getattr(dec.value, 'id', '')}.{dec.attr}"
            if full in DATACLASS_DECORATORS:
                return True
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id in DATACLASS_DECORATORS:
                return True
            if isinstance(func, ast.Attribute):
                full = f"{getattr(func.value, 'id', '')}.{func.attr}"
                if full in DATACLASS_DECORATORS:
                    return True

    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in DATACLASS_BASES:
            return True
        if isinstance(base, ast.Attribute) and base.attr in DATACLASS_BASES:
            return True

    return False


def _class_namespace(
    class_node: ast.ClassDef, method_names: set[str]
) -> tuple[set[str], dict[str, set[str]]]:
    """Class-body bindings: plain class attributes, and method aliases.

    ``x = property(_get_x)`` or ``__str__ = __repr__`` makes ``x`` refer to
    those methods; a receiver read of ``x`` reaches them.
    """
    attributes: set[str] = set()
    references: dict[str, set[str]] = {}
    pending = list(class_node.body)
    while pending:
        statement = pending.pop()
        if isinstance(statement, (*FUNCTION_NODES, ast.ClassDef)):
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if statement.value is None:
                continue
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            referenced = {
                child.id
                for child in ast.walk(statement.value)
                if isinstance(child, ast.Name) and child.id in method_names
            }
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        if referenced:
                            references.setdefault(child.id, set()).update(referenced)
                        else:
                            attributes.add(child.id)
            continue
        for field in ("body", "orelse", "finalbody"):
            pending.extend(getattr(statement, field, None) or [])
        for handler in getattr(statement, "handlers", None) or []:
            pending.extend(handler.body)
        for case in getattr(statement, "cases", None) or []:
            pending.extend(case.body)
    return attributes, references


class _ClassConfigurationWrites(_CohesionVisitor):
    """Track mutations through the class name with normal lexical alias flow."""

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Del) and self._alias(node.value):
            self.usage.writes.add(node.attr)
        super().visit_Attribute(node)

    def visit_Assign(self, node):
        # A local alias assignment does not expose the class to unknown code.
        if all(isinstance(target, ast.Name) for target in node.targets):
            self._consume(node.value)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            self._consume(node.value)
        super().visit_AnnAssign(node)

    def visit_NamedExpr(self, node):
        self._consume(node.value)
        super().visit_NamedExpr(node)


def _class_configuration_writes(class_node):
    writes = set()
    for method in class_method_nodes(class_node):
        bindings = _scope_bindings(method)
        parameters = {
            item.arg
            for item in (
                *method.args.posonlyargs,
                *method.args.args,
                *method.args.kwonlyargs,
            )
        }
        parameters.update(
            item.arg for item in (method.args.vararg, method.args.kwarg) if item
        )
        globals_ = set()
        pending = list(method.body)
        while pending:
            item = pending.pop()
            if isinstance(item, (*FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(item, ast.Global):
                globals_.update(item.names)
            pending.extend(ast.iter_child_nodes(item))
        if class_node.name in parameters | (bindings.names - globals_):
            continue
        facts = _ClassConfigurationWrites(class_node.name, method, class_receiver=True)
        for statement in method.body:
            facts.visit(statement)
        if facts.dynamic_writes or facts.escapes:
            return None
        writes.update(facts.usage.writes)
    return writes


def _immutable_configuration_attrs(class_node):
    """Read-only literal defaults are configuration, not owned mutable state.

    Unknown values, mutable containers and repeated bindings keep their normal
    state weight. Named class writes and unknown class mutations prevent the
    read-only exemption; receiver writes restore the field's state edge too.
    """

    def immutable(value):
        return isinstance(value, ast.Constant) or (
            isinstance(value, ast.Tuple) and all(immutable(item) for item in value.elts)
        )

    literal = set()
    unknown = set()
    pending = list(class_node.body)
    while pending:
        statement = pending.pop()
        if isinstance(statement, (*FUNCTION_NODES, ast.ClassDef)):
            continue
        if isinstance(statement, ast.Delete):
            unknown.update(
                child.id
                for target in statement.targets
                for child in ast.walk(target)
                if isinstance(child, ast.Name)
            )
        if any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id in {"locals", "vars"}
            and not child.args
            and not child.keywords
            for child in ast.walk(statement)
        ):
            return set()
        if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        if (
                            isinstance(statement, ast.AugAssign)
                            or not immutable(statement.value)
                            or child.id in literal
                        ):
                            unknown.add(child.id)
                        else:
                            literal.add(child.id)
            continue
        for field in ("body", "orelse", "finalbody"):
            pending.extend(getattr(statement, field, None) or [])
        for handler in getattr(statement, "handlers", None) or []:
            pending.extend(handler.body)
        for case in getattr(statement, "cases", None) or []:
            pending.extend(case.body)
    if not literal - unknown:
        return set()
    writes = _class_configuration_writes(class_node)
    return literal - unknown - writes if writes is not None else set()


def _extract_method_info(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    kinds=None,
) -> _MethodInfo:
    info = _MethodInfo(func_node.name, func_node.lineno)

    dec_names = _get_decorator_names(func_node.decorator_list)
    kind = method_kind(func_node, kinds=kinds)
    info.is_static = kind == "static"
    info.is_classmethod = kind == "class"
    info.is_property = "property" in dec_names
    info.is_init = func_node.name in INIT_METHODS

    if info.is_static:
        return info

    facts = _receiver_facts(func_node, kinds, class_receiver=info.is_classmethod)
    if facts is None:
        return info
    usage = facts.usage
    attributes = usage.attributes - _RECEIVER_META_ATTRS
    if info.is_classmethod:
        info.cls_attrs.update(attributes)
    else:
        info.self_attrs.update(attributes)
    info.self_calls.update(usage.calls - _RECEIVER_META_ATTRS)
    info.writes.update(usage.writes - _RECEIVER_META_ATTRS)
    info.links.extend(facts.links)
    info.escapes = facts.escapes
    info.dynamic_writes = facts.dynamic_writes

    if info.is_property:
        private_attrs = {a for a in info.self_attrs if a.startswith("_")}
        if len(private_attrs) == 1:
            info.property_backing = private_attrs.pop()

    return info


def _analyze_cohesion_graph(
    class_node: ast.ClassDef, *, kinds
) -> dict[str, Any] | None:
    if kinds is None:
        kinds = resolve_method_kinds(class_node)
    by_name: dict[str, _MethodInfo] = {}
    for item in class_method_nodes(class_node):
        info = _extract_method_info(item, kinds)
        if info.is_static:
            continue
        if info.name in by_name:
            by_name[info.name].merge(info)
        else:
            by_name[info.name] = info
    methods = list(by_name.values())

    if len(methods) < 2:
        return None

    property_map: dict[str, str] = {}
    for m in methods:
        if m.property_backing:
            property_map[m.property_backing] = m.name

    def normalize_attr(attr: str) -> str:
        if attr in property_map:
            return property_map[attr]
        return attr

    method_attrs: dict[str, set[str]] = {}
    for m in methods:
        attrs = set()
        for a in m.self_attrs:
            attrs.add(normalize_attr(a))
        for a in m.cls_attrs:
            attrs.add(normalize_attr(a))
        method_attrs[m.name] = attrs

    all_attrs: set[str] = set()
    for attrs in method_attrs.values():
        all_attrs.update(attrs)

    method_names = []
    for m in methods:
        method_names.append(m.name)

    n = len(method_names)
    pairs_no_share = 0
    pairs_share = 0

    for i in range(n):
        for j in range(i + 1, n):
            a_attrs = method_attrs[method_names[i]]
            b_attrs = method_attrs[method_names[j]]
            if a_attrs & b_attrs:
                pairs_share += 1
            else:
                pairs_no_share += 1

    lcom1 = max(0, pairs_no_share - pairs_share)

    uf = _UnionFind()
    for m in methods:
        uf.make_set(m.name)

    attr_to_methods: dict[str, list[str]] = {}
    for m_name, attrs in method_attrs.items():
        for attr in attrs:
            attr_to_methods.setdefault(attr, []).append(m_name)

    for attr, m_names in attr_to_methods.items():
        for i in range(1, len(m_names)):
            uf.union(m_names[0], m_names[i])

    method_name_set = set(method_names)
    class_attrs, class_refs = _class_namespace(class_node, method_name_set)

    def method_targets(name: str) -> set[str]:
        if name in method_name_set:
            return {name}
        return class_refs.get(name, set())

    for m in methods:
        # A receiver attribute naming a method is a call, a bound-method
        # reference (callback) or a property read: all reach that method.
        for target in m.self_attrs | m.cls_attrs | m.self_calls:
            for method in method_targets(target):
                uf.union(m.name, method)
        for chain in m.links:
            for candidate in chain:
                targets = method_targets(candidate)
                if targets:
                    for method in targets:
                        uf.union(m.name, method)
                    break

    assigned = {normalize_attr(a) for m in methods for a in m.writes}
    assigned.update(normalize_attr(a) for a in class_attrs)
    owned_state = assigned - {
        normalize_attr(attribute)
        for attribute in _immutable_configuration_attrs(class_node)
    }
    owned_state.update(
        normalize_attr(attribute) for method in methods for attribute in method.writes
    )

    # A write to an unnamed attribute may be what assigns a field that no
    # source line assigns by name, so it may reach every method reading one.
    unassigned = all_attrs - assigned - method_name_set - set(class_refs)
    for writer in methods:
        if writer.dynamic_writes:
            for m_name, attrs in method_attrs.items():
                if attrs & unassigned:
                    uf.union(writer.name, m_name)

    init_methods = []
    for m in methods:
        if m.is_init:
            init_methods.append(m.name)

    for i in range(1, len(init_methods)):
        uf.union(init_methods[0], init_methods[i])

    if init_methods:
        init_attrs = set()
        for im in init_methods:
            init_attrs.update(method_attrs.get(im, set()))
        for m in methods:
            if m.is_dunder and m.name in INTERFACE_DUNDERS:
                if method_attrs[m.name] & init_attrs:
                    uf.union(init_methods[0], m.name)

    components = uf.components()
    lcom4 = len(components)
    m_count = len(methods)
    a_count = len(all_attrs)

    if a_count > 0 and m_count > 1:
        sum_methods_using_attr = 0
        for ms in attr_to_methods.values():
            sum_methods_using_attr += len(ms)

        lcom5 = ((sum_methods_using_attr / a_count) - m_count) / (1 - m_count)

        if lcom5 < 0.0:
            lcom5 = 0.0
        elif lcom5 > 1.0:
            lcom5 = 1.0
    else:
        lcom5 = 0.0

    cohesion_groups = []
    for root, members in sorted(components.items(), key=lambda x: -len(x[1])):
        group_attrs = set()
        for member in members:
            group_attrs.update(method_attrs.get(member, set()))
        cohesion_groups.append(
            {
                "methods": sorted(members),
                "shared_attributes": sorted(group_attrs),
                "size": len(members),
                "touches_assigned_state": bool(group_attrs & owned_state),
            }
        )

    return {
        "lcom1": lcom1,
        "lcom4": lcom4,
        "lcom5": round(lcom5, 3),
        "method_count": m_count,
        "attribute_count": a_count,
        "cohesion_groups": cohesion_groups,
        "is_dataclass": _is_dataclass_or_container(class_node),
        "stateless_methods": sorted(m.name for m in methods if not m.uses_receiver),
        "receiver_escapes": sorted(
            m.name for m in methods if m.escapes or m.dynamic_writes
        ),
    }


def analyze_cohesion(
    class_node: ast.ClassDef, *, kinds=None, declaration_ids=None
) -> dict[str, Any] | None:
    if kinds is None:
        kinds = resolve_method_kinds(class_node)
    methods = list(class_method_nodes(class_node))
    unknown = [
        method for method in methods if method_kind(method, kinds=kinds) == "unknown"
    ]
    if declaration_ids is None:
        declaration_ids = _declaration_method_ids(class_node)
    implemented_names = {
        method.name
        for method in methods
        if id(method) not in declaration_ids
        and method_kind(method, kinds=kinds) != "static"
    }
    unknown_names = {method.name for method in unknown}

    def implementation_groups(result, eligible_names, stateless):
        # A method that never touches the receiver is not a responsibility
        # group by itself; neither is a group with no eligible method.
        return [
            group
            for group in result["cohesion_groups"]
            if eligible_names.intersection(group["methods"])
            and not (group["size"] == 1 and group["methods"][0] in stateless)
        ]

    def add_implementation_metrics(result, lower_names, upper=None):
        # Unknown bindings have no facts under the strict graph; they are
        # unproven, not stateless.
        stateless = set(result["stateless_methods"]) - unknown_names
        escapes = set(result["receiver_escapes"])
        groups = implementation_groups(result, lower_names - escapes, stateless)
        result["implementation_cohesion_groups"] = groups
        result["implementation_lcom4_lower_bound"] = len(groups)
        result["implementation_state_groups"] = sum(
            1 for group in groups if group["touches_assigned_state"]
        )
        result["implementation_lcom4_upper_bound"] = len(
            implementation_groups(upper or result, implemented_names, stateless)
        )
        result["excluded_stateless_methods"] = sorted(
            group["methods"][0]
            for group in result["cohesion_groups"]
            if group["size"] == 1
            and group["methods"][0] in stateless
            and group["methods"][0] in implemented_names
        )
        result["declaration_only_methods"] = [
            {"name": method.name, "line": method.lineno}
            for method in methods
            if id(method) in declaration_ids
        ]

    if not unknown:
        result = _analyze_cohesion_graph(class_node, kinds=kinds)
        if result is not None:
            result["lcom4_lower_bound"] = result["lcom4"]
            result["lcom4_upper_bound"] = result["lcom4"]
            add_implementation_metrics(result, implemented_names)
        return result

    optimistic = dict(kinds)
    optimistic.update({method: "instance" for method in unknown})
    lower = _analyze_cohesion_graph(class_node, kinds=optimistic)
    upper = _analyze_cohesion_graph(class_node, kinds=kinds)
    if lower is None or upper is None:
        return None
    known_names = {
        method.name
        for method in methods
        if method_kind(method, kinds=kinds) in {"instance", "class"}
    }
    # An unknown-only component may consist entirely of static methods, which
    # are excluded from LCOM. It cannot establish class disconnection.
    lower["cohesion_groups"] = [
        group
        for group in lower["cohesion_groups"]
        if known_names.intersection(group["methods"])
    ]
    lower["lcom4"] = len(lower["cohesion_groups"])
    lower["lcom4_lower_bound"] = lower["lcom4"]
    lower["lcom4_upper_bound"] = upper["lcom4"]
    lower["receiver_binding_uncertain"] = sorted(unknown_names)
    lower["method_count_range"] = [len(known_names), lower["method_count"]]
    # These values depend on the missing receiver edges and are not exact.
    lower["lcom1"] = None
    lower["lcom5"] = None
    lower["attribute_count"] = None
    add_implementation_metrics(lower, implemented_names & known_names, upper)
    return lower


def _abstract_decorator_bindings(module: ast.Module) -> tuple[set[str], set[str]]:
    """Local names for ``abc.abstractmethod`` and its siblings, and ``abc``."""
    names: set[str] = set()
    modules: set[str] = set()
    for statement in ast.walk(module):
        if isinstance(statement, ast.ImportFrom) and statement.module == "abc":
            names.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name in ABSTRACT_DECORATORS
            )
        elif isinstance(statement, ast.Import):
            modules.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "abc"
            )
    return names, modules


class LCOMRule(SkylosRule):
    rule_id = "SKY-Q702"
    name = "Lack of Cohesion of Methods"

    def __init__(self, low_threshold=2, high_threshold=4):
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self._method_kinds = {}
        self._declaration_ids = None
        self._protocol_class_ids: set[int] = set()
        self._imports = None

    def _identity(self, expression):
        return self._imports.resolve(expression) if self._imports is not None else None

    def _is_abstract(self, method) -> bool:
        for decorator in method.decorator_list:
            if self._identity(decorator) in {
                f"abc.{name}" for name in ABSTRACT_DECORATORS
            }:
                return True
        return False

    def _is_abstract_interface(self, node: ast.ClassDef) -> bool:
        """Every receiver method is ``@abstractmethod`` or a declaration stub."""
        declarations = self._declaration_ids or set()
        kinds = self._method_kinds or None
        methods = [
            method
            for method in class_method_nodes(node)
            if method_kind(method, kinds=kinds) != "static"
        ]
        return bool(methods) and all(
            self._is_abstract(method) or id(method) in declarations
            for method in methods
        )

    def visit_node(
        self, node: ast.AST, context: dict[str, Any]
    ) -> Optional[list[dict[str, Any]]]:
        if isinstance(node, ast.Module):
            self._method_kinds = context_method_kinds(node, context)
            self._declaration_ids = _declaration_method_ids(node)
            self._imports = MetricImports(
                node,
                {
                    "abc": ABSTRACT_DECORATORS,
                    "typing": {"Protocol", "TypedDict", "NamedTuple"},
                    "typing_extensions": {"Protocol", "TypedDict", "NamedTuple"},
                    "dataclasses": {"dataclass"},
                    "attr": {"s", "attrs", "define"},
                    "attrs": {"define", "frozen"},
                    "pydantic": {"BaseModel", "BaseSettings"},
                    "pydantic_settings": {"BaseSettings"},
                },
                filename=context.get("filename"),
                project_root=context.get("project_root"),
            )
            self._protocol_class_ids = {
                id(candidate)
                for candidate in ast.walk(node)
                if isinstance(candidate, ast.ClassDef)
                and any(
                    self._identity(base)
                    in {"typing.Protocol", "typing_extensions.Protocol"}
                    for base in candidate.bases
                )
            }
            return None
        if not isinstance(node, ast.ClassDef):
            return None
        # Structural interfaces describe a contract, not responsibilities.
        if id(node) in self._protocol_class_ids or self._is_abstract_interface(node):
            return None
        filename = context.get("filename", "")
        if is_non_production_python(filename, context.get("project_root")):
            return None

        result = analyze_cohesion(
            node,
            kinds=self._method_kinds or None,
            declaration_ids=self._declaration_ids,
        )
        if result is None:
            return None

        # A decorator/base spelling alone is not a container contract. An
        # unrelated local `define` or `BaseModel` must retain normal checks.
        result["is_dataclass"] = any(
            self._identity(
                decorator.func if isinstance(decorator, ast.Call) else decorator
            )
            in {
                "dataclasses.dataclass",
                "attr.s",
                "attr.attrs",
                "attr.define",
                "attrs.define",
                "attrs.frozen",
            }
            for decorator in node.decorator_list
        ) or any(
            self._identity(base)
            in {
                "pydantic.BaseModel",
                "pydantic.BaseSettings",
                "pydantic_settings.BaseSettings",
                "typing.TypedDict",
                "typing.NamedTuple",
                "typing_extensions.TypedDict",
                "typing_extensions.NamedTuple",
            }
            for base in node.bases
        )

        lcom4 = result["implementation_lcom4_lower_bound"]

        if result["is_dataclass"] and lcom4 <= self.high_threshold + 2:
            return None

        if lcom4 <= self.low_threshold:
            return None

        # Groups that only touch inherited or framework-provided fields may
        # be connected through the base class; require two with own state.
        if result["implementation_state_groups"] < 2:
            return None

        if lcom4 > self.high_threshold:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        groups = result["implementation_cohesion_groups"]
        group_descs = []
        for i, g in enumerate(groups[:4], 1):
            methods = ", ".join(g["methods"][:5])
            if len(g["methods"]) > 5:
                methods += f" (+{len(g['methods']) - 5} more)"
            group_descs.append(f"Group {i}: [{methods}]")
        groups_str = "; ".join(group_descs)
        uncertain = result.get("receiver_binding_uncertain")
        escapes = result.get("receiver_escapes")
        declarations = result["declaration_only_methods"]
        implementation_upper = result["implementation_lcom4_upper_bound"]
        message = (
            f"Class '{node.name}' has at least {lcom4} disconnected source method groups "
            f"(implementation LCOM4 bounds: {lcom4}–{implementation_upper}). "
            "The groups remain disconnected even with possible receiver bindings. "
            f"Review the responsibilities: {groups_str}"
            if uncertain or escapes
            else (
                f"Class '{node.name}' has {lcom4} disconnected implemented source method groups "
                f"(implementation LCOM4={lcom4}). "
                f"{len(groups)} disconnected method groups found. "
                f"Review the responsibilities: {groups_str}"
            )
        )

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "class",
                "name": node.name,
                "simple_name": node.name,
                "value": lcom4,
                "threshold": self.low_threshold,
                "lcom1": None if declarations else result["lcom1"],
                "lcom4": lcom4,
                "lcom5": None if declarations else result["lcom5"],
                "method_count": result["method_count"],
                "attribute_count": result["attribute_count"],
                "cohesion_groups": groups_str,
                "declared_lcom4": result["lcom4"],
                "declared_lcom1": result["lcom1"],
                "declared_lcom5": result["lcom5"],
                "implementation_lcom4_lower_bound": lcom4,
                "implementation_lcom4_upper_bound": implementation_upper,
                "declaration_only_methods": declarations,
                "excluded_stateless_methods": result["excluded_stateless_methods"],
                "receiver_escapes": escapes,
                "message": message,
                **(
                    {
                        "lcom4_lower_bound": lcom4,
                        "lcom4_upper_bound": implementation_upper,
                        "receiver_binding_uncertain": uncertain,
                        "method_count_range": result["method_count_range"],
                    }
                    if uncertain
                    else {}
                ),
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
