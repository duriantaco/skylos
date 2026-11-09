"""Source-only checks for a sanitizer's imported provider.

Never import a scanned provider to discover whether it is the native library.
"""

import ast
import os
import stat
from pathlib import Path
from .builtin_bindings import builtin_references
from .project_imports import project_import_context
from skylos.analysis.ast_cache import (
    in_python_ast_cache_session,
    register_dependent_clear,
)

from .danger_fs.closed_world import _SKIP_DIRS
from .project_source import project_source_snapshot


_IMPORT_STATE = (
    "sys.path",
    "sys.meta_path",
    "sys.path_hooks",
    "sys.path_importer_cache",
    "sys.modules",
)
_SETTERS = {
    "__setattr__",
    "__delattr__",
    "__setitem__",
    "__delitem__",
    "update",
    "setdefault",
    "pop",
    "clear",
    "add_constructor",
    "add_multi_constructor",
}
_READ_BUILTINS = {
    "print",
    "len",
    "str",
    "repr",
    "bool",
    "tuple",
    "list",
    "set",
    "frozenset",
}
_IMMUTABLE_VALUES = {
    "os.name",
    "ssl.CERT_NONE",
    "ssl.CERT_OPTIONAL",
    "ssl.CERT_REQUIRED",
    "ssl.PROTOCOL_TLS_CLIENT",
    "ssl.PROTOCOL_TLS",
    "ssl.PROTOCOL_TLS_SERVER",
}
_MODELED_CAPABILITY_CALLS = {
    "yaml.load",
    "yaml.load_all",
    "builtins.isinstance",
    "builtins.issubclass",
}
_YAML_DATA_ONLY_LOADERS = frozenset(
    {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.BaseLoader",
        "yaml.CBaseLoader",
        "yaml.loader.SafeLoader",
        "yaml.loader.BaseLoader",
        "yaml.cyaml.CSafeLoader",
        "yaml.cyaml.CBaseLoader",
    }
)


class _Effects:
    def __init__(self, tree):
        self.complete = isinstance(tree, ast.Module)
        self.nodes = []
        if self.complete:
            for node in ast.walk(tree):
                self.nodes.append(node)
                if len(self.nodes) > 50000:
                    self.complete = False
                    self.nodes = []
                    break
        self.aliases = {}
        self.alias_work = 0
        self.ref_work = 0
        self.stable_results = {}
        self.yaml_builtin_getattrs = None
        self.value_bindings = {}
        self.iteration_bindings = {}
        self.parameter_bindings = set()
        self.origin_bindings = set()
        self.class_nodes = {}
        self.parents = {
            id(child): parent
            for parent in self.nodes
            for child in ast.iter_child_nodes(parent)
        }
        self.bindings = {}
        self.globals = {}
        self.nonlocals = {}
        for node in self.nodes:
            scope = self.scope(node)
            bound = self.bindings.setdefault(scope, set())
            if isinstance(node, ast.Global):
                self.globals.setdefault(scope, set()).update(node.names)
            elif isinstance(node, ast.Nonlocal):
                self.nonlocals.setdefault(scope, set()).update(node.names)
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                bound.add(node.id)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                bound.add(node.name)
                kind = "class" if isinstance(node, ast.ClassDef) else "function"
                self.add_alias((scope, node.name), {f"@{kind}:{id(node)}"})
                self.origin_bindings.add((scope, node.name))
                if isinstance(node, ast.ClassDef):
                    self.class_nodes[f"@class:{id(node)}"] = node
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.parameter_bindings.update(
                        (node, arg.arg)
                        for arg in ast.walk(node.args)
                        if isinstance(arg, ast.arg)
                    )
                    self.bindings.setdefault(node, set()).update(
                        arg.arg
                        for arg in ast.walk(node.args)
                        if isinstance(arg, ast.arg)
                    )
            elif isinstance(node, ast.Lambda):
                self.parameter_bindings.update(
                    (node, arg.arg)
                    for arg in ast.walk(node.args)
                    if isinstance(arg, ast.arg)
                )
                self.bindings.setdefault(node, set()).update(
                    arg.arg for arg in ast.walk(node.args) if isinstance(arg, ast.arg)
                )
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or (
                        alias.name.split(".")[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    bound.add(local)
                    if alias.name == "*":
                        self.complete = False
                    if isinstance(node, ast.Import):
                        imported = (
                            alias.name if alias.asname else alias.name.split(".")[0]
                        )
                    elif node.module and not node.level:
                        imported = node.module + "." + alias.name
                    else:
                        continue
                    self.add_alias((scope, local), {imported})
                    self.origin_bindings.add((scope, local))
        for node in self.nodes:
            if isinstance(node, (ast.For, ast.comprehension)) and isinstance(
                node.target, ast.Name
            ):
                key = (
                    self.binding_scope(self.scope(node.target), node.target.id),
                    node.target.id,
                )
                self.iteration_bindings.setdefault(key, []).append(node.iter)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and isinstance(
                            name.ctx, ast.Store
                        ):
                            key = (
                                self.binding_scope(self.scope(name), name.id),
                                name.id,
                            )
                            self.value_bindings.setdefault(key, []).append(node.value)
        for _ in range(32):
            changed = False
            for node in self.nodes:
                if isinstance(node, ast.ClassDef):
                    bases = set().union(*(self.refs(base) for base in node.bases))
                    if bases:
                        key = (
                            self.binding_scope(self.scope(node), node.name),
                            node.name,
                        )
                        changed |= self.add_alias(key, bases)
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    positional = [*node.args.posonlyargs, *node.args.args]
                    defaults = (
                        list(
                            zip(
                                positional[-len(node.args.defaults) :],
                                node.args.defaults,
                            )
                        )
                        if node.args.defaults
                        else []
                    )
                    defaults.extend(
                        (arg, value)
                        for arg, value in zip(
                            node.args.kwonlyargs, node.args.kw_defaults
                        )
                        if value is not None
                    )
                    for argument, value in defaults:
                        refs = self.refs(value)
                        if refs:
                            changed |= self.add_alias((node, argument.arg), refs)
                if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = self.refs(node.value)
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for target in targets:
                        for name in ast.walk(target):
                            if (
                                isinstance(name, ast.Name)
                                and isinstance(name.ctx, ast.Store)
                                and value
                            ):
                                key = (
                                    self.binding_scope(self.scope(name), name.id),
                                    name.id,
                                )
                                changed |= self.add_alias(key, value)
                elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                    value = self.refs(node.iter)
                    if value != {"sys.path"}:
                        for name in ast.walk(node.target):
                            if isinstance(name, ast.Name):
                                key = (
                                    self.binding_scope(self.scope(name), name.id),
                                    name.id,
                                )
                                changed |= self.add_alias(key, value)
                if not self.complete:
                    break
            if not self.complete:
                break
            if not changed:
                break
        else:
            self.complete = False

    def add_alias(self, key, values):
        self.alias_work += len(values)
        current = self.aliases.get(key, set())
        if (
            self.alias_work > 8192
            or len(current | values) > 64
            or any(len(name) > 256 for name in values)
        ):
            self.complete = False
            return False
        changed = not values <= current
        self.aliases.setdefault(key, set()).update(values)
        return changed

    def scope(self, node):
        child = node
        parent = self.parents.get(id(child))
        while parent is not None:
            if (
                isinstance(
                    parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
                and child in parent.body
            ):
                return parent
            if isinstance(parent, ast.Lambda) and child is parent.body:
                return parent
            if isinstance(
                parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
            ):
                return parent
            child, parent = parent, self.parents.get(id(parent))
        return None

    def lookup(self, node):
        key = self.lookup_key(node)
        return self.aliases.get(key, set()) if key is not None else set()

    def lookup_key(self, node):
        scope = self.scope(node)
        for _ in range(64):
            scope = self.binding_scope(scope, node.id)
            key = (scope, node.id)
            if key in self.aliases:
                return key
            if node.id in self.bindings.get(scope, ()) or scope is None:
                return key
            previous = scope
            scope = self.scope(scope)
            if isinstance(
                previous, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                while isinstance(scope, ast.ClassDef):
                    scope = self.scope(scope)
        self.complete = False
        return None

    def binding_scope(self, scope, name):
        if name in self.globals.get(scope, ()):
            return None
        if name in self.nonlocals.get(scope, ()):
            scope = self.scope(scope)
            for _ in range(64):
                if scope is None:
                    self.complete = False
                    return None
                if not isinstance(scope, ast.ClassDef) and name in self.bindings.get(
                    scope, ()
                ):
                    return scope
                scope = self.scope(scope)
            self.complete = False
            return None
        return scope

    def refs(self, node, depth=0):
        if node is None:
            return set()
        self.ref_work += 1
        if depth > 32 or self.ref_work > 65536:
            self.complete = False
            return set()
        if isinstance(node, ast.Name):
            return self.lookup(node)
        if isinstance(node, ast.Attribute):
            values = {
                value + "." + node.attr for value in self.refs(node.value, depth + 1)
            }
            if any(len(name) > 256 for name in values):
                self.complete = False
                return set()
            return values
        if isinstance(node, ast.Subscript):
            bases = self.refs(node.value, depth + 1)
            if (
                bases == {"sys.path"}
                and isinstance(node.ctx, ast.Load)
                and isinstance(node.slice, ast.Slice)
            ):
                return set()
            if isinstance(node.slice, ast.Constant) and isinstance(
                node.slice.value, str
            ):
                return {
                    base[:-9] + "." + node.slice.value
                    if base.endswith(".__dict__")
                    else base
                    for base in bases
                }
            return bases
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(self.refs(value, depth + 1) for value in node.elts))
        if isinstance(node, ast.Dict):
            return set().union(*(self.refs(value, depth + 1) for value in node.values))
        if isinstance(node, ast.IfExp):
            return self.refs(node.body, depth + 1) | self.refs(node.orelse, depth + 1)
        if isinstance(node, ast.BoolOp):
            return set().union(*(self.refs(value, depth + 1) for value in node.values))
        if isinstance(node, ast.NamedExpr):
            return self.refs(node.value, depth + 1)
        if isinstance(
            node,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return set().union(
                *(self.refs(value, depth + 1) for value in ast.iter_child_nodes(node))
            )
        if isinstance(node, ast.comprehension):
            return self.refs(node.iter, depth + 1)
        if isinstance(node, ast.Starred):
            return self.refs(node.value, depth + 1)
        if isinstance(node, ast.Compare):
            if all(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
                return set()
            return self.refs(node.left, depth + 1) | set().union(
                *(self.refs(value, depth + 1) for value in node.comparators)
            )
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.UnaryOp)):
            return set()
        if isinstance(node, ast.Call):
            functions = self.refs(node.func, depth + 1)
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if functions == {"sys.path.copy"} and not node.args and not node.keywords:
                return set()
            if self.safe_reader(node.func) and (
                name in {"list", "tuple", "set", "frozenset"}
                or functions
                & {
                    "builtins.list",
                    "builtins.tuple",
                    "builtins.set",
                    "builtins.frozenset",
                }
            ):
                if (
                    len(node.args) == 1
                    and isinstance(node.args[0], (ast.Name, ast.Attribute))
                    and self.refs(node.args[0], depth + 1) == {"sys.path"}
                ):
                    return set()
                return set().union(
                    *(self.refs(value, depth + 1) for value in node.args)
                )
            if (
                (name == "getattr" or functions == {"builtins.getattr"})
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                return {
                    value + "." + node.args[1].value
                    for value in self.refs(node.args[0], depth + 1)
                }
            if (name == "vars" or functions == {"builtins.vars"}) and len(
                node.args
            ) == 1:
                return {
                    value + ".__dict__" for value in self.refs(node.args[0], depth + 1)
                }
            if (
                len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return {
                    name.rsplit(".", 1)[0] + "." + node.args[0].value
                    for name in functions
                    if name.endswith(".__getattribute__")
                }
        elif isinstance(node, ast.expr):
            return set().union(
                *(self.refs(value, depth + 1) for value in ast.iter_child_nodes(node))
            )
        return set()

    def safe_reader(self, node):
        if isinstance(node, ast.Name) and node.id in _READ_BUILTINS:
            scope = self.scope(node)
            while scope is not None:
                if node.id in self.bindings.get(scope, ()):
                    return False
                scope = self.scope(scope)
            return node.id not in self.bindings.get(None, ())
        functions = self.refs(node)
        return bool(functions) and functions <= {
            "builtins." + name for name in _READ_BUILTINS
        }

    def literal_source(self, node, seen=None, depth=0):
        if depth > 32:
            self.complete = False
            return None
        if not isinstance(node, ast.Name):
            return node
        key = self.lookup_key(node)
        seen = set() if seen is None else seen
        if key in seen or key in self.origin_bindings:
            return None
        values = self.value_bindings.get(key, ())
        if len(values) != 1:
            return None
        return self.literal_source(values[0], seen | {key}, depth + 1)

    def scalar_literal(self, node):
        if isinstance(node, ast.Constant):
            return type(node.value) in {
                str,
                bytes,
                int,
                float,
                complex,
                bool,
                type(None),
            }
        if isinstance(node, ast.Tuple):
            return all(self.scalar_literal(value) for value in node.elts)
        names = self.refs(node)
        return bool(names) and names <= _IMMUTABLE_VALUES

    def native_container(self, node):
        node = self.literal_source(node)
        if isinstance(node, (ast.List, ast.Tuple)):
            return node
        if isinstance(node, ast.Dict) and all(
            key is not None and self.scalar_literal(key) for key in node.keys
        ):
            return node
        return None

    def canonical_reference(self, node, seen=None, depth=0):
        if depth > 32:
            self.complete = False
            return False
        if isinstance(node, ast.Attribute):
            return self.canonical_reference(node.value, seen, depth + 1)
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            container = self.native_container(node.value)
            if not isinstance(container, (ast.List, ast.Tuple)) or any(
                isinstance(value, ast.Starred) for value in container.elts
            ):
                return False
            index = node.slice
            sign = 1
            if isinstance(index, ast.UnaryOp) and isinstance(index.op, ast.USub):
                sign, index = -1, index.operand
            if not isinstance(index, ast.Constant) or type(index.value) is not int:
                return False
            position = sign * index.value
            if not -len(container.elts) <= position < len(container.elts):
                return False
            return self.canonical_reference(container.elts[position], seen, depth + 1)
        if not isinstance(node, ast.Name):
            return False
        key = self.lookup_key(node)
        seen = set() if seen is None else seen
        if key in seen:
            return False
        values = self.value_bindings.get(key, ())
        iterations = self.iteration_bindings.get(key, ())
        if iterations and key in self.parameter_bindings:
            return False
        if values or iterations:
            assigned = all(
                self.canonical_reference(value, seen | {key}, depth + 1)
                for value in values
            )
            for iterable in iterations:
                container = self.native_container(iterable)
                if not isinstance(container, (ast.List, ast.Tuple)) or any(
                    isinstance(value, ast.Starred) for value in container.elts
                ):
                    return False
                if not all(
                    self.canonical_reference(value, seen | {key}, depth + 1)
                    for value in container.elts
                ):
                    return False
            return assigned
        return key in self.origin_bindings

    def safe_yaml_loader_getattr(self, node, depth=0):
        """A builtin read of a native data-only loader does not expose YAML."""
        if (
            depth > 32
            or not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Name)
            or node.func.id != "getattr"
            or len(node.args) not in {2, 3}
            or node.keywords
            or self.refs(node.args[0]) != {"yaml"}
            or not self.canonical_reference(node.args[0])
            or not isinstance(node.args[1], ast.Constant)
            or not isinstance(node.args[1].value, str)
            or "." in node.args[1].value
            or "yaml." + node.args[1].value not in _YAML_DATA_ONLY_LOADERS
        ):
            return False
        if self.yaml_builtin_getattrs is None:
            self.yaml_builtin_getattrs = builtin_references(self.nodes[0], {"getattr"})
        if id(node.func) not in self.yaml_builtin_getattrs:
            return False
        if len(node.args) == 2:
            return True
        default = node.args[2]
        if isinstance(default, ast.Call):
            return self.safe_yaml_loader_getattr(default, depth + 1)
        names = self.refs(default)
        return (
            bool(names)
            and names <= _YAML_DATA_ONLY_LOADERS
            and self.canonical_reference(default)
        )

    def safe_reader_call(self, node):
        if self.safe_yaml_loader_getattr(node):
            return True
        if not self.safe_reader(node.func):
            return False
        functions = self.refs(node.func)
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else next(iter(functions), "").rpartition(".")[2]
        )
        if name in {"set", "frozenset"}:
            return False  # hashing/equality may dispatch a different element's code
        if name in {"list", "tuple"}:
            return (
                len(node.args) == 1
                and not node.keywords
                and (
                    self.refs(node.args[0]) == {"sys.path"}
                    and self.canonical_reference(node.args[0])
                    or self.native_container(node.args[0]) is not None
                )
            )
        return True

    def implicit_use_is_safe(self, node, sensitive, immutable_values=None):
        immutable_values = (
            _IMMUTABLE_VALUES if immutable_values is None else immutable_values
        )

        def capability(value):
            return any(
                sensitive(name) and name not in immutable_values
                for name in self.refs(value)
            )

        if isinstance(node, ast.Compare):
            return all(
                isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops
            ) or not any(capability(value) for value in [node.left, *node.comparators])
        if isinstance(node, ast.BinOp) and (
            capability(node.left) or capability(node.right)
        ):
            left, right = (
                self.native_container(node.left),
                self.native_container(node.right),
            )
            return (
                left is not None
                and right is not None
                and type(left) is type(right)
                and (
                    isinstance(node.op, ast.Add)
                    and isinstance(left, (ast.List, ast.Tuple))
                    or isinstance(node.op, ast.BitOr)
                    and isinstance(left, ast.Dict)
                )
            )
        if isinstance(node, ast.UnaryOp):
            return not capability(node.operand)
        if isinstance(node, ast.BoolOp):
            return not any(capability(value) for value in node.values[:-1])
        if isinstance(node, (ast.IfExp, ast.If, ast.While, ast.Assert)):
            return not capability(node.test)
        if isinstance(node, ast.Set):
            return not any(capability(value) for value in node.elts)
        if isinstance(node, ast.SetComp):
            return not capability(node.elt)
        if isinstance(node, ast.DictComp):
            return not capability(node.key)
        if isinstance(node, ast.ClassDef):
            bases = [base for base in node.bases if capability(base)]
            return (
                not bases
                or len(node.bases) == 1
                and not node.keywords
                and not node.decorator_list
                and all(
                    self.canonical_reference(base) and self.pure_class_base(base)
                    for base in bases
                )
            )
        if isinstance(node, ast.Dict):
            return all(
                not capability(key)
                if key is not None
                else not capability(value)
                or isinstance(self.native_container(value), ast.Dict)
                for key, value in zip(node.keys, node.values)
            )
        if isinstance(node, ast.Subscript):
            if capability(node.slice):
                return False
            if capability(node.value):
                native_namespace = any(
                    name in {"sys.path", "sys.modules"}
                    or name.endswith((".__dict__", ".__globals__"))
                    for name in self.refs(node.value)
                )
                key = (
                    isinstance(node.slice, ast.Slice)
                    and all(
                        value is None or self.scalar_literal(value)
                        for value in [
                            node.slice.lower,
                            node.slice.upper,
                            node.slice.step,
                        ]
                    )
                    or self.scalar_literal(node.slice)
                )
                return key and (
                    native_namespace or self.native_container(node.value) is not None
                )
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and capability(node.value)
        ):
            if not self.canonical_reference(node.value):
                return False
            for name in self.refs(node.value):
                klass = self.class_nodes.get(name)
                if klass is None:
                    continue
                if klass.keywords or klass.decorator_list:
                    return False
                for field in klass.body:
                    if isinstance(field, (ast.Assign, ast.AnnAssign)):
                        targets = (
                            field.targets
                            if isinstance(field, ast.Assign)
                            else [field.target]
                        )
                        if any(
                            isinstance(target, ast.Name) and target.id == node.attr
                            for target in targets
                        ) and not self.scalar_literal(field.value):
                            return False
                    elif (
                        isinstance(field, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and field.name == node.attr
                        and field.decorator_list
                    ):
                        return False
        if isinstance(node, ast.Starred) and capability(node.value):
            return self.native_container(node.value) is not None
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and capability(
            node.iter
        ):
            return (
                self.refs(node.iter) == {"sys.path"}
                and self.canonical_reference(node.iter)
                or self.native_container(node.iter) is not None
            )
        if isinstance(node, ast.FormattedValue):
            return not capability(node.value)
        if isinstance(node, (ast.Await, ast.YieldFrom)):
            return not capability(node.value)
        if isinstance(node, ast.withitem):
            return not capability(node.context_expr)
        if isinstance(node, ast.Match):
            return not capability(node.subject)
        if isinstance(node, ast.MatchValue):
            return not capability(node.value)
        if isinstance(node, ast.MatchMapping):
            return not any(capability(value) for value in node.keys)
        return True

    def pure_class_base(self, node, seen=None):
        seen = set() if seen is None else seen
        for name in self.refs(node):
            klass = self.class_nodes.get(name)
            if klass is None:
                continue
            if (
                name in seen
                or klass.keywords
                or klass.decorator_list
                or len(klass.bases) > 1
            ):
                return False
            for method in klass.body:
                if (
                    isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and method.name == "__init_subclass__"
                ):
                    if method.decorator_list or not all(
                        isinstance(statement, ast.Pass)
                        or isinstance(statement, ast.Return)
                        and (
                            statement.value is None
                            or isinstance(statement.value, ast.Constant)
                            and statement.value.value is None
                        )
                        or isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str)
                        for statement in method.body
                    ):
                        return False
            if not all(
                self.canonical_reference(base)
                and self.pure_class_base(base, seen | {name})
                for base in klass.bases
            ):
                return False
        return True

    def stable(
        self,
        sensitive,
        *,
        environment=False,
        key=None,
        callable_names=(),
        opaque_ok=False,
        immutable_values=(),
    ):
        if immutable_values and key is not None:
            key = (key, "immutable-values", tuple(sorted(immutable_values)))
        if not self.complete:
            return False
        if key is not None and key in self.stable_results:
            return self.stable_results[key]
        result = self._stable_scan(
            sensitive,
            environment=environment,
            callable_names=callable_names,
            opaque_ok=opaque_ok,
            immutable_values=immutable_values,
        )
        if key is not None:
            self.stable_results[key] = result
        return result and self.complete

    def _stable_scan(
        self,
        sensitive,
        *,
        environment=False,
        callable_names=(),
        opaque_ok=False,
        immutable_values=(),
    ):
        if not self.complete:
            return False
        immutable_values = _IMMUTABLE_VALUES | frozenset(immutable_values)
        for node in self.nodes:
            if not self.implicit_use_is_safe(node, sensitive, immutable_values):
                return False
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if any(sensitive(name) for name in self.refs(node)):
                    return False
            if isinstance(node, ast.Call):
                functions = self.refs(node.func)
                if any(
                    sensitive(name) and name not in immutable_values
                    for name in functions
                ):
                    if not self.canonical_reference(node.func) or not functions <= set(
                        callable_names
                    ):
                        return False
                if (
                    not opaque_ok
                    and isinstance(node.func, ast.Name)
                    and node.func.id
                    in {
                        "exec",
                        "eval",
                        "__import__",
                    }
                ):
                    return False
                if (
                    environment
                    and not opaque_ok
                    and any(
                        name == "importlib" or name.startswith("importlib.")
                        for name in functions
                    )
                ):
                    return False
                # Any method of mutable import state may mutate it. Saved
                # aliases and provider reflective setters remain capabilities.
                if (
                    environment
                    and functions != {"sys.path.copy"}
                    and any(sensitive(name) for name in functions)
                ):
                    return False
                if any(
                    sensitive(name) and name.rsplit(".", 1)[-1] in _SETTERS
                    for name in functions
                ):
                    return False
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and node.args
                ):
                    if any(sensitive(name) for name in self.refs(node.args[0])):
                        return False
                arguments = [*node.args, *[kw.value for kw in node.keywords]]
                escaped = any(
                    sensitive(name) and name not in immutable_values
                    for argument in arguments
                    for name in self.refs(argument)
                )
                if (
                    escaped
                    and not self.safe_reader_call(node)
                    and not functions <= _MODELED_CAPABILITY_CALLS
                ):
                    return False
                if escaped and not functions and not self.safe_reader_call(node):
                    return False
            elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom, ast.Lambda)):
                if any(
                    sensitive(name) and name not in immutable_values
                    for name in self.refs(
                        node.body if isinstance(node, ast.Lambda) else node.value
                    )
                ):
                    return False
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if not all(isinstance(target, ast.Name) for target in targets) and any(
                    sensitive(name) and name not in immutable_values
                    for name in self.refs(node.value)
                ):
                    return False
        return self.complete


def _effects(tree):
    try:
        result = getattr(tree, "_skylos_native_effects", None)
        if result is None:
            result = _Effects(tree)
            if tree is not None:
                tree._skylos_native_effects = result
        return result
    except (RecursionError, TypeError, ValueError):
        return None


def import_environment_is_stable(tree, opaque_ok=False):
    """No visible import search/cache/hook mutation or opaque capability escape.

    With ``opaque_ok`` only visible mutation counts: ``exec``/``eval``,
    ``__import__`` and ``importlib`` calls are not treated as rewrites."""
    effects = _effects(tree)
    return bool(
        effects
        and effects.stable(
            lambda name: (
                name == "sys"
                or name.startswith("sys.__")
                or any(
                    name == root or name.startswith(root + ".")
                    for root in _IMPORT_STATE
                )
            ),
            environment=True,
            key=("environment", opaque_ok),
            callable_names={"sys.path.copy"},
            opaque_ok=opaque_ok,
        )
    )


def _provider_effects(
    qualified_names, tree, local_symbols=(), opaque_ok=False, immutable_values=()
):
    if not import_environment_is_stable(tree, opaque_ok):
        return False
    effects = _effects(tree)
    names = set(qualified_names)
    for symbol in local_symbols:
        head, separator, rest = symbol.partition(".")
        names.update(
            value + ("." + rest if separator else "")
            for value in effects.aliases.get((None, head), ())
        )
    ancestors = {
        ".".join(name.split(".")[:index])
        for name in names
        for index in range(1, len(name.split(".")) + 1)
    }
    roots = {name.split(".", 1)[0] for name in names}

    def sensitive(name):
        return (
            name in ancestors
            or any(name.startswith(value + ".") for value in names)
            or any(name.startswith(root + ".__") for root in roots)
        )

    safe_methods = {
        base + method
        for base in ("yaml.SafeLoader", "yaml.CSafeLoader")
        for method in (".construct_mapping", ".__init__")
    }
    return effects.stable(
        sensitive,
        key=("provider", tuple(sorted(names)), opaque_ok),
        callable_names=names | safe_methods,
        opaque_ok=opaque_ok,
        immutable_values=immutable_values,
    )


def provider_effects_are_stable(qualified, tree):
    """Native provider capabilities stay local and unmodified in this tree."""
    return _provider_effects((qualified,), tree)


def provider_binding_is_stable(qualified, tree, filename, project_root=None):
    """Project effects plus absence of a source/opaque native provider."""
    if qualified in _YAML_DATA_ONLY_LOADERS and not provider_binding_is_stable(
        "builtins.getattr", tree, filename, project_root
    ):
        return False
    if not provider_is_unshadowed(qualified, filename, project_root):
        return False
    context = None
    try:
        if Path(filename).is_file():
            context = project_import_context(tree, filename, project_root)
    except (OSError, RuntimeError, ValueError, TypeError):
        return False
    if context is not None and qualified.split(".", 1)[0] in context.modules:
        return False
    if project_provider_effects_are_stable(qualified, tree, filename, project_root):
        return True
    return provider_is_visibly_untampered(qualified, tree, filename, project_root)


_IMPORT_HOOK_NAMES = frozenset(
    {"meta_path", "path_hooks", "path_importer_cache", "addsitedir"}
)
_MODULE_SUFFIXES = (".py", ".pyw", ".pyi", ".pyc", ".pyo", ".so", ".pyd")
_SOURCE_SUFFIXES = (".py", ".pyw", ".pyi")
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_ZIP_END_SIGNATURE = b"PK\x05\x06"
_ZIP_END_RECORD = 22
_ZIP_END_WINDOW = _ZIP_END_RECORD + 65_535
_INSTALLED_PACKAGE_DIRS = frozenset({"site-packages", "dist-packages"})
_MODULE_DUNDERS = frozenset(
    {"__class__", "__dict__", "__getattr__", "__getattribute__"}
)
_OPAQUE_LOADERS = frozenset(
    {
        "SourcelessFileLoader",
        "ExtensionFileLoader",
        "zipimporter",
        "load_compiled",
        "load_dynamic",
        "load_package",
    }
)
_LOADER_PATH_ARGUMENTS = {
    "SourceFileLoader": (1, "path"),
    "spec_from_file_location": (1, "location"),
    "run_path": (0, "path_name"),
    "load_source": (1, "pathname"),
    "execfile": (0, None),
}
_CODE_BUILTINS = frozenset({"exec", "eval", "compile"})
_READERS = frozenset({"read", "read_text", "read_bytes"})
_PATH_MODULES = frozenset(
    {
        "os",
        "os.path",
        "posixpath",
        "ntpath",
        "pathlib",
        "pathlib.Path",
        "pathlib.PurePath",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
        "pathlib.PurePosixPath",
        "pathlib.PureWindowsPath",
        "builtins",
    }
)
_PATH_FUNCTIONS = frozenset(
    {
        "join",
        "dirname",
        "abspath",
        "realpath",
        "normpath",
        "fspath",
        "Path",
        "PurePath",
        "PosixPath",
        "WindowsPath",
        "PurePosixPath",
        "PureWindowsPath",
        "resolve",
        "absolute",
        "parent",
        "parents",
        "getcwd",
        "open",
        "read",
        "read_text",
        "read_bytes",
        "str",
        "path",
        "__truediv__",
    }
)
_MAX_SHIPPED_FILES = 200_000
_MAX_SHIPPED_DIRECTORIES = 50_000
_MAX_TAIL_BYTES = 512_000_000
_MAX_EXTRA_FILE_BYTES = 2_000_000
_MAX_EXTRA_TOTAL_BYTES = 32_000_000
_MAX_EXTRA_NODES = 1_000_000
_MAX_CODE_STRING_DEPTH = 3
_MAX_EVAL_DEPTH = 8
_UNRESOLVED = object()
_INVENTORIES = {}
_EXTRA_TREES = {}
_FAILED_INVENTORY = ("failed",)


def _literal_text(node):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("latin-1")
    return None


def _names_package(text, root):
    return text == root or text.startswith(root + ".")


def _parsed_code(text):
    """A string literal that is itself Python with a statement beyond a bare
    name or constant (for example code handed to ``exec``), else None."""
    if "\n" not in text and ";" not in text and "=" not in text and "(" not in text:
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    for statement in tree.body:
        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, (ast.Name, ast.Constant)
        ):
            return tree
    return None


def _call_name(func):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


_PATH_FUNCTION_NAMES = frozenset(
    {
        "os.path.join",
        "os.path.dirname",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.normpath",
        "posixpath.join",
        "posixpath.dirname",
        "posixpath.abspath",
        "posixpath.realpath",
        "posixpath.normpath",
        "ntpath.join",
        "ntpath.dirname",
        "ntpath.abspath",
        "ntpath.realpath",
        "ntpath.normpath",
        "os.fspath",
        "builtins.str",
        "builtins.open",
    }
)
_PATH_JOINERS = frozenset({"join"})
_CAPABILITIES = (
    frozenset(
        {
            "exec",
            "eval",
            "compile",
            "getattr",
            "setattr",
            "delattr",
            "vars",
            "globals",
            "locals",
            "__import__",
            "import_module",
            "reload",
        }
    )
    | frozenset(_LOADER_PATH_ARGUMENTS)
    | _OPAQUE_LOADERS
)
_REFLECTORS = frozenset({"setattr", "delattr"})
_CAPABILITY_MODULES = frozenset(
    {"builtins", "importlib", "importlib.util", "importlib.machinery", "runpy", "imp"}
)
_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_VALUE_MODULES = frozenset({"os", "os.path", "posixpath", "ntpath", "builtins"})
_VALUE_MODULE_NAMES = ("os", "path", "posixpath", "ntpath", "builtins")
_REEXPORT_MODULE_NAMES = ("os", "posixpath", "ntpath", "builtins")
_REQUEST_SCOPED = {"flask": ("flask.g", "flask.session", "flask.request")}
_FUNCTION_DUNDERS = frozenset(
    {"__code__", "__defaults__", "__kwdefaults__", "__wrapped__", "__call__"}
)
_SCOPE_DUNDERS = frozenset({"__globals__", "__closure__", "__builtins__"})


def _comprehension_walrus_targets(comprehension):
    """Names a ``:=`` inside a comprehension binds: they belong to the scope
    containing the comprehension (PEP 572), through nested comprehensions
    but not nested functions, lambdas or classes."""
    pending = list(ast.iter_child_nodes(comprehension))
    while pending:
        node = pending.pop()
        if isinstance(node, (*_FUNCTION_SCOPES, ast.ClassDef)):
            continue
        if isinstance(node, ast.NamedExpr):
            yield node.target.id
        pending.extend(ast.iter_child_nodes(node))


def _scope_info(scope):
    """``(bindings, globals, nonlocals)`` for a module, function, lambda,
    class or comprehension scope: the ``(kind, value)`` bindings it makes
    itself (parameters, stores, defs, classes, imports, match captures,
    comprehension targets), not those of nested scopes, plus its ``global``
    and ``nonlocal`` declarations. Decorators, defaults, annotations,
    class bases and a comprehension's first iterable belong to the
    enclosing scope and are walked there."""
    bindings = {}
    declared_global = set()
    declared_nonlocal = set()

    def bind(name, kind, value):
        bindings.setdefault(name, []).append((kind, value))

    in_comprehension = isinstance(scope, _COMPREHENSIONS)
    pending = []
    if isinstance(scope, _FUNCTION_SCOPES):
        for arg in ast.walk(scope.args):
            if isinstance(arg, ast.arg):
                bind(arg.arg, "other", None)
        if isinstance(scope, ast.Lambda):
            pending.append(scope.body)
        else:
            pending.extend(scope.body)
    elif isinstance(scope, ast.ClassDef):
        pending.extend(scope.body)
    elif isinstance(scope, _COMPREHENSIONS):
        for index, generator in enumerate(scope.generators):
            for name in _stored_names(generator.target):
                bind(name.id, "other", None)
            if index:
                pending.append(generator.iter)
            pending.extend(generator.ifs)
        if isinstance(scope, ast.DictComp):
            pending.extend([scope.key, scope.value])
        else:
            pending.append(scope.elt)
    else:
        pending.extend(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Global):
            declared_global.update(node.names)
            continue
        if isinstance(node, ast.Nonlocal):
            declared_nonlocal.update(node.names)
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name, "other", None)
            pending.extend(node.decorator_list)
            if isinstance(node, ast.ClassDef):
                pending.extend(node.bases)
                pending.extend(keyword.value for keyword in node.keywords)
            else:
                pending.extend(node.args.defaults)
                pending.extend(item for item in node.args.kw_defaults if item)
            continue
        if isinstance(node, ast.Lambda):
            pending.extend(node.args.defaults)
            pending.extend(item for item in node.args.kw_defaults if item)
            continue
        if isinstance(node, _COMPREHENSIONS):
            pending.append(node.generators[0].iter)
            if not in_comprehension:
                for name in _comprehension_walrus_targets(node):
                    bind(name, "other", None)
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bind(alias.asname, "module", alias.name)
                else:
                    head = alias.name.split(".", 1)[0]
                    bind(head, "module", head)
            continue
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    bind("*", "other", None)
                elif node.module and not node.level:
                    bind(
                        alias.asname or alias.name,
                        "import",
                        node.module + "." + alias.name,
                    )
                else:
                    bind(
                        alias.asname or alias.name,
                        "relative",
                        "." * node.level + (node.module or "") + "." + alias.name,
                    )
            continue
        if isinstance(node, ast.NamedExpr) and in_comprehension:
            pending.append(node.value)
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bind(target.id, "assign", node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bind(node.target.id, "assign", node.value)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target.id, "alias", node.value)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id, "other", None)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bind(node.name, "other", None)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name, "other", None)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest, "other", None)
        pending.extend(ast.iter_child_nodes(node))
    return bindings, declared_global, declared_nonlocal


_NAMESPACE_WRITERS = frozenset(
    {
        "update",
        "setdefault",
        "pop",
        "popitem",
        "clear",
        "__setitem__",
        "__delitem__",
        "__ior__",
    }
)
_PATH_PARENTS = frozenset({"dirname"})


def _stored_names(target):
    """The names a target actually binds: ``Name`` nodes in store or delete
    position, through tuples, lists and starred targets, never the names
    read inside a subscript or attribute target."""
    pending = [target]
    while pending:
        current = pending.pop()
        if isinstance(current, ast.Name):
            if isinstance(current.ctx, (ast.Store, ast.Del)):
                yield current
        elif isinstance(current, (ast.Tuple, ast.List)):
            pending.extend(current.elts)
        elif isinstance(current, ast.Starred):
            pending.append(current.value)


def _bound_names(node):
    """Every ``(name, kind, value)`` binding in ``node``: assignments (with
    their value), augmented and annotated assignments, named expressions,
    loop, ``with`` and ``except`` targets, deletes, ``global``/``nonlocal``
    declarations, parameters, ``def``/``class`` names and imports (with the
    imported dotted name)."""
    for part in ast.walk(node):
        if isinstance(part, ast.Assign):
            for target in part.targets:
                for name in _stored_names(target):
                    value = None
                    if target is name:
                        value = part.value
                    yield name.id, "assign", value
        elif isinstance(part, ast.NamedExpr):
            yield part.target.id, "alias", part.value
        elif isinstance(part, (ast.AugAssign, ast.AnnAssign)):
            for name in _stored_names(part.target):
                value = None
                if isinstance(part, ast.AnnAssign) and part.target is name:
                    value = part.value
                yield name.id, "assign", value
        elif isinstance(part, (ast.For, ast.AsyncFor, ast.comprehension)):
            for name in _stored_names(part.target):
                yield name.id, "other", None
        elif isinstance(part, ast.withitem) and part.optional_vars is not None:
            for name in _stored_names(part.optional_vars):
                yield name.id, "other", None
        elif isinstance(part, ast.ExceptHandler) and part.name:
            yield part.name, "other", None
        elif isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name:
            yield part.name, "other", None
        elif isinstance(part, ast.MatchMapping) and part.rest:
            yield part.rest, "other", None
        elif isinstance(part, ast.Delete):
            for target in part.targets:
                for name in _stored_names(target):
                    yield name.id, "other", None
        elif isinstance(part, (ast.Global, ast.Nonlocal)):
            for name in part.names:
                yield name, "other", None
        elif isinstance(part, ast.arg):
            yield part.arg, "other", None
        elif isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield part.name, "other", None
        elif isinstance(part, ast.Import):
            for alias in part.names:
                if alias.asname:
                    yield alias.asname, "module", alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    yield head, "module", head
        elif isinstance(part, ast.ImportFrom):
            for alias in part.names:
                if alias.name == "*":
                    yield "*", "other", None
                elif part.module and not part.level:
                    yield (
                        alias.asname or alias.name,
                        "import",
                        part.module + "." + alias.name,
                    )
                elif part.level:
                    yield (
                        alias.asname or alias.name,
                        "relative",
                        "." * part.level + (part.module or "") + "." + alias.name,
                    )
                else:
                    yield alias.asname or alias.name, "other", None


class _ScanContext:
    """State shared by a file and the code strings inside it: every binding
    of every name, provider and path-module names, and the loader and code
    calls whose paths are checked after the whole file."""

    def __init__(self, root, source_path):
        self.root = root
        self.source_path = source_path
        self.bindings = {}
        self.provider_names = {root}
        self.path_names = set()
        self.builtins_names = set()
        self.module_bindings = {}
        self.provider_spellings = frozenset({root})
        self.value_spellings = frozenset(_VALUE_MODULE_NAMES)
        self.reexport_spellings = frozenset({root, *_REEXPORT_MODULE_NAMES})
        self.provider_module_spellings = frozenset({root})
        self.provider_pairs = frozenset()
        self.value_pairs = frozenset()
        self.provider_paths = {}
        self.module_names = ()
        self.package = False
        self.scope_cache = {}
        self.loader_calls = []
        self.code_calls = []
        self.opaque_code = False

    def learn(self, tree):
        if isinstance(tree, ast.Module):
            bindings, _, _ = _scope_info(tree)
            for name, entries in bindings.items():
                self.module_bindings.setdefault(name, []).extend(entries)
        for name, kind, value in _bound_names(tree):
            self.bindings.setdefault(name, []).append((kind, value))
        changed = True
        rounds = 0
        while changed and rounds < 16:
            changed = False
            rounds += 1
            for name, entries in self.bindings.items():
                for kind, value in entries:
                    changed = self._classify(name, kind, value) or changed

    def _classify(self, name, kind, value):
        before = (
            name in self.provider_names,
            name in self.path_names,
            name in self.builtins_names,
        )
        if kind in ("import", "module", "relative"):
            leaf = value.rsplit(".", 1)[-1]
            if _names_package(value, self.root) or (
                kind != "module" and leaf == self.root
            ):
                self.provider_names.add(name)
            if value in _PATH_MODULES or (
                kind != "module" and leaf in _VALUE_MODULE_NAMES
            ):
                self.path_names.add(name)
            if value == "builtins" or (kind != "module" and leaf == "builtins"):
                self.builtins_names.add(name)
        elif kind in ("assign", "alias") and value is not None:
            source = self._unwrap(value)
            if isinstance(source, ast.Name):
                if source.id in self.provider_names:
                    self.provider_names.add(name)
                if source.id in self.path_names:
                    self.path_names.add(name)
                if source.id in self.builtins_names:
                    self.builtins_names.add(name)
        after = (
            name in self.provider_names,
            name in self.path_names,
            name in self.builtins_names,
        )
        return before != after

    def _unwrap(self, node):
        while isinstance(node, ast.NamedExpr):
            node = node.value
        return node

    def sole_binding(self, name):
        entries = self.bindings.get(name, ())
        if len(entries) != 1 or "*" in self.bindings:
            return None
        if entries[0][0] == "alias":
            return None
        return entries[0]

    def qualified(self, func):
        """The dotted stdlib name a call target is proven to mean: a name
        bound exactly once by an import, an attribute chain on a module
        name bound exactly once by an import, or an unbound builtin."""
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        binding = self.sole_binding(current.id)
        if binding is None:
            if current.id in self.bindings or "*" in self.bindings:
                return None
            if parts:
                return None
            return "builtins." + current.id
        kind, value = binding
        if kind not in ("import", "module"):
            return None
        return ".".join([value, *reversed(parts)])

    def receiver_root(self, node):
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.NamedExpr)):
            if isinstance(node, ast.Call):
                node = node.func
            else:
                node = node.value
        if isinstance(node, ast.Name):
            return node.id
        return None


class _ProviderMentions(ast.NodeVisitor):
    """One pass for any literal way project code could name, rewrite or
    redirect the provider: the helper or provider package (or a file named
    for it) as a string or bytes literal or a keyword; an attribute store of
    the helper name; a store of a module-level dunder on a provider name or
    alias, or a dunder named by literal; a store of a path function or
    attribute on a path module or class; an import-hook or ``site`` name;
    an opaque bytecode or native loader; ``__builtins__``; and the same
    inside string literals that are themselves code. Source-loader and
    ``exec``/``eval``/``compile`` calls are collected for path checks."""

    def __init__(self, leaf, context, depth=0):
        self.leaf = leaf
        self.context = context
        self.root = context.root
        self.depth = depth
        self.found = False
        self.stack = []

    def generic_visit(self, node):
        if not self.found and self._mentions(node):
            self.found = True
        if not self.found:
            self.stack.append(node)
            super().generic_visit(node)
            self.stack.pop()

    def _parent(self):
        if self.stack:
            return self.stack[-1]
        return None

    def _info(self, scope):
        cache = self.context.scope_cache
        info = cache.get(id(scope))
        if info is None:
            info = _scope_info(scope)
            cache[id(scope)] = info
        return info

    def _scope_applies(self, scope, child, grandchild):
        """Whether a read reached through ``child`` (and ``grandchild``) is
        evaluated inside ``scope``."""
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return any(child is statement for statement in scope.body)
        if isinstance(scope, ast.Lambda):
            return child is scope.body
        if isinstance(scope, _COMPREHENSIONS):
            first = scope.generators[0]
            return not (child is first and grandchild is first.iter)
        return False

    def _resolve(self, name, node):
        """Every binding a read of ``name`` at ``node`` may resolve to under
        Python's scoping rules: function, lambda and comprehension bodies
        are definitive local scopes; a class body may still read the outer
        binding before its own exists, so both are returned; class scopes
        are invisible to nested functions and comprehensions; ``global``
        and ``nonlocal`` are honoured. An unbound name yields a builtin
        entry."""
        path = [*self.stack, node]
        inside_function = False
        class_entries = []
        for index in range(len(self.stack) - 1, -1, -1):
            scope = path[index]
            if not isinstance(
                scope, (*_FUNCTION_SCOPES, ast.ClassDef, *_COMPREHENSIONS)
            ):
                continue
            child = path[index + 1]
            grandchild = None
            if index + 2 < len(path):
                grandchild = path[index + 2]
            if not self._scope_applies(scope, child, grandchild):
                continue
            if isinstance(scope, ast.ClassDef) and inside_function:
                continue
            bindings, declared_global, declared_nonlocal = self._info(scope)
            if isinstance(scope, (*_FUNCTION_SCOPES, *_COMPREHENSIONS)):
                inside_function = True
            if name in declared_global:
                break
            if name in declared_nonlocal:
                continue
            if name not in bindings:
                continue
            if isinstance(scope, ast.ClassDef):
                class_entries.extend(bindings[name])
                continue
            return [*class_entries, *bindings[name]]
        outer = self.context.module_bindings.get(name)
        if outer is None:
            outer = [("builtin", None)]
        return [*class_entries, *outer]

    def _tracked_module(self, entries):
        """Any binding the read may resolve to imports the provider package
        (``import``) or a value module such as ``os``, ``os.path`` or
        ``builtins``, or imports a name spelled like one from anywhere (a
        project re-export such as ``from shop.helpers import flask``); a
        later rebinding does not prove the import unused."""
        for kind, value in entries:
            if kind == "module" and (
                _names_package(value, self.root) or value in _VALUE_MODULES
            ):
                return True
            if kind not in ("import", "relative"):
                continue
            pair = self._import_pair(kind, value)
            if (
                value in _VALUE_MODULES
                or pair in self.context.provider_pairs
                or pair in self.context.value_pairs
            ):
                return True
        return False

    def _import_pair(self, kind, value):
        """``(absolute module, member)`` for a ``from`` import binding."""
        module, _, member = value.rpartition(".")
        if kind == "relative":
            level = len(module) - len(module.lstrip("."))
            for importer in self.context.module_names:
                module = _absolute_module(
                    module.lstrip("."), level, importer, self.context.package
                )
                break
        return module, member

    def _capability(self, name, entries):
        for kind, value in entries:
            if kind == "builtin" and name in _CAPABILITIES:
                return True
            if (
                kind == "import"
                and value.rsplit(".", 1)[-1] in _CAPABILITIES
                and value.rsplit(".", 1)[0] in _CAPABILITY_MODULES
            ):
                return True
        return False

    def _plain_use(self, node):
        """A capability, provider module or path module used directly:
        called, read as ``module.attribute``, or handed to a getattr/
        setattr-style helper with a literal member that is neither a
        capability, a path function nor the helper name."""
        parent = self._parent()
        if isinstance(parent, ast.Attribute) and parent.value is node:
            return True
        if not isinstance(parent, ast.Call):
            return False
        if parent.func is node:
            return True
        if not parent.args or parent.args[0] is not node or len(parent.args) < 2:
            return False
        if _call_name(parent.func) not in ("setattr", "getattr", "hasattr", "delattr"):
            return False
        member = _literal_text(parent.args[1])
        return member is not None and not (
            member in _CAPABILITIES
            or member in _PATH_FUNCTIONS
            or member in _MODULE_DUNDERS
            or member == self.leaf
        )

    def _mentions(self, node):
        text = _literal_text(node)
        if text is not None:
            if (
                text == self.leaf
                or _names_package(text, self.root)
                or text in _IMPORT_HOOK_NAMES
                or text in _OPAQUE_LOADERS
                or text in _MODULE_DUNDERS
                or text in _FUNCTION_DUNDERS
                or text in _SCOPE_DUNDERS
                or self._names_provider_file(text)
            ):
                return True
            return self._code_mentions(text)
        if isinstance(node, ast.keyword):
            return node.arg in (self.leaf, self.root)
        if isinstance(node, ast.alias):
            imported = node.name.rsplit(".", 1)[-1]
            parent = self._parent()
            module = None
            if isinstance(parent, ast.ImportFrom) and not parent.level:
                module = parent.module
            if (
                node.asname
                and node.asname != imported
                and imported in _CAPABILITIES
                and module in _CAPABILITY_MODULES
            ):
                return True
            return (
                node.name == "site"
                or node.name in _IMPORT_HOOK_NAMES
                or imported in _OPAQUE_LOADERS
            )
        if isinstance(node, ast.ImportFrom):
            if node.module == "builtins":
                return True
            if (
                node.module
                and not node.level
                and _names_package(node.module, self.root)
                and any(alias.name == "*" for alias in node.names)
            ):
                return True
            return node.module == "site"
        if isinstance(node, ast.Name):
            if node.id == "__builtins__":
                return True
            if not isinstance(node.ctx, ast.Load):
                return False
            entries = self._resolve(node.id, node)
            if self._tracked_module(entries) or self._capability(node.id, entries):
                return not self._plain_use(node)
            return False
        if isinstance(node, ast.Call):
            return self._call_mentions(node)
        if isinstance(node, ast.Attribute):
            if (
                node.attr in _IMPORT_HOOK_NAMES
                or node.attr in _OPAQUE_LOADERS
                or node.attr in _SCOPE_DUNDERS
            ):
                return True
            if not isinstance(node.ctx, (ast.Store, ast.Del)):
                return self._attribute_value_mentions(node)
            if node.attr == self.leaf or node.attr in _FUNCTION_DUNDERS:
                return True
            path = self._provider_path(node.value)
            if path is not None and not self._request_scoped(path):
                return True
            receiver = self.context.receiver_root(node.value)
            chain = self._chain_names(node.value)
            if node.attr in _MODULE_DUNDERS and (
                receiver in self.context.provider_names
                or receiver in self.context.provider_spellings
                or bool(chain & self.context.provider_spellings)
            ):
                return True
            return node.attr in _PATH_FUNCTIONS and (
                receiver in self.context.path_names
                or (
                    receiver in self.context.value_spellings
                    and receiver not in _VALUE_MODULE_NAMES
                )
                or bool(chain & self.context.value_spellings)
            )
        if isinstance(node, ast.Subscript) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            return self._module_dict_write(node.value)
        return False

    def _provider_path(self, node, depth=0):
        """The dotted path inside the provider package an expression denotes
        (``flask``, ``flask.helpers``, ``flask.g.user``), resolving names by
        scope, ``from <provider> import x``, module-qualified re-exports of
        the provider module, attribute chains, subscripts and literal
        ``getattr``; None when it is not provably inside the provider."""
        if depth > _MAX_EVAL_DEPTH:
            return None
        while isinstance(node, ast.NamedExpr):
            node = node.value
        if isinstance(node, ast.Attribute):
            base = self._provider_path(node.value, depth + 1)
            if base is not None:
                return base + "." + node.attr
            qualified = self._qualified_in_scope(node)
            if qualified is None:
                return None
            return self.context.provider_paths.get(tuple(qualified.rsplit(".", 1)))
        if isinstance(node, ast.Subscript):
            base = self._provider_path(node.value, depth + 1)
            if base is None:
                return None
            return base + ".[]"
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and _literal_text(node.args[1]) is not None
            ):
                base = self._provider_path(node.args[0], depth + 1)
                if base is None:
                    return None
                return base + "." + _literal_text(node.args[1])
            return None
        if not isinstance(node, ast.Name):
            return None
        for kind, value in self._resolve(node.id, node):
            if kind == "module" and _names_package(value, self.root):
                return value
            if kind in ("assign", "alias") and value is not None:
                aliased = self._provider_path(value, depth + 1)
                if aliased is not None:
                    return aliased
                continue
            if kind not in ("import", "relative"):
                continue
            module, member = self._import_pair(kind, value)
            if _names_package(module, self.root):
                return module + "." + member
            known = self.context.provider_paths.get((module, member))
            if known is not None:
                return known
        return None

    def _reexported_module(self, node):
        """A project attribute that is, by module-qualified identity, the
        provider module or a value module (``helpers.f`` where
        ``shop.helpers`` does ``import flask as f``)."""
        qualified = self._qualified_in_scope(node)
        if qualified is None:
            return False
        pair = tuple(qualified.rsplit(".", 1))
        return pair in self.context.provider_pairs or pair in self.context.value_pairs

    def _qualified_in_scope(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or not parts:
            return None
        for kind, value in self._resolve(node.id, node):
            if kind == "module":
                return ".".join([value, *reversed(parts)])
            if kind in ("import", "relative"):
                module, member = self._import_pair(kind, value)
                return ".".join([module, member, *reversed(parts)])
        return None

    def _request_scoped(self, path):
        """A request-scoped provider object an application writes to
        normally (``flask.g.user = ...``), not library state."""
        return any(
            path == allowed or path.startswith(allowed + ".")
            for allowed in _REQUEST_SCOPED.get(self.root, ())
        )

    def _chain_names(self, node):
        """Every attribute name in a receiver chain such as ``h.flask``."""
        names = set()
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.NamedExpr)):
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
                node = node.value
            elif isinstance(node, ast.Call):
                node = node.func
            else:
                node = node.value
        return names

    def _attribute_value_mentions(self, node):
        """Taking the namespace of a path module or the provider, using a
        path module reached by attribute (``os.path``) or a provider or value
        module re-exported as a project attribute (``helpers.flask``) as a
        value, or using a capability attribute (``builtins.exec``,
        ``importlib.import_module``) as a value."""
        receiver = self.context.receiver_root(node.value)
        chain = self._chain_names(node.value)
        if node.attr == "__dict__" and (
            receiver in self.context.path_names
            or receiver in self.context.provider_names
            or bool(chain & self.context.provider_spellings)
            or bool(chain & self.context.value_spellings)
        ):
            return True
        if self._reexported_module(node):
            return not self._plain_use(node)
        qualified = self.context.qualified(node)
        if qualified in _VALUE_MODULES:
            return not self._plain_use(node)
        if node.attr in _CAPABILITIES and (
            self.context.qualified(node.value) in _CAPABILITY_MODULES
        ):
            return not self._plain_use(node)
        return False

    def _module_dict_write(self, value):
        """A write into the namespace of a path module or a provider name:
        ``os.path.__dict__["join"] = ...`` or ``vars(flask)[...] = ...``."""
        if isinstance(value, ast.Attribute) and value.attr == "__dict__":
            receiver = self.context.receiver_root(value.value)
        elif (
            isinstance(value, ast.Call)
            and _call_name(value.func) == "vars"
            and value.args
        ):
            receiver = self.context.receiver_root(value.args[0])
        else:
            return False
        return (
            receiver in self.context.path_names
            or receiver in self.context.provider_names
        )

    def _call_mentions(self, node):
        func = node.func
        name = _call_name(func)
        if name in _OPAQUE_LOADERS:
            return True
        if (
            isinstance(func, ast.Name)
            and func.id in ("globals", "locals", "vars")
            and not node.args
            and not node.keywords
        ):
            return True
        if name == "vars" and node.args:
            receiver = self.context.receiver_root(node.args[0])
            if (
                receiver in self.context.path_names
                or receiver in self.context.provider_names
            ):
                return True
        if name in _REFLECTORS and node.args:
            receiver = self.context.receiver_root(node.args[0])
            if receiver in self.context.provider_names:
                return True
            if receiver in self.context.path_names:
                member = None
                if len(node.args) > 1:
                    member = _literal_text(node.args[1])
                if member is None or member in _PATH_FUNCTIONS:
                    return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _NAMESPACE_WRITERS
            and self._module_dict_write(func.value)
        ):
            return True
        if name == "getattr" and any(
            _literal_text(argument) in _CODE_BUILTINS for argument in node.args[1:2]
        ):
            return True
        if name in _LOADER_PATH_ARGUMENTS:
            self.context.loader_calls.append((name, node))
            return False
        alias = self._loader_alias(func)
        if alias is not None:
            self.context.loader_calls.append((alias, node))
            return False
        if name in _CODE_BUILTINS and self._code_builtin(func):
            self.context.code_calls.append(node)
        return False

    def _loader_alias(self, func):
        if not isinstance(func, ast.Name):
            return None
        for kind, value in self.context.bindings.get(func.id, ()):
            if (
                kind in ("import", "module")
                and value.rsplit(".", 1)[-1] in _LOADER_PATH_ARGUMENTS
            ):
                return value.rsplit(".", 1)[-1]
            if kind == "assign" and value is not None:
                source = _call_name(self.context._unwrap(value))
                if source in _LOADER_PATH_ARGUMENTS:
                    return source
                if isinstance(self.context._unwrap(value), ast.Name):
                    target = self.context._unwrap(value).id
                    if target in _LOADER_PATH_ARGUMENTS:
                        return target
        return None

    def _code_builtin(self, func):
        if isinstance(func, ast.Name):
            return True
        receiver = self.context.receiver_root(func.value)
        return receiver in self.context.builtins_names

    def _names_provider_file(self, text):
        if "/" not in text and "\\" not in text:
            return False
        parts = [part for part in text.replace("\\", "/").split("/") if part]
        return any(
            part == self.root or part.startswith(self.root + ".") for part in parts
        )

    def _code_mentions(self, text):
        code = _parsed_code(text)
        if code is None:
            return False
        if self.depth >= _MAX_CODE_STRING_DEPTH:
            return True
        self.context.learn(code)
        inner = _ProviderMentions(self.leaf, self.context, self.depth + 1)
        inner.visit(code)
        return inner.found


class _PathEvaluator:
    """Absolute literal path values built from ``__file__`` (never rebound
    in the file): string literals, f-strings of constants, ``+`` and ``/``
    joins, proven ``os.path.join``/``dirname``/``abspath``/``realpath``/
    ``normpath``, ``str``/``fspath``/``Path`` and friends, ``.parent``,
    bounded ``.parents[n]``, ``.resolve()``/``.absolute()``, and names
    bound exactly once by a plain assignment. Anything else, including a
    relative result whose runtime base is unknown, is unresolved."""

    def __init__(self, context):
        self.context = context

    def value(self, node, depth=0):
        if depth > _MAX_EVAL_DEPTH:
            return _UNRESOLVED
        text = _literal_text(node)
        if text is not None:
            return text
        if isinstance(node, ast.NamedExpr):
            return _UNRESOLVED
        if isinstance(node, ast.Name):
            return self._name(node.id, depth)
        if isinstance(node, ast.JoinedStr):
            return self._joined(node, depth)
        if isinstance(node, ast.BinOp):
            return self._binop(node, depth)
        if isinstance(node, ast.Call):
            return self._call(node, depth)
        return _UNRESOLVED

    def _name(self, name, depth):
        if name == "__file__":
            if name in self.context.bindings or not self.context.source_path:
                return _UNRESOLVED
            return str(self.context.source_path)
        binding = self.context.sole_binding(name)
        if binding is None or binding[0] != "assign" or binding[1] is None:
            return _UNRESOLVED
        return self.value(binding[1], depth + 1)

    def _joined(self, node, depth):
        parts = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if part.format_spec is not None or part.conversion not in (-1, 115):
                    return _UNRESOLVED
                part = part.value
            resolved = self.value(part, depth + 1)
            if resolved is _UNRESOLVED:
                return _UNRESOLVED
            parts.append(resolved)
        return "".join(parts)

    def _binop(self, node, depth):
        left = self.value(node.left, depth + 1)
        right = self.value(node.right, depth + 1)
        if left is _UNRESOLVED or right is _UNRESOLVED:
            return _UNRESOLVED
        if isinstance(node.op, ast.Add):
            return left + right
        return _UNRESOLVED

    def _call(self, node, depth):
        if node.keywords:
            return _UNRESOLVED
        qualified = self.context.qualified(node.func)
        if qualified not in _PATH_FUNCTION_NAMES or qualified == "builtins.open":
            return _UNRESOLVED
        arguments = [self.value(argument, depth + 1) for argument in node.args]
        if any(argument is _UNRESOLVED for argument in arguments) or not arguments:
            return _UNRESOLVED
        leaf = qualified.rsplit(".", 1)[-1]
        if leaf in _PATH_JOINERS:
            return os.path.join(*arguments)
        if len(arguments) != 1:
            return _UNRESOLVED
        if leaf in _PATH_PARENTS:
            return os.path.dirname(arguments[0])
        if leaf in ("abspath", "realpath", "normpath"):
            return os.path.normpath(arguments[0])
        return arguments[0]

    def code_source(self, node, depth=0):
        """The path an ``exec``/``eval``/``compile`` argument reads code
        from: a file read (``open(p).read()``, ``Path(p).read_text()``, a
        ``compile`` of one, or a name bound once to one), whose path must
        then resolve; ``_UNRESOLVED`` for such a read whose path does not.
        ``None`` for anything else: a literal is scanned as a code string and
        a computed value is the accepted residual."""
        if depth > _MAX_EVAL_DEPTH:
            return None
        if isinstance(node, ast.Name):
            binding = self.context.sole_binding(node.id)
            if binding is None or binding[0] != "assign" or binding[1] is None:
                return None
            return self.code_source(binding[1], depth + 1)
        if not isinstance(node, ast.Call):
            return None
        if self.context.qualified(node.func) == "builtins.compile" and node.args:
            return self.code_source(node.args[0], depth + 1)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _READERS and not node.args:
            opener = func.value
            if (
                isinstance(opener, ast.Call)
                and self.context.qualified(opener.func) == "builtins.open"
                and opener.args
            ):
                return self.value(opener.args[0], depth + 1)
            return _UNRESOLVED
        return None


def _loader_path_node(name, call):
    position, keyword = _LOADER_PATH_ARGUMENTS[name]
    for item in call.keywords:
        if keyword is not None and item.arg == keyword:
            return item.value
        if item.arg is None:
            return None
    if len(call.args) > position and not any(
        isinstance(argument, ast.Starred) for argument in call.args[: position + 1]
    ):
        return call.args[position]
    return None


def _target_is_scanned(path, allowed):
    """A resolved absolute path that is one of the project sources the
    fallback already scans."""
    if path is _UNRESOLVED or not os.path.isabs(path):
        return False
    try:
        resolved = str(Path(path).resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return resolved in allowed


def _import_nodes(tree, depth=0):
    """Import statements in ``tree`` and in its literal code strings."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
            continue
        text = _literal_text(node)
        if text is None or depth >= _MAX_CODE_STRING_DEPTH:
            continue
        code = _parsed_code(text)
        if code is not None:
            yield from _import_nodes(code, depth + 1)


def _module_names(path, project_root):
    """Dotted module names a project file can be imported as (relative to
    the project root, and to a ``src`` directory when present)."""
    if not path or not project_root:
        return ()
    try:
        relative = Path(path).resolve().relative_to(Path(project_root).resolve())
    except (OSError, RuntimeError, ValueError):
        return ()
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    names = [".".join(parts)]
    if len(parts) > 1 and parts[0] == "src":
        names.append(".".join(parts[1:]))
    return tuple(name for name in names if name)


def _absolute_module(module, level, importer, package):
    """The absolute module ``from <dots><module> import ...`` names inside
    ``importer`` (``package`` when the importer is a package ``__init__``)."""
    if not level:
        return module or ""
    base = importer.split(".")
    if not package:
        base = base[:-1]
    if level > 1:
        base = base[: len(base) - (level - 1)]
    return ".".join(part for part in [*base, module or ""] if part)


def _owned_imports(scope):
    """Import statements a function or class body makes itself, not those
    of its nested scopes."""
    pending = list(scope.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (*_FUNCTION_SCOPES, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
            continue
        pending.extend(ast.iter_child_nodes(node))


def _global_imports(scope):
    """Imports inside a function or class (or a scope nested in it) that
    bind a name their own scope declares ``global``, so they export a module
    name. Each scope is visited once and owns only its own imports."""
    scopes = [scope]
    while scopes:
        current = scopes.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _, declared_global, _ = _scope_info(current)
            if declared_global:
                for part in _owned_imports(current):
                    names = {
                        alias.asname or alias.name.split(".", 1)[0]
                        for alias in part.names
                    }
                    if names & declared_global:
                        yield part
        pending = list(ast.iter_child_nodes(current))
        while pending:
            node = pending.pop()
            if isinstance(node, (*_FUNCTION_SCOPES, ast.ClassDef)):
                scopes.append(node)
                continue
            pending.extend(ast.iter_child_nodes(node))


def _module_level_imports(tree, depth=0):
    """Imports that bind module-level names: not inside a function, lambda
    or class body; code strings at module level count."""
    pending = list(ast.iter_child_nodes(tree))
    while pending:
        node = pending.pop()
        if isinstance(node, (*_FUNCTION_SCOPES, ast.ClassDef)):
            yield from _global_imports(node)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
            continue
        text = _literal_text(node)
        if text is not None and depth < _MAX_CODE_STRING_DEPTH:
            code = _parsed_code(text)
            if code is not None:
                yield from _module_level_imports(code, depth + 1)
            continue
        pending.extend(ast.iter_child_nodes(node))


def _module_identities(sources, root, project_root):
    """``(provider_pairs, value_pairs, provider_paths)``.

    ``provider_pairs`` and ``value_pairs`` are the ``(module, name)`` pairs
    that are the provider package module or a value module, along real
    import edges: ``import flask as f`` in ``shop.helpers`` gives
    ``("shop.helpers", "f")``, and ``from shop.helpers import f as g`` in
    ``shop.client`` then gives ``("shop.client", "g")``. A name spelled the
    same elsewhere is not confused with them. Only module-level imports
    (including literal code strings run at module level) export a name."""
    provider = set()
    value = set()
    paths = {}
    edges = {}
    pending = []

    def add(group, pair):
        if pair not in group:
            group.add(pair)
            pending.append(pair)

    def add_path(pair, dotted):
        if pair not in paths:
            paths[pair] = dotted
            pending.append(pair)

    for path, tree in sources:
        importers = _module_names(path, project_root) or ("",)
        package = str(path).endswith("__init__.py")
        for node in _module_level_imports(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    imported = alias.name
                    if not alias.asname:
                        imported = alias.name.split(".", 1)[0]
                    for importer in importers:
                        if _names_package(imported, root):
                            add(provider, (importer, local))
                            add_path((importer, local), imported)
                        if imported in _VALUE_MODULES:
                            add(value, (importer, local))
                continue
            for importer in importers:
                target = _absolute_module(node.module, node.level, importer, package)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = (importer, alias.asname or alias.name)
                    if target + "." + alias.name in _VALUE_MODULES:
                        add(value, local)
                    if _names_package(target, root):
                        add_path(local, target + "." + alias.name)
                    edges.setdefault((target, alias.name), []).append(local)
    while pending:
        pair = pending.pop()
        for local in edges.get(pair, ()):
            if pair in provider:
                add(provider, local)
            if pair in value:
                add(value, local)
            if pair in paths:
                add_path(local, paths[pair])
    return frozenset(provider), frozenset(value), paths


def _module_spellings(trees, root):
    """``(provider, value, reexport, provider_modules)`` spellings: every
    local name the project gives the provider package, one of its members,
    or a value module by import, including in literal code strings and
    transitively through project re-exports (``import flask as f`` then
    ``from shop.helpers import f as provider``), resolved by a dependency
    worklist to the full fixpoint. ``provider`` (modules and renamed
    members) drives mutation checks; ``provider_modules`` (module aliases
    only) and ``reexport`` drive the module-as-value rule, so a renamed
    member such as ``from flask import request as req`` can still be passed
    around."""
    provider_modules = {root}
    provider_members = set()
    value = set(_VALUE_MODULE_NAMES)
    by_name = {}
    pending = []

    def add(group, name):
        if name not in group:
            group.add(name)
            pending.append(name)

    for tree in trees:
        for node in _import_nodes(tree):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                if isinstance(node, ast.Import):
                    if _names_package(alias.name, root) and alias.asname:
                        add(provider_modules, local)
                    if alias.name in _VALUE_MODULES and alias.asname:
                        add(value, local)
                    continue
                module = node.module or ""
                if alias.asname and _names_package(module, root):
                    add(provider_members, local)
                if module + "." + alias.name in _VALUE_MODULES:
                    add(value, local)
                by_name.setdefault(alias.name, []).append(local)
    pending.extend(provider_modules | provider_members | value)
    while pending:
        name = pending.pop()
        for local in by_name.get(name, ()):
            if name in provider_modules:
                add(provider_modules, local)
            if name in provider_members:
                add(provider_members, local)
            if name in value:
                add(value, local)
    provider = provider_modules | provider_members
    reexport = {
        *provider_modules,
        *_REEXPORT_MODULE_NAMES,
        *(value - set(_VALUE_MODULE_NAMES)),
    }
    return (
        frozenset(provider),
        frozenset(value),
        frozenset(reexport),
        frozenset(provider_modules),
    )


def _provider_mentions(
    tree, root, leaf, source_path=None, allowed=frozenset(), spellings=None
):
    """Whether ``tree`` mentions the provider, cached. Every source-loader
    call and every ``exec``/``eval``/``compile`` that reads a file must
    resolve, from ``__file__``, to a project source in ``allowed`` (one the
    fallback scans itself); otherwise it is a mention. Deliberately broad:
    a project file with any mention loses the fallback trust and keeps
    base's strict result; analysis that cannot finish counts as a
    mention."""
    cache = tree.__dict__.setdefault("_skylos_provider_mentions", {})
    key = (root, leaf, str(source_path), id(allowed), id(spellings))
    if key in cache and cache[key][1] is allowed and cache[key][2] is spellings:
        return cache[key][0]
    context = _ScanContext(root, source_path or "")
    if spellings is not None:
        (
            context.provider_spellings,
            context.value_spellings,
            context.reexport_spellings,
            context.provider_module_spellings,
            context.provider_pairs,
            context.value_pairs,
            context.provider_paths,
            project_root,
        ) = spellings
        context.module_names = _module_names(source_path, project_root)
        context.package = str(source_path).endswith("__init__.py")
    visitor = _ProviderMentions(leaf, context)
    try:
        context.learn(tree)
        visitor.visit(tree)
        evaluator = _PathEvaluator(context)
        for name, call in context.loader_calls:
            if visitor.found:
                break
            node = _loader_path_node(name, call)
            if node is None or not _target_is_scanned(evaluator.value(node), allowed):
                visitor.found = True
        for call in context.code_calls:
            if visitor.found or not call.args:
                break
            source = evaluator.code_source(call.args[0])
            if source is None:
                continue
            if not _target_is_scanned(source, allowed):
                visitor.found = True
    except RecursionError:
        visitor.found = True
    cache[key] = (visitor.found, allowed, spellings)
    return visitor.found


def _directory_stamp(directories):
    stamp = []
    for directory in directories:
        try:
            stamp.append(os.stat(directory).st_mtime_ns)
        except OSError:
            return None
    return tuple(stamp)


def _zip_scan(path, budget, project_root):
    """``(is_zip, bytes_read)`` for a regular file, from its first four
    bytes and the end-record window a ZIP comment can occupy; None on a read
    error or once ``budget`` is spent."""
    try:
        base = Path(project_root).resolve()
        path = Path(path).resolve()
        path.relative_to(base)
        with open(path, "rb") as handle:
            head = handle.read(4)
            if head in _ZIP_SIGNATURES:
                return True, 4
            size = handle.seek(0, os.SEEK_END)
            if size < _ZIP_END_RECORD:
                return False, 4
            window = min(size, _ZIP_END_WINDOW)
            if window > budget:
                return None
            handle.seek(size - window)
            return _ZIP_END_SIGNATURE in handle.read(window), 4 + window
    except (OSError, RuntimeError, ValueError):
        return None


def _installed_environment(directory, name, key):
    """``site-packages``/``dist-packages`` of a virtual environment (a
    ``pyvenv.cfg`` above it inside the project): installed code, not
    project code."""
    if name not in _INSTALLED_PACKAGE_DIRS:
        return False
    current = Path(directory)
    stop = Path(key)
    while current != stop and stop in current.parents:
        if (current / "pyvenv.cfg").is_file():
            return True
        current = current.parent
    return (stop / "pyvenv.cfg").is_file()


def _regular_file(path):
    try:
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            mode = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode)


def _walk_inventory(key):
    directories = []
    names = set()
    archived = False
    extra_sources = []
    failures = []
    seen = 0
    budget = _MAX_TAIL_BYTES
    for directory, dirs, entries in os.walk(key, onerror=failures.append):
        skipped = bool(set(Path(directory).relative_to(key).parts) & _SKIP_DIRS)
        dirs[:] = [
            name
            for name in dirs
            if name != ".git" and not _installed_environment(directory, name, key)
        ]
        directories.append(directory)
        if len(directories) > _MAX_SHIPPED_DIRECTORIES:
            return None
        for name in entries:
            seen += 1
            if seen > _MAX_SHIPPED_FILES:
                return None
            path = os.path.join(directory, name)
            if not _regular_file(path):
                return None
            if name.endswith(_MODULE_SUFFIXES):
                stem = name.split(".", 1)[0]
                if stem == "__init__":
                    names.add(Path(directory).name)
                else:
                    names.add(stem)
                if skipped and name.endswith(_SOURCE_SUFFIXES):
                    extra_sources.append(path)
            if archived:
                continue
            scanned = _zip_scan(path, budget, key)
            if scanned is None:
                return None
            archived, used = scanned
            budget -= used
    if failures:
        return None
    stamp = _directory_stamp(directories)
    if stamp is None:
        return None
    return tuple(directories), stamp, frozenset(names), archived, tuple(extra_sources)


def _project_inventory(project_root):
    """What the whole project tree ships, from one walk per analyzer run:
    module and package names (source, bytecode or extension, including
    ``__pycache__`` and tool directories such as ``node_modules``; only
    ``.git`` and virtual-environment package directories are left out),
    whether any regular file is a ZIP archive by content, and the Python
    sources in directories the source snapshot skips. Cleared with the AST
    cache session; outside a run it is reused only while every walked
    directory keeps its modification time. None when it cannot be read
    completely within the caps, or the tree holds a special file."""
    key = str(Path(project_root).resolve())
    session = in_python_ast_cache_session()
    cached = _INVENTORIES.get(key)
    if cached is _FAILED_INVENTORY and session:
        return None
    if (
        cached is not None
        and cached is not _FAILED_INVENTORY
        and (session or _directory_stamp(cached[0]) == cached[1])
    ):
        return cached
    inventory = _walk_inventory(key)
    if inventory is None:
        _INVENTORIES[key] = _FAILED_INVENTORY
    else:
        _INVENTORIES[key] = inventory
    return inventory


register_dependent_clear(_INVENTORIES.clear)
register_dependent_clear(_EXTRA_TREES.clear)


def _ships_provider_module(project_root, root):
    """Anything in the project tree that an import path change could load as
    the provider: a module or package named ``root``, or any ZIP archive.
    Unreadable counts as shipped."""
    inventory = _project_inventory(project_root)
    if inventory is None:
        return True
    return inventory[3] or root in inventory[2]


def _parse_extra(path, budget, project_root):
    """``(tree, bytes)`` for a source outside the snapshot, read only after
    its size fits ``budget`` and the per-file cap. The tree is None when the
    file is not Python this interpreter can compile, so it cannot run. None
    when it cannot be read or parsed within the caps."""
    try:
        base = Path(project_root).resolve()
        path = Path(path).resolve()
        path.relative_to(base)
    except (OSError, RuntimeError, ValueError):
        return None
    cached = _EXTRA_TREES.get(path)
    if cached is not None:
        return cached
    try:
        size = os.stat(path).st_size
        if size > _MAX_EXTRA_FILE_BYTES or size > budget:
            return None
        with open(path, "rb") as handle:
            data = handle.read(min(_MAX_EXTRA_FILE_BYTES, budget) + 1)
    except (OSError, RuntimeError, ValueError):
        return None
    if len(data) > _MAX_EXTRA_FILE_BYTES or len(data) > budget:
        return None
    try:
        tree = ast.parse(data)
    except (SyntaxError, ValueError):
        return None, len(data)
    except (RecursionError, MemoryError):
        return None
    nodes = 0
    for _ in ast.walk(tree):
        nodes += 1
        if nodes > _MAX_EXTRA_NODES:
            return None
    _EXTRA_TREES[path] = (tree, len(data))
    return tree, len(data)


_ALLOWED = {}
register_dependent_clear(_ALLOWED.clear)


def _resolved(path):
    try:
        return str(Path(path).resolve())
    except (OSError, RuntimeError, ValueError):
        return None


def _sources_mention_provider(project_root, sources, root, leaf):
    """The mention scan over ``sources`` (``(path, tree)`` pairs) and the
    Python sources the snapshot skips. A loader or file-reading ``exec``
    must target one of these scanned sources. Unreadable or over-cap
    sources count as mentions; a file that is not compilable Python cannot
    run and is skipped. One byte budget, charged on every check, covers
    every extra file."""
    inventory = _project_inventory(project_root)
    if inventory is None:
        return True
    budget = _MAX_EXTRA_TOTAL_BYTES
    pending = list(sources)
    for path in inventory[4]:
        parsed = _parse_extra(path, budget, project_root)
        if parsed is None:
            return True
        budget -= parsed[1]
        if budget < 0:
            return True
        if parsed[0] is not None:
            pending.append((path, parsed[0]))
    snapshot, _ = project_source_snapshot(project_root)
    key = (str(Path(project_root).resolve()), id(inventory), id(snapshot), root)
    known = _ALLOWED.get(key)
    if known is None:
        members = [*snapshot, *inventory[4]]
        allowed = frozenset(
            resolved
            for resolved in (_resolved(path) for path in members)
            if resolved is not None
        )
        extra = [tree for path, tree in pending if path in inventory[4]]
        sources_with_paths = [
            *snapshot.items(),
            *((path, tree) for path, tree in pending if path in inventory[4]),
        ]
        spellings = (
            *_module_spellings([*snapshot.values(), *extra], root),
            *_module_identities(sources_with_paths, root, project_root),
            str(project_root),
        )
        known = (allowed, spellings)
        _ALLOWED[key] = known
    allowed, spellings = known
    seen = set()
    for path, tree in pending:
        if id(tree) in seen:
            continue
        seen.add(id(tree))
        if _provider_mentions(tree, root, leaf, path, allowed, spellings):
            return True
    return False


def provider_is_visibly_untampered(qualified, tree, filename, project_root=None):
    """Library-model trust when the full effects proof cannot finish.

    The strict proof fails closed on any opaque import machinery (``exec``,
    ``__import__``, ``importlib``) or an import walk past its budget, which
    distrusts framework helpers in ordinary plugin-loading or large
    projects. Here the provider stays trusted unless code visibly rewrites
    it: the reachable modules and this tree get the full effects scan with
    opaque calls allowed, and every project source file gets the broad
    mention scan of ``_provider_mentions``. Computed reflection and code
    outside the project are not modelled, as in library-model scanners.

    Only function helpers and immutable constants use this fallback. A
    class provider (``yaml.SafeLoader``, ``ssl.SSLContext``) carries mutable
    state its own methods can change from any code holding it, so it keeps
    base's strict result.

    It still fails closed when anything in the project tree could be loaded
    as the provider after an import path change (a module or package named
    for it, or any ZIP archive), when any file literally mentions the
    helper, the package or an import hook, when the project cannot be read
    completely, or when a scanned module's effects are too large to finish.
    Import path changes themselves are not modelled: with no loadable fake
    in the tree they can only reach code outside the project."""
    root = qualified.split(".", 1)[0]
    leaf = qualified.rsplit(".", 1)[-1]
    if leaf[:1].isupper() and qualified not in _IMMUTABLE_VALUES:
        return False
    names = frozenset({qualified})
    effect_trees = [(tree, ())]
    try:
        source = Path(filename).resolve()
        context = None
        if source.is_file():
            context = project_import_context(tree, source, project_root)
    except (OSError, RuntimeError, ValueError, TypeError):
        context = None
    if context is not None:
        names = context.qualified_names(qualified)
        effect_trees.extend(
            (parsed, context.local_symbols(path, names))
            for path, parsed in context.entries
        )
    if not project_root:
        return False
    snapshot, complete = project_source_snapshot(project_root)
    if not complete or _ships_provider_module(project_root, root):
        return False
    sources = [(filename, tree)]
    if context is not None:
        sources.extend(context.entries)
    sources.extend(snapshot.items())
    if _sources_mention_provider(project_root, sources, root, leaf):
        return False
    for parsed, local_symbols in effect_trees:
        effects = _effects(parsed)
        if effects is None or not effects.complete:
            return False
        if not _provider_effects(names, parsed, local_symbols, opaque_ok=True):
            return False
    return True


def project_provider_effects_are_stable(qualified, tree, filename, project_root=None):
    """Effects across reachable source without asserting native file absence.

    This API also guards local-provider negative proofs. Source/package/src
    labels are equated only through actual snapshot paths. Every call validates
    source metadata; AST/import walks and provider decisions use that validated
    snapshot identity, never an AST-only cached project verdict.
    """
    try:
        source = Path(filename).resolve()
        if not source.is_file():
            return project_root is None and provider_effects_are_stable(qualified, tree)
    except (OSError, RuntimeError, ValueError, TypeError):
        return (
            project_root is None
            and filename is None
            and provider_effects_are_stable(qualified, tree)
        )
    context = project_import_context(tree, source, project_root)
    if context is None:
        return False
    names = context.qualified_names(qualified)
    cached = context.provider_results.get(names)
    if cached is not None:
        return cached and all(
            (effects := _effects(parsed)) is not None and effects.complete
            for _, parsed in context.entries
        )
    result = all(
        _provider_effects(names, parsed, context.local_symbols(path, names))
        for path, parsed in context.entries
    )
    context.provider_results[names] = result
    return result


def _reachable_trees(tree, filename, project_root):
    context = project_import_context(tree, filename, project_root)
    return [parsed for _, parsed in context.entries] if context is not None else None


def provider_is_unshadowed(qualified, filename, project_root=None):
    """Reject project source, bytecode and extension modules with this root.

    Library API models assume ordinary stable installed providers. A project
    file with the same import root needs its own source proof instead. Inspect
    both the source directory and project root, including package ancestors.
    """
    try:
        source = Path(filename).resolve()
        root = Path(project_root).resolve() if project_root else source.parent
        # Tree-only callers have no project-provider inventory. Keep the API's
        # installed-provider model; real scans always supply an existing file.
        if not source.is_file():
            return project_root is None
        if not source.is_relative_to(root):
            return False
        module = qualified.split(".", 1)[0]
        directory = source.parent
        for _ in range(64):
            if (directory / module).exists():
                return False
            for path in directory.glob(module + ".*"):
                if path.suffix in {".py", ".pyi", ".pyc", ".pyo", ".so", ".pyd"}:
                    return False
            if directory == root:
                return True
            directory = directory.parent
        return False
    except (OSError, RuntimeError, ValueError, TypeError):
        return False
