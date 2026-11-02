"""Source-only checks for a sanitizer's imported provider.

Never import a scanned provider to discover whether it is the native library.
"""

import ast
from pathlib import Path
from .project_imports import project_import_context


_IMPORT_STATE = (
    "sys.path",
    "sys.meta_path",
    "sys.path_hooks",
    "sys.path_importer_cache",
    "sys.modules",
)
_IMPORT_MACHINERY_ROOTS = frozenset(
    {"sys", "builtins", "importlib", "imp", "pkgutil", "runpy", "site", "zipimport"}
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

    def safe_reader_call(self, node):
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

    def implicit_use_is_safe(self, node, sensitive):
        def capability(value):
            return any(
                sensitive(name) and name not in _IMMUTABLE_VALUES
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

    def stable(self, sensitive, *, environment=False, key=None, callable_names=()):
        if not self.complete:
            return False
        if key is not None and key in self.stable_results:
            return self.stable_results[key]
        result = self._stable_scan(
            sensitive, environment=environment, callable_names=callable_names
        )
        if key is not None:
            self.stable_results[key] = result
        return result and self.complete

    def literal_import_is_read(self, node, sensitive):
        """``__import__("ssl").attr`` read in place: an import statement.

        One literal module name, no other arguments, not import machinery or
        a sensitive provider, and the result only read through attributes or
        subscripts, never stored, passed, bound or returned."""
        if node.keywords or len(node.args) != 1:
            return False
        argument = node.args[0]
        if not isinstance(argument, ast.Constant) or not isinstance(
            argument.value, str
        ):
            return False
        parts = argument.value.split(".")
        if not all(part.isidentifier() for part in parts):
            return False
        if parts[0] in _IMPORT_MACHINERY_ROOTS:
            return False
        prefixes = {".".join(parts[:count]) for count in range(1, len(parts) + 1)}
        if any(sensitive(name) for name in prefixes):
            return False
        current = node
        parent = self.parents.get(id(node))
        if not isinstance(parent, ast.Attribute) or parent.value is not node:
            return False
        while isinstance(parent, (ast.Attribute, ast.Subscript)) and (
            parent.value is current
        ):
            if not isinstance(parent.ctx, ast.Load):
                return False
            current = parent
            parent = self.parents.get(id(parent))
        return True

    def _stable_scan(self, sensitive, *, environment=False, callable_names=()):
        if not self.complete:
            return False
        for node in self.nodes:
            if not self.implicit_use_is_safe(node, sensitive):
                return False
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if any(sensitive(name) for name in self.refs(node)):
                    return False
            if isinstance(node, ast.Call):
                functions = self.refs(node.func)
                if any(
                    sensitive(name) and name not in _IMMUTABLE_VALUES
                    for name in functions
                ):
                    if not self.canonical_reference(node.func) or not functions <= set(
                        callable_names
                    ):
                        return False
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "exec",
                    "eval",
                }:
                    return False
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "__import__"
                    and not self.literal_import_is_read(node, sensitive)
                ):
                    return False
                if environment and any(
                    name == "importlib" or name.startswith("importlib.")
                    for name in functions
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
                    sensitive(name) and name not in _IMMUTABLE_VALUES
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
                    sensitive(name) and name not in _IMMUTABLE_VALUES
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
                    sensitive(name) and name not in _IMMUTABLE_VALUES
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


def import_environment_is_stable(tree):
    """No visible import search/cache/hook mutation or opaque capability escape."""
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
            key=("environment",),
            callable_names={"sys.path.copy"},
        )
    )


def _provider_effects(qualified_names, tree, local_symbols=()):
    if not import_environment_is_stable(tree):
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
        key=("provider", tuple(sorted(names))),
        callable_names=names | safe_methods,
    )


def provider_effects_are_stable(qualified, tree):
    """Native provider capabilities stay local and unmodified in this tree."""
    return _provider_effects((qualified,), tree)


def provider_binding_is_stable(qualified, tree, filename, project_root=None):
    """Project effects plus absence of a source/opaque native provider."""
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
    return project_provider_effects_are_stable(qualified, tree, filename, project_root)


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
