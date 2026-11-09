"""Bounded source evaluation of actual registry-to-module lookup values.

This optional proof never imports project modules or evaluates Python objects.
Unknown branches, escaped tables and replaced bindings provide no new evidence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


_UNKNOWN = object()
_MISSING = object()
_BREAK = object()
_CONTINUE = object()
_RAISE = object()
_MAX_STEPS = 50_000
_MAX_DEPTH = 32
_MAX_ITEMS = 256
_BUILTINS = {
    "getattr",
    "hasattr",
    "setattr",
    "delattr",
    "type",
    "object",
    "dict",
    "staticmethod",
    "classmethod",
}


class _Limit(Exception):
    pass


class _RaisedCompletion(Exception):
    """A proven source raise prevents the remaining caller expression."""


@dataclass(eq=False)
class _Name:
    value: str


@dataclass(eq=False)
class _Table:
    data: dict
    valid: bool = True


@dataclass(eq=False)
class _Builtin:
    name: str


@dataclass(eq=False)
class _Frame:
    module: str
    values: dict = field(default_factory=dict)
    parent: _Frame | None = None
    globals: set = field(default_factory=set)
    nonlocals: set = field(default_factory=set)
    class_scope: bool = False
    uncertain_exit: bool = False
    possible_return: bool = False

    def get(self, name):
        current = self
        if name in self.globals:
            while current.parent is not None:
                current = current.parent
        while current is not None:
            if name in current.values:
                return current.values[name]
            current = current.parent
        return _MISSING


@dataclass(eq=False)
class _Module:
    name: str
    frame: _Frame
    tree: ast.Module | None = None
    started: bool = False
    failed: bool = False


@dataclass(eq=False)
class _Function:
    node: ast.AST
    frame: _Frame
    definition: object
    defaults: dict
    binding: str = "instance"
    suspended: bool = False


@dataclass(eq=False)
class _Class:
    attrs: dict
    definition: object = None


@dataclass(eq=False)
class _Instance:
    cls: _Class
    attrs: dict = field(default_factory=dict)


@dataclass(eq=False)
class _Bound:
    receiver: object
    function: _Function


@dataclass
class _Return:
    value: object


@dataclass
class NestedRegistryReport:
    targets: list = field(default_factory=list)
    complete: bool = True
    incomplete_reason: str | None = None
    steps: int = 0


def _local_names(statements):
    """Visit each lexical body once, without entering nested scopes."""
    names, globals_, nonlocals = set(), set(), set()
    pending = list(statements)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.Import):
            names.update(
                alias.asname or alias.name.split(".")[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Global):
            globals_.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            nonlocals.update(node.names)
        pending.extend(ast.iter_child_nodes(node))
    return names - globals_ - nonlocals, globals_, nonlocals


class _RegistryProof:
    def __init__(self, definitions, parsed):
        self.report = NestedRegistryReport()
        self.targets = {}
        self.active = set()
        self.depth = 0
        self.functions = []
        self.invoked = set()
        self.definitions = {
            (str(Path(item.filename).resolve()), item.line): item
            for item in definitions.values()
            if item.type in {"function", "method", "class"}
        }
        module_names = {}
        for item in definitions.values():
            node = getattr(item, "node", None)
            if (
                item.type in {"function", "class"}
                and getattr(node, "col_offset", -1) == 0
            ):
                module_names[str(Path(item.filename).resolve())] = item.name.rpartition(
                    "."
                )[0]
        self.modules = {}
        for item in parsed:
            path = Path(item.path).resolve()
            name = module_names.get(str(path))
            if name is None:
                parts = [] if path.stem == "__init__" else [path.stem]
                parent = path.parent
                while (parent / "__init__.py").is_file():
                    parts.insert(0, parent.name)
                    parent = parent.parent
                name = ".".join(parts)
            module = _Module(name, _Frame(name), item.tree)
            module.path = str(path)
            self.modules[name] = module

    def step(self):
        self.report.steps += 1
        if self.report.steps > _MAX_STEPS:
            raise _Limit("step_budget")

    def module(self, name):
        module = self.modules.get(name)
        if module is None:
            module = _Module(name, _Frame(name))
            self.modules[name] = module
        if module.failed:
            raise _RaisedCompletion()
        if not module.started:
            module.started = True
            if module.tree is not None:
                try:
                    if self.suite(module.tree.body, module.frame) is _RAISE:
                        raise _RaisedCompletion()
                except _RaisedCompletion:
                    module.failed = True
                    raise
        return module

    def set_name(self, frame, name, value):
        target = frame
        if name in frame.globals:
            target = self.modules[frame.module].frame
        elif name in frame.nonlocals:
            target = frame.parent
            while target is not None and name not in target.values:
                target = target.parent
            if target is None:
                return
        target.values[name] = value

    def assign(self, target, value, frame):
        self.step()
        if isinstance(target, ast.Name):
            self.set_name(frame, target.id, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            values = (
                value
                if isinstance(value, (tuple, list)) and len(value) == len(target.elts)
                else [_UNKNOWN] * len(target.elts)
            )
            for child, item in zip(target.elts, values):
                self.assign(child, item, frame)
        elif isinstance(target, ast.Attribute):
            self.set_attr(self.eval(target.value, frame), target.attr, value)
        elif isinstance(target, ast.Subscript):
            table = self.eval(target.value, frame)
            key = self.key(self.eval(target.slice, frame))
            if isinstance(table, _Table):
                if key is _UNKNOWN:
                    table.valid = False
                else:
                    table.data[key] = self.registry_name(value)

    def set_attr(self, receiver, name, value):
        if isinstance(receiver, _Module):
            receiver.frame.values[name] = value
        elif isinstance(receiver, (_Class, _Instance)):
            receiver.attrs[name] = value

    def attr(self, receiver, name):
        if isinstance(receiver, _Module):
            if name in receiver.frame.values:
                return receiver.frame.values[name]
            if (
                receiver.name == "builtins"
                and receiver.tree is None
                and name in _BUILTINS
            ):
                return _Builtin(name)
        elif isinstance(receiver, _Instance):
            if name in receiver.attrs:
                return receiver.attrs[name]
            value = receiver.cls.attrs.get(name, _UNKNOWN)
            if isinstance(value, _Function) and value.binding != "static":
                return _Bound(
                    receiver.cls if value.binding == "class" else receiver, value
                )
            return value
        elif isinstance(receiver, _Class):
            value = receiver.attrs.get(name, _UNKNOWN)
            if isinstance(value, _Function) and value.binding == "class":
                return _Bound(receiver, value)
            return value
        return _UNKNOWN

    @staticmethod
    def key(value):
        if isinstance(value, _Name):
            return value.value
        return (
            value
            if isinstance(value, (str, int, float, bool, type(None)))
            else _UNKNOWN
        )

    @staticmethod
    def registry_name(value):
        return _Name(value) if isinstance(value, str) else value

    @staticmethod
    def truth(value):
        if isinstance(value, _Name):
            return bool(value.value)
        if isinstance(value, _Table):
            return bool(value.data) if value.valid else None
        if isinstance(value, (str, int, float, bool, tuple, list, type(None))):
            return bool(value)
        return None

    def suite(self, statements, frame):
        self.depth += 1
        try:
            if self.depth > _MAX_DEPTH:
                raise _Limit("scope_depth")
            for node in statements:
                self.step()
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.imports(node, frame)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.function(node, frame)
                elif isinstance(node, ast.ClassDef):
                    if node.decorator_list or node.keywords:
                        self.set_name(frame, node.name, _UNKNOWN)
                        continue
                    # Unknown bases may replace attribute lookup and construction.
                    bases = [self.eval(base, frame) for base in node.bases]
                    if len(bases) > 1 or any(
                        not isinstance(base, _Class)
                        and not (isinstance(base, _Builtin) and base.name == "object")
                        for base in bases
                    ):
                        self.set_name(frame, node.name, _UNKNOWN)
                        continue
                    local = _Frame(frame.module, parent=frame, class_scope=True)
                    self.suite(node.body, local)
                    attrs = {}
                    for base in reversed(bases):
                        if isinstance(base, _Class):
                            attrs.update(base.attrs)
                    attrs.update(local.values)
                    definition = self.definitions.get(
                        (self.modules[frame.module].path, node.lineno)
                    )
                    self.set_name(frame, node.name, _Class(attrs, definition))
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    if node.value is not None:
                        value = self.eval(node.value, frame)
                        for target in (
                            node.targets
                            if isinstance(node, ast.Assign)
                            else [node.target]
                        ):
                            self.assign(target, value, frame)
                elif isinstance(node, ast.Expr):
                    self.eval(node.value, frame)
                elif isinstance(node, ast.Return):
                    return _Return(self.eval(node.value, frame))
                elif isinstance(node, ast.Raise):
                    return _RAISE
                elif isinstance(node, ast.Break):
                    return _BREAK
                elif isinstance(node, ast.Continue):
                    return _CONTINUE
                elif isinstance(node, ast.If):
                    condition = self.truth(self.eval(node.test, frame))
                    if condition is None:
                        self.invalidate(node.body + node.orelse, frame)
                        left = self.terminal(node.body)
                        right = self.terminal(node.orelse)
                        if left is not None and right is not None:
                            if isinstance(left, _Return) and isinstance(right, _Return):
                                return _Return(
                                    None
                                    if left.value is None and right.value is None
                                    else _UNKNOWN
                                )
                            return left if left is right else _Return(_UNKNOWN)
                        frame.uncertain_exit |= self.may_return_non_none(
                            node.body + node.orelse
                        )
                        frame.possible_return |= self.may_return_non_none(
                            node.body + node.orelse, any_return=True
                        )
                    else:
                        result = self.suite(
                            node.body if condition else node.orelse, frame
                        )
                        if result is not None:
                            return result
                elif isinstance(node, ast.For):
                    iterable = self.eval(node.iter, frame)
                    if not isinstance(iterable, (tuple, list)):
                        self.invalidate(node.body + node.orelse, frame)
                        self.assign(node.target, _UNKNOWN, frame)
                        continue
                    if len(iterable) > _MAX_ITEMS:
                        raise _Limit("iteration_budget")
                    broke = False
                    for value in iterable:
                        self.assign(node.target, value, frame)
                        result = self.suite(node.body, frame)
                        if result is _BREAK:
                            broke = True
                            break
                        if result is _CONTINUE:
                            continue
                        if result is not None:
                            return result
                    if not broke:
                        result = self.suite(node.orelse, frame)
                        if result is not None:
                            return result
                elif not isinstance(node, (ast.Pass, ast.Global, ast.Nonlocal)):
                    self.invalidate([node], frame)
        finally:
            self.depth -= 1
        return None

    def terminal(self, statements, depth=0):
        """Summarize guaranteed exits without evaluating an unknown branch."""
        if depth > _MAX_DEPTH:
            raise _Limit("control_flow_depth")
        for node in statements:
            self.step()
            if isinstance(node, ast.Return):
                return _Return(
                    None
                    if node.value is None
                    or isinstance(node.value, ast.Constant)
                    and node.value.value is None
                    else _UNKNOWN
                )
            if isinstance(node, ast.Raise):
                return _RAISE
            if isinstance(node, ast.Break):
                return _BREAK
            if isinstance(node, ast.Continue):
                return _CONTINUE
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant):
                    result = self.terminal(
                        node.body if node.test.value else node.orelse, depth + 1
                    )
                else:
                    left, right = (
                        self.terminal(node.body, depth + 1),
                        self.terminal(node.orelse, depth + 1),
                    )
                    result = None
                    if left is not None and right is not None:
                        if isinstance(left, _Return) and isinstance(right, _Return):
                            result = _Return(
                                None
                                if left.value is None and right.value is None
                                else _UNKNOWN
                            )
                        else:
                            result = left if left is right else _Return(_UNKNOWN)
                if result is not None:
                    return result
        return None

    def may_return_non_none(self, statements, *, any_return=False):
        pending = list(statements)
        while pending:
            node = pending.pop()
            self.step()
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(node, ast.Raise) and not any_return:
                return True
            if isinstance(node, ast.Return) and (
                any_return
                or node.value is not None
                and not (
                    isinstance(node.value, ast.Constant) and node.value.value is None
                )
            ):
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    def invalidate(self, statements, frame):
        names, _, _ = _local_names(statements)
        for name in names:
            self.set_name(frame, name, _UNKNOWN)
        # Mutations in unsupported control flow cannot preserve table/module proof.
        pending = list(statements)
        while pending:
            node = pending.pop()
            self.step()
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(node, ast.Attribute):
                receiver = self.eval(node.value, frame)
                if isinstance(receiver, _Table):
                    receiver.valid = False
                elif isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.set_attr(receiver, node.attr, _UNKNOWN)
            elif isinstance(node, ast.Subscript) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                receiver = self.eval(node.value, frame)
                if isinstance(receiver, _Table):
                    receiver.valid = False
            pending.extend(ast.iter_child_nodes(node))

    def imports(self, node, frame):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported = self.import_module(alias.name)
                bound = (
                    imported if alias.asname else self.module(alias.name.split(".")[0])
                )
                self.set_name(frame, alias.asname or alias.name.split(".")[0], bound)
        else:
            package = frame.module
            source_module = self.modules.get(frame.module)
            if source_module is not None and not getattr(
                source_module, "path", ""
            ).endswith("/__init__.py"):
                package = package.rpartition(".")[0]
            parts = package.split(".") if package else []
            if node.level:
                parts = parts[: len(parts) - node.level + 1]
                module_name = ".".join(
                    [*parts, *([node.module] if node.module else [])]
                )
            else:
                module_name = node.module or ""
            imported = self.import_module(module_name)
            for alias in node.names:
                if alias.name == "*":
                    exports = imported.frame.values.get("__all__", _MISSING)
                    if imported.name == "builtins" and imported.tree is None:
                        for name in _BUILTINS:
                            self.set_name(frame, name, self.attr(imported, name))
                    elif (
                        imported.tree is None
                        or exports is not _MISSING
                        and not isinstance(exports, tuple)
                    ):
                        for name in _BUILTINS:
                            self.set_name(frame, name, _UNKNOWN)
                    elif isinstance(exports, tuple):
                        for name in exports:
                            name = self.key(name)
                            if isinstance(name, str):
                                self.set_name(frame, name, self.attr(imported, name))
                    else:
                        for name, value in imported.frame.values.items():
                            if not name.startswith("_"):
                                self.set_name(frame, name, value)
                else:
                    if (
                        alias.name not in imported.frame.values
                        and module_name + "." + alias.name in self.modules
                    ):
                        self.import_module(module_name + "." + alias.name)
                    self.set_name(
                        frame,
                        alias.asname or alias.name,
                        self.attr(imported, alias.name),
                    )

    def import_module(self, name):
        parts = name.split(".")
        parent = None
        for index, part in enumerate(parts):
            current = self.module(".".join(parts[: index + 1]))
            if parent is not None:
                parent.frame.values[part] = current
            parent = current
        return parent

    def function(self, node, frame):
        binding = "instance"
        for decorator in node.decorator_list:
            value = self.eval(decorator, frame)
            if not isinstance(value, _Builtin) or value.name not in {
                "staticmethod",
                "classmethod",
            }:
                self.set_name(frame, node.name, _UNKNOWN)
                return
            binding = "static" if value.name == "staticmethod" else "class"
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults = {
            argument.arg: self.eval(default, frame)
            for argument, default in zip(
                positional[-len(node.args.defaults) :], node.args.defaults
            )
        }
        defaults.update(
            {
                argument.arg: self.eval(default, frame)
                for argument, default in zip(
                    node.args.kwonlyargs, node.args.kw_defaults
                )
                if default is not None
            }
        )
        definition = self.definitions.get(
            (self.modules[frame.module].path, node.lineno)
        )
        function = _Function(
            node,
            frame.parent if frame.class_scope else frame,
            definition,
            defaults,
            binding,
        )
        pending = list(node.body)
        function.suspended = isinstance(node, ast.AsyncFunctionDef)
        while pending:
            child = pending.pop()
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                function.suspended = True
            pending.extend(ast.iter_child_nodes(child))
        self.functions.append(function)
        self.set_name(frame, node.name, function)

    def invoke(self, function, args, keywords):
        if isinstance(function, _Bound):
            args = [function.receiver, *args]
            function = function.function
        if isinstance(function, _Class):
            if {
                "__getattribute__",
                "__getattr__",
                "__new__",
                "__setattr__",
            }.intersection(function.attrs):
                return _UNKNOWN
            instance = _Instance(function)
            init = self.attr(instance, "__init__")
            if "__init__" not in function.attrs:
                return instance if not args and not keywords else _UNKNOWN
            if not isinstance(init, (_Function, _Bound)):
                return _UNKNOWN
            # Failed binding, raised/unknown returns and non-None __init__
            # results cannot prove that construction reaches a later method.
            if self.invoke(init, args, keywords) is not None:
                return _UNKNOWN
            return instance
        if not isinstance(function, _Function) or function.suspended:
            return _UNKNOWN
        if id(function) in self.active:
            raise _Limit("recursive_call")
        node = function.node
        positional = [*node.args.posonlyargs, *node.args.args]
        if len(args) > len(positional) and node.args.vararg is None:
            return _UNKNOWN
        positional_names = {argument.arg for argument in positional[: len(args)]}
        permitted = {
            argument.arg for argument in [*node.args.args, *node.args.kwonlyargs]
        }
        if positional_names.intersection(keywords) or any(
            argument.arg in keywords for argument in node.args.posonlyargs
        ):
            return _UNKNOWN
        if node.args.kwarg is None and set(keywords) - permitted:
            return _UNKNOWN
        local_names, globals_, nonlocals = _local_names(node.body)
        local = _Frame(
            function.frame.module,
            dict.fromkeys(local_names, _UNKNOWN),
            function.frame,
            globals_,
            nonlocals,
        )
        supplied = dict(function.defaults)
        supplied.update(
            {argument.arg: value for argument, value in zip(positional, args)}
        )
        supplied.update(keywords)
        required = [*positional, *node.args.kwonlyargs]
        if any(argument.arg not in supplied for argument in required):
            return _UNKNOWN
        local.values.update(supplied)
        if node.args.vararg:
            local.values[node.args.vararg.arg] = tuple(args[len(positional) :])
        if node.args.kwarg:
            local.values[node.args.kwarg.arg] = _Table(
                {
                    key: value
                    for key, value in keywords.items()
                    if key not in {arg.arg for arg in required}
                }
            )
        self.active.add(id(function))
        self.invoked.add(id(function))
        try:
            try:
                result = self.suite(node.body, local)
                if result is _RAISE:
                    raise _RaisedCompletion()
            except _RaisedCompletion:
                if local.possible_return:
                    return _UNKNOWN
                raise
            if local.uncertain_exit:
                return _UNKNOWN
            return result.value if isinstance(result, _Return) else None
        finally:
            self.active.remove(id(function))

    def eval(self, node, frame):
        self.step()
        self.depth += 1
        try:
            if self.depth > _MAX_DEPTH:
                raise _Limit("expression_depth")
            return self.expression(node, frame)
        finally:
            self.depth -= 1

    def expression(self, node, frame):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            value = frame.get(node.id)
            if value is not _MISSING:
                return value
            builtins = self.modules.get("builtins")
            if builtins is not None and node.id in builtins.frame.values:
                return builtins.frame.values[node.id]
            return _Builtin(node.id) if node.id in _BUILTINS else _UNKNOWN
        if isinstance(node, ast.Attribute):
            return self.attr(self.eval(node.value, frame), node.attr)
        if isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) > _MAX_ITEMS:
                raise _Limit("container_budget")
            return tuple(self.eval(item, frame) for item in node.elts)
        if isinstance(node, ast.Dict):
            if len(node.keys) > _MAX_ITEMS:
                raise _Limit("container_budget")
            data = {}
            for key, value in zip(node.keys, node.values):
                if key is None:
                    extra = self.eval(value, frame)
                    if not isinstance(extra, _Table) or not extra.valid:
                        return _UNKNOWN
                    data.update(extra.data)
                    continue
                key = self.key(self.eval(key, frame))
                if key is _UNKNOWN:
                    return _UNKNOWN
                data[key] = self.registry_name(self.eval(value, frame))
            return _Table(data)
        if isinstance(node, ast.Subscript):
            table, key = (
                self.eval(node.value, frame),
                self.key(self.eval(node.slice, frame)),
            )
            if isinstance(table, _Table) and table.valid:
                return table.data.get(key, _UNKNOWN)
            if (
                isinstance(table, tuple)
                and isinstance(key, int)
                and -len(table) <= key < len(table)
            ):
                return table[key]
            return _UNKNOWN
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.truth(self.eval(node.operand, frame))
            return not value if value is not None else _UNKNOWN
        if isinstance(node, ast.BoolOp):
            result = _UNKNOWN
            for item in node.values:
                result = self.eval(item, frame)
                truth = self.truth(result)
                if truth is None:
                    return _UNKNOWN
                if truth == isinstance(node.op, ast.Or):
                    return result
            return result
        if isinstance(node, ast.IfExp):
            condition = self.truth(self.eval(node.test, frame))
            return (
                self.eval(node.body if condition else node.orelse, frame)
                if condition is not None
                else _UNKNOWN
            )
        if isinstance(node, ast.Call):
            return self.call(node, frame)
        return _UNKNOWN

    def call(self, node, frame):
        receiver = _UNKNOWN
        if isinstance(node.func, ast.Attribute):
            receiver = self.eval(node.func.value, frame)
            function = self.attr(receiver, node.func.attr)
        else:
            function = self.eval(node.func, frame)
        args = [self.eval(argument, frame) for argument in node.args]
        keywords = {
            keyword.arg: self.eval(keyword.value, frame) for keyword in node.keywords
        }
        if len(node.keywords) != len(keywords):
            return _UNKNOWN
        if (
            any(isinstance(argument, ast.Starred) for argument in node.args)
            or None in keywords
        ):
            return _UNKNOWN
        if isinstance(node.func, ast.Attribute):
            if isinstance(receiver, _Table):
                if not receiver.valid:
                    return _UNKNOWN
                method = node.func.attr
                if method == "get":
                    if keywords or len(args) not in {1, 2}:
                        return _UNKNOWN
                    return receiver.data.get(
                        self.key(args[0]), args[1] if len(args) > 1 else None
                    )
                if method in {"values", "items", "keys"}:
                    if args or keywords:
                        return _UNKNOWN
                    items = (
                        receiver.data.values()
                        if method == "values"
                        else receiver.data.items()
                        if method == "items"
                        else receiver.data.keys()
                    )
                    return tuple(items)
                if method == "update":
                    if len(args) > 1:
                        return _UNKNOWN
                    if args and (not isinstance(args[0], _Table) or not args[0].valid):
                        receiver.valid = False
                    else:
                        receiver.data.update(args[0].data if args else {})
                        receiver.data.update(
                            {
                                key: self.registry_name(value)
                                for key, value in keywords.items()
                            }
                        )
                    return None
                receiver.valid = False
                return _UNKNOWN
        if isinstance(function, _Builtin):
            name = function.name
            signatures = {
                "getattr": {2, 3},
                "hasattr": {2},
                "setattr": {3},
                "delattr": {2},
                "type": {1, 3},
                "object": {0},
                "dict": {0, 1},
                "staticmethod": {1},
                "classmethod": {1},
            }
            if (
                len(args) not in signatures.get(name, set())
                or keywords
                and name != "dict"
            ):
                return _UNKNOWN
            if name in {"getattr", "hasattr"} and len(args) >= 2:
                receiver, member = args[:2]
                key = self.key(member)
                target = self.attr(receiver, key) if isinstance(key, str) else _UNKNOWN
                if (
                    isinstance(member, _Name)
                    and isinstance(receiver, _Module)
                    and isinstance(target, (_Function, _Class))
                    and target.definition is not None
                ):
                    self.targets[id(target.definition)] = target.definition
                if name == "hasattr":
                    return (
                        target is not _UNKNOWN
                        if isinstance(receiver, (_Module, _Class, _Instance))
                        else _UNKNOWN
                    )
                return (
                    target
                    if target is not _UNKNOWN
                    else args[2]
                    if len(args) > 2
                    else _UNKNOWN
                )
            if name in {"setattr", "delattr"} and len(args) >= 2:
                member = self.key(args[1])
                if isinstance(member, str):
                    self.set_attr(
                        args[0], member, args[2] if len(args) > 2 else _UNKNOWN
                    )
                else:
                    self.escape([args[0]])
                return None
            if (
                name == "type"
                and len(args) == 3
                and isinstance(args[2], _Table)
                and args[2].valid
            ):
                if (
                    isinstance(self.key(args[0]), str)
                    and isinstance(args[1], tuple)
                    and len(args[1]) <= 1
                    and all(isinstance(key, str) for key in args[2].data)
                    and all(
                        isinstance(base, _Builtin) and base.name == "object"
                        for base in args[1]
                    )
                ):
                    return _Class(dict(args[2].data))
            if name == "dict":
                if args and (not isinstance(args[0], _Table) or not args[0].valid):
                    return _UNKNOWN
                data = dict(args[0].data) if args else {}
                data.update(
                    {key: self.registry_name(value) for key, value in keywords.items()}
                )
                return _Table(data)
            return _UNKNOWN
        if isinstance(function, (_Function, _Bound, _Class)):
            return self.invoke(function, args, keywords)
        self.escape([*args, *keywords.values()])
        return _UNKNOWN

    def escape(self, values):
        pending, seen = list(values), set()
        while pending:
            value = pending.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            self.step()
            if isinstance(value, _Table):
                value.valid = False
                pending.extend(value.data.values())
            elif isinstance(value, (tuple, list)):
                pending.extend(value)
            elif isinstance(value, _Module):
                pending.extend(value.frame.values.values())
                value.frame.values = dict.fromkeys(value.frame.values, _UNKNOWN)
            elif isinstance(value, _Class):
                pending.extend(value.attrs.values())
                value.attrs = dict.fromkeys(value.attrs, _UNKNOWN)
            elif isinstance(value, _Instance):
                pending.extend(value.attrs.values())
                value.attrs.update(dict.fromkeys(value.cls.attrs, _UNKNOWN))

    def collect(self):
        try:
            for name in tuple(self.modules):
                try:
                    self.module(name)
                except _RaisedCompletion:
                    continue
            # Framework/trace entrypoints may execute without a source call.
            for function in tuple(self.functions):
                refs = getattr(function.definition, "heuristic_refs", {}) or {}
                if id(function) in self.invoked or not {
                    "framework_root",
                    "package_entrypoint",
                    "test_entrypoint",
                    "trace_hit",
                    "coverage_hit",
                }.intersection(refs):
                    continue
                arguments = [
                    _UNKNOWN
                    for _ in [*function.node.args.posonlyargs, *function.node.args.args]
                ]
                try:
                    self.invoke(function, arguments, {})
                except _RaisedCompletion:
                    continue
            self.report.targets = list(self.targets.values())
        except _Limit as error:
            self.report.complete = False
            self.report.incomplete_reason = str(error)
            self.report.targets = []
        return self.report


def collect_nested_registry_targets(definitions, parsed_files):
    parsed = list(parsed_files)
    has_table, has_lookup = False, False
    for source in parsed:
        for node in ast.walk(source.tree):
            if isinstance(node, ast.Dict):
                has_table = True
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "dict"
            ):
                has_table = True
            elif isinstance(node, ast.Name) and node.id in {"getattr", "hasattr"}:
                has_lookup = True
            elif isinstance(node, ast.Attribute) and node.attr in {
                "getattr",
                "hasattr",
            }:
                has_lookup = True
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module == "builtins"
                and any(alias.name in {"getattr", "hasattr"} for alias in node.names)
            ):
                has_lookup = True
            if has_table and has_lookup:
                return _RegistryProof(definitions, parsed).collect()
    return NestedRegistryReport()
