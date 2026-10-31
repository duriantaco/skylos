"""Finite source values for provider dispatch; no target code is executed."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field as dataclass_field

from skylos.deadcode._registration_common import _FUNCTION_NODES, _import_aliases
from skylos.deadcode.provider_method_liveness import _ProviderCalls


@dataclass(eq=False)
class _DispatchValue:
    kind: str
    node: object = None
    fields: dict = dataclass_field(default_factory=dict)
    receiver: object = None
    guards: tuple = ()
    valid: bool = True


class _AbruptDispatch(Exception):
    pass


class _SourceDispatch(_ProviderCalls):
    """Supplement provider calls with finite values in actual invocation frames.

    This deliberately does not change the receiver helper used by logging.
    Unknown operations invalidate values they receive; they never turn a method
    spelling or a stored class into evidence that its body executes.
    """

    def __init__(self, definitions, parsed_files, *, framework_owners=()):
        super().__init__(definitions, parsed_files)
        self.environments = {}
        self.active = set()
        self.events = []
        self.invalid_classes = set()
        self.invalid_functions = set()
        self.invalid_modules = set()
        self.invalid_registries = set()
        self.invalid_builtins = False
        self.class_checks = {}
        self.default_values = {}
        self.module_states = {}
        self.invalid_native = set()
        self.framework_owners = framework_owners
        self.audit_only = 0
        self.branch_depth = 0

    def initialize(self, tree):
        if tree in self.module_states:
            return self.module_states[tree] == "complete"
        self.module_states[tree] = "initializing"
        env = self.environments.setdefault(tree, {})
        try:
            _, complete = self.block(tree.body, tree, env, tree)
        except _AbruptDispatch:
            complete = False
        self.module_states[tree] = "complete" if complete else "incomplete"
        return complete

    def imports_complete(self, node, scope):
        file_key = self.file_for_node[scope]
        names, modules = _import_aliases(
            ast.Module(body=[node], type_ignores=[]),
            self.modules[file_key],
            self.files[file_key].path,
        )
        providers = list(modules.values())
        providers.extend(name.rsplit(".", 1)[0] for name in names.values())
        for provider in providers:
            parts = tuple(provider.split("."))
            for end in range(1, len(parts) + 1):
                matches = self.module_paths.get(parts[:end], ())
                if len(matches) == 1 and not self.initialize(matches[0].tree):
                    return False
        return True

    def plain_class(self, node, seen=frozenset()):
        self.step()
        if node in self.class_checks:
            return self.class_checks[node]
        if node in seen or node.decorator_list or node.keywords:
            return False
        self.class_checks[node] = False
        scope = self.method_scope(node)
        if scope is None or any(
            name in self._scope_bindings(node)
            for name in (
                "__new__",
                "__getattr__",
                "__getattribute__",
                "__setattr__",
                "__slots__",
                "__init_subclass__",
                "__mro_entries__",
            )
        ):
            return False
        for statement in node.body:
            if not isinstance(
                statement,
                (*_FUNCTION_NODES, ast.Assign, ast.AnnAssign, ast.Expr, ast.Pass),
            ):
                # Class execution can install lookup/construction protocols.
                # Do not infer a plain class through unmodeled body statements.
                return False
            if isinstance(statement, ast.Expr) and not (
                isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                return False
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                try:
                    ast.literal_eval(statement.value)
                except (ValueError, TypeError, SyntaxError):
                    return False
        for base in node.bases:
            target = self.resolve(base, self.context(node))
            if (
                target is None
                or target[1] != "class"
                or not self.plain_class(target[0], seen | {node})
            ):
                return False
        self.class_checks[node] = True
        return True

    def builtin(self, node, name, context):
        values = self.value(node, context, {}, context)
        return (
            len(values) == 1
            and isinstance(values[0], _DispatchValue)
            and (
                values[0].kind == "builtin"
                and values[0].node == name
                and self.usable(values[0])
            )
        )

    def imported(self, name, binding, scope, caller, seen):
        file_key = self.file_for_node[scope]
        names, modules = _import_aliases(
            ast.Module(body=[binding], type_ignores=[]),
            self.modules[file_key],
            self.files[file_key].path,
        )
        dotted = names.get(name) or modules.get(name) or ""
        if dotted == "builtins":
            return [_DispatchValue("builtins", "builtins")]
        if dotted.startswith("builtins."):
            return [_DispatchValue("builtin", dotted.split(".", 1)[1])]
        if dotted == "sys":
            return [_DispatchValue("native", "sys")]
        if dotted == "sys.exit":
            return [_DispatchValue("nonreturning", "sys")]
        parts = tuple(dotted.split("."))
        matches = self.module_paths.get(parts, ())
        if len(matches) == 1:
            if (
                not self.initialize(matches[0].tree)
                or matches[0].tree in self.invalid_modules
            ):
                return []
            return [_DispatchValue("module", matches[0].tree)]
        matches = self.module_paths.get(parts[:-1], ())
        if len(matches) == 1:
            tree = matches[0].tree
            if not self.initialize(tree) or tree in self.invalid_modules:
                return []
            return self.value(
                ast.Name(id=parts[-1]),
                tree,
                self.environments.setdefault(tree, {}),
                caller,
                seen,
            )
        if dotted in {"django", "django.urls"}:
            return [_DispatchValue("native", dotted)]
        if dotted in {"django.urls.path", "django.urls.re_path", "django.urls.include"}:
            return [
                _DispatchValue(
                    "django_registration",
                    dotted,
                    guards=(_DispatchValue("native", "django.urls"),),
                )
            ]
        return []

    def guarded(self, value, guard):
        if not isinstance(value, _DispatchValue):
            return value
        return _DispatchValue(
            value.kind,
            value.node,
            value.fields,
            value.receiver,
            (*value.guards, value, guard),
            value.valid,
        )

    def invalidate(self, values, seen=None):
        seen = set() if seen is None else seen
        for value in values:
            if not isinstance(value, _DispatchValue) or id(value) in seen:
                continue
            seen.add(id(value))
            value.valid = False
            if value.kind == "class":
                self.invalid_classes.add(value.node)
            elif value.kind in {"function", "opaque_function"}:
                self.invalid_functions.add(value.node)
            elif value.kind == "module":
                self.invalid_modules.add(value.node)
                env = self.environments.setdefault(value.node, {})
                for name in self._scope_bindings(value.node):
                    self.invalidate(
                        self.value(ast.Name(id=name), value.node, env, value.node), seen
                    )
            elif value.kind == "registry":
                self.invalid_registries.add(value.node)
            elif value.kind == "builtins":
                self.invalid_builtins = True
            elif value.kind == "native":
                self.invalid_native.add(value.node)
            self.invalidate(value.guards, seen)
            for members in value.fields.values():
                self.invalidate(members, seen)

    def usable(self, value, seen=None):
        if not isinstance(value, _DispatchValue):
            return True
        seen = set() if seen is None else seen
        if id(value) in seen:
            return True
        seen.add(id(value))
        return (
            value.valid
            and value.node not in self.invalid_classes
            and value.node not in self.invalid_functions
            and value.node not in self.invalid_modules
            and (value.node not in self.invalid_registries)
            and not (value.kind == "builtin" and self.invalid_builtins)
            and not (
                value.kind in {"native", "nonreturning"}
                and value.node in self.invalid_native
            )
            and all(self.usable(guard, seen) for guard in value.guards)
        )

    def value(self, node, context, env, caller, seen=frozenset()):
        self.step()
        if node is None or node in seen or len(seen) >= 40:
            return []
        seen = seen | {node}
        if isinstance(node, ast.Constant):
            return [node.value]
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            binding, scope = self._lookup(node.id, context)
            if isinstance(binding, (ast.ClassDef, *_FUNCTION_NODES)):
                if isinstance(binding, _FUNCTION_NODES) and binding.decorator_list:
                    return []
                kind = "class" if isinstance(binding, ast.ClassDef) else "function"
                return [_DispatchValue(kind, binding)]
            if isinstance(binding, (ast.Import, ast.ImportFrom)):
                return self.imported(node.id, binding, scope, caller, seen)
            if binding is not None and not isinstance(binding, ast.arg):
                outer = (
                    env if scope is context else self.environments.setdefault(scope, {})
                )
                result = self.value(binding, scope, outer, caller, seen)
                if isinstance(scope, ast.Module):
                    outer[node.id] = result
                return result
            if scope is None and node.id in {
                "map",
                "list",
                "tuple",
                "set",
                "input",
                "property",
            }:
                return [_DispatchValue("builtin", node.id)]
            return []
        if isinstance(node, (ast.Tuple, ast.List)):
            return [
                _DispatchValue(
                    "sequence",
                    fields={
                        i: self.value(item, context, env, caller, seen)
                        for i, item in enumerate(node.elts)
                    },
                )
            ]
        if isinstance(node, ast.Dict):
            values = {}
            finite = True
            for key, item in zip(node.keys, node.values):
                self.value(key, context, env, caller, seen)
                members = self.value(item, context, env, caller, seen)
                if not isinstance(key, ast.Constant) or not isinstance(
                    key.value, (str, int)
                ):
                    finite = False
                else:
                    values[key.value] = members
            return [_DispatchValue("registry", node, fields=values)] if finite else []
        if isinstance(node, ast.Subscript):
            keys = self.value(node.slice, context, env, caller, seen)
            result = []
            for registry in self.value(node.value, context, env, caller, seen):
                if (
                    not isinstance(registry, _DispatchValue)
                    or registry.kind not in {"registry", "sequence"}
                    or not self.usable(registry)
                ):
                    continue
                selected = keys if keys else registry.fields
                for key in selected:
                    if isinstance(key, (str, int)):
                        if keys and len(keys) == 1 and key not in registry.fields:
                            raise _AbruptDispatch
                        result.extend(
                            self.guarded(item, registry)
                            for item in registry.fields.get(key, ())
                        )
            return result
        if isinstance(node, ast.Attribute):
            result = []
            for receiver in self.value(node.value, context, env, caller, seen):
                if not isinstance(receiver, _DispatchValue) or not self.usable(
                    receiver
                ):
                    continue
                if receiver.kind == "module":
                    result.extend(
                        self.value(
                            ast.Name(id=node.attr),
                            receiver.node,
                            self.environments.setdefault(receiver.node, {}),
                            caller,
                            seen,
                        )
                    )
                    continue
                if receiver.kind == "builtins":
                    result.append(
                        _DispatchValue("builtin", node.attr, guards=(receiver,))
                    )
                    continue
                if receiver.kind == "native":
                    if receiver.node == "sys" and node.attr == "exit":
                        result.append(
                            _DispatchValue("nonreturning", "sys", guards=(receiver,))
                        )
                    elif receiver.node == "django" and node.attr == "urls":
                        result.append(
                            _DispatchValue("native", "django.urls", guards=(receiver,))
                        )
                    elif receiver.node == "django.urls" and node.attr in {
                        "path",
                        "re_path",
                        "include",
                    }:
                        result.append(
                            _DispatchValue(
                                "django_registration",
                                "django.urls." + node.attr,
                                guards=(receiver,),
                            )
                        )
                    else:
                        result.append(
                            _DispatchValue(
                                "opaque_bound", receiver=receiver, guards=(receiver,)
                            )
                        )
                    continue
                if receiver.kind in {"function", "opaque_function"}:
                    if node.attr not in {
                        "__name__",
                        "__qualname__",
                        "__module__",
                        "__doc__",
                    }:
                        result.append(
                            _DispatchValue(
                                "opaque_function", receiver.node, guards=(receiver,)
                            )
                        )
                    continue
                if receiver.kind == "urlpattern":
                    member = {"callback": "callback", "default_args": "kwargs"}.get(
                        node.attr
                    )
                    if member is not None:
                        result.extend(
                            self.guarded(item, receiver)
                            for item in receiver.fields.get(member, [])
                        )
                    else:
                        result.append(
                            _DispatchValue(
                                "opaque_bound", receiver=receiver, guards=(receiver,)
                            )
                        )
                    continue
                if receiver.kind in {"registry", "sequence"}:
                    kind = (
                        "registry_get"
                        if receiver.kind == "registry" and node.attr == "get"
                        else "opaque_bound"
                    )
                    result.append(
                        _DispatchValue(kind, receiver=receiver, guards=(receiver,))
                    )
                    continue
                if receiver.kind not in {"class", "instance"}:
                    continue
                if not self.plain_class(receiver.node):
                    # A non-plain class cannot prove dispatch, but its exact
                    # source method remains a capability for effect auditing.
                    target = self.resolve(node, context)
                    if target and target[1] == "function":
                        result.append(
                            _DispatchValue(
                                "opaque_function", target[0], guards=(receiver,)
                            )
                        )
                    continue
                if node.attr in receiver.fields:
                    result.extend(
                        self.guarded(item, receiver)
                        for item in receiver.fields[node.attr]
                    )
                    continue
                methods = self.method_scope(receiver.node).class_methods.get(
                    node.attr, ()
                )
                if len(methods) != 1:
                    result.append(
                        _DispatchValue(
                            "opaque_bound", receiver=receiver, guards=(receiver,)
                        )
                    )
                    continue
                method = methods[0]
                if method.decorator_list:
                    if (
                        receiver.kind == "instance"
                        and len(method.decorator_list) == 1
                        and self.builtin(
                            method.decorator_list[0], "property", self.context(method)
                        )
                    ):
                        result.extend(
                            self.invoke(
                                _DispatchValue(
                                    "function",
                                    method,
                                    receiver=receiver,
                                    guards=(
                                        receiver,
                                        _DispatchValue("builtin", "property"),
                                    ),
                                ),
                                [],
                                {},
                                caller,
                            )
                        )
                    continue
                result.append(
                    _DispatchValue(
                        "function",
                        method,
                        receiver=receiver if receiver.kind == "instance" else None,
                        guards=(receiver,),
                    )
                )
            # Only module-qualified imports may use the existing exact lookup;
            # an unsupported receiver must not bypass the guards above.
            if not result:
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value
                binding = (
                    self._lookup(root.id, context)[0]
                    if isinstance(root, ast.Name)
                    else None
                )
                target = (
                    self.resolve(node, context)
                    if isinstance(binding, (ast.Import, ast.ImportFrom))
                    else None
                )
                if (
                    target
                    and target[1] in {"class", "function"}
                    and not isinstance(self.context(target[0]), ast.ClassDef)
                ):
                    result.append(_DispatchValue(target[1], target[0]))
            return result
        if isinstance(node, ast.IfExp):
            choices = (node.body, node.orelse)
            truth = self.truth(node.test, context, env, caller)
            if truth is not None:
                choices = (node.body if truth else node.orelse,)
            return [
                value
                for choice in choices
                for value in self.value(choice, context, env, caller, seen)
            ]
        if isinstance(node, ast.NamedExpr):
            values = self.value(node.value, context, env, caller, seen)
            self.assign(node.target, values, context, env, caller)
            return values
        if isinstance(node, ast.BoolOp):
            result = []
            for expression in node.values:
                values = self.value(expression, context, env, caller, seen)
                truth = self.value_truth(values)
                if truth is None:
                    self.invalidate(values)
                result.extend(values)
                if (isinstance(node.op, ast.And) and truth is False) or (
                    isinstance(node.op, ast.Or) and truth is True
                ):
                    break
            return result
        if isinstance(node, ast.Call):
            args = [self.value(arg, context, env, caller, seen) for arg in node.args]
            kwargs = {
                kw.arg: self.value(kw.value, context, env, caller, seen)
                for kw in node.keywords
            }
            if None in kwargs or any(isinstance(arg, ast.Starred) for arg in node.args):
                self.invalidate(
                    [item for values in args + list(kwargs.values()) for item in values]
                )
                # An unbound expansion cannot establish a completed call/frame.
                raise _AbruptDispatch
            functions = self.value(node.func, context, env, caller, seen)
            if not functions:
                self.invalidate(
                    [item for values in args + list(kwargs.values()) for item in values]
                )
                if isinstance(node.func, ast.Attribute):
                    self.invalidate(
                        self.value(node.func.value, context, env, caller, seen)
                    )
            return [
                value
                for function in functions
                for value in self.invoke(function, args, kwargs, caller)
            ]
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            first = self.value(node.generators[0].iter, context, env, caller, seen)
            if (
                len(first) == 1
                and isinstance(first[0], _DispatchValue)
                and (
                    first[0].kind in {"sequence", "registry"}
                    and not first[0].fields
                    and self.usable(first[0])
                )
            ):
                kind = "registry" if isinstance(node, ast.DictComp) else "sequence"
                return [_DispatchValue(kind, node)]
        # Declining an expression's value does not erase its possible effects.
        # Audit children without inventing execution evidence for an unmodeled
        # operation (including comprehension control flow or overloaded ops).
        previous = len(self.events)
        self.audit_only += 1
        children = ast.iter_child_nodes(node)
        if isinstance(node, ast.Lambda):
            children = iter([*node.args.defaults, *filter(None, node.args.kw_defaults)])
        try:
            for child in children:
                self.invalidate(self.value(child, context, env, caller, seen))
        finally:
            self.audit_only -= 1
            del self.events[previous:]
        return []

    def invoke(self, function, args, kwargs, caller):
        self.step()
        if not isinstance(function, _DispatchValue) or not self.usable(function):
            self.invalidate(
                [item for values in args + list(kwargs.values()) for item in values]
            )
            return []
        if function.kind == "opaque_bound":
            self.invalidate(
                [
                    function.receiver,
                    *[
                        item
                        for values in args + list(kwargs.values())
                        for item in values
                    ],
                ]
            )
            return []
        if function.kind == "nonreturning":
            raise _AbruptDispatch
        if function.kind == "django_registration":
            if function.node.endswith(".include"):
                supplied = self.native_arguments(args, kwargs, ("arg", "namespace"), 1)
                argument = supplied["arg"]
                if len(argument) != 1 or not isinstance(argument[0], str):
                    return []
                matches = self.module_paths.get(tuple(argument[0].split(".")), ())
                if len(matches) == 1:
                    if not self.initialize(matches[0].tree):
                        raise _AbruptDispatch
                    namespace = supplied.get("namespace", [None])
                    if namespace not in ([None], [""]):
                        app_name = self.environments.get(matches[0].tree, {}).get(
                            "app_name", []
                        )
                        if (
                            not app_name
                            and len(namespace) == 1
                            and isinstance(namespace[0], str)
                        ):
                            raise _AbruptDispatch
                        return []
                    return [
                        _DispatchValue(
                            "urlinclude", matches[0].tree, guards=(function,)
                        )
                    ]
                return []
            if "Pattern" in kwargs:
                self.invalidate(
                    [item for values in args + list(kwargs.values()) for item in values]
                )
                return []
            supplied = self.native_arguments(
                args, kwargs, ("route", "view", "kwargs", "name"), 2
            )
            route = supplied["route"]
            view = supplied["view"]
            options = supplied.get("kwargs", [None])
            if options != [None] and not (
                len(options) == 1
                and isinstance(options[0], _DispatchValue)
                and options[0].kind == "registry"
                and self.usable(options[0])
            ):
                if options:
                    raise _AbruptDispatch
                return []
            name = supplied.get("name", [None])
            if len(name) != 1 or not isinstance(name[0], (str, type(None))):
                return []
            if len(route) != 1 or not isinstance(route[0], str) or len(route[0]) > 300:
                return []
            if function.node.endswith(".re_path"):
                try:
                    pattern = re.compile(route[0])
                except re.error:
                    raise _AbruptDispatch from None
                if pattern.groups:
                    return []
            elif "<" in route[0] or ">" in route[0]:
                return []
            return [
                _DispatchValue(
                    "urlpattern",
                    fields={
                        "callback": view,
                        "kwargs": options
                        if options != [None] and options[0].fields
                        else [_DispatchValue("registry", object())],
                    },
                    guards=(function,),
                )
            ]
        if function.kind == "registry_get":
            if kwargs or len(args) not in {1, 2}:
                self.invalidate([function.receiver])
                return []
            keys = args[0] if args[0] else function.receiver.fields
            result = []
            for key in keys:
                if isinstance(key, (str, int)):
                    result.extend(
                        self.guarded(item, function.receiver)
                        for item in function.receiver.fields.get(
                            key, args[1] if len(args) == 2 else []
                        )
                    )
            return result
        if function.kind == "builtin":
            if function.node == "map" and len(args) == 2 and not kwargs:
                sequences = [
                    item
                    for item in args[1]
                    if isinstance(item, _DispatchValue) and item.kind == "sequence"
                ]
                if len(sequences) == 1:
                    return [
                        _DispatchValue(
                            "map",
                            fields=sequences[0].fields,
                            receiver=args[0],
                            guards=(function, sequences[0]),
                        )
                    ]
            if (
                function.node in {"list", "tuple", "set"}
                and len(args) == 1
                and not kwargs
            ):
                result = []
                for mapped in args[0]:
                    if (
                        isinstance(mapped, _DispatchValue)
                        and mapped.kind == "map"
                        and self.usable(mapped)
                    ):
                        for values in mapped.fields.values():
                            for callback in mapped.receiver:
                                callback = self.guarded(
                                    self.guarded(callback, mapped), function
                                )
                                result.extend(
                                    self.invoke(callback, [values], {}, caller)
                                )
                return result
            return []
        if function.kind == "class":
            if not self.plain_class(function.node):
                return []
            record = _DispatchValue(
                "instance", function.node, guards=(*function.guards, function)
            )
            initializers = self.method_scope(function.node).class_methods.get(
                "__init__", ()
            )
            if initializers:
                if len(initializers) != 1 or initializers[0].decorator_list:
                    return []
                initializer = initializers[0]
                if any(
                    not isinstance(
                        item,
                        (ast.Assign, ast.AnnAssign, ast.Expr, ast.Pass, ast.Return),
                    )
                    for item in initializer.body
                ):
                    return []
                if any(
                    isinstance(item, ast.Return)
                    and item.value is not None
                    and not (
                        isinstance(item.value, ast.Constant)
                        and item.value.value is None
                    )
                    for item in initializer.body
                ):
                    return []
                previous = len(self.events)
                self.invoke(
                    _DispatchValue("function", initializer, receiver=record),
                    args,
                    kwargs,
                    caller,
                )
                if (
                    len(self.events) == previous
                    or self.events[previous][0] is not initializer
                    or self.completions(initializer.body) == {"raise"}
                ):
                    return []
            elif args or kwargs:
                return []
            return [record] if self.usable(record) else []
        if function.kind != "function" or self.deferred_body(function.node):
            return []
        node = function.node
        if node in self.active or node.args.vararg or node.args.kwarg:
            return []
        positional = [*node.args.posonlyargs, *node.args.args]
        supplied = (
            [[function.receiver]] if function.receiver is not None else []
        ) + args
        if len(supplied) > len(positional):
            return []
        env = {param.arg: values for param, values in zip(positional, supplied)}
        for name, values in kwargs.items():
            if (
                name in {param.arg for param in node.args.posonlyargs}
                or name in env
                or name
                not in {param.arg for param in [*positional, *node.args.kwonlyargs]}
            ):
                return []
            env[name] = values
        defaults = (
            dict(
                zip(
                    [param.arg for param in positional[-len(node.args.defaults) :]],
                    node.args.defaults,
                )
            )
            if node.args.defaults
            else {}
        )
        defaults.update(
            {
                param.arg: value
                for param, value in zip(node.args.kwonlyargs, node.args.kw_defaults)
                if value is not None
            }
        )
        for param in [*positional, *node.args.kwonlyargs]:
            if param.arg not in env:
                if param.arg not in defaults:
                    return []
                captured = self.default_values.get(node, {})
                if param.arg in captured:
                    env[param.arg] = captured[param.arg]
                elif isinstance(defaults[param.arg], ast.Constant):
                    env[param.arg] = [defaults[param.arg].value]
                else:
                    # A default is evaluated by its definition, never its call.
                    return []
        self.events.append((node, caller, function))
        self.active.add(node)
        try:
            result, _ = self.block(node.body, node, env, node)
            return [self.guarded(value, function) for value in result]
        finally:
            self.active.remove(node)

    def native_arguments(self, args, kwargs, names, required):
        if len(args) > len(names) or any(name not in names for name in kwargs):
            raise _AbruptDispatch
        supplied = dict(zip(names, args))
        for name, values in kwargs.items():
            if name in supplied:
                raise _AbruptDispatch
            supplied[name] = values
        if any(name not in supplied for name in names[:required]):
            raise _AbruptDispatch
        return supplied

    def truth(self, node, context, env, caller):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left = self.value(node.left, context, env, caller)
            right = self.value(node.comparators[0], context, env, caller)
            if len(left) == len(right) == 1 and all(
                isinstance(item, (str, int, bool, type(None))) for item in left + right
            ):
                if isinstance(node.ops[0], ast.Eq):
                    return left[0] == right[0]
                if isinstance(node.ops[0], ast.NotEq):
                    return left[0] != right[0]
            self.invalidate(left + right)
            return None
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return self.value_truth(self.value(node, context, env, caller))

    def value_truth(self, values):
        if len(values) == 1 and isinstance(
            values[0], (str, int, float, bool, type(None))
        ):
            return bool(values[0])
        return None

    def assign(self, target, values, context, env, caller):
        if self.audit_only:
            self.invalidate(values)
            if isinstance(target, ast.Name):
                self.invalidate(env.get(target.id, []))
                env[target.id] = []
            elif isinstance(target, (ast.Attribute, ast.Subscript)):
                self.invalidate(self.value(target.value, context, env, caller))
            return
        if isinstance(target, ast.Name):
            env[target.id] = values
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            for receiver in self.value(target.value, context, env, caller):
                if isinstance(receiver, _DispatchValue):
                    if (
                        isinstance(target, ast.Attribute)
                        and receiver.kind == "instance"
                    ):
                        if self.branch_depth:
                            # Unknown/abrupt branches share object identities.
                            # Decline their heap write instead of donating it to
                            # another branch, including imported module state.
                            self.invalidate([receiver])
                            continue
                        members = self.method_scope(receiver.node).class_methods.get(
                            target.attr, ()
                        )
                        if any(method.decorator_list for method in members):
                            self.invalidate([receiver])
                        else:
                            receiver.fields[target.attr] = values
                    else:
                        self.invalidate([receiver])

    def definition_effects(self, node, context, env, caller):
        """Headers execute now, while their bodies remain deferred.

        Their effects can invalidate a registry/receiver used by later calls.
        This supplemental proof does not add new liveness roots for headers.
        """
        previous = len(self.events)
        try:
            if isinstance(node, _FUNCTION_NODES):
                positional = [*node.args.posonlyargs, *node.args.args]
                defaults = (
                    dict(
                        zip(
                            [
                                param.arg
                                for param in positional[-len(node.args.defaults) :]
                            ],
                            node.args.defaults,
                        )
                    )
                    if node.args.defaults
                    else {}
                )
                defaults.update(
                    {
                        param.arg: value
                        for param, value in zip(
                            node.args.kwonlyargs, node.args.kw_defaults
                        )
                        if value is not None
                    }
                )
                self.default_values[node] = {
                    name: self.value(value, context, env, caller)
                    for name, value in defaults.items()
                }
                for argument in [
                    *positional,
                    *node.args.kwonlyargs,
                    node.args.vararg,
                    node.args.kwarg,
                ]:
                    if argument is not None:
                        self.value(argument.annotation, context, env, caller)
                self.value(node.returns, context, env, caller)
                declared = _DispatchValue("function", node)
            else:
                for expression in [*node.bases, *(kw.value for kw in node.keywords)]:
                    self.value(expression, context, env, caller)
                self.block(node.body, node, {}, caller)
                declared = _DispatchValue("class", node)
            for decorator in reversed(node.decorator_list):
                functions = self.value(decorator, context, env, caller)
                for function in functions:
                    self.invoke(function, [[declared]], {}, caller)
        finally:
            del self.events[previous:]

    def block(self, statements, context, env, caller):
        returns = []
        for node in statements:
            self.step()
            if not self.possible_site(node):
                continue
            if isinstance(node, (ast.ClassDef, *_FUNCTION_NODES)):
                self.definition_effects(node, context, env, caller)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if not self.imports_complete(node, context):
                    return returns, False
                continue
            if isinstance(node, ast.Pass):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                values = self.value(node.value, context, env, caller)
                for target in (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                ):
                    self.assign(target, values, context, env, caller)
            elif isinstance(node, ast.Expr):
                self.value(node.value, context, env, caller)
                if self.call_raises(node.value, frozenset()):
                    return returns, False
            elif isinstance(node, ast.Return):
                return returns + self.value(node.value, context, env, caller), False
            elif isinstance(node, ast.Raise):
                return returns, False
            elif isinstance(node, ast.If):
                truth = self.truth(node.test, context, env, caller)
                branches = (
                    (node.body, node.orelse)
                    if truth is None
                    else (node.body if truth else node.orelse,)
                )
                continuing = []
                for branch in branches:
                    branch_env = dict(env)
                    self.branch_depth += truth is None
                    try:
                        values, falls = self.block(branch, context, branch_env, caller)
                    finally:
                        self.branch_depth -= truth is None
                    returns.extend(values)
                    if falls:
                        continuing.append(branch_env)
                if not continuing:
                    return returns, False
                for name in set().union(*continuing):
                    env[name] = [
                        value for branch in continuing for value in branch.get(name, [])
                    ]
            else:
                # Unmodeled control flow cannot establish later call execution.
                self.invalidate([value for values in env.values() for value in values])
                self.value(node, context, env, caller)
                return returns, False
        return returns, True

    def targets(self):
        for parsed in self.files.values():
            self.initialize(parsed.tree)
        for owner, command_entry in self.framework_owners:
            tree = self.files[self.file_for_node[owner]].tree
            if (
                not self.initialize(tree)
                or owner in self.invalid_functions
                or self.context(owner) in self.invalid_classes
                or tree in self.invalid_modules
            ):
                continue
            # Explicit framework roots receive external arguments. This entry
            # frame is separate from strict binding of ordinary source calls.
            args = owner.args
            positional = [*args.posonlyargs, *args.args]
            if args.defaults or args.kwonlyargs or len(positional) > 1:
                continue
            if (args.vararg or args.kwarg) and not (
                command_entry and len(positional) == 1
            ):
                continue
            params = [
                *args.posonlyargs,
                *args.args,
                *args.kwonlyargs,
                args.vararg,
                args.kwarg,
            ]
            env = {param.arg: [] for param in params if param is not None}
            self.active.add(owner)
            try:
                self.block(owner.body, owner, env, owner)
            except _AbruptDispatch:
                pass
            finally:
                self.active.remove(owner)
        return [
            (node, caller) for node, caller, value in self.events if self.usable(value)
        ]
