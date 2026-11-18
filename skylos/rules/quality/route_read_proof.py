"""Finite readonly route proof with values bound separately for every call.

Only actual native FastAPI scalar contracts seed input types. Unsupported
syntax, receiver escapes, stores and unknown serialization keep the finding.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.danger.import_proof import (
    project_provider_effects_are_stable,
    provider_binding_is_stable,
)
from skylos.rules.danger.project_imports import project_import_context
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex
from skylos.security.framework_contracts import native_http_pipeline_is_intact
from skylos.security.receiver_bindings import _Module
from skylos.security.receiver_resolution import ReceiverResolver

_SCALARS = frozenset({"str", "int", "float", "bool", "none"})
_CONTAINERS = frozenset({"list", "tuple", "dict"})
_BUILTINS = frozenset(
    {"str", "int", "float", "bool", "abs", "round", "min", "max", "len"}
)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class _Native:
    kinds: frozenset[str]
    children: tuple = ()

    def serializable(self):
        return (
            bool(self.kinds)
            and self.kinds <= _SCALARS | _CONTAINERS
            and all(native(value) for value in self.children)
        )


@dataclass
class _Receiver:
    ref: object
    source: object
    qualified: str


def native(value):
    return isinstance(value, _Native) and value.serializable()


def merge(values):
    if not values or not all(native(value) for value in values):
        return None
    return _Native(
        frozenset().union(*(value.kinds for value in values)),
        tuple(child for value in values for child in value.children),
    )


class _Proof:
    MAX_WORK = 4096
    MAX_DEPTH = 12

    def __init__(self, tree, filename, root):
        self.resolver = ReceiverResolver(tree, filename, root)
        self.root = root
        self.work = 0
        self.active = set()
        self.builtin_refs = {}

    def tick(self):
        self.work += 1
        return self.work <= self.MAX_WORK

    def stable(self, qualified, source):
        return project_provider_effects_are_stable(
            qualified, source.tree, source.path, self.root
        )

    def builtin(self, source, node, names):
        if not isinstance(node, ast.Name) or node.id not in names:
            return False
        key = str(source.path)
        if key not in self.builtin_refs:
            self.builtin_refs[key] = builtin_references(source.tree, _BUILTINS)
        return id(node) in self.builtin_refs[key] and provider_binding_is_stable(
            "builtins." + node.id, source.tree, source.path, self.root
        )

    def annotation(self, source, node):
        if self.builtin(source, node, _SCALARS):
            return _Native(frozenset({node.id}))
        if isinstance(node, ast.Constant) and node.value is None:
            return _Native(frozenset({"none"}))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return merge(
                [
                    self.annotation(source, node.left),
                    self.annotation(source, node.right),
                ]
            )
        return None

    def framework_intact(self, source):
        return native_http_pipeline_is_intact(source.tree, source.path, self.root)

    def inputs(self, fn):
        source = self.resolver.main
        if not source.name or not all(
            part.isidentifier() for part in source.name.split(".")
        ):
            return None
        if len(fn.decorator_list) != 1 or fn.args.vararg or fn.args.kwarg:
            return None
        dec = fn.decorator_list[0]
        if not (
            isinstance(dec, ast.Call)
            and isinstance(dec.func, ast.Attribute)
            and isinstance(dec.func.value, ast.Name)
            and dec.func.attr in {"get", "post", "put", "patch", "delete"}
            and len(dec.args) == 1
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
            and not dec.keywords
        ):
            return None
        name = dec.func.value.id
        bindings = source.bindings(source.tree).get(name, ())
        if len(bindings) != 1 or name in source.mutated or source.dynamic_namespace:
            return None
        if any(
            isinstance(node, ast.Global) and name in node.names
            for node in ast.walk(source.tree)
        ):
            return None
        if not self.framework_intact(source):
            return None
        for use in ast.walk(source.tree):
            if (
                not isinstance(use, ast.Name)
                or not isinstance(use.ctx, ast.Load)
                or use.id != name
            ):
                continue
            scope = source.scope(use)
            while scope is not source.tree and not source.bindings(scope).get(name):
                scope = source.scope(scope)
                if isinstance(scope, ast.ClassDef):
                    scope = source.scope(scope)
            if scope is not source.tree:
                if any(
                    isinstance(binding, (ast.Global, ast.Nonlocal))
                    for binding, _, _ in source.bindings(scope).get(name, ())
                ):
                    return None
                continue
            method = source.parents.get(use)
            registration = source.parents.get(method)
            owner = source.parents.get(registration)
            if not (
                isinstance(method, ast.Attribute)
                and method.value is use
                and method.attr in {"get", "post", "put", "patch", "delete"}
                and isinstance(registration, ast.Call)
                and registration.func is method
                and isinstance(owner, _FUNCTIONS)
                and registration in owner.decorator_list
                and len(registration.args) == 1
                and isinstance(registration.args[0], ast.Constant)
                and isinstance(registration.args[0].value, str)
                and not registration.keywords
            ):
                return None
        if not self.stable(source.name + "." + name, source) or not self.stable(
            source.name + "." + fn.name, source
        ):
            return None
        ctor = bindings[0][1]
        if not isinstance(ctor, ast.Call) or ctor.args or ctor.keywords:
            return None
        provider = UntrustedSourceIndex(source.tree).resolved_import(
            None, ast.unparse(ctor.func)
        )
        if provider not in {
            "fastapi.FastAPI",
            "fastapi.applications.FastAPI",
        } or not provider_binding_is_stable(
            provider, source.tree, source.path, self.root
        ):
            return None
        if any(
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id == fn.name
            for node in ast.walk(source.tree)
        ):
            return None
        params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        defaults = (
            [None]
            * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
            + list(fn.args.defaults)
            + list(fn.args.kw_defaults)
        )
        env = {}
        for parameter, default in zip(params, defaults):
            value = self.annotation(source, parameter.annotation)
            if value is None:
                return None
            if default is not None:
                default_value = self.value(source, default, {}, 0)
                if not isinstance(default, ast.Constant) or not native(default_value):
                    return None
                value = merge([value, default_value])
            env[parameter.arg] = value
        return env

    def captures(self, source, expression, receiver, seen=frozenset()):
        if expression is None:
            return False
        if expression in seen or len(seen) >= self.MAX_DEPTH:
            return True
        seen = seen | {expression}
        for node in ast.walk(expression):
            if not self.tick():
                return True
            if not isinstance(node, ast.Name):
                continue
            ref = self.resolver._expr(source, node)
            if (
                ref is not None
                and ref.kind in {"instance", "class"}
                and ref.name == receiver.name
            ):
                return True
            scope = source.scope(node)
            if node.id in {"self", "cls"} and isinstance(scope, _FUNCTIONS):
                owner = source.scope(scope)
                if (
                    isinstance(owner, ast.ClassDef)
                    and source.path == receiver.module.path
                    and owner.name == receiver.node.name
                ):
                    return True
            bindings = source.bindings(scope).get(node.id, ())
            while not bindings and scope is not source.tree:
                scope = source.scope(scope)
                if isinstance(scope, ast.ClassDef):
                    scope = source.scope(scope)
                bindings = source.bindings(scope).get(node.id, ())
            if any(
                isinstance(binding, (ast.Assign, ast.AnnAssign))
                and self.captures(source, value, receiver, seen)
                for binding, value, _ in bindings
            ):
                return True
        return False

    def receiver(self, value):
        ref = value.ref
        if (
            ref.kind != "instance"
            or ref.module is None
            or not self.resolver._class_safe(ref)
            or not self.stable(ref.name, ref.module)
            or not self.stable(value.qualified, value.source)
        ):
            return False
        context = project_import_context(
            value.source.tree, value.source.path, self.root
        )
        if context is None or len(context.entries) > self.resolver.MAX_FILES:
            return False
        for path, tree in context.entries:
            if path == value.source.path and any(
                isinstance(node, ast.Global)
                and value.qualified.rsplit(".", 1)[-1] in node.names
                for node in ast.walk(tree)
            ):
                return False
            source = self.resolver.modules.get(str(path))
            if source is None:
                source = _Module(tree, path, self.resolver._module_name(path))
                self.resolver.modules[str(path)] = source
            for node in ast.walk(tree):
                if not self.tick():
                    return False
                if isinstance(node, ast.Call) and any(
                    self.captures(source, argument, ref)
                    for argument in [
                        *node.args,
                        *[keyword.value for keyword in node.keywords],
                    ]
                ):
                    return False
        return True

    def value(self, source, node, env, depth):
        if node is None or depth > self.MAX_DEPTH or not self.tick():
            return None
        if isinstance(node, ast.Constant):
            kind = "none" if node.value is None else type(node.value).__name__
            return _Native(frozenset({kind})) if kind in _SCALARS else None
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            ref = self.resolver._expr(source, node)
            return (
                _Receiver(ref, source, source.name + "." + node.id)
                if ref is not None and ref.kind == "instance" and ref.model is None
                else None
            )
        if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
            parts = (
                [*node.keys, *node.values] if isinstance(node, ast.Dict) else node.elts
            )
            values = tuple(self.value(source, part, env, depth + 1) for part in parts)
            kind = (
                "dict"
                if isinstance(node, ast.Dict)
                else "list"
                if isinstance(node, ast.List)
                else "tuple"
            )
            return (
                _Native(frozenset({kind}), values)
                if all(native(value) for value in values)
                else None
            )
        if isinstance(node, ast.BinOp):
            left, right = (
                self.value(source, part, env, depth + 1)
                for part in (node.left, node.right)
            )
            if not native(left) or not native(right):
                return None
            kinds = left.kinds | right.kinds
            if kinds <= {"int", "float", "bool"} and isinstance(
                node.op,
                (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow),
            ):
                return _Native(
                    frozenset(
                        {
                            "float"
                            if "float" in kinds or isinstance(node.op, ast.Div)
                            else "int"
                        }
                    )
                )
            return (
                _Native(frozenset({"str"}))
                if kinds == {"str"} and isinstance(node.op, ast.Add)
                else None
            )
        if isinstance(node, (ast.Compare, ast.UnaryOp)):
            parts = (
                [node.left, *node.comparators]
                if isinstance(node, ast.Compare)
                else [node.operand]
            )
            values = [self.value(source, part, env, depth + 1) for part in parts]
            if not all(native(value) for value in values):
                return None
            if isinstance(node, ast.Compare) or isinstance(node.op, ast.Not):
                return _Native(frozenset({"bool"}))
            return values[0] if values[0].kinds <= {"int", "float", "bool"} else None
        if isinstance(node, ast.BoolOp):
            return merge(
                [self.value(source, part, env, depth + 1) for part in node.values]
            )
        if isinstance(node, ast.IfExp):
            return (
                merge(
                    [
                        self.value(source, node.body, env, depth + 1),
                        self.value(source, node.orelse, env, depth + 1),
                    ]
                )
                if native(self.value(source, node.test, env, depth + 1))
                else None
            )
        if (
            not isinstance(node, ast.Call)
            or any(isinstance(arg, ast.Starred) for arg in node.args)
            or any(keyword.arg is None for keyword in node.keywords)
        ):
            return None
        arguments = [self.value(source, arg, env, depth + 1) for arg in node.args]
        keywords = {
            keyword.arg: self.value(source, keyword.value, env, depth + 1)
            for keyword in node.keywords
        }
        if any(value is None for value in [*arguments, *keywords.values()]):
            return None
        if self.builtin(source, node.func, _BUILTINS):
            if not all(native(value) for value in [*arguments, *keywords.values()]):
                return None
            name = node.func.id
            if name in {"min", "max", "abs", "round"}:
                return (
                    merge(arguments)
                    if arguments
                    and all(
                        value.kinds <= {"int", "float", "bool"} for value in arguments
                    )
                    else None
                )
            return _Native(frozenset({"int" if name == "len" else name}))
        if isinstance(node.func, ast.Attribute):
            owner = self.value(source, node.func.value, env, depth + 1)
            if not isinstance(owner, _Receiver) or not self.receiver(owner):
                return None
            ref = self.resolver._attribute(owner.ref, node.func.attr, 0, frozenset())
            qualified = owner.ref.name
            arguments.insert(0, owner)
        else:
            ref = self.resolver._expr(source, node.func)
            qualified = ref.name if ref is not None else ""
        if (
            ref is None
            or ref.module is None
            or not isinstance(ref.node, ast.FunctionDef)
            or ref.kind not in {"method", "function"}
        ):
            return None
        return self.call(
            ref.node, ref.module, arguments, keywords, qualified, depth + 1
        )

    def block(self, source, statements, env, depth):
        returned, terminated = [], False
        for node in statements:
            if not self.tick():
                return None
            if isinstance(node, ast.Pass):
                continue
            if isinstance(node, ast.Return):
                value = (
                    _Native(frozenset({"none"}))
                    if node.value is None
                    else self.value(source, node.value, env, depth + 1)
                )
                if not native(value):
                    return None
                returned.append(value)
                terminated = True
            elif isinstance(node, ast.Assign):
                if any(not isinstance(target, ast.Name) for target in node.targets):
                    return None
                value = self.value(source, node.value, env, depth + 1)
                if value is None:
                    return None
                for target in node.targets:
                    env[target.id] = value
            elif isinstance(node, ast.Expr):
                if self.value(source, node.value, env, depth + 1) is None:
                    return None
            elif isinstance(node, ast.If):
                if not native(self.value(source, node.test, env, depth + 1)):
                    return None
                left, right = dict(env), dict(env)
                yes, no = (
                    self.block(source, node.body, left, depth + 1),
                    self.block(source, node.orelse, right, depth + 1),
                )
                if yes is None or no is None:
                    return None
                returned.extend([*yes[0], *no[0]])
                terminated |= yes[1] and no[1]
                env.clear()
                for name in left.keys() & right.keys():
                    value = (
                        left[name]
                        if left[name] is right[name]
                        else merge([left[name], right[name]])
                    )
                    if value is not None:
                        env[name] = value
            else:
                return None
        return returned, terminated

    def call(self, fn, source, arguments, keywords, qualified, depth):
        key = (str(source.path), id(fn))
        if (
            depth > self.MAX_DEPTH
            or key in self.active
            or fn.args.vararg
            or fn.args.kwarg
            or not self.stable(qualified, source)
        ):
            return None
        positional = [*fn.args.posonlyargs, *fn.args.args]
        if len(arguments) > len(positional):
            return None
        env = dict(zip((parameter.arg for parameter in positional), arguments))
        allowed = {parameter.arg for parameter in [*fn.args.args, *fn.args.kwonlyargs]}
        for name, value in keywords.items():
            if name not in allowed or name in env:
                return None
            env[name] = value
        defaults = (
            dict(
                zip(
                    (
                        parameter.arg
                        for parameter in positional[-len(fn.args.defaults) :]
                    ),
                    fn.args.defaults,
                )
            )
            if fn.args.defaults
            else {}
        )
        defaults.update(
            {
                parameter.arg: value
                for parameter, value in zip(fn.args.kwonlyargs, fn.args.kw_defaults)
                if value is not None
            }
        )
        for parameter in [*positional, *fn.args.kwonlyargs]:
            if parameter.arg not in env:
                env[parameter.arg] = self.value(
                    source, defaults.get(parameter.arg), {}, depth + 1
                )
                if env[parameter.arg] is None:
                    return None
        self.active.add(key)
        try:
            result = self.block(source, fn.body, env, depth + 1)
            if result is None:
                return None
            values, terminated = result
            return merge(
                values + ([] if terminated else [_Native(frozenset({"none"}))])
            )
        finally:
            self.active.remove(key)


def source_read_only_route(module, function, filename, project_root=None):
    if not filename or project_root is None:
        return False
    try:
        proof = _Proof(module, filename, project_root)
        inputs = proof.inputs(function)
        if inputs is None:
            return False
        result = proof.block(proof.resolver.main, function.body, inputs, 0)
        return result is not None and all(native(value) for value in result[0])
    except (OSError, ValueError, TypeError, RecursionError):
        return False
