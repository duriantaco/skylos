"""Negative reachability for closed, source-owned type-keyed registries.

A bounded abstract interpreter tracks instance dictionaries, copied snapshots,
closures and callable identity. It interprets AST data only and never imports or
executes target code. Unsupported calls, escaping state, unknown keys/control
flow, packages and explicit external entrypoints yield no negative proof.
"""

from __future__ import annotations

import ast
from copy import copy
from dataclasses import dataclass
from pathlib import Path

from skylos.deadcode.nested_registry_proofs import (
    _MISSING,
    _UNKNOWN,
    _Bound,
    _Class,
    _Function,
    _Instance,
    _Limit,
    _RegistryProof,
    _Table,
)
from skylos.deadcode.python_ast import parse_python_files


@dataclass(frozen=True)
class _Type:
    name: str


_MAX_SCALAR_SIZE = 8192


def _bounded(value):
    if type(value) in {str, bytes} and len(value) > _MAX_SCALAR_SIZE:
        raise _Limit("scalar_size_budget")
    if type(value) is int and value.bit_length() > _MAX_SCALAR_SIZE:
        raise _Limit("integer_size_budget")
    return value


class _ClosedProof(_RegistryProof):
    def __init__(self, definitions, parsed):
        super().__init__(definitions, parsed)
        self.stack = []
        self.closed_owners = set()
        self.registered = set()
        self.lookup_count = 0
        self.instances = set()
        self.class_bases = {}
        self.types = {
            name: _Type(name)
            for name in ("str", "bytes", "int", "float", "bool", "object", "NoneType")
        }

    def collect(self):
        # Registration itself is being refined, not assumed to invoke every
        # stored callback. Explicit external entrypoints are excluded below.
        try:
            for name in tuple(self.modules):
                self.module(name)
        except _Limit as error:
            self.report.complete = False
            self.report.incomplete_reason = str(error)
        return self.report

    def module(self, name):
        if name not in self.modules:
            raise _Limit("external_module")
        return super().module(name)

    def invalidate(self, statements, frame):
        raise _Limit("unsupported_control_flow")

    def suite(self, statements, frame):
        for statement in statements:
            bases = []
            if isinstance(statement, ast.ClassDef):
                if statement.decorator_list or statement.keywords:
                    raise _Limit("unsupported_class_protocol")
                for base in statement.bases:
                    if not isinstance(base, ast.Name):
                        raise _Limit("effectful_class_base")
                    value = self.eval(base, frame)
                    bases.append(value)
                    definition = value.definition if isinstance(value, _Class) else None
                    body = getattr(getattr(definition, "node", None), "body", ())
                    if (
                        definition is None
                        or not body
                        or any(
                            not isinstance(n, ast.Pass)
                            and not (
                                isinstance(n, ast.Expr)
                                and isinstance(n.value, ast.Constant)
                                and isinstance(n.value.value, str)
                            )
                            for n in body
                        )
                    ):
                        raise _Limit("unknown_class_base")
            result = super().suite([statement], frame)
            if isinstance(statement, ast.ClassDef):
                created = frame.get(statement.name)
                if not isinstance(created, _Class):
                    raise _Limit("unknown_created_class")
                self.class_bases[id(created)] = tuple(bases)
            if result is not None:
                return result
        return None

    def set_attr(self, receiver, name, value):
        if name.startswith("__") and name.endswith("__"):
            raise _Limit("magic_attribute_mutation")
        if not isinstance(receiver, (_Class, _Instance)):
            raise _Limit("unknown_mutation_target")
        return super().set_attr(receiver, name, value)

    def key(self, value):
        if value is _UNKNOWN:
            raise _Limit("unknown_registry_key")
        if isinstance(value, (_Type, _Class)):
            return value
        if isinstance(value, tuple):
            if len(value) > 256 or any(isinstance(part, tuple) for part in value):
                raise _Limit("compound_key_budget")
            return tuple(self.key(v) for v in value)
        result = super().key(value)
        if result is _UNKNOWN:
            raise _Limit("unsupported_registry_key")
        return result

    def function(self, node, frame):
        if not node.decorator_list:
            return super().function(node, frame)
        decorators = [self.eval(d, frame) for d in node.decorator_list]
        if not all(isinstance(d, (_Function, _Bound)) for d in decorators):
            raise _Limit("external_decorator")
        plain = copy(node)
        plain.decorator_list = []
        super().function(plain, frame)
        value = frame.get(node.name)
        for decorator in reversed(decorators):
            value = self.invoke(decorator, [value], {})
        if self.stack:
            self.closed_owners.add(id(self.stack[-1].node))
        self.set_name(frame, node.name, value)

    def assign(self, target, value, frame):
        if isinstance(target, ast.Subscript):
            table = self.eval(target.value, frame)
            if not isinstance(table, _Table) or not table.valid:
                raise _Limit("unknown_mutation_target")
            key = self.key(self.eval(target.slice, frame))
            if key not in table.data and len(table.data) >= 256:
                raise _Limit("registry_item_budget")
            parts = key if isinstance(key, tuple) else (key,)
            if (
                isinstance(value, _Function)
                and value.definition is not None
                and any(isinstance(part, (_Type, _Class)) for part in parts)
            ):
                self.registered.add(
                    (
                        str(Path(value.definition.filename).resolve()),
                        value.definition.line,
                    )
                )
            table.data[key] = self.registry_name(value)
            return
        if isinstance(target, ast.Attribute) and not isinstance(
            self.eval(target.value, frame), (_Class, _Instance)
        ):
            raise _Limit("unknown_mutation_target")
        return super().assign(target, value, frame)

    def invoke(self, function, args, keywords):
        unbound = function.function if isinstance(function, _Bound) else function
        if isinstance(unbound, _Class):
            self.instances.add(id(unbound))
        if isinstance(unbound, _Function):
            self.stack.append(unbound)
        try:
            result = super().invoke(function, args, keywords)
            if result is _UNKNOWN:
                raise _Limit("unknown_call_result")
            return result
        finally:
            if isinstance(unbound, _Function):
                self.stack.pop()

    def _mro(self, cls, seen=frozenset()):
        self.step()
        if id(cls) in seen or len(seen) >= 32:
            raise _Limit("type_hierarchy_budget")
        if id(cls) in self.class_bases:
            bases = self.class_bases[id(cls)]
            return (
                (cls, *self._mro(bases[0], seen | {id(cls)}))
                if bases
                else (cls, self.types["object"])
            )
        if id(cls) in seen or cls.definition is None:
            raise _Limit("unknown_type_hierarchy")
        definition = cls.definition
        module = next(
            (
                m
                for m in self.modules.values()
                if getattr(m, "path", None) == str(Path(definition.filename).resolve())
            ),
            None,
        )
        node = getattr(definition, "node", None)
        if module is None or not isinstance(node, ast.ClassDef) or len(node.bases) > 1:
            raise _Limit("unknown_type_hierarchy")
        if not node.bases:
            return (cls, self.types["object"])
        base = self.eval(node.bases[0], module.frame)
        if not isinstance(base, _Class):
            raise _Limit("unknown_type_hierarchy")
        return (cls, *self._mro(base, seen | {id(cls)}))

    def attr(self, receiver, name):
        if isinstance(receiver, _Class) and name == "__mro__":
            return self._mro(receiver)
        if isinstance(receiver, _Class) and name == "__name__":
            return receiver.definition.simple_name if receiver.definition else _UNKNOWN
        if isinstance(receiver, _Type) and name == "__mro__":
            if receiver.name == "bool":
                return (receiver, self.types["int"], self.types["object"])
            return (
                (receiver,)
                if receiver.name == "object"
                else (receiver, self.types["object"])
            )
        return super().attr(receiver, name)

    def expression(self, node, frame):
        if isinstance(node, ast.Constant):
            return _bounded(node.value)
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            table = self.eval(node.value, frame)
            if isinstance(table, _Table):
                if not table.valid:
                    raise _Limit("escaped_registry")
                self.lookup_count += 1
                return table.data.get(self.key(self.eval(node.slice, frame)), _UNKNOWN)
            raise _Limit("unsupported_subscript_receiver")
        if (
            isinstance(node, ast.Name)
            and node.id in self.types
            and frame.get(node.id) is _MISSING
        ):
            return self.types[node.id]
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and len(node.comparators) == 1
        ):
            left, right = (
                self.eval(node.left, frame),
                self.eval(node.comparators[0], frame),
            )
            if left is _UNKNOWN or right is _UNKNOWN:
                raise _Limit("unknown_condition")
            if left is not None and right is not None:
                raise _Limit("noncanonical_identity_comparison")
            if isinstance(node.ops[0], ast.Is):
                return left is right
            if isinstance(node.ops[0], ast.IsNot):
                return left is not right
        if isinstance(node, ast.BinOp):
            left, right = self.eval(node.left, frame), self.eval(node.right, frame)
            if (
                type(left) in {int, float}
                and type(right) in {int, float}
                and isinstance(node.op, ast.Mult)
            ):
                _bounded(left)
                _bounded(right)
                if (
                    type(left) is int
                    and type(right) is int
                    and left.bit_length() + right.bit_length() > _MAX_SCALAR_SIZE
                ):
                    raise _Limit("integer_multiplication_budget")
                if (
                    type(left) is float
                    and type(right) is int
                    and right.bit_length() > 1024
                    or type(right) is float
                    and type(left) is int
                    and left.bit_length() > 1024
                ):
                    raise _Limit("float_conversion_budget")
                return _bounded(left * right)
            raise _Limit("unsupported_operator")
        result = super().expression(node, frame)
        if result is _UNKNOWN:
            raise _Limit("unsupported_expression")
        return result

    def call(self, node, frame):
        if len(node.args) > 256 or len(node.keywords) > 256:
            raise _Limit("call_argument_budget")
        if isinstance(node.func, ast.Name) and frame.get(node.func.id) is _MISSING:
            if node.func.id == "print" and not node.keywords:
                for argument in node.args:
                    value = self.eval(argument, frame)
                    if isinstance(
                        value,
                        (_Table, _Class, _Instance, _Function, _Bound, tuple, list),
                    ):
                        raise _Limit("object_output_escape")
                return None
            if node.func.id == "type" and len(node.args) == 1 and not node.keywords:
                value = self.eval(node.args[0], frame)
                if isinstance(value, _Instance):
                    return value.cls
                name = type(value).__name__
                if name in self.types and value is not _UNKNOWN:
                    return self.types[name]
                raise _Limit("unknown_input_type")
            if (
                node.func.id in {"str", "repr"}
                and len(node.args) == 1
                and not node.keywords
            ):
                value = self.eval(node.args[0], frame)
                if type(value) in {str, bytes, int, bool, float, type(None)}:
                    _bounded(value)
                    return _bounded(
                        str(value) if node.func.id == "str" else repr(value)
                    )
                raise _Limit("object_conversion_escape")
        if isinstance(node.func, ast.Attribute):
            if any(isinstance(child, ast.Call) for child in ast.walk(node.func.value)):
                raise _Limit("effectful_receiver_expression")
            receiver = self.eval(node.func.value, frame)
            if isinstance(receiver, _Table):
                if len(receiver.data) > 256:
                    raise _Limit("registry_item_budget")
                if node.func.attr == "update":
                    if len(node.args) > 1 or len(node.keywords) > 256:
                        raise _Limit("registry_item_budget")
                    incoming = (
                        self.eval(node.args[0], frame) if node.args else _Table({})
                    )
                    if (
                        not isinstance(incoming, _Table)
                        or not incoming.valid
                        or not receiver.valid
                    ):
                        raise _Limit("unknown_registry_update")
                    keywords = {k.arg: self.eval(k.value, frame) for k in node.keywords}
                    if (
                        None in keywords
                        or len(set(receiver.data) | set(incoming.data) | set(keywords))
                        > 256
                    ):
                        raise _Limit("registry_item_budget")
                    receiver.data.update(incoming.data)
                    receiver.data.update(keywords)
                    return None
            if (
                isinstance(receiver, _Table)
                and node.func.attr == "copy"
                and not node.args
                and not node.keywords
            ):
                if not receiver.valid:
                    raise _Limit("escaped_registry")
                return _Table(dict(receiver.data))
            if isinstance(receiver, _Table) and node.func.attr == "get":
                self.lookup_count += 1
            if (
                type(receiver) in {str, bytes}
                and node.func.attr in {"upper", "lower", "casefold", "strip", "hex"}
                and not node.args
                and not node.keywords
            ):
                function = getattr(type(receiver), node.func.attr, None)
                if function is not None:
                    _bounded(receiver)
                    return _bounded(function(receiver))
        result = super().call(node, frame)
        if isinstance(result, _Table) and len(result.data) > 256:
            raise _Limit("registry_item_budget")
        if result is _UNKNOWN:
            raise _Limit("unknown_consumer")
        return result

    def escape(self, values):
        raise _Limit("unknown_consumer_or_escape")


def closed_type_registry_unused(definitions, files, project_root):
    root = Path(project_root)
    if any(
        (root / name).exists() for name in ("pyproject.toml", "setup.py", "setup.cfg")
    ):
        return set()
    import os

    inspected = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [
            name
            for name in dirs
            if name not in {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}
        ]
        if any((Path(directory) / name).is_symlink() for name in [*dirs, *names]):
            return set()
        inspected += len(dirs) + len(names)
        if inspected > 256 or any(Path(name).suffix != ".py" for name in names):
            return set()
    paths = [Path(p) for p in files if str(p).endswith(".py")]
    if not paths or len(paths) > 32 or any(p.name == "__init__.py" for p in paths):
        return set()
    import sys

    if any(
        p.parent.resolve() != root.resolve() or p.stem in sys.stdlib_module_names
        for p in paths
    ):
        # Namespace packages and built-in/frozen-module precedence are outside
        # this flat source-owned module proof.
        return set()
    parsed = parse_python_files(paths)
    if len(parsed) != len(paths):
        return set()
    for source in parsed:
        for node in ast.walk(source.tree):
            modeled = {
                "type",
                "str",
                "bytes",
                "int",
                "float",
                "bool",
                "object",
                "dict",
                "getattr",
                "hasattr",
                "setattr",
                "delattr",
                "print",
                "repr",
                "staticmethod",
                "classmethod",
                "builtins",
                "__builtins__",
            }
            if (
                isinstance(node, ast.Name)
                and node.id in modeled
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return set()
            if isinstance(node, ast.arg) and node.arg in modeled:
                return set()
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name in modeled
            ):
                return set()
            if isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                (alias.asname or alias.name.split(".")[0]) in modeled
                for alias in node.names
            ):
                return set()
            if isinstance(
                node, (ast.AsyncFunctionDef, ast.Yield, ast.YieldFrom, ast.Lambda)
            ):
                return set()
            if isinstance(node, ast.Call) and (
                any(isinstance(a, ast.Starred) for a in node.args)
                or any(k.arg is None for k in node.keywords)
            ):
                return set()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                default is not None and not isinstance(default, ast.Constant)
                for default in [*node.args.defaults, *node.args.kw_defaults]
            ):
                return set()
            if isinstance(node, ast.AnnAssign):
                return set()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                args += [
                    arg
                    for arg in (node.args.vararg, node.args.kwarg)
                    if arg is not None
                ]
                if node.returns is not None or any(
                    arg.annotation is not None for arg in args
                ):
                    return set()
            if isinstance(node, ast.ClassDef):
                if node.decorator_list or node.keywords:
                    return set()
                if any(
                    not isinstance(
                        member, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass)
                    )
                    and not (
                        isinstance(member, ast.Expr)
                        and isinstance(member.value, ast.Constant)
                        and isinstance(member.value.value, str)
                    )
                    for member in node.body
                ):
                    return set()
                if any(
                    isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and (
                        member.decorator_list
                        or member.name.startswith("__")
                        and member.name.endswith("__")
                        and member.name != "__init__"
                    )
                    for member in node.body
                ):
                    return set()
    explicit_roots = {
        "package_entrypoint",
        "test_entrypoint",
        "trace_hit",
        "coverage_hit",
    }
    if any(
        explicit_roots.intersection(getattr(d, "heuristic_refs", {}))
        for d in definitions.values()
    ):
        return set()
    # Restrict negative proof to actual type-key lookup syntax, not ordinary
    # registration libraries whose external caller set is deliberately open.
    if not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "type"
        for p in parsed
        for n in ast.walk(p.tree)
    ):
        return set()
    proof = _ClosedProof(definitions, parsed)
    result = proof.collect()
    if not result.complete or not proof.lookup_count:
        return set()
    instantiated_classes = [
        f
        for m in proof.modules.values()
        for f in m.frame.values.values()
        if isinstance(f, _Class) and id(f) in proof.instances
    ]
    candidate_locations = set(proof.registered)
    # Registration methods and their returned closures can themselves become
    # dead when a source-owned instance replaces the method before first use.
    for cls in instantiated_classes:
        for function in cls.attrs.values():
            if not isinstance(function, _Function):
                continue
            node = function.node
            if any(
                isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store)
                for n in ast.walk(node)
            ):
                filename = proof.modules[function.frame.module].path
                for location in proof.definitions:
                    if (
                        location[0] == filename
                        and node.lineno <= location[1] <= node.end_lineno
                    ):
                        candidate_locations.add(location)
    for function in proof.functions:
        if id(function.node) in proof.closed_owners:
            filename = proof.modules[function.frame.module].path
            for location in proof.definitions:
                if (
                    location[0] == filename
                    and function.node.lineno < location[1] <= function.node.end_lineno
                ):
                    candidate_locations.add(location)
    invoked = {
        (str(Path(f.definition.filename).resolve()), f.definition.line)
        for f in proof.functions
        if id(f) in proof.invoked and f.definition is not None
    }
    protected = {
        "package_entrypoint",
        "test_entrypoint",
        "trace_hit",
        "coverage_hit",
    }
    return {
        key
        for key, d in definitions.items()
        if (str(Path(d.filename).resolve()), d.line) in candidate_locations - invoked
        and d.type in {"function", "method"}
        and not getattr(d, "is_exported", False)
        and not protected.intersection(getattr(d, "heuristic_refs", {}))
    }


def apply_closed_registry_proof(definitions, keys):
    """Replace source-registration hints only after the complete closed proof."""
    for key in keys:
        definition = definitions.get(key)
        if definition is None:
            continue
        definition.references = 0
        for name in (
            "framework_root",
            "reachable_from_root",
            "unresolved_receiver",
            "unresolved_callback",
            "dead_code_liveness:registered_by_decorator",
            "grep_verify",
        ):
            definition.heuristic_refs.pop(name, None)
        definition.heuristic_refs["closed_type_registry_unused"] = 1.0
        definition.heuristic_refs["unreachable_group"] = 1.0
        definition.framework_signals[:] = [
            s
            for s in definition.framework_signals
            if s not in {"framework_decorator", "registered_by_decorator"}
        ]
        if not getattr(definition, "skip_reason", None):
            definition.confidence = max(80, definition.confidence)
