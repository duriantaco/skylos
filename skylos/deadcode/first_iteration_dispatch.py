"""Exclude private literal backend tails behind an unconditional first return.

Only implicit string-name evidence is removed. Extra opaque lookups, escaped
record fields, mutations and ambiguous producers leave existing evidence intact.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.deadcode._registration_common import _FUNCTION_NODES
from skylos.deadcode._registration_receivers import _RegistrationReceivers
from skylos.deadcode.python_ast import parse_python_files


def proven_unselected_method_strings(definitions):
    paths = {
        Path(d.filename)
        for d in definitions.values()
        if str(d.filename).endswith(".py")
    }
    parsed = parse_python_files(paths)
    receivers = _RegistrationReceivers(definitions, parsed)
    for source in parsed:
        receivers.prepare(source)
    parents = receivers.parents
    for source in parsed:
        for node in ast.walk(source.tree):
            if isinstance(node, _FUNCTION_NODES) and node.name in {
                "__getattr__",
                "__getattribute__",
            }:
                return set()
            if isinstance(node, ast.Attribute) and node.attr in {
                "getattr",
                "__getattribute__",
                "__dict__",
            }:
                return set()
            if isinstance(node, ast.Name) and node.id == "getattr":
                parent = parents.get(node)
                if not isinstance(parent, ast.Call) or parent.func is not node:
                    return set()
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"vars", "dir"}
            ):
                return set()
    lookups = [
        n
        for source in parsed
        for n in ast.walk(source.tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "getattr"
    ]
    if len(lookups) != 1:
        return set()
    lookup = lookups[0]
    if (
        len(lookup.args) != 2
        or lookup.keywords
        or not all(isinstance(arg, ast.Name) for arg in lookup.args)
        or receivers._lookup("getattr", receivers.context(lookup))[1] is not None
    ):
        return set()
    invocation = parents.get(lookup)
    returned = parents.get(invocation)
    loop = parents.get(returned)
    if not (
        isinstance(invocation, ast.Call)
        and invocation.func is lookup
        and isinstance(returned, ast.Return)
        and isinstance(loop, ast.For)
        and loop.body == [returned]
        and not loop.orelse
        and isinstance(loop.iter, ast.Attribute)
        and isinstance(loop.iter.value, ast.Name)
        and isinstance(loop.target, (ast.Tuple, ast.List))
        and len(loop.target.elts) == 2
        and all(isinstance(item, ast.Name) for item in loop.target.elts)
        and loop.target.elts[1].id == lookup.args[1].id
    ):
        return set()
    current, outer = parents.get(loop), None
    while current is not None and not isinstance(current, _FUNCTION_NODES):
        if (
            isinstance(current, ast.For)
            and isinstance(current.target, ast.Name)
            and current.target.id == loop.iter.value.id
        ):
            outer = current
            break
        current = parents.get(current)
    if not (
        outer
        and isinstance(outer.iter, ast.Attribute)
        and isinstance(outer.iter.value, ast.Name)
        and outer.iter.value.id == lookup.args[0].id
    ):
        return set()
    field, property_name = loop.iter.attr, outer.iter.attr
    for statement in outer.body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and node.id == outer.target.id:
                parent = parents.get(node)
                if not (
                    isinstance(node.ctx, ast.Load)
                    and isinstance(parent, ast.Attribute)
                    and parent.value is node
                ):
                    return set()
    producers = []
    for source in parsed:
        for owner in ast.walk(source.tree):
            if not isinstance(owner, ast.ClassDef):
                continue
            for method in owner.body:
                if (
                    not isinstance(method, _FUNCTION_NODES)
                    or method.name != property_name
                ):
                    continue
                if (
                    len(method.decorator_list) != 1
                    or not isinstance(method.decorator_list[0], ast.Name)
                    or method.decorator_list[0].id != "property"
                    or receivers._lookup("property", receivers.context(method))[1]
                    is not None
                    or len(method.body) != 1
                    or not isinstance(method.body[0], ast.Return)
                    or not isinstance(method.body[0].value, (ast.Tuple, ast.List))
                ):
                    return set()
                producers.append((source, owner, method, method.body[0].value.elts))
    if len(producers) != 1:
        return set()
    source, owner, method, items = producers[0]
    if any(
        isinstance(n, _FUNCTION_NODES) and n.name in {"__getattribute__", "__getattr__"}
        for n in owner.body
    ):
        return set()
    kept, tail = set(), set()
    constructor, field_write = None, None
    for item in items:
        if not isinstance(item, ast.Call) or item.keywords:
            return set()
        target = receivers.resolve(item.func, receivers.context(method))
        if (
            not target
            or target[1] != "class"
            or constructor is not None
            and target[0] is not constructor
        ):
            return set()
        constructor = target[0]
        initializers = [
            n
            for n in constructor.body
            if isinstance(n, _FUNCTION_NODES) and n.name == "__init__"
        ]
        if len(initializers) != 1 or len(constructor.body) != 1:
            return set()
        init = initializers[0]
        args = [*init.args.posonlyargs, *init.args.args]
        field_parameter = None
        for statement in init.body:
            if not (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Attribute)
                and isinstance(statement.targets[0].value, ast.Name)
                and args
                and statement.targets[0].value.id == args[0].arg
                and isinstance(statement.value, ast.Name)
            ):
                return set()
            if statement.targets[0].attr == field:
                if field_write is not None and field_write is not statement.targets[0]:
                    return set()
                field_write = statement.targets[0]
                field_parameter = statement.value.id
        position = next(
            (i - 1 for i, arg in enumerate(args) if arg.arg == field_parameter), None
        )
        if position is None or not 0 <= position < len(item.args):
            return set()
        rows = item.args[position]
        if not isinstance(rows, (ast.Tuple, ast.List)) or not rows.elts:
            return set()
        for i, row in enumerate(rows.elts):
            if not (
                isinstance(row, (ast.Tuple, ast.List))
                and len(row.elts) == 2
                and all(
                    isinstance(x, ast.Constant) and isinstance(x.value, str)
                    for x in row.elts
                )
            ):
                return set()
            (kept if i == 0 else tail).add(row.elts[1].value)
    if constructor is None:
        return set()
    for file in parsed:
        for node in ast.walk(file.tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {field, property_name}
                and node not in {loop.iter, outer.iter, field_write}
            ):
                return set()
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr", "exec", "eval"}
            ):
                return set()
    owners = [
        d.name
        for d in definitions.values()
        if getattr(d, "type", None) == "class"
        and str(Path(d.filename).resolve()) == str(source.path.resolve())
        and d.line == owner.lineno
    ]
    if len(owners) != 1:
        return set()
    return {(owners[0], name) for name in tail - kept if name.startswith("_")}
