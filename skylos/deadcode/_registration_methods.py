"""Bound receiver methods used as callback registration decorators."""

from __future__ import annotations
import ast
from pathlib import Path
from typing import Any, Sequence
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _resolved,
    _is_signature_stub,
    _is_static,
)
from skylos.deadcode._registration_flow import _method_index, _RegistrationFlow
from skylos.deadcode._registration_receivers import _RegistrationReceivers


def find_method_registered_targets(
    definitions: dict[str, Any],
    parsed_files: Sequence[ParsedPythonFile],
) -> list[Any]:
    method_index = _method_index(parsed_files)
    if not method_index:
        return []
    flow = _RegistrationFlow(method_index)
    receivers = _RegistrationReceivers(definitions, parsed_files)
    verdicts: dict[tuple[int, int], bool] = {}

    def registering(owner, name: str, binding: str) -> bool:
        scope = receivers.method_scope(owner)
        if scope is None:
            return False
        candidates = []
        for method in scope.class_methods.get(name, ()):
            if not _is_signature_stub(method):
                candidates.append(method)
        if not candidates:
            return False
        for method in candidates:
            if binding == "class" and not _is_static(method):
                is_classmethod = False
                for decorator in method.decorator_list:
                    if (
                        isinstance(decorator, ast.Name)
                        and decorator.id == "classmethod"
                    ):
                        is_classmethod = True
                        break
                if not is_classmethod:
                    return False
            key = id(method), id(scope)
            if key not in verdicts:
                params = []
                for arg in (*method.args.posonlyargs, *method.args.args):
                    params.append(arg.arg)
                if _is_static(method):
                    position = 0
                else:
                    position = 1
                verdicts[key] = position < len(params) and flow.registers(
                    method, params[position], scope
                )
            if not verdicts[key]:
                return False
        return True

    def registering_factory(owner, name: str, binding: str) -> bool:
        # ``@table.accepts(str)``: the method returns a nested function that
        # stores its first parameter. Proven from the body, not the name.
        scope = receivers.method_scope(owner)
        if scope is None:
            return False
        candidates = [
            method
            for method in scope.class_methods.get(name, ())
            if not _is_signature_stub(method)
        ]
        if not candidates:
            return False
        for method in candidates:
            is_classmethod = any(
                isinstance(decorator, ast.Name) and decorator.id == "classmethod"
                for decorator in method.decorator_list
            )
            if binding == "class" and not _is_static(method) and not is_classmethod:
                return False
            key = id(method), id(scope), "factory"
            if key not in verdicts:
                verdicts[key] = _returns_registering_closure(method, scope, flow)
            if not verdicts[key]:
                return False
        return True

    resolved_files: dict[Path, str] = {}
    defs_by_line: dict[tuple[str, int], Any] = {}
    for defn in definitions.values():
        if getattr(defn, "type", None) not in {"function", "method"}:
            continue
        try:
            path = Path(getattr(defn, "filename", ""))
            line = int(getattr(defn, "line", 0) or 0)
        except (TypeError, ValueError):
            continue
        defs_by_line.setdefault((_resolved(path, resolved_files), line), defn)

    targets: list[Any] = []
    seen: set[int] = set()
    for parsed in parsed_files:
        file_key = None
        for node in ast.walk(parsed.tree):
            if not isinstance(node, _FUNCTION_NODES):
                continue
            for decorator in node.decorator_list:
                factory = isinstance(decorator, ast.Call)
                member = decorator.func if factory else decorator
                if not isinstance(member, ast.Attribute):
                    continue
                receivers.prepare(parsed)
                receiver = receivers.resolve(member.value, receivers.context(node))
                check = registering_factory if factory else registering
                if (
                    receiver is None
                    or receiver[1] not in {"class", "instance"}
                    or receivers.member_rebound(
                        member.value,
                        receiver[0],
                        member.attr,
                        receivers.context(node),
                        instance=receiver[1] == "instance",
                    )
                    or not check(receiver[0], member.attr, receiver[1])
                ):
                    continue
                if file_key is None:
                    file_key = _resolved(parsed.path, resolved_files)
                defn = defs_by_line.get((file_key, node.lineno))
                if defn is not None and id(defn) not in seen:
                    seen.add(id(defn))
                    targets.append(defn)
                break
    return targets


def _returns_registering_closure(method, scope, flow: _RegistrationFlow) -> bool:
    """Whether every return hands back a nested function that stores its argument."""
    nested = {
        statement.name: statement
        for statement in method.body
        if isinstance(statement, _FUNCTION_NODES)
    }
    returned = [node.value for node in _own_returns(method)]
    if not returned:
        return False
    for value in returned:
        if not (isinstance(value, ast.Name) and value.id in nested):
            return False
        inner = nested[value.id]
        params = [arg.arg for arg in (*inner.args.posonlyargs, *inner.args.args)]
        if not params or not flow.registers(inner, params[0], scope):
            return False
    return True


def _own_returns(function):
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            yield node
            continue
        if isinstance(node, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))
