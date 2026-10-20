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
                if not isinstance(decorator, ast.Attribute):
                    continue
                receivers.prepare(parsed)
                receiver = receivers.resolve(decorator.value, receivers.context(node))
                if (
                    receiver is None
                    or receiver[1] not in {"class", "instance"}
                    or receivers.member_rebound(
                        decorator.value,
                        receiver[0],
                        decorator.attr,
                        receivers.context(node),
                        instance=receiver[1] == "instance",
                    )
                    or not registering(receiver[0], decorator.attr, receiver[1])
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
