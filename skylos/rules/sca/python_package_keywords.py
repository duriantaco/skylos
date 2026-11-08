"""Whether a call on a package's function or class takes a keyword, read statically.

A keyword that lands in ``**kwargs`` is followed through the package: a literal
read of it, a forward to another function or class, or a store on ``self`` that a
later call forwards. What cannot be followed is ``PASSTHROUGH``, never a rejection.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from skylos.rules.sca.python_module_reader import (
    FUNCTION_NODES,
    call_name,
    first_parameter,
)

MAX_FORWARD_HOPS = 6
ACCEPTED = "accepted"
REJECTED = "rejected"
PASSTHROUGH = "passthrough"
UNREAD = "unread"
_PLAIN_FUNCTION_DECORATORS = frozenset(
    {
        "abstractmethod",
        "asynccontextmanager",
        "cache",
        "classmethod",
        "contextmanager",
        "deprecated",
        "final",
        "lru_cache",
        "no_type_check",
        "overload",
        "override",
        "singledispatch",
        "singledispatchmethod",
        "staticmethod",
        "type_check_only",
        "wraps",
    }
)
_KEYWORD_METHODS = frozenset({"setdefault", "pop", "get", "update"})


@dataclass(frozen=True)
class Signature:
    named: frozenset[str]
    var_keyword: str | None
    node: Any = None
    module: str = ""
    owner: Any = None
    opaque: bool = False


def signature_of(node: Any, module: str, owner: Any) -> Signature:
    args = node.args
    named = frozenset(item.arg for item in (*args.args, *args.kwonlyargs))
    var_keyword = None
    if args.kwarg is not None:
        var_keyword = args.kwarg.arg
    opaque = any(
        call_name(getattr(decorator, "func", decorator))
        not in _PLAIN_FUNCTION_DECORATORS
        for decorator in node.decorator_list
    )
    return Signature(named, var_keyword, node, module, owner, opaque)


def _combined(statuses: set[str]) -> str:
    if ACCEPTED in statuses:
        return ACCEPTED
    if UNREAD in statuses or not statuses:
        return UNREAD
    if PASSTHROUGH in statuses:
        return PASSTHROUGH
    return REJECTED


def _mentions(node: ast.AST, text: str) -> bool:
    return any(
        isinstance(item, ast.Constant) and item.value == text for item in ast.walk(node)
    )


def _is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def _forwarded_name(call: ast.Call, name: str) -> ast.Name | None:
    for keyword in call.keywords:
        if keyword.arg is None and _is_name(keyword.value, name):
            return keyword.value
    return None


def _stored_attributes(node: ast.Assign, name: str, first: str) -> list[str]:
    if not _is_name(node.value, name):
        return []
    return [
        target.attr
        for target in node.targets
        if isinstance(target, ast.Attribute) and _is_name(target.value, first)
    ]


def _harmless_read(node: ast.AST, name: str) -> ast.AST | None:
    """The ``name`` node of a use that cannot pass the keyword on elsewhere."""
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _KEYWORD_METHODS
            and _is_name(func.value, name)
        ):
            return func.value
    elif isinstance(node, ast.Subscript) and _is_name(node.value, name):
        return node.value
    return None


def _var_keyword_uses(
    node: ast.AST, name: str
) -> tuple[list[ast.Call], list[str], bool]:
    """(calls forwarding ``**name``, ``self`` attributes it is stored in, any
    other use a static read cannot follow)."""
    forwards: list[ast.Call] = []
    stored: list[str] = []
    harmless: set[int] = set()
    first = first_parameter(node)
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            forwarded = _forwarded_name(item, name)
            if forwarded is not None:
                forwards.append(item)
                harmless.add(id(forwarded))
        elif isinstance(item, ast.Assign):
            attributes = _stored_attributes(item, name, first)
            if attributes:
                stored.extend(attributes)
                harmless.add(id(item.value))
        elif isinstance(item, ast.Compare):
            harmless.update(id(part) for part in item.comparators if _is_name(part, name))
        read = _harmless_read(item, name)
        if read is not None:
            harmless.add(id(read))
    other = any(
        _is_name(item, name) and id(item) not in harmless for item in ast.walk(node)
    )
    return forwards, stored, other


def _stored_forwards(node: ast.AST, first: str, attribute: str) -> list[ast.Call]:
    calls = []
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        for keyword in item.keywords:
            value = keyword.value
            if (
                keyword.arg is None
                and isinstance(value, ast.Attribute)
                and value.attr == attribute
                and _is_name(value.value, first)
            ):
                calls.append(item)
    return calls


class KeywordReader:
    """Answers one surface's keyword questions; ``surface`` resolves names."""

    def __init__(self, surface: Any):
        self.surface = surface

    def status(
        self,
        targets: Iterable[Any],
        keyword: str,
        depth: int = 0,
        seen: frozenset = frozenset(),
    ) -> str:
        statuses: set[str] = set()
        for target in targets:
            signatures = self.surface.signatures(target)
            if signatures is None:
                statuses.add(UNREAD)
                continue
            for signature in signatures:
                statuses.add(self._signature_status(signature, keyword, depth, seen))
        return _combined(statuses)

    def _signature_status(
        self, signature: Signature, keyword: str, depth: int, seen: frozenset
    ) -> str:
        if keyword in signature.named:
            return ACCEPTED
        if signature.opaque:
            return UNREAD
        if signature.var_keyword is None:
            return REJECTED
        return self._forward_status(signature, keyword, depth, seen)

    def _forward_status(
        self, signature: Signature, keyword: str, depth: int, seen: frozenset
    ) -> str:
        node = signature.node
        if depth >= MAX_FORWARD_HOPS or id(node) in seen or node is None:
            return PASSTHROUGH
        if _mentions(node, keyword):
            return ACCEPTED
        seen = seen | {id(node)}
        forwards, stored, other = _var_keyword_uses(node, signature.var_keyword)
        if other:
            return PASSTHROUGH
        if not forwards and not stored:
            return ACCEPTED
        statuses = {
            self._call_status(call, signature, keyword, depth + 1, seen)
            for call in forwards
        }
        for attribute in stored:
            statuses.add(
                self._stored_status(attribute, signature, keyword, depth + 1, seen)
            )
        return _combined(statuses)

    def _call_status(
        self,
        call: ast.Call,
        signature: Signature,
        keyword: str,
        depth: int,
        seen: frozenset,
    ) -> str:
        targets = self._call_targets(call.func, signature)
        if not targets:
            return PASSTHROUGH
        status = self.status(targets, keyword, depth, seen)
        if status == UNREAD:
            return PASSTHROUGH
        return status

    def _call_targets(self, func: ast.expr, signature: Signature) -> list[Any]:
        owner = signature.owner
        if isinstance(func, ast.Attribute) and owner is not None:
            value = func.value
            if isinstance(value, ast.Call) and call_name(value.func) == "super":
                return self.surface.inherited_member(owner, func.attr)
            if _is_name(value, first_parameter(signature.node)):
                result = self.surface.class_member(owner, func.attr)
                return list(result.targets)
        return self.surface.expression_targets(signature.module, func)

    def _stored_status(
        self,
        attribute: str,
        signature: Signature,
        keyword: str,
        depth: int,
        seen: frozenset,
    ) -> str:
        owner = signature.owner
        if owner is None:
            return PASSTHROUGH
        statuses: set[str] = set()
        for current in self.surface.mro(owner):
            if _mentions(current.node, keyword):
                return ACCEPTED
            for method in current.node.body:
                if isinstance(method, FUNCTION_NODES):
                    statuses |= self._method_forward_statuses(
                        method, current, attribute, keyword, depth, seen
                    )
        if not statuses:
            return PASSTHROUGH
        return _combined(statuses)

    def _method_forward_statuses(
        self, method, owner, attribute, keyword, depth, seen
    ) -> set[str]:
        context = signature_of(method, owner.module, owner)
        return {
            self._call_status(call, context, keyword, depth, seen)
            for call in _stored_forwards(method, first_parameter(method), attribute)
        }
