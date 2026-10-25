from __future__ import annotations

from skylos.changemap.symbols import KIND_CLASS, KIND_METHOD
from skylos.changemap.ts_core import FUNCTION_VALUES, Decl, TsFile, decorator_names, make_scope, make_symbol
from skylos.changemap.ts_nodes import BODY, IDENTIFIER, NAME, VALUE
from skylos.changemap.ts_walk import Scope, resolve_name


def _extends_clauses(node) -> list:
    heritages = [c for c in node.named_children if c.type == "class_heritage"]
    return [clause for h in heritages for clause in h.named_children if clause.type == "extends_clause"]


def _clause_value(clause):
    value = clause.child_by_field_name(VALUE)
    if value is None and clause.named_children:
        value = clause.named_children[0]
    return value


def _extends_identifier(node):
    values = [_clause_value(clause) for clause in _extends_clauses(node)]
    return next((v for v in values if v is not None and v.type == IDENTIFIER), None)


def _class_base(node, file: TsFile, scope: Scope) -> str | None:
    value = _extends_identifier(node)
    if value is None:
        return None
    return resolve_name(file.text(value), scope, file.local_tops)


def _member_function(member):
    if member.type == "method_definition":
        return member
    value = member.child_by_field_name(VALUE)
    if value is not None and value.type in FUNCTION_VALUES:
        return value
    return None


def _member_name(member, file: TsFile) -> str | None:
    name = member.child_by_field_name(NAME) or member.child_by_field_name("property")
    if name is None:
        return None
    return file.text(name)


def _is_getter(member) -> bool:
    return member.type == "method_definition" and any(c.type == "get" for c in member.children)


def _method(file: TsFile, class_name: str, member, pending: list, scope: Scope) -> set[int]:
    decorators = decorator_names(pending, file)
    if _is_getter(member):
        decorators.append("property")
    start = (pending or [member])[0]
    decl = Decl(f"{class_name}.{_member_name(member, file)}", KIND_METHOD, member, start, _member_function(member), decorators)
    make_symbol(file, decl, scope)
    return {n.id for n in pending + [member]}


def _class_members(file: TsFile, class_name: str, body, scope: Scope) -> tuple[set[int], dict[str, str]]:
    skipped: set[int] = set()
    attributes: dict[str, str] = {}
    pending: list = []
    for member in body.named_children:
        if member.type == "decorator":
            pending.append(member)
            continue
        name = _member_name(member, file)
        if name and _member_function(member) is not None:
            skipped |= _method(file, class_name, member, pending, scope)
        elif name and member.child_by_field_name(VALUE) is not None:
            attributes[name] = file.tokens(member.child_by_field_name(VALUE))
        pending = []
    return skipped, attributes


def parse_class(file: TsFile, node, start_node) -> str | None:
    name_node = node.child_by_field_name(NAME)
    if name_node is None:
        return None
    name = file.text(name_node)
    base = _class_base(node, file, make_scope(file))
    body = node.child_by_field_name(BODY)
    members = set()
    skipped, attributes = set(), {}
    if body is not None:
        members = {n for n in (_member_name(m, file) for m in body.named_children) if n}
    scope = make_scope(file, name, base, members)
    if body is not None:
        skipped, attributes = _class_members(file, name, body, scope)
    decorators = decorator_names([c for c in node.children if c.type == "decorator"], file)
    symbol = make_symbol(file, Decl(name, KIND_CLASS, node, start_node, None, decorators), scope)
    symbol.cached_shape = file.tokens(node, frozenset(skipped))
    symbol.attributes = attributes
    return name
