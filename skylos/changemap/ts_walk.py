from __future__ import annotations

from dataclasses import dataclass, field

from skylos.changemap.ts_guards import status_guard, throw_facts
from skylos.changemap.ts_nodes import ARGUMENTS, CALL, CONSTRUCTOR, FUNCTION, IDENTIFIER, MEMBER, NEW, OBJECT, PROPERTY

_RISKY_ATTRIBUTES = frozenset({"dangerouslySetInnerHTML"})
_SKIP_NESTED = frozenset({"class_declaration", "class"})
_RISKY_GLOBALS = frozenset({"eval", "Function"})
_JSX_ELEMENTS = frozenset({"jsx_opening_element", "jsx_self_closing_element"})


@dataclass
class Scope:
    module: str
    class_name: str | None
    names: dict[str, str]
    namespaces: dict[str, str]
    locals_typed: dict[str, str]
    base_class: str | None
    text: object
    own_members: frozenset = frozenset()


@dataclass
class BodyFacts:
    calls: set[str] = field(default_factory=set)
    sites: dict[str, int] = field(default_factory=dict)
    shapes: dict[str, list[tuple[int, bool]]] = field(default_factory=dict)
    unresolved: list[tuple[str, int]] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    reads: set[str] = field(default_factory=set)


def _line(node) -> int:
    return node.start_point[0] + 1


def _argument_shape(arguments) -> tuple[int, bool]:
    if arguments is None:
        return 0, False
    items = [c for c in arguments.named_children if c.type != "comment"]
    return len(items), any(c.type == "spread_element" for c in items)


def resolve_name(name: str, scope: Scope, local_tops: set[str]) -> str | None:
    if name in scope.names:
        return scope.names[name]
    if name in local_tops:
        return f"{scope.module}.{name}"
    return None


class _Walk:
    def __init__(self, scope: Scope, local_tops: set[str], security_named):
        self.scope = scope
        self.tops = local_tops
        self.security_named = security_named
        self.facts = BodyFacts()
        self.text = scope.text

    def record(self, target: str | None, node, arguments) -> None:
        if not target:
            return
        facts = self.facts
        facts.calls.add(target)
        line = _line(node)
        if target not in facts.sites or line < facts.sites[target]:
            facts.sites[target] = line
        facts.shapes.setdefault(target, []).append(_argument_shape(arguments))

    def resolve(self, name: str) -> str | None:
        return resolve_name(name, self.scope, self.tops)

    def this_target(self, obj, prop: str) -> str | None:
        scope = self.scope
        if not scope.class_name:
            return None
        if scope.base_class and prop not in scope.own_members:
            return f"{scope.base_class}.{prop}"
        return f"{scope.module}.{scope.class_name}.{prop}"

    def super_target(self, obj, prop: str) -> str | None:
        if self.scope.base_class:
            return f"{self.scope.base_class}.{prop}"
        return None

    def new_target(self, obj, prop: str) -> str | None:
        cls = obj.child_by_field_name(CONSTRUCTOR)
        if cls is None or cls.type != IDENTIFIER:
            return None
        resolved = self.resolve(self.text(cls))
        if resolved:
            return f"{resolved}.{prop}"
        return None

    def identifier_target(self, obj, prop: str) -> str | None:
        name = self.text(obj)
        scope = self.scope
        if name in scope.namespaces:
            return f"{scope.namespaces[name]}.{prop}"
        if name in scope.locals_typed:
            return f"{scope.locals_typed[name]}.{prop}"
        resolved = self.resolve(name)
        if resolved:
            return f"{resolved.removesuffix('.default')}.{prop}"
        return None

    def member_target(self, obj, prop: str) -> str | None:
        handlers = {
            "this": self.this_target, "super": self.super_target,
            NEW: self.new_target, IDENTIFIER: self.identifier_target,
        }
        handler = handlers.get(obj.type)
        if handler is None:
            return None
        return handler(obj, prop)

    def identifier_call(self, node, func, arguments) -> None:
        name = self.text(func)
        resolved = self.resolve(name)
        if resolved is None and (name in _RISKY_GLOBALS or self.security_named(name)):
            resolved = name
        self.record(resolved, node, arguments)

    def member_call(self, node, func, arguments) -> None:
        prop_node = func.child_by_field_name(PROPERTY)
        obj = func.child_by_field_name(OBJECT)
        if prop_node is None or obj is None:
            return
        prop = self.text(prop_node)
        target = self.member_target(obj, prop)
        if target:
            self.record(target, node, arguments)
            return
        self.facts.unresolved.append((prop, _line(node)))
        if self.security_named(prop):
            self.record(f"{self.text(obj)}.{prop}", node, arguments)

    def call(self, node) -> None:
        func = node.child_by_field_name(FUNCTION)
        arguments = node.child_by_field_name(ARGUMENTS)
        if func is None:
            return
        if func.type == IDENTIFIER:
            self.identifier_call(node, func, arguments)
        elif func.type == MEMBER:
            self.member_call(node, func, arguments)
        self.status_guard(node)

    def new(self, node) -> None:
        cls = node.child_by_field_name(CONSTRUCTOR)
        if cls is not None and cls.type == IDENTIFIER:
            name = self.text(cls)
            resolved = self.resolve(name)
            if resolved is None and name in _RISKY_GLOBALS:
                resolved = name
            self.record(resolved, node, node.child_by_field_name(ARGUMENTS))
        self.status_guard(node)

    def jsx(self, node) -> None:
        name = node.child_by_field_name("name")
        if name is not None and name.type == IDENTIFIER and self.text(name)[:1].isupper():
            self.record(self.resolve(self.text(name)), node, None)

    def status_guard(self, node) -> None:
        guard = status_guard(node, self.text)
        if guard:
            self.facts.guards.append(guard)

    def throw(self, node) -> None:
        rejection, guard = throw_facts(node, self.text)
        if rejection:
            self.facts.rejections.append(rejection)
        if guard:
            self.facts.guards.append(guard)

    def read(self, node) -> None:
        self.facts.reads.add(self.text(node))

    def member_read(self, node) -> None:
        obj = node.child_by_field_name(OBJECT)
        prop = node.child_by_field_name(PROPERTY)
        if obj is not None and prop is not None and obj.type == "this":
            self.facts.reads.add("this." + self.text(prop))

    def attribute(self, node) -> None:
        if self.text(node).split("=", 1)[0].strip() in _RISKY_ATTRIBUTES:
            self.record("dangerouslySetInnerHTML", node, None)

    def handlers(self) -> dict:
        table = {
            CALL: self.call, NEW: self.new, "throw_statement": self.throw, IDENTIFIER: self.read,
            MEMBER: self.member_read, "jsx_attribute": self.attribute,
        }
        for kind in _JSX_ELEMENTS:
            table[kind] = self.jsx
        return table


def walk_body(body, scope: Scope, local_tops: set[str], security_named) -> BodyFacts:
    walk = _Walk(scope, local_tops, security_named)
    if body is None:
        return walk.facts
    table = walk.handlers()
    stack = [body]
    while stack:
        node = stack.pop()
        handler = table.get(node.type)
        if handler is not None:
            handler(node)
        stack.extend(c for c in node.children if c.type not in _SKIP_NESTED)
    walk.facts.guards.sort()
    return walk.facts
