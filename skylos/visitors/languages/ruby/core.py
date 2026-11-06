"""Bounded, syntax-aware Ruby symbols, visibility, and source-visible calls.

Public Ruby APIs are retained. Private methods are candidates only where no
source-visible call or unresolved dispatch could reach them. This is not a
Ruby interpreter, Rails route evaluator, or whole-project type resolver.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from skylos.visitors.base import Definition

try:
    from tree_sitter import Language, Parser
    import tree_sitter_ruby
except ImportError:  # Reported by the adapter, never treated as a clean scan.
    Language = Parser = tree_sitter_ruby = None


def parse(source: bytes):
    if tree_sitter_ruby is None or Language is None or Parser is None:
        return None
    return Parser(Language(tree_sitter_ruby.language())).parse(source).root_node


def descendants(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


@dataclass
class Scope:
    body: object
    owner: str = ""
    singleton: bool = False
    method: str = ""
    locals: set[str] = field(default_factory=set)
    bindings: dict[str, str] = field(default_factory=dict)


class RubyCore:
    def __init__(self, file_path: str, source: bytes):
        self.file_path = file_path
        self.source = source
        self.root_node = parse(source)
        self.defs = []
        self.refs = []
        self.raw_imports = []
        self.scopes = []
        self.classes = {}
        self.base_nodes = {}
        self.methods = {}
        self.dynamic_dispatch = []
        self.rails_classes = set()
        self._referenced = set()

    def text(self, node):
        return (
            self.source[node.start_byte : node.end_byte].decode("utf-8") if node else ""
        )

    def method_name(self, owner, name, singleton=False):
        return f"{owner}{'.' if singleton else '#'}{name}" if owner else name

    def _class_name(self, node, owner):
        name = self.text(node).removeprefix("::").replace("::", ".")
        if self.text(node).startswith("::") or "." in name or not owner:
            return name
        return f"{owner}.{name}"

    def _add_method(self, node, owner, singleton, visibility):
        name = self.text(node.child_by_field_name("name"))
        if node.type == "singleton_method":
            receiver = node.named_children[0]
            if self.text(receiver) != "self":
                owner = self.text(receiver).replace("::", ".")
            singleton = True
        canonical = self.method_name(owner, name, singleton)
        definition = Definition(
            canonical,
            "method" if owner else "function",
            self.file_path,
            node.start_point[0] + 1,
        )
        definition.simple_name = definition.binding_name = name
        definition.is_exported = bool(
            owner and visibility != "private" and name != "initialize"
        )
        self.defs.append(definition)
        self.methods.setdefault(canonical, []).append(definition)
        body = node.child_by_field_name("body")
        scope = Scope(body, owner, singleton, canonical)
        parameters = node.child_by_field_name("parameters")
        if parameters:
            scope.locals.update(
                self.text(n) for n in descendants(parameters) if n.type == "identifier"
            )
        self.scopes.append(scope)

    def _collect(self, body, owner="", singleton=False):
        if body is None:
            return
        self.scopes.append(Scope(body, owner, bool(owner) or singleton))
        visibility = "public"
        updates = []
        for node in body.named_children:
            if node.type in {"class", "module"}:
                name = self._class_name(node.child_by_field_name("name"), owner)
                definition = Definition(
                    name, "class", self.file_path, node.start_point[0] + 1
                )
                definition.is_exported = True
                superclass = node.child_by_field_name("superclass")
                if superclass and superclass.named_children:
                    self.base_nodes[name] = superclass.named_children[0]
                    definition.base_classes = [
                        self.text(superclass.named_children[0])
                        .removeprefix("::")
                        .replace("::", ".")
                    ]
                self.defs.append(definition)
                self.classes[name] = definition
                self._collect(node.child_by_field_name("body"), name)
            elif node.type in {"method", "singleton_method"}:
                self._add_method(node, owner, singleton, visibility)
            elif (
                node.type == "singleton_class"
                and self.text(node.child_by_field_name("value")) == "self"
            ):
                self._collect(node.child_by_field_name("body"), owner, True)
            elif node.type == "identifier" and self.text(node) in {
                "private",
                "protected",
                "public",
            }:
                visibility = self.text(node)
            elif node.type == "call":
                method = self.text(node.child_by_field_name("method"))
                args = node.child_by_field_name("arguments")
                receiver = node.child_by_field_name("receiver")
                if (
                    receiver is None
                    and method
                    in {
                        "private",
                        "protected",
                        "public",
                        "private_class_method",
                        "public_class_method",
                    }
                    and args
                ):
                    for arg in args.named_children:
                        if arg.type in {"method", "singleton_method"}:
                            self._add_method(arg, owner, singleton, method)
                        elif arg.type == "simple_symbol":
                            updates.append((self.text(arg)[1:], method))
        for name, mode in updates:
            canonical = self.method_name(
                owner, name, singleton or mode.endswith("class_method")
            )
            for definition in self.methods.get(canonical, []):
                definition.is_exported = not mode.startswith("private")

    def _constant(self, node, scope):
        if node is None or node.type not in {"constant", "scope_resolution"}:
            return ""
        value = self.text(node).removeprefix("::").replace("::", ".")
        if self.text(node).startswith("::"):
            return value
        parts = scope.owner.split(".")
        for size in range(len(parts), -1, -1):
            candidate = ".".join([*parts[:size], value])
            if candidate in self.classes:
                return candidate
        return value

    def _receiver(self, node, scope):
        if node is None or node.type == "self":
            return scope.owner, scope.singleton
        if node.type in {"constant", "scope_resolution"}:
            return self._constant(node, scope), True
        if node.type == "identifier":
            return scope.bindings.get(self.text(node), ""), False
        if (
            node.type == "call"
            and self.text(node.child_by_field_name("method")) == "new"
        ):
            return self._constant(node.child_by_field_name("receiver"), scope), False
        return "", False

    def _ref(self, name, scope=None):
        definitions = self.methods.get(name, [])
        if name not in self.classes and not definitions:
            return
        if scope and scope.method == name:
            return  # Recursion alone does not establish an entrypoint.
        if name not in self._referenced:
            self.refs.append((name, self.file_path))
            self._referenced.add(name)
        if scope and scope.method and scope.method != name:
            for caller in self.methods.get(scope.method, []):
                caller.calls.add(name)
            for definition in definitions:
                definition.called_by.add(scope.method)

    def _resolve_call(self, owner, method, singleton, scope, visited=None):
        visited = set() if visited is None else visited
        if owner in visited:
            return False
        visited.add(owner)
        canonical = self.method_name(owner, method, singleton)
        if canonical in self.methods:
            self._ref(canonical, scope)
            return True
        definition = self.classes.get(owner)
        if definition:
            for base in definition.base_classes:
                if self._resolve_call(base, method, singleton, scope, visited):
                    return True
        return False

    def _global_call(self, name, scope):
        # A bare Ruby call may target Object's private top-level methods in
        # another required source file. Keep the actual call spelling, never
        # a string/symbol or a same-named receiver method.
        if name in self.methods:
            self._ref(name, scope)
        elif name not in self._referenced:
            self.refs.append((name, self.file_path))
            self._referenced.add(name)

    def _uncertain(self, owner, scope, node, reason, method=""):
        self.dynamic_dispatch.append(
            {"line": node.start_point[0] + 1, "reason": reason}
        )
        for name, definitions in self.methods.items():
            matches_owner = (
                not owner
                or name.startswith(owner + "#")
                or name.startswith(owner + ".")
            )
            if matches_owner and (not method or definitions[0].simple_name == method):
                self._ref(name, scope)
                for definition in definitions:
                    if reason not in definition.dynamic_signals:
                        definition.dynamic_signals.append(reason)

    def _prepare_locals(self, scope):
        if scope.body is None:
            return
        assignments = []
        pending = [scope.body]
        while pending:
            node = pending.pop()
            if node is not scope.body and node.type in {
                "method",
                "singleton_method",
                "class",
                "module",
                "singleton_class",
            }:
                continue
            if node.type in {"assignment", "operator_assignment"}:
                left = node.child_by_field_name("left")
                if left and left.type == "identifier":
                    name = self.text(left)
                    scope.locals.add(name)
                    assignments.append((name, node.child_by_field_name("right")))
            if node.type in {"block_parameters", "lambda_parameters"}:
                scope.locals.update(
                    self.text(n) for n in descendants(node) if n.type == "identifier"
                )
            pending.extend(node.named_children)
        counts = Counter(name for name, _ in assignments)
        for name, right in assignments:
            if counts[name] == 1:
                owner, singleton = self._receiver(right, scope)
                if owner and not singleton:
                    scope.bindings[name] = owner

    def _walk(self, node, scope):
        if node is None or (
            node is not scope.body
            and node.type
            in {"class", "module", "method", "singleton_method", "singleton_class"}
        ):
            return
        if node.type in {"constant", "scope_resolution"}:
            self._ref(self._constant(node, scope), scope)
            if node.type == "scope_resolution":
                return
        elif node.type == "identifier":
            name = self.text(node)
            if name not in scope.locals and name not in {
                "private",
                "protected",
                "public",
            }:
                if not self._resolve_call(scope.owner, name, scope.singleton, scope):
                    self._global_call(name, scope)
            return
        elif node.type == "call":
            method_node = node.child_by_field_name("method")
            method = self.text(method_node)
            receiver = node.child_by_field_name("receiver")
            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            owner, singleton = self._receiver(receiver, scope)
            if method == "new" and receiver is not None:
                self._ref(owner, scope)
                if not self._resolve_call(owner, "new", True, scope):
                    self._resolve_call(owner, "initialize", False, scope)
            else:
                resolved = self._resolve_call(owner, method, singleton, scope)
                if receiver is None and not resolved:
                    self._global_call(method, scope)
                if receiver is not None and not owner and not resolved:
                    self._uncertain("", scope, node, "unresolved Ruby receiver", method)
            if method in {"send", "public_send", "method"}:
                selector = args[0] if args else None
                if selector and selector.type in {"simple_symbol", "string"}:
                    value = (
                        self.text(selector)[1:]
                        if selector.type == "simple_symbol"
                        else self.literal_string(selector)
                    )
                    if value:
                        self._resolve_call(owner, value, singleton, scope)
                    else:
                        self._uncertain(
                            owner, scope, node, "dynamic Ruby method selector"
                        )
                else:
                    self._uncertain(owner, scope, node, "dynamic Ruby method selector")
            if method in {
                "eval",
                "instance_eval",
                "class_eval",
                "module_eval",
                "include",
                "prepend",
                "extend",
                "alias_method",
                "define_method",
            }:
                self._uncertain(
                    owner, scope, node, "Ruby metaprogramming changes dispatch"
                )
            if (
                method
                in {"before_action", "before_filter", "after_action", "around_action"}
                and receiver is None
                and scope.owner in self.rails_classes
                and not scope.method
            ):
                if self.method_name(scope.owner, method, True) not in self.methods:
                    for arg in args:
                        if arg.type == "simple_symbol":
                            self._resolve_call(
                                scope.owner, self.text(arg)[1:], False, scope
                            )
                        elif arg.type not in {"pair", "hash"}:
                            self._uncertain(
                                scope.owner,
                                scope,
                                node,
                                "dynamic Rails callback selector",
                            )
                    block = node.child_by_field_name("block")
                    if block:
                        self._walk(
                            block,
                            Scope(
                                block,
                                scope.owner,
                                False,
                                locals=set(scope.locals),
                                bindings=dict(scope.bindings),
                            ),
                        )
            if (
                method == "action"
                and owner in self.rails_classes
                and args
                and args[0].type == "simple_symbol"
            ):
                self._resolve_call(owner, self.text(args[0])[1:], False, scope)
            if (
                receiver is None
                and method in {"require", "require_relative", "load"}
                and args
            ):
                source = self.literal_string(args[0])
                if source:
                    self.raw_imports.append(
                        {"source": source, "names": [], "line": node.start_point[0] + 1}
                    )
            for child in node.named_children:
                if child != method_node and not (
                    child.type in {"block", "do_block"}
                    and method
                    in {
                        "before_action",
                        "before_filter",
                        "after_action",
                        "around_action",
                    }
                    and scope.owner in self.rails_classes
                ):
                    self._walk(child, scope)
            return
        elif node.type in {"alias", "undef"}:
            self._uncertain(
                scope.owner, scope, node, "Ruby alias or undef changes dispatch"
            )
        for child in node.named_children:
            self._walk(child, scope)

    def literal_string(self, node):
        if (
            node is None
            or node.type != "string"
            or any(n.type != "string_content" for n in node.named_children)
        ):
            return None
        # Escapes/interpolation have runtime semantics; don't invent a value.
        raw = self.text(node)
        return raw[1:-1] if len(raw) >= 2 and "\\" not in raw else None

    def scan(self):
        if self.root_node is None or self.root_node.has_error:
            return
        self._collect(self.root_node)
        for name, node in self.base_nodes.items():
            self.classes[name].base_classes = [
                self._constant(node, Scope(node, name.rpartition(".")[0]))
            ]
        action_controller_shadowed = any(
            n == "ActionController" or n.startswith("ActionController.")
            for n in self.classes
        )
        if not action_controller_shadowed:
            self.rails_classes = {
                name
                for name, definition in self.classes.items()
                if set(definition.base_classes)
                & {"ActionController.Base", "ActionController.API"}
            }
        for scope in self.scopes:
            self._prepare_locals(scope)
            self._walk(scope.body, scope)
        # Reopened definitions cannot be safely removed in isolation.
        for name, definitions in self.methods.items():
            if len(definitions) > 1:
                for definition in definitions:
                    definition.is_exported = True
                    definition.dynamic_signals.append("Ruby method is redefined")
