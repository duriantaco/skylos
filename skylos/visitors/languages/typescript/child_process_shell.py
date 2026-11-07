"""Bounded import and option proofs for Node's optional-shell argv APIs.

The argv APIs are safe by default. A request-taint sink needs a real Node
provider and an effective shell option, including property order in spreads.
This helper resolves values only; the handler analyzer supplies request taint.
"""

from __future__ import annotations

from dataclasses import dataclass, field


_METHODS = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})
_MODULES = frozenset({"child_process", "node:child_process"})
_FUNCTIONS = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
)
_SCOPES = _FUNCTIONS | {
    "program",
    "statement_block",
    "switch_body",
    "for_statement",
    "for_in_statement",
    "catch_clause",
}
_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }
)
_UNKNOWN = object()
_ABSENT = object()
_COLLECTION_LIMIT = 200_000
_QUERY_LIMIT = 20_000


def _unwrap(node):
    while node is not None and node.type in _WRAPPERS:
        node = next(
            (
                c
                for c in node.named_children
                if c.type
                not in {"type_annotation", "predefined_type", "type_identifier"}
            ),
            None,
        )
    return node


def _nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


@dataclass
class _Binding:
    node: object
    value: object = None
    kind: str = "value"
    imported: str = ""
    projection: str = ""
    writes: list = field(default_factory=list)


class ShellProcessCalls:
    def __init__(self, source: bytes, root):
        self.source = source
        self.root = root
        self.bindings: dict[tuple[int, str], list[_Binding]] = {}
        self.assignments = []
        self.member_writes = []
        self.budget = _COLLECTION_LIMIT
        self.complete = True
        for node in _nodes(root):
            if not self._consume():
                break
            self._collect(node)
        for assignment in self.assignments:
            lhs = _unwrap(assignment.child_by_field_name("left"))
            binding = self._lookup(self._text(lhs), assignment)
            if binding is not None:
                binding.writes.append(assignment)
        self.collection_complete = self.complete

    def _consume(self):
        self.budget -= 1
        if self.budget < 0:
            self.complete = False
        return self.budget >= 0

    def _text(self, node):
        return (
            self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")
            if node is not None
            else ""
        )

    def _string(self, node):
        node = _unwrap(node)
        if node is not None and node.type == "string":
            raw = self._text(node)
            if "\\" not in raw:
                return raw[1:-1]
        return None

    def _scope(self, node, function=False):
        current = node.parent
        while current is not None:
            if current.type in (_FUNCTIONS | {"program"} if function else _SCOPES):
                return current
            current = current.parent
        return self.root

    def _bind(self, name, binding, scope=None):
        if name is not None:
            scope = scope or self._scope(name)
            self.bindings.setdefault((scope.id, self._text(name)), []).append(binding)

    def _patterns(self, pattern):
        if pattern is None:
            return []
        if pattern.type in {"identifier", "shorthand_property_identifier_pattern"}:
            return [pattern]
        if pattern.type == "pair_pattern":
            return self._patterns(pattern.child_by_field_name("value"))
        if pattern.type in {"required_parameter", "optional_parameter"}:
            return self._patterns(pattern.child_by_field_name("pattern"))
        if pattern.type in {"assignment_pattern", "object_assignment_pattern"}:
            return self._patterns(pattern.child_by_field_name("left"))
        return [
            name
            for child in pattern.named_children
            if child.type != "type_annotation"
            for name in self._patterns(child)
        ]

    def _collect(self, node):
        if node.type == "import_statement":
            module = self._string(node.child_by_field_name("source"))
            for child in _nodes(node):
                if child.type == "import_specifier":
                    name = child.child_by_field_name("name")
                    local = child.child_by_field_name("alias") or name
                    self._bind(
                        local,
                        _Binding(
                            local,
                            kind="import",
                            imported=self._text(name) if module in _MODULES else "",
                        ),
                    )
                elif child.type in {"namespace_import", "import_clause"}:
                    for local in child.named_children:
                        if local.type == "identifier":
                            self._bind(
                                local,
                                _Binding(
                                    local,
                                    kind="import",
                                    imported="*" if module in _MODULES else "",
                                ),
                            )
        elif node.type == "variable_declarator":
            pattern = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            declaration = node.parent
            function = (
                declaration is not None and declaration.type == "variable_declaration"
            )
            for name in self._patterns(pattern):
                projection = ""
                if pattern.type == "object_pattern":
                    projection = self._text(name)
                    parent = name.parent
                    if parent is not None and parent.type == "pair_pattern":
                        projection = self._text(parent.child_by_field_name("key"))
                self._bind(
                    name,
                    _Binding(name, value, projection=projection),
                    self._scope(node, function),
                )
        elif node.type == "formal_parameters":
            for name in self._patterns(node):
                self._bind(name, _Binding(name), self._scope(node, True))
        elif node.type == "arrow_function":
            for name in self._patterns(node.child_by_field_name("parameter")):
                self._bind(name, _Binding(name), node)
        elif node.type in {
            "function_declaration",
            "class_declaration",
            "generator_function_declaration",
        }:
            name = node.child_by_field_name("name")
            self._bind(name, _Binding(name), self._scope(node))
        elif node.type == "catch_clause":
            for name in self._patterns(node.child_by_field_name("parameter")):
                self._bind(name, _Binding(name), node)
        elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
            lhs = _unwrap(node.child_by_field_name("left"))
            if lhs is not None and lhs.type == "identifier":
                self.assignments.append(node)
            elif lhs is not None and lhs.type in {
                "member_expression",
                "subscript_expression",
            }:
                self.member_writes.append(node)
        elif (
            node.type == "unary_expression"
            and self._text(node.child_by_field_name("operator")) == "delete"
        ):
            lhs = _unwrap(node.child_by_field_name("argument"))
            if lhs is not None and lhs.type in {
                "member_expression",
                "subscript_expression",
            }:
                self.member_writes.append(node)

    def _lookup(self, name, use):
        current = use
        while current is not None:
            if current.type in _SCOPES:
                bindings = self.bindings.get((current.id, name))
                if bindings:
                    return bindings[0] if len(bindings) == 1 else None
            current = current.parent
        return None

    def _values(self, expression, depth=0):
        expression = _unwrap(expression)
        if depth > 16:
            self.complete = False
            return []
        if expression is None or not self._consume():
            return []
        if expression.type != "identifier":
            return [(expression, "", "")]
        binding = self._lookup(self._text(expression), expression)
        if binding is None:
            return []
        if binding.kind == "import":
            return [(None, binding.imported, "")]
        values = (
            [(binding.value, "", binding.projection)]
            if binding.node.start_byte < expression.start_byte
            else []
        )
        for write in binding.writes:
            if write.end_byte >= expression.start_byte:
                continue
            rhs = write.child_by_field_name("right")
            statement = write.parent
            block = statement.parent if statement is not None else None
            if (
                statement is not None
                and statement.type == "expression_statement"
                and block is not None
                and block.type in {"program", "statement_block"}
                and block.start_byte <= expression.start_byte < block.end_byte
            ):
                values = [(rhs, "", "")]
            else:
                values.append((rhs, "", ""))
        resolved = []
        for value, imported, projection in values:
            if value is not None and value.type == "identifier":
                resolved.extend(
                    (v, imported, projection or nested_projection)
                    for v, imported, nested_projection in self._values(value, depth + 1)
                )
            else:
                resolved.append((value, imported, projection))
        return resolved

    def _property(self, expression):
        if expression.type == "member_expression":
            return self._text(expression.child_by_field_name("property"))
        return self._string(expression.child_by_field_name("index"))

    def _provider(self, expression, depth=0):
        if depth > 16:
            self.complete = False
            return set()
        found = set()
        for value, imported, projection in self._values(expression, depth):
            if imported:
                found.add(projection or imported)
            elif value is not None and value.type == "call_expression":
                callee = value.child_by_field_name("function")
                args = value.child_by_field_name("arguments")
                if (
                    callee is not None
                    and self._text(callee) == "require"
                    and self._lookup("require", callee) is None
                    and args is not None
                    and args.named_children
                    and self._string(args.named_children[0]) in _MODULES
                ):
                    found.add(projection or "*")
            elif value is not None and value.type in {
                "member_expression",
                "subscript_expression",
            }:
                method = self._property(value)
                obj = value.child_by_field_name("object")
                if method in _METHODS and "*" in self._provider(obj, depth + 1):
                    if not self._overwritten_method(method, value):
                        found.add(method)
        return found

    def _strong_write(self, write, use):
        statement = write.parent
        block = statement.parent if statement is not None else None
        return (
            statement is not None
            and statement.type == "expression_statement"
            and block is not None
            and block.type in {"program", "statement_block"}
            and block.start_byte <= use.start_byte < block.end_byte
        )

    def _overwritten_method(self, method, use):
        overwritten = False
        for write in self.member_writes:
            if write.end_byte >= use.start_byte or not self._strong_write(write, use):
                continue
            lhs = _unwrap(
                write.child_by_field_name("left")
                or write.child_by_field_name("argument")
            )
            if self._property(lhs) == method and "*" in self._provider(
                lhs.child_by_field_name("object")
            ):
                rhs = write.child_by_field_name("right")
                overwritten = method not in self._provider(rhs)
        return overwritten

    def _updated_shell(self, current, write, depth):
        if write.type == "unary_expression":
            return {_ABSENT}
        updated = self._shell_value(write.child_by_field_name("right"), depth + 1)
        operator = self._text(write.child_by_field_name("operator"))
        if operator == "||=":
            return ({True} if True in current else set()) | (
                updated if current - {True} else set()
            )
        if operator == "&&=":
            return (current & {False, _ABSENT}) | (
                updated if current - {False, _ABSENT} else set()
            )
        if operator == "??=":
            return (current - {_ABSENT, _UNKNOWN}) | (
                updated if current & {_ABSENT, _UNKNOWN} else set()
            )
        return updated

    def _shell_value(self, expression, depth=0):
        states = set()
        for value, _, _ in self._values(expression, depth):
            if value is None:
                states.add(_UNKNOWN)
            elif value.type in {"true", "false"}:
                states.add(value.type == "true")
            else:
                string = self._string(value)
                states.add(bool(string) if string is not None else _UNKNOWN)
        return states or {_UNKNOWN}

    def _shell(self, expression, depth=0):
        if depth > 16:
            self.complete = False
            return {_UNKNOWN}
        states = set()
        for value, _, _ in self._values(expression, depth):
            if value is None or value.type != "object":
                states.add(_UNKNOWN)
                continue
            current = {_ABSENT}
            for child in value.named_children:
                if child.type == "spread_element" and child.named_children:
                    spread = self._shell(child.named_children[0], depth + 1)
                    current = (
                        current if _ABSENT in spread or _UNKNOWN in spread else set()
                    ) | (spread - {_ABSENT})
                elif child.type == "pair":
                    key = child.child_by_field_name("key")
                    name = (
                        self._string(key)
                        if key is not None and key.type == "string"
                        else self._text(key)
                    )
                    if (
                        key is not None
                        and key.type == "computed_property_name"
                        and key.named_children
                    ):
                        name = self._string(key.named_children[0])
                    if name == "shell":
                        current = self._shell_value(
                            child.child_by_field_name("value"), depth + 1
                        )
                elif (
                    child.type == "shorthand_property_identifier"
                    and self._text(child) == "shell"
                ):
                    current = self._shell_value(child, depth + 1)
            for write in self.member_writes:
                if write.end_byte >= expression.start_byte:
                    continue
                lhs = _unwrap(
                    write.child_by_field_name("left")
                    or write.child_by_field_name("argument")
                )
                if self._property(lhs) != "shell":
                    continue
                targets = self._values(lhs.child_by_field_name("object"), depth + 1)
                if any(
                    target is not None and target.id == value.id
                    for target, _, _ in targets
                ):
                    updated = self._updated_shell(current, write, depth)
                    current = (
                        updated
                        if self._strong_write(write, expression)
                        else current | updated
                    )
            states.update(current)
        return states or {_UNKNOWN}

    def _args(self, arguments, depth=0):
        if depth > 16:
            self.complete = False
            return []
        if arguments is None:
            return []
        result = []
        for arg in arguments.named_children:
            if arg.type == "comment":
                continue
            if arg.type != "spread_element":
                result.append(arg)
                continue
            if not arg.named_children:
                return []
            values = self._values(arg.named_children[0], depth + 1)
            if len(values) != 1 or values[0][0] is None or values[0][0].type != "array":
                return []
            result.extend(self._args(values[0][0], depth + 1))
        return result

    def command_parts(self, call):
        if not self.collection_complete:
            return None
        # Each candidate gets the same work allowance. Earlier unrelated calls
        # cannot consume a later candidate's proof budget.
        self.budget = _QUERY_LIMIT
        methods = self._provider(call.child_by_field_name("function")) & _METHODS
        if not methods:
            return None
        args = self._args(call.child_by_field_name("arguments"))
        if len(args) < 2:
            return None
        second = self._values(args[1])
        options_at = (
            1
            if second
            and all(v is not None and v.type == "object" for v, _, _ in second)
            else 2
        )
        if options_at >= len(args):
            return None
        # Unknown objects alone do not prove an optional shell. A known true
        # or nonempty shell path does; a later explicit false removes it.
        if True not in self._shell(args[options_at]):
            return None
        return sorted(methods)[0], args[:options_at]
