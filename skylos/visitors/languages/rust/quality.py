"""Conservative source-level Rust quality checks, without macro expansion."""

from __future__ import annotations

from pathlib import Path

from skylos.visitors.languages.typescript import (
    _SKYLOS_IGNORE_END_RE,
    _comment_body,
    _parse_typescript_directive,
)


_COMMENTS = {"line_comment", "block_comment"}
_ATTRIBUTES = {"attribute_item", "inner_attribute_item"}
_MACROS = {"macro_invocation", "macro_definition", "token_tree"}
_TERMINATORS = {
    "return_expression": "return",
    "break_expression": "break",
    "continue_expression": "continue",
}


def scan_quality(root_node, file_path: str, source: bytes) -> list[dict]:
    if root_node is None or root_node.has_error:
        return []
    return _Quality(file_path, source).scan(root_node)


def quality_inline_ignores(root_node, source: bytes):
    """Use the existing directive grammar on parser-owned Rust comments only."""
    if root_node is None or root_node.has_error:
        return set(), {}
    events = {}
    pending = [root_node]
    while pending:
        node = pending.pop()
        if node.type in _MACROS:
            continue
        if node.type not in _COMMENTS:
            pending.extend(reversed(node.named_children))
            continue
        body = _comment_body(
            source[node.start_byte : node.end_byte].decode("utf-8", "replace")
        )
        parsed = _parse_typescript_directive(body) if body is not None else None
        if parsed is None:
            continue
        kind, rules, end = parsed
        line = node.start_point[0] + 1
        events.setdefault(line, []).append((kind, rules))
        if kind == "start" and _SKYLOS_IGNORE_END_RE.search(body.lstrip(), end):
            events[line].append(("end", set()))
    ignored = set()
    by_rule = {}
    in_block = False
    for line in range(1, source.count(b"\n") + 2):
        if in_block:
            ignored.add(line)
        for kind, rules in events.get(line, ()):
            if kind == "rules":
                by_rule.setdefault(line, set()).update(rules)
            else:
                ignored.add(line)
            if kind in {"start", "end"}:
                in_block = kind == "start"
    return ignored, by_rule


class _Quality:
    def __init__(self, file_path, source):
        self.file_path = file_path
        self.source = source
        self.findings = []
        self.checked_conditions = set()

    def text(self, node):
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")

    def descendants(self, node):
        pending = [node]
        while pending:
            child = pending.pop()
            yield child
            if child.type not in _MACROS:
                pending.extend(reversed(child.named_children))

    def has_kind(self, node, kinds):
        return any(child.type in kinds for child in self.descendants(node))

    def pattern_names(self, node):
        if node is None:
            return set()
        return {
            self.text(child)
            for child in self.descendants(node)
            if child.type in {"identifier", "shorthand_field_identifier"}
        }

    def bool_expression(self, node, bools):
        if node is None:
            return False
        if node.type == "identifier":
            return self.text(node) in bools
        if node.type == "boolean_literal":
            return True
        if node.type == "parenthesized_expression" and len(node.named_children) == 1:
            return self.bool_expression(node.named_children[0], bools)
        if node.type == "unary_expression" and node.children[0].type == "!":
            return self.bool_expression(node.named_children[-1], bools)
        return False

    def use_shadows_bool(self, node, prefix=""):
        if node.type == "use_wildcard":
            return True  # A glob may import a type with a primitive's name.
        if node.type == "use_as_clause":
            alias = node.child_by_field_name("alias")
            return alias is not None and self.text(alias).removeprefix("r#") == "bool"
        if node.type == "scoped_identifier":
            name = node.child_by_field_name("name")
            path = node.child_by_field_name("path")
            if name is not None and self.text(name) == "self":
                return path is not None and self.text(path).split("::")[-1] == "bool"
            return name is not None and self.text(name).removeprefix("r#") == "bool"
        if node.type == "scoped_use_list":
            path = node.child_by_field_name("path")
            prefix = self.text(path).split("::")[-1] if path is not None else prefix
            node = node.child_by_field_name("list") or node
        if node.type in {"identifier", "self"}:
            return self.text(node).removeprefix("r#") == "bool" or (
                node.type == "self" and prefix == "bool"
            )
        return any(
            self.use_shadows_bool(child, prefix) for child in node.named_children
        )

    def scope_shadows_bool(self, node):
        for child in node.named_children:
            if child.type == "use_declaration" and self.use_shadows_bool(child):
                return True
            if self.expression(child).type == "macro_invocation":
                return True  # Expansion may introduce an item named bool.
            if child.type in {
                "type_item",
                "struct_item",
                "enum_item",
                "union_item",
                "trait_item",
                "mod_item",
                "extern_crate_declaration",
            }:
                identifier = child.child_by_field_name(
                    "alias"
                ) or child.child_by_field_name("name")
                if (
                    identifier is not None
                    and self.text(identifier).removeprefix("r#") == "bool"
                ):
                    return True
        return False

    def parameter_bools(self, parameters, outer=(), *, primitive_bool=True):
        bools = set(outer)
        if parameters is None:
            return bools
        for parameter in parameters.named_children:
            pattern = parameter.child_by_field_name("pattern") or parameter
            bools.difference_update(self.pattern_names(pattern))
            annotation = parameter.child_by_field_name("type")
            if pattern.type == "identifier" and annotation is not None:
                if primitive_bool and self.text(annotation) == "bool":
                    bools.add(self.text(pattern))
        return bools

    def finding(self, rule, node, name, message, **extra):
        self.findings.append(
            {
                "rule_id": rule,
                "kind": "quality",
                "severity": "MEDIUM",
                "type": "function",
                "name": name,
                "simple_name": name.rsplit(".", 1)[-1],
                "message": message,
                "file": self.file_path,
                "basename": Path(self.file_path).name,
                "line": node.start_point[0] + 1,
                "col": node.start_point[1],
                **extra,
            }
        )

    @staticmethod
    def expression(statement):
        if statement.type == "expression_statement" and statement.named_children:
            return statement.named_children[0]
        return statement

    @staticmethod
    def is_item(node):
        return node.type.endswith("_item") or node.type in {
            "use_declaration",
            "macro_definition",
            "function_signature_item",
        }

    def executable(self, node):
        return (
            node.type not in _COMMENTS | _ATTRIBUTES | {"empty_statement", "label"}
            and not self.is_item(node)
            and self.expression(node).type not in _MACROS
        )

    def unreachable(self, block, name):
        terminator = None
        for statement in block.named_children:
            if not self.executable(statement):
                continue
            if terminator:
                self.finding(
                    "SKY-UC002",
                    statement,
                    name,
                    f"Unreachable code after {terminator}.",
                )
                return
            terminator = _TERMINATORS.get(self.expression(statement).type)

    def tokens(self, node):
        if node.type in _COMMENTS:
            return ()
        # Whitespace in literals is data. Keep the complete literal spelling.
        if not node.children or node.type.endswith("literal"):
            return ((node.type, self.text(node)),)
        return tuple(token for child in node.children for token in self.tokens(child))

    def duplicate_bodies(self, condition, bools, name):
        if condition.start_byte in self.checked_conditions:
            return
        branches = []
        current = condition
        location = condition
        safe = True
        while current is not None:
            self.checked_conditions.add(current.start_byte)
            predicate = current.child_by_field_name("condition")
            safe &= self.bool_expression(predicate, bools)
            body = current.child_by_field_name("consequence")
            if body is None:
                return
            branches.append((body, location))
            alternative = current.child_by_field_name("alternative")
            if alternative is None:
                break
            child = next(
                (
                    item
                    for item in alternative.named_children
                    if item.type not in _COMMENTS
                ),
                None,
            )
            if child is None:
                break
            location = alternative  # The later branch starts at its else token.
            if child.type == "block":
                branches.append((child, location))
                break
            if child.type != "if_expression":
                return
            current = child
        if not safe:
            return
        seen = {}
        for body, location in branches:
            if self.has_kind(body, _ATTRIBUTES | _MACROS):
                continue
            if sum(self.executable(item) for item in body.named_children) < 2:
                continue
            key = self.tokens(body)
            if key not in seen:
                seen[key] = location.start_point[0] + 1
                continue
            first_line = seen[key]
            self.finding(
                "SKY-Q305",
                location,
                name,
                f"Function '{name}' has duplicate branch bodies first seen at line {first_line}.",
                value="duplicate_body",
                threshold=0,
                metadata={"first_branch_line": first_line},
            )

    def scan(self, root):
        self.walk(root, set(), "")
        return self.findings

    def walk(self, node, bools, name, primitive_bool=True):
        if node.type in _MACROS | _COMMENTS | _ATTRIBUTES:
            return
        if node.type in {"source_file", "block", "declaration_list"}:
            primitive_bool = primitive_bool and not self.scope_shadows_bool(node)
        type_parameters = node.child_by_field_name("type_parameters")
        if type_parameters is not None:
            for parameter in type_parameters.named_children:
                identifier = parameter.child_by_field_name("name")
                if (
                    identifier is not None
                    and self.text(identifier).removeprefix("r#") == "bool"
                ):
                    primitive_bool = False
        if node.type == "function_item":
            identifier = node.child_by_field_name("name")
            body = node.child_by_field_name("body")
            if identifier is not None and body is not None:
                function_name = ".".join(filter(None, [name, self.text(identifier)]))
                parameters = node.child_by_field_name("parameters")
                self.walk(
                    body,
                    self.parameter_bools(parameters, primitive_bool=primitive_bool),
                    function_name,
                    primitive_bool,
                )
            return
        if node.type in {"impl_item", "mod_item"}:
            identifier = node.child_by_field_name(
                "type" if node.type == "impl_item" else "name"
            )
            if identifier is not None:
                name = ".".join(filter(None, [name, self.text(identifier)]))
            if node.type == "mod_item":
                # Modules do not implicitly import their parent's type items.
                primitive_bool = True
        if node.type == "closure_expression":
            parameters = node.child_by_field_name("parameters")
            body = node.child_by_field_name("body")
            if body is not None:
                self.walk(
                    body,
                    self.parameter_bools(
                        parameters, bools, primitive_bool=primitive_bool
                    ),
                    name,
                    primitive_bool,
                )
            return
        if node.type == "block":
            # Conditional attributes can remove bindings or a terminator.
            # Without cfg expansion, keep the entire affected block quiet.
            if self.has_kind(node, _ATTRIBUTES):
                return
            self.unreachable(node, name)
            local = set(bools)
            for child in node.named_children:
                if self.is_item(child):
                    identifier = child.child_by_field_name("name")
                    if identifier is not None:
                        local.discard(self.text(identifier))
                    if child.type == "use_declaration":
                        local.difference_update(self.pattern_names(child))
            for child in node.named_children:
                self.walk(child, local, name, primitive_bool)
                if child.type == "let_declaration":
                    pattern = child.child_by_field_name("pattern")
                    annotation = child.child_by_field_name("type")
                    value = child.child_by_field_name("value")
                    proven_bool = (
                        primitive_bool and self.text(annotation) == "bool"
                        if annotation is not None
                        else self.bool_expression(value, local)
                    )
                    local.difference_update(self.pattern_names(pattern))
                    if (
                        proven_bool
                        and pattern is not None
                        and pattern.type == "identifier"
                    ):
                        local.add(self.text(pattern))
            return
        if node.type == "if_expression":
            self.duplicate_bodies(node, bools, name)
            condition = node.child_by_field_name("condition")
            local = set(bools)
            if condition is not None:
                for child in self.descendants(condition):
                    if child.type == "let_condition":
                        local.difference_update(
                            self.pattern_names(child.child_by_field_name("pattern"))
                        )
            for child in node.named_children:
                environment = (
                    local if child == node.child_by_field_name("consequence") else bools
                )
                self.walk(child, environment, name, primitive_bool)
            return
        if node.type in {"for_expression", "match_arm", "while_expression"}:
            local = set(bools)
            local.difference_update(
                self.pattern_names(node.child_by_field_name("pattern"))
            )
            condition = node.child_by_field_name("condition")
            if condition is not None:
                for child in self.descendants(condition):
                    if child.type == "let_condition":
                        local.difference_update(
                            self.pattern_names(child.child_by_field_name("pattern"))
                        )
            for child in node.named_children:
                self.walk(child, local, name, primitive_bool)
            return
        for child in node.named_children:
            self.walk(child, bools, name, primitive_bool)
