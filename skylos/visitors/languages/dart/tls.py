"""Prove disabled peer verification on a source-visible dart:io HttpClient."""

from dataclasses import dataclass

_CALLBACK = b"badCertificateCallback"


def _children(node):
    return [child for child in node.named_children if child.type != "comment"]


def _unwrap(node):
    while node is not None and node.type == "parenthesized_expression":
        children = _children(node)
        node = children[0] if len(children) == 1 else None
    return node


def _accepts_every_certificate(node):
    node = _unwrap(node)
    if node is None or node.type != "function_expression":
        return False
    body = node.child_by_field_name("body")
    statements = _children(body) if body is not None else []
    if len(statements) == 1 and statements[0].type == "block":
        statements = _children(statements[0])
        if len(statements) != 1 or statements[0].type != "return_statement":
            return False
        statements = _children(statements[0])
    return len(statements) == 1 and statements[0].type == "true"


def _http_client_imports(imports):
    owned = set()
    ambiguous = set()
    for item in imports:
        prefix = item["prefix"]
        if "HttpClient" in item["hide"] or (
            item["show"] and "HttpClient" not in item["show"]
        ):
            continue
        root = prefix.encode() if prefix else b"HttpClient"
        path = (root, b"HttpClient") if prefix else (root,)
        if item["sources"] == ["dart:io"]:
            owned.add(path)
        elif prefix or "HttpClient" in item["show"]:
            ambiguous.add(path)
    return owned - ambiguous


def _assignable(node):
    if node.type == "identifier":
        return (node.text,)
    if node.type in {"assignable_expression", "unconditional_assignable_selector"}:
        parts = []
        for child in _children(node):
            path = _assignable(child)
            if not path:
                return ()
            parts.extend(path)
        return tuple(parts)
    return ()


@dataclass(eq=False)
class _Client:
    accepting_callback: object = None


class _Block:
    def __init__(self, import_paths, names, findings):
        self.import_paths = import_paths
        self.names = names
        self.findings = findings
        self.clients = {}

    def client(self, expr):
        expr = _unwrap(expr)
        if expr is None:
            return None
        if expr.type == "identifier":
            return self.clients.get(expr.text)
        if expr.type != "method_invocation":
            return None
        callee = expr.child_by_field_name("function")
        path = _assignable(callee) if callee is not None else ()
        if path and path in self.import_paths and path[0] not in self.names:
            return _Client()
        return None

    def cascade(self, client, sections):
        for section in sections:
            if section.type != "cascade_section":
                continue
            parts = _children(section)
            if (
                len(parts) == 2
                and parts[0].type == "cascade_selector"
                and parts[0].text == _CALLBACK
                and any(child.type == "=" for child in section.children)
            ):
                self.set_callback(client, parts[1], section)

    @staticmethod
    def set_callback(client, value, site):
        client.accepting_callback = site if _accepts_every_certificate(value) else None

    def observe(self, client):
        if client is not None and client.accepting_callback is not None:
            self.findings.add(client.accepting_callback)

    def statement(self, node):
        if node.type == "local_variable_declaration":
            for definition in _children(node):
                name = definition.child_by_field_name("name")
                if name is None:
                    continue
                values = definition.children_by_field_name("value")
                client = self.client(values[0]) if values else None
                self.clients[name.text] = client
                if client is not None:
                    self.cascade(client, values[1:])
                    self.observe_call(values[0])
            return

        parts = _children(node)
        if node.type == "expression_statement" and parts:
            expr = parts[0]
            if expr.type == "assignment_expression":
                lhs = expr.child_by_field_name("left")
                rhs = expr.child_by_field_name("right")
                path = _assignable(lhs) if lhs is not None else ()
                operator = expr.child_by_field_name("operator")
                if operator is None or operator.type != "=":
                    return
                if len(path) == 1 and path[0] in self.clients:
                    self.clients[path[0]] = self.client(rhs)
                elif len(path) == 2 and path[1] == _CALLBACK:
                    client = self.clients.get(path[0])
                    if client is not None:
                        self.set_callback(client, rhs, expr)
                return
            self.observe_call(expr)
            return

        if node.type == "return_statement" and parts:
            client = self.client(parts[0])
            if client is not None:
                self.cascade(client, parts[1:])
                self.observe(client)

    def observe_call(self, node):
        if node.type in {"await_expression", "parenthesized_expression"}:
            children = _children(node)
            if len(children) == 1:
                self.observe_call(children[0])
        elif node.type == "method_invocation":
            callee = node.child_by_field_name("function")
            path = _assignable(callee) if callee is not None else ()
            if len(path) == 2 and path[1] in {
                b"get",
                b"getUrl",
                b"head",
                b"headUrl",
                b"post",
                b"postUrl",
                b"put",
                b"putUrl",
                b"patch",
                b"patchUrl",
                b"delete",
                b"deleteUrl",
                b"open",
                b"openUrl",
            }:
                self.observe(self.clients.get(path[0]))


def scan_bad_certificate_callbacks(core):
    root = core.root_node
    if root is None or b"badCertificateCallback" not in core.source:
        return []
    paths = _http_client_imports(core.binding_metadata.get("imports", ()))
    if not paths:
        return []
    module_names = {
        definition.name.encode()
        for definition in core.defs
        if definition.type in {"class", "function", "variable"}
    }
    findings = set()
    pending = [root]
    while pending:
        node = pending.pop()
        pending.extend(reversed(_children(node)))
        if node.type != "block" or node.parent.type != "function_body":
            continue
        statements = _children(node)
        signature = node.parent.prev_named_sibling
        names = set(module_names)
        if signature is not None:
            for parameter in core._descendants_of_type(signature, "formal_parameter"):
                name = parameter.child_by_field_name("name")
                if name is not None:
                    names.add(name.text)
        for statement in statements:
            if statement.type == "local_variable_declaration":
                for definition in _children(statement):
                    name = definition.child_by_field_name("name")
                    if name is not None:
                        names.add(name.text)
        block = _Block(paths, names, findings)
        for statement in statements:
            block.statement(statement)
            if statement.type in {"return_statement", "throw_statement"}:
                break
            if statement.type in {
                "if_statement",
                "for_statement",
                "while_statement",
                "switch_statement",
                "try_statement",
            }:
                block.clients.clear()
        for client in block.clients.values():
            block.observe(client)

    return [
        {
            "rule_id": "SKY-D210",
            "severity": "HIGH",
            "message": "Dart HttpClient accepts every untrusted TLS certificate.",
            "file": core.file_path,
            "line": node.start_point[0] + 1,
            "col": node.start_point[1],
            "category": "danger",
        }
        for node in sorted(findings, key=lambda node: node.start_byte)
    ]
