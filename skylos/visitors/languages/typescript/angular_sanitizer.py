"""SKY-D226: Angular ``DomSanitizer.bypassSecurityTrust*`` of a dynamic value.

``bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl(x)`` tells Angular not
to sanitize ``x`` when it is bound to ``[innerHTML]``, ``[src]`` and the like.
Any value the component did not write itself is then raw markup or a raw
URL in the page.

* HIGH: the value comes (through local variables of the same function) from
  data the browser user or a link controls: ``ActivatedRoute`` params, query
  params and fragments, ``location``/``document.URL``/``document.cookie``,
  ``localStorage``/``sessionStorage``, ``window.name``, a message event's
  ``data``, or a decoded token from one of those.
* MEDIUM: any other non-constant value, such as HTTP response fields or
  parameters (stored XSS when the server returns user-supplied text).

Not reported: literals and constants, and ``Url``/``ResourceUrl`` values
whose literal ``scheme://host/`` prefix fixes the origin.
The file must import from ``@angular/platform-browser``.
"""

from __future__ import annotations

import re

_BYPASS_METHODS = frozenset(
    {
        "bypassSecurityTrustHtml",
        "bypassSecurityTrustScript",
        "bypassSecurityTrustStyle",
        "bypassSecurityTrustUrl",
        "bypassSecurityTrustResourceUrl",
    }
)
_URL_METHODS = frozenset({"bypassSecurityTrustUrl", "bypassSecurityTrustResourceUrl"})
_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)
_CLIENT_SOURCE_RE = re.compile(
    r"\b(?:queryParams|queryParamMap|paramMap|fragment)\b"
    r"|\bsnapshot\.params\b|\broute\.params\b"
    r"|\b(?:window\.)?location\.(?:href|search|hash|pathname)\b"
    r"|\bdocument\.(?:URL|documentURI|cookie|referrer|location)\b"
    r"|\b(?:localStorage|sessionStorage)\.getItem\b"
    r"|\bwindow\.name\b"
)
_FIXED_HOST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/'\"`$]+/")
_MAX_HOPS = 4


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node):
    while node is not None and node.type in {
        "parenthesized_expression",
        "as_expression",
        "non_null_expression",
        "satisfies_expression",
        "await_expression",
    }:
        inner = next(iter(node.named_children), None)
        if inner is None:
            return node
        node = inner
    return node


def _imports_angular_browser(root, source: bytes) -> bool:
    for statement in root.named_children:
        if statement.type != "import_statement":
            continue
        module = statement.child_by_field_name("source")
        if module is not None and _text(source, module).strip("'\"") == (
            "@angular/platform-browser"
        ):
            return True
    return False


class _Values:
    """Local ``const``/``let`` values and assignments of one function."""

    def __init__(self, function, source: bytes):
        self.source = source
        self.values: dict[str, list] = {}
        body = function.child_by_field_name("body") if function is not None else None
        if body is None:
            return
        stack = [body]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if name is not None and value is not None:
                    for bound in self._names(name):
                        self.values.setdefault(bound, []).append(value)
            elif node.type == "assignment_expression":
                left = _unwrap(node.child_by_field_name("left"))
                right = node.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    self.values.setdefault(_text(source, left), []).append(right)

    def _names(self, pattern) -> list[str]:
        if pattern.type == "identifier":
            return [_text(self.source, pattern)]
        names = []
        stack = list(pattern.children)
        while stack:
            child = stack.pop()
            if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                names.append(_text(self.source, child))
            else:
                stack.extend(child.children)
        return names

    def constant(self, node, depth: int = 0) -> bool:
        node = _unwrap(node)
        if node is None or depth > _MAX_HOPS:
            return False
        if node.type in {"string", "number", "true", "false", "null"}:
            return True
        if node.type == "template_string":
            return not any(
                child.type == "template_substitution" for child in node.named_children
            )
        if node.type == "binary_expression":
            return self.constant(
                node.child_by_field_name("left"), depth + 1
            ) and self.constant(node.child_by_field_name("right"), depth + 1)
        if node.type == "identifier":
            values = self.values.get(_text(self.source, node))
            return bool(values) and all(self.constant(v, depth + 1) for v in values)
        return False

    def client_controlled(self, node, depth: int = 0) -> bool:
        node = _unwrap(node)
        if node is None or depth > _MAX_HOPS:
            return False
        if _CLIENT_SOURCE_RE.search(_text(self.source, node)):
            return True
        stack = [node]
        names = set()
        while stack:
            current = stack.pop()
            if current.type == "identifier":
                names.add(_text(self.source, current))
            if current.type in _FUNCTION_TYPES:
                continue
            stack.extend(current.children)
        return any(
            self.client_controlled(value, depth + 1)
            for name in names
            for value in self.values.get(name, ())
        )


def _fixed_origin(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    while node.type == "binary_expression":
        node = _unwrap(node.child_by_field_name("left"))
        if node is None:
            return False
    text = _text(source, node)
    if node.type == "string":
        return bool(_FIXED_HOST_RE.match(text[1:]))
    if node.type == "template_string":
        return bool(_FIXED_HOST_RE.match(text[1:]))
    return False


def _enclosing_function(node):
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def check_angular_sanitizer_bypass(
    root_node, source_bytes: bytes, file_path: str, findings: list[dict]
) -> None:
    if b"bypassSecurityTrust" not in source_bytes or not _imports_angular_browser(
        root_node, source_bytes
    ):
        return
    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None or callee.type != "member_expression":
            continue
        prop = callee.child_by_field_name("property")
        method = _text(source_bytes, prop) if prop is not None else ""
        if method not in _BYPASS_METHODS:
            continue
        args = node.child_by_field_name("arguments")
        value = next(
            (c for c in (args.named_children if args else []) if c.type != "comment"),
            None,
        )
        if value is None:
            continue
        # A value built inside a nested callback can read the enclosing
        # method's locals, so each enclosing function contributes values.
        functions = []
        current = _enclosing_function(node)
        while current is not None and len(functions) < 4:
            functions.append(_Values(current, source_bytes))
            current = _enclosing_function(current)
        merged = _Values(None, source_bytes)
        for values in reversed(functions):
            for name, nodes in values.values.items():
                merged.values.setdefault(name, []).extend(nodes)
        if merged.constant(value):
            continue
        if method in _URL_METHODS and _fixed_origin(source_bytes, value):
            continue
        client = merged.client_controlled(value)
        findings.append(
            {
                "rule_id": "SKY-D226",
                "severity": "HIGH" if client else "MEDIUM",
                "message": (
                    f"DomSanitizer.{method}() turns off Angular sanitization for "
                    + (
                        "a value from the URL, browser storage or another "
                        "client-controlled source"
                        if client
                        else "a value the component did not write (for example "
                        "HTTP response data)"
                    )
                    + " — XSS. Bind the value normally or sanitize it first."
                ),
                "file": str(file_path),
                "line": node.start_point[0] + 1,
                "col": 0,
            }
        )
