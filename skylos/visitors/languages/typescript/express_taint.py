"""Request-taint sinks for Express-style TypeScript/JavaScript handlers.

A small, bounded, intra-handler taint walk. A finding is produced only when a
value read from the handler's request object (``req.body``, ``req.params``,
``req.query``, ``req.headers``, ``req.cookies`` ...) reaches one of:

* ``child_process.exec`` / ``execSync`` command text (SKY-D212)
* ``res.send`` / ``res.write`` / ``res.end`` HTML built from the value (SKY-D228)
* ``res.sendFile`` / ``res.download`` path without a ``root`` option (SKY-D215)
* ``$queryRawUnsafe`` / ``$executeRawUnsafe`` query text (SKY-D211)

It also reports ``process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`` (SKY-D210),
which needs no source evidence.

Propagation is intentionally narrow: through local ``const``/``let``
bindings, destructuring, string concatenation, template literals, ``||``/``??``
/ternaries and string-returning methods. Arbitrary function calls stop taint,
and sanitizers relevant to the sink (``escapeHtml``, ``path.basename``,
``Number`` ...) remove it.
"""

from __future__ import annotations

import re
from typing import Any

_MAX_NODES = 200_000
_MAX_LABEL = 80

_CHILD_PROCESS_MODULES = frozenset({"child_process", "node:child_process"})
_EXEC_FUNCS = frozenset({"exec", "execSync"})
_REQUEST_FIELDS = frozenset(
    {
        "body",
        "params",
        "query",
        "headers",
        "cookies",
        "signedCookies",
        "files",
        "file",
        "url",
        "originalUrl",
        "path",
        "hostname",
    }
)
_REQUEST_ACCESSOR_METHODS = frozenset({"get", "header", "param"})
_REQUEST_PARAM_NAMES = frozenset({"req", "request"})
_RESPONSE_NAMES = frozenset({"res", "response", "reply"})
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "all", "use", "options", "head"}
)
_REQUEST_TYPE_RE = re.compile(r"\b(?:Request|FastifyRequest|IncomingMessage)\b")

_STRING_METHODS = frozenset(
    {
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toString",
        "slice",
        "substring",
        "substr",
        "replace",
        "replaceAll",
        "concat",
        "padStart",
        "padEnd",
        "normalize",
        "at",
        "join",
        "split",
    }
)
_PASSTHROUGH_CALLS = frozenset({"String", "decodeURIComponent", "decodeURI"})
_PATH_BUILDERS = frozenset({"join", "resolve", "normalize"})
_UNIVERSAL_SANITIZERS = frozenset(
    {"Number", "parseInt", "parseFloat", "Boolean", "isValidObjectId"}
)
_SANITIZERS = {
    "cmd": frozenset({"quote", "shellEscape", "shellescape", "escapeShellArg"}),
    "xss": frozenset(
        {
            "escape",
            "escapeHtml",
            "escapeHTML",
            "htmlEscape",
            "encodeHTML",
            "encode",
            "encodeURIComponent",
            "sanitize",
            "sanitizeHtml",
            "sanitizeHTML",
            "filterXSS",
            "xss",
        }
    ),
    "path": frozenset({"basename"}),
    "sql": frozenset(),
}
_HTML_TAG_RE = re.compile(r"<\s*[A-Za-z!/]")
_UNWRAP_TYPES = frozenset(
    {
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "non_null_expression",
        "satisfies_expression",
        "type_assertion",
    }
)
_FUNCTION_TYPES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function",
        "function_declaration",
        "method_definition",
    }
)
_SOURCE_HINT_RE = re.compile(
    rb"child_process|\.send|\.write|\.end\s*\(|sendFile|download|RawUnsafe"
)
_TLS_ENV = "NODE_TLS_REJECT_UNAUTHORIZED"


def _text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _unwrap(node):
    while node is not None and node.type in _UNWRAP_TYPES:
        inner = None
        for child in node.named_children:
            if child.type not in {"type_annotation", "type_identifier"}:
                inner = child
                break
        if inner is None:
            break
        node = inner
    return node


def _iter_nodes(root):
    stack = [root]
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > _MAX_NODES:
            return
        yield node
        stack.extend(reversed(node.children))


def _string_value(source: bytes, node) -> str | None:
    node = _unwrap(node)
    if node is None:
        return None
    if node.type == "string":
        return _text(source, node)[1:-1]
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return _text(source, node)[1:-1]
    return None


def _member_path(source: bytes, node) -> list[str] | None:
    """Return ['req', 'params', 'x'] for req.params.x / req['params'].x."""
    parts: list[str] = []
    node = _unwrap(node)
    while node is not None:
        if node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop is None:
                return None
            parts.append(_text(source, prop))
            node = _unwrap(node.child_by_field_name("object"))
        elif node.type == "subscript_expression":
            index = node.child_by_field_name("index")
            value = _string_value(source, index) if index is not None else None
            parts.append(value if value is not None else "*")
            node = _unwrap(node.child_by_field_name("object"))
        elif node.type in {"identifier", "this"}:
            parts.append(_text(source, node))
            parts.reverse()
            return parts
        else:
            return None
    return None


def _callee_last_name(source: bytes, callee) -> str | None:
    callee = _unwrap(callee)
    if callee is None:
        return None
    if callee.type == "identifier":
        return _text(source, callee)
    if callee.type == "member_expression":
        prop = callee.child_by_field_name("property")
        return _text(source, prop) if prop is not None else None
    return None


def _call_args(call) -> list:
    args = call.child_by_field_name("arguments")
    if args is None or args.type != "arguments":
        return []
    return [c for c in args.named_children if c.type != "comment"]


def _pattern_names(source: bytes, pattern) -> list[str]:
    names: list[str] = []
    for node in _iter_nodes(pattern):
        if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
            parent = node.parent
            # default values in `{ a = b }` are not bound names
            if (
                parent is not None
                and parent.type in {"assignment_pattern", "object_assignment_pattern"}
                and parent.child_by_field_name("right") == node
            ):
                continue
            names.append(_text(source, node))
    return names


def _param_nodes(func) -> list:
    params = func.child_by_field_name("parameters")
    if params is None:
        single = func.child_by_field_name("parameter")
        return [single] if single is not None else []
    return [c for c in params.named_children if c.type != "comment"]


def _param_name_and_type(source: bytes, param) -> tuple[str | None, str]:
    if param.type == "identifier":
        return _text(source, param), ""
    pattern = param.child_by_field_name("pattern")
    type_node = param.child_by_field_name("type")
    type_text = _text(source, type_node) if type_node is not None else ""
    if pattern is not None and pattern.type == "identifier":
        return _text(source, pattern), type_text
    return None, type_text


def _is_route_callback(source: bytes, func) -> bool:
    parent = func.parent
    if parent is None or parent.type != "arguments":
        return False
    call = parent.parent
    if call is None or call.type != "call_expression":
        return False
    name = _callee_last_name(source, call.child_by_field_name("function"))
    return name in _ROUTE_METHODS


def _handler_names(source: bytes, func) -> tuple[str, str] | None:
    params = _param_nodes(func)
    if not params:
        return None
    req_name, req_type = _param_name_and_type(source, params[0])
    if not req_name:
        return None
    res_name = "res"
    if len(params) > 1:
        name, _ = _param_name_and_type(source, params[1])
        if name:
            res_name = name
    if req_name in _REQUEST_PARAM_NAMES or _REQUEST_TYPE_RE.search(req_type or ""):
        return req_name, res_name
    if len(params) >= 2 and _is_route_callback(source, func):
        return req_name, res_name
    return None


class _ChildProcessNames:
    def __init__(self, source: bytes, root):
        self.functions: set[str] = set()  # exec / aliased exec
        self.modules: set[str] = set()  # cp in cp.exec
        for node in _iter_nodes(root):
            if node.type == "import_statement":
                self._import(source, node)
            elif node.type == "variable_declarator":
                self._require(source, node)

    def _import(self, source: bytes, node) -> None:
        module_node = node.child_by_field_name("source")
        if module_node is None or _string_value(source, module_node) not in (
            _CHILD_PROCESS_MODULES
        ):
            return
        for sub in _iter_nodes(node):
            if sub.type == "import_specifier":
                name = sub.child_by_field_name("name")
                alias = sub.child_by_field_name("alias")
                if name is not None and _text(source, name) in _EXEC_FUNCS:
                    self.functions.add(_text(source, alias or name))
            elif sub.type == "namespace_import":
                for child in sub.named_children:
                    if child.type == "identifier":
                        self.modules.add(_text(source, child))
            elif sub.type == "import_clause":
                for child in sub.named_children:
                    if child.type == "identifier":
                        self.modules.add(_text(source, child))

    def _require(self, source: bytes, node) -> None:
        value = _unwrap(node.child_by_field_name("value"))
        name = node.child_by_field_name("name")
        if value is None or name is None or not _is_child_process_require(
            source, value
        ):
            return
        if name.type == "identifier":
            self.modules.add(_text(source, name))
        elif name.type == "object_pattern":
            for child in name.named_children:
                if child.type == "shorthand_property_identifier_pattern":
                    if _text(source, child) in _EXEC_FUNCS:
                        self.functions.add(_text(source, child))
                elif child.type == "pair_pattern":
                    key = child.child_by_field_name("key")
                    val = child.child_by_field_name("value")
                    if (
                        key is not None
                        and val is not None
                        and _text(source, key) in _EXEC_FUNCS
                        and val.type == "identifier"
                    ):
                        self.functions.add(_text(source, val))

    def is_exec_call(self, source: bytes, call) -> bool:
        callee = _unwrap(call.child_by_field_name("function"))
        if callee is None:
            return False
        if callee.type == "identifier":
            return _text(source, callee) in self.functions
        if callee.type == "member_expression":
            prop = callee.child_by_field_name("property")
            obj = _unwrap(callee.child_by_field_name("object"))
            if prop is None or obj is None or _text(source, prop) not in _EXEC_FUNCS:
                return False
            if obj.type == "identifier":
                return _text(source, obj) in self.modules
            return _is_child_process_require(source, obj)
        return False


def _is_child_process_require(source: bytes, node) -> bool:
    if node is None or node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None or _text(source, callee) != "require":
        return False
    args = _call_args(node)
    return bool(args) and _string_value(source, args[0]) in _CHILD_PROCESS_MODULES


def _has_html_literal(source: bytes, node) -> bool:
    node = _unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        for child in node.named_children:
            if child.type == "string_fragment" and _HTML_TAG_RE.search(
                _text(source, child)
            ):
                return True
        return False
    if node.type == "string":
        return bool(_HTML_TAG_RE.search(_text(source, node)))
    if node.type == "binary_expression":
        return _has_html_literal(
            source, node.child_by_field_name("left")
        ) or _has_html_literal(source, node.child_by_field_name("right"))
    return False


class _HandlerTaint:
    def __init__(self, source: bytes, func, req_name: str, res_name: str):
        self.source = source
        self.func = func
        self.req = req_name
        self.res = res_name
        # name -> label of the original request source
        self.origins: dict[str, str] = {}
        self.html_names: set[str] = set()
        # name -> set of sink kinds whose sanitizer was applied at binding
        self.sanitized_for: dict[str, set[str]] = {}
        body = func.child_by_field_name("body")
        self.body = body
        self.nodes = list(_iter_nodes(body)) if body is not None else []
        self._propagate()

    # -- source / propagation -------------------------------------------
    def _request_label(self, node) -> str | None:
        path = _member_path(self.source, node)
        if not path or len(path) < 2:
            return None
        if path[0] == self.req and path[1] in _REQUEST_FIELDS:
            text = _text(self.source, node)
            if len(text) > _MAX_LABEL:
                text = text[:_MAX_LABEL] + "..."
            return f"request data `{text}`"
        return None

    def taint(self, node, kind: str) -> str | None:
        node = _unwrap(node)
        if node is None:
            return None
        t = node.type
        if t == "identifier":
            name = _text(self.source, node)
            if kind in self.sanitized_for.get(name, ()):
                return None
            return self.origins.get(name)
        if t in {"member_expression", "subscript_expression"}:
            label = self._request_label(node)
            if label:
                return label
            obj = node.child_by_field_name("object")
            return self.taint(obj, kind)
        if t == "call_expression":
            return self._call_taint(node, kind)
        if t == "template_string":
            for child in node.named_children:
                if child.type == "template_substitution":
                    for inner in child.named_children:
                        label = self.taint(inner, kind)
                        if label:
                            return label
            return None
        if t == "binary_expression":
            return self.taint(node.child_by_field_name("left"), kind) or self.taint(
                node.child_by_field_name("right"), kind
            )
        if t == "ternary_expression":
            return self.taint(
                node.child_by_field_name("consequence"), kind
            ) or self.taint(node.child_by_field_name("alternative"), kind)
        return None

    def _call_taint(self, node, kind: str) -> str | None:
        callee = _unwrap(node.child_by_field_name("function"))
        name = _callee_last_name(self.source, callee)
        if name in _UNIVERSAL_SANITIZERS or name in _SANITIZERS.get(kind, ()):
            return None
        args = _call_args(node)
        if callee is not None and callee.type == "member_expression":
            obj = _unwrap(callee.child_by_field_name("object"))
            obj_path = _member_path(self.source, obj) if obj is not None else None
            if (
                obj_path == [self.req]
                and name in _REQUEST_ACCESSOR_METHODS
                and args
            ):
                text = _text(self.source, node)
                if len(text) > _MAX_LABEL:
                    text = text[:_MAX_LABEL] + "..."
                return f"request data `{text}`"
            if name in _STRING_METHODS:
                label = self.taint(obj, kind)
                if label:
                    return label
                if name in {"concat", "join"}:
                    for arg in args:
                        label = self.taint(arg, kind)
                        if label:
                            return label
                return None
            if obj_path == ["path"] and name in _PATH_BUILDERS:
                for arg in args:
                    label = self.taint(arg, kind)
                    if label:
                        return label
            return None
        if name in _PASSTHROUGH_CALLS:
            for arg in args:
                label = self.taint(arg, kind)
                if label:
                    return label
        return None

    def _bind(self, names: list[str], value) -> bool:
        changed = False
        label = self.taint(value, "any")
        if label is None:
            return False
        sanitized = {
            kind for kind in _SANITIZERS if self.taint(value, kind) is None
        }
        html = _has_html_literal(self.source, value)
        for name in names:
            if name not in self.origins:
                self.origins[name] = label
                changed = True
            if sanitized:
                self.sanitized_for.setdefault(name, set()).update(sanitized)
            if html and name not in self.html_names:
                self.html_names.add(name)
                changed = True
        return changed

    def _propagate(self) -> None:
        for _ in range(3):
            changed = False
            for node in self.nodes:
                if node.type == "variable_declarator":
                    name = node.child_by_field_name("name")
                    value = node.child_by_field_name("value")
                    if name is None or value is None:
                        continue
                    changed |= self._bind(_pattern_names(self.source, name), value)
                elif node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None:
                        if left.type == "identifier":
                            changed |= self._bind(
                                [_text(self.source, left)], right
                            )
                elif node.type == "augmented_assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and left.type == (
                        "identifier"
                    ):
                        changed |= self._bind([_text(self.source, left)], right)
            if not changed:
                break

    def derived_names(self, node) -> list[str]:
        names: list[str] = []
        for sub in _iter_nodes(node):
            if sub.type == "identifier":
                name = _text(self.source, sub)
                if name in self.origins and name not in names:
                    names.append(name)
        return names[:4]


def _evidence(
    taint: _HandlerTaint, expr, label: str, *, sink: str, missing_guard: str
) -> dict[str, Any]:
    path = [
        f"untrusted `{name}` from {taint.origins[name]}"
        for name in taint.derived_names(expr)
    ]
    if not path:
        path = [f"untrusted input from {label}"]
    path.append(f"reaches {sink}")
    return {
        "evidence_kind": "ts_request_taint",
        "source": label,
        "sources": [label],
        "sink": sink,
        "path": path,
        "guards_seen": [],
        "guards_missing": [missing_guard],
        "analysis_complete": False,
    }


def _object_has_key(source: bytes, node, key: str) -> bool:
    node = _unwrap(node)
    if node is None or node.type != "object":
        return False
    for child in node.named_children:
        if child.type == "pair":
            k = child.child_by_field_name("key")
            if k is not None and _text(source, k).strip("'\"") == key:
                return True
        elif child.type == "shorthand_property_identifier":
            if _text(source, child) == key:
                return True
    return False


_PATH_GUARD_RE_TEMPLATE = r"\b{name}\s*\.\s*(?:startsWith|includes|indexOf)\s*\("


def _path_guarded(taint: _HandlerTaint, arg, sink_node) -> bool:
    """A prior `if` testing startsWith/includes on the sink value is a guard."""
    names = set(taint.derived_names(arg))
    arg = _unwrap(arg)
    if arg is not None and arg.type == "identifier":
        names.add(_text(taint.source, arg))
    if not names:
        return False
    for node in taint.nodes:
        if node.start_byte >= sink_node.start_byte:
            break
        if node.type != "if_statement":
            continue
        cond = node.child_by_field_name("condition")
        if cond is None:
            continue
        cond_text = _text(taint.source, cond)
        for name in names:
            if re.search(_PATH_GUARD_RE_TEMPLATE.format(name=re.escape(name)), cond_text):
                return True
    return False


def _finding(
    file_path: str,
    node,
    rule_id: str,
    severity: str,
    message: str,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": str(file_path),
        "line": node.start_point[0] + 1,
        "col": node.start_point[1],
    }
    if evidence is not None:
        finding["security_evidence"] = evidence
    return finding


def _check_tls_env(source: bytes, root, file_path: str) -> list[dict[str, Any]]:
    findings = []
    for node in _iter_nodes(root):
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        right = _unwrap(node.child_by_field_name("right"))
        if left is None or right is None:
            continue
        path = _member_path(source, left)
        if path != ["process", "env", _TLS_ENV]:
            continue
        value = _string_value(source, right)
        if value is None and right.type == "number":
            value = _text(source, right)
        if value is None or value.strip() != "0":
            continue
        findings.append(
            _finding(
                file_path,
                node,
                "SKY-D210",
                "HIGH",
                "NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate "
                "verification for every outbound connection in the process",
                None,
            )
        )
    return findings


def _check_handler(
    source: bytes,
    file_path: str,
    taint: _HandlerTaint,
    cp_names: _ChildProcessNames,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in taint.nodes:
        if node.type != "call_expression":
            continue
        callee = _unwrap(node.child_by_field_name("function"))
        if callee is None:
            continue
        args = _call_args(node)
        if not args:
            continue
        first = args[0]

        if cp_names.is_exec_call(source, node):
            label = taint.taint(first, "cmd")
            if label:
                findings.append(
                    _finding(
                        file_path,
                        node,
                        "SKY-D212",
                        "CRITICAL",
                        "Command injection: request data reaches "
                        "child_process.exec() command text. Use execFile() "
                        "with an argument array.",
                        _evidence(
                            taint,
                            first,
                            label,
                            sink="child_process.exec() command",
                            missing_guard="argument array (execFile/spawn) or shell quoting",
                        ),
                    )
                )
            continue

        if callee.type != "member_expression":
            continue
        prop = callee.child_by_field_name("property")
        obj = _unwrap(callee.child_by_field_name("object"))
        if prop is None or obj is None:
            continue
        method = _text(source, prop)

        if method in {"$queryRawUnsafe", "$executeRawUnsafe"}:
            label = taint.taint(first, "sql")
            if label:
                findings.append(
                    _finding(
                        file_path,
                        node,
                        "SKY-D211",
                        "CRITICAL",
                        f"SQL injection: request data interpolated into "
                        f"{method}() query text. Use $queryRaw`...` or pass "
                        "values as parameters.",
                        _evidence(
                            taint,
                            first,
                            label,
                            sink=f"{method}() query text",
                            missing_guard="parameterized query",
                        ),
                    )
                )
            continue

        if obj.type != "identifier":
            continue
        receiver = _text(source, obj)
        if receiver != taint.res and receiver not in _RESPONSE_NAMES:
            continue

        if method in {"send", "write", "end"}:
            label = taint.taint(first, "xss")
            if not label:
                continue
            html = _has_html_literal(source, first)
            unwrapped = _unwrap(first)
            if (
                not html
                and unwrapped is not None
                and unwrapped.type == "identifier"
                and _text(source, unwrapped) in taint.html_names
            ):
                html = True
            if not html:
                continue
            findings.append(
                _finding(
                    file_path,
                    node,
                    "SKY-D228",
                    "HIGH",
                    f"XSS: HTML built from unescaped request data is sent "
                    f"with {receiver}.{method}()",
                    _evidence(
                        taint,
                        first,
                        label,
                        sink=f"{receiver}.{method}() HTML response",
                        missing_guard="HTML escaping or a template engine with autoescape",
                    ),
                )
            )
        elif method in {"sendFile", "download"}:
            if len(args) > 1 and _object_has_key(source, args[1], "root"):
                continue
            label = taint.taint(first, "path")
            if not label or _path_guarded(taint, first, node):
                continue
            findings.append(
                _finding(
                    file_path,
                    node,
                    "SKY-D215",
                    "HIGH",
                    f"Path traversal: request data reaches {receiver}.{method}() "
                    "without a root option or normalized-prefix check",
                    _evidence(
                        taint,
                        first,
                        label,
                        sink=f"{receiver}.{method}() path",
                        missing_guard="{ root } option, path.basename, or startsWith check on the resolved path",
                    ),
                )
            )
    return findings


def scan_express_taint_sinks(
    root_node, source: bytes, file_path: str, *, is_test_file: bool = False
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not is_test_file and _TLS_ENV.encode() in source:
        findings.extend(_check_tls_env(source, root_node, file_path))
    if not _SOURCE_HINT_RE.search(source):
        return findings

    cp_names = _ChildProcessNames(source, root_node)
    seen: set[tuple[str, int, int]] = set()
    for node in _iter_nodes(root_node):
        if node.type not in _FUNCTION_TYPES:
            continue
        names = _handler_names(source, node)
        if names is None:
            continue
        taint = _HandlerTaint(source, node, *names)
        for finding in _check_handler(source, file_path, taint, cp_names):
            key = (finding["rule_id"], finding["line"], finding["col"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def merge_express_taint_findings(
    findings: list[dict[str, Any]], new_findings: list[dict[str, Any]]
) -> None:
    """Append new findings, enriching an existing same-line same-rule finding."""
    for finding in new_findings:
        existing = next(
            (
                f
                for f in findings
                if f.get("rule_id") == finding["rule_id"]
                and f.get("line") == finding["line"]
            ),
            None,
        )
        if existing is None:
            findings.append(finding)
            continue
        if "security_evidence" in finding and "security_evidence" not in existing:
            existing["security_evidence"] = finding["security_evidence"]
