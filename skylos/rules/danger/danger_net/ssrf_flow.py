from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor, URL_SANITIZERS


HTTP_MODULES = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "urllib3",
        "http",
        "treq",
        "asks",
        "pycurl",
        "grequests",
    }
)

HTTP_RECEIVER_NAMES = frozenset(
    {
        "requests",
        "httpx",
        "client",
        "http_client",
        "http",
        "session",
        "aiohttp",
        "resp",
        "response",
    }
)

NON_HTTP_RECEIVER_NAMES = frozenset(
    {
        "dict",
        "defaultdict",
        "cache",
        "registry",
        "resolver",
        "graph",
        "visited",
        "seen",
        "mapping",
        "config",
        "settings",
        "env",
        "os",
        "self",
    }
)


def _qualified_name_from_call(node):
    func = node.func
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _receiver_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        value = node.func.value
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            return value.attr
    return None


def _qualified_name_from_expr(node: ast.AST) -> str | None:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _has_safe_base_url(node):
    if not node.values:
        return True

    first = node.values[0]

    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        val = first.value

        if "://" in val:
            parts = val.split("://", 1)
            if len(parts) > 1 and "/" in parts[1]:
                return True

    return False


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_absolute_host(value):
    if not isinstance(value, str) or "://" not in value:
        return False
    scheme, rest = value.split("://", 1)
    host = rest.split("/", 1)[0]
    return bool(scheme and host)


def _leftmost_constant_prefix(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            if isinstance(value, ast.FormattedValue):
                return ""
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _leftmost_constant_prefix(node.left)
    return ""


def _urljoin_target_can_override_host(node):
    literal = _constant_string(node)
    if literal is not None:
        return literal.startswith(("http://", "https://", "//"))

    prefix = _leftmost_constant_prefix(node)
    if prefix.startswith(("http://", "https://", "//")):
        return True

    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and ("://" in value.value or value.value.startswith("//"))
            for value in node.values
        )

    return False


def _urljoin_target_is_host_constrained(node):
    literal = _constant_string(node)
    if literal is not None:
        return not _urljoin_target_can_override_host(node)

    prefix = _leftmost_constant_prefix(node)
    if not prefix:
        return False
    if prefix.startswith(("http://", "https://", "//")):
        return False
    if prefix.startswith(("/", "\\")):
        return False
    if ":" in prefix:
        return False
    if "/" not in prefix and "\\" not in prefix:
        return False
    if "://" in prefix:
        return False
    return True


def _is_fixed_host_urljoin(node):
    if not isinstance(node, ast.Call):
        return False
    qn = _qualified_name_from_call(node)
    if qn not in {"urljoin", "urllib.parse.urljoin"}:
        return False
    if len(node.args) < 2:
        return False

    base = _constant_string(node.args[0])
    if not _has_absolute_host(base):
        return False

    return _urljoin_target_is_host_constrained(node.args[1])


def _tainted_url_is_ssrf_relevant(checker, node):
    if isinstance(node, ast.JoinedStr) and _has_safe_base_url(node):
        return False
    if _is_fixed_host_urljoin(node):
        return False
    return checker.is_tainted(node)


def _is_interpolated_string(node):
    if isinstance(node, ast.JoinedStr):
        if _has_safe_base_url(node):
            return False
        return True

    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def _safe_expr_text(node: ast.AST | None, max_length: int = 160) -> str:
    if node is None:
        return "unknown"
    try:
        text = ast.unparse(node)
    except Exception:
        text = type(node).__name__
    text = " ".join(str(text).split())
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text or "unknown"


def _request_base_name(node: ast.AST | None) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None


def _source_label(node: ast.AST, *, interpolated: bool) -> str:
    if _request_base_name(node) == "request":
        return "request-derived URL value"
    if isinstance(node, ast.Name):
        return f"tainted variable `{node.id}`"
    if isinstance(node, ast.JoinedStr) or interpolated:
        return "interpolated URL expression"
    return "tainted URL expression"


def _ssrf_security_evidence(
    *,
    symbol: str,
    sink: str,
    url_arg: ast.AST,
    interpolated: bool,
) -> dict:
    source = _source_label(url_arg, interpolated=interpolated)
    expression = _safe_expr_text(url_arg)
    entrypoint = symbol if symbol and symbol != "<module>" else None

    evidence = {
        "evidence_kind": "source_to_sink",
        "source": source,
        "sink": sink,
        "path": [
            source,
            f"url expression `{expression}`",
            f"HTTP sink `{sink}`",
        ],
        "guards_seen": [],
        "guards_missing": [
            "URL host or scheme allowlist",
            "private, loopback, and metadata host rejection",
        ],
        "confidence_reason": (
            "Untrusted URL data can influence the outbound HTTP request target."
        ),
        "test_hint": (
            "Assert untrusted input cannot control the request host and private "
            "or metadata URLs are rejected before the HTTP client call."
        ),
        "fix_shape": "validate and allowlist the URL before the HTTP request",
    }
    if entrypoint:
        evidence["entrypoint"] = entrypoint
    return evidence


class _SSRFFlowChecker(TaintVisitor):
    HTTP_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}

    def __init__(self, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.http_names: set[str] = set()
        self.http_receiver_alias_stack: list[set[str]] = [set()]

    def _push(self):
        super()._push()
        self.http_receiver_alias_stack.append(set())

    def _pop(self):
        if len(self.http_receiver_alias_stack) > 1:
            self.http_receiver_alias_stack.pop()
        super()._pop()

    def _mark_http_receiver_alias(self, name: str) -> None:
        if not self.http_receiver_alias_stack:
            self.http_receiver_alias_stack.append(set())
        self.http_receiver_alias_stack[-1].add(name)

    def _is_known_http_receiver_name(self, name: str) -> bool:
        if name in self.http_names:
            return True
        return any(name in scope for scope in reversed(self.http_receiver_alias_stack))

    def _is_http_reference(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            return self._is_http_reference(node.func)

        if isinstance(node, ast.Name):
            return self._is_known_http_receiver_name(node.id)

        qual_name = _qualified_name_from_expr(node)
        if not qual_name:
            return False

        root = qual_name.split(".", 1)[0]
        if root in HTTP_MODULES:
            return True
        return self._is_known_http_receiver_name(root)

    def _track_http_receiver_aliases(self, targets, value: ast.AST | None) -> None:
        if value is None or not self._is_http_reference(value):
            return

        for target in targets:
            if isinstance(target, ast.Name):
                self._mark_http_receiver_alias(target.id)
            elif isinstance(target, ast.Attribute):
                self._mark_http_receiver_alias(target.attr)

    def is_tainted(self, node):
        if isinstance(node, ast.JoinedStr) and _has_safe_base_url(node):
            return False
        if _is_fixed_host_urljoin(node):
            return False
        return super().is_tainted(node)

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in HTTP_MODULES:
                self.http_names.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_level = node.module.split(".")[0]
            if top_level in HTTP_MODULES:
                for alias in node.names:
                    self.http_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node):
        self._track_http_receiver_aliases(node.targets, node.value)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        self._track_http_receiver_aliases([node.target], node.value)
        super().visit_AnnAssign(node)

    def _is_likely_http_receiver(self, node: ast.Call) -> bool:
        name = _receiver_name(node)
        if name is None:
            return False

        if self._is_known_http_receiver_name(name):
            return True

        if name.lower() in NON_HTTP_RECEIVER_NAMES:
            return False

        if name.lower() in HTTP_RECEIVER_NAMES:
            return True

        lower = name.lower()
        if any(hint in lower for hint in ("http", "request", "client", "session")):
            return True

        return False

    def _append_finding(self, node: ast.Call, url_arg: ast.AST, sink: str) -> None:
        interpolated = _is_interpolated_string(url_arg)
        symbol = self._current_symbol()
        self.findings.append(
            {
                "rule_id": "SKY-D216",
                "severity": "CRITICAL",
                "message": "Possible SSRF: tainted URL passed to HTTP client.",
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": symbol,
                "metadata": {
                    "security_evidence": _ssrf_security_evidence(
                        symbol=symbol,
                        sink=sink,
                        url_arg=url_arg,
                        interpolated=interpolated,
                    )
                },
            }
        )

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)

        if qn and "." in qn:
            parts = qn.rsplit(".", 1)
            func = parts[1]
            if func in self.HTTP_METHODS and node.args:
                if self._is_likely_http_receiver(node):
                    url_arg = node.args[0]
                    if _is_interpolated_string(
                        url_arg
                    ) or _tainted_url_is_ssrf_relevant(self, url_arg):
                        self._append_finding(node, url_arg, qn)

        if qn and qn.endswith(".urlopen") and node.args:
            url_arg = node.args[0]
            if _is_interpolated_string(url_arg) or _tainted_url_is_ssrf_relevant(
                self, url_arg
            ):
                self._append_finding(node, url_arg, qn)

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SSRFFlowChecker(file_path, findings, sanitizers=URL_SANITIZERS)
        checker.visit(tree)
    except Exception as e:
        print(f"SSRF flow analysis failed for {file_path}: {e}", file=sys.stderr)
