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

    if isinstance(first, ast.FormattedValue):
        if isinstance(first.value, ast.Name) and first.value.id.isupper():
            return True

    return False


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


class _SSRFFlowChecker(TaintVisitor):
    HTTP_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}

    def __init__(self, file_path, findings, sanitizers=None):
        super().__init__(file_path, findings, sanitizers=sanitizers)
        self.http_names: set[str] = set()

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

    def _is_likely_http_receiver(self, node: ast.Call) -> bool:
        name = _receiver_name(node)
        if name is None:
            return False

        if name.lower() in NON_HTTP_RECEIVER_NAMES:
            return False

        if name in self.http_names:
            return True

        if name.lower() in HTTP_RECEIVER_NAMES:
            return True

        lower = name.lower()
        if any(hint in lower for hint in ("http", "request", "client", "session")):
            return True

        return False

    def visit_Call(self, node):
        qn = _qualified_name_from_call(node)

        if qn and "." in qn:
            parts = qn.rsplit(".", 1)
            func = parts[1]
            if func in self.HTTP_METHODS and node.args:
                if self._is_likely_http_receiver(node):
                    url_arg = node.args[0]
                    if _is_interpolated_string(url_arg) or self.is_tainted(url_arg):
                        self.findings.append(
                            {
                                "rule_id": "SKY-D216",
                                "severity": "CRITICAL",
                                "message": "Possible SSRF: tainted URL passed to HTTP client.",
                                "file": str(self.file_path),
                                "line": node.lineno,
                                "col": node.col_offset,
                                "symbol": self._current_symbol(),
                            }
                        )

        if qn and qn.endswith(".urlopen") and node.args:
            url_arg = node.args[0]
            if _is_interpolated_string(url_arg) or self.is_tainted(url_arg):
                self.findings.append(
                    {
                        "rule_id": "SKY-D216",
                        "severity": "CRITICAL",
                        "message": "Possible SSRF: tainted URL passed to HTTP client.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SSRFFlowChecker(file_path, findings, sanitizers=URL_SANITIZERS)
        checker.visit(tree)
    except Exception as e:
        print(f"SSRF flow analysis failed for {file_path}: {e}", file=sys.stderr)
