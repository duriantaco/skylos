from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

RULE_ID = "SKY-D282"

_WEBHOOK_PROVIDER_HINTS = (
    "stripe",
    "github",
    "clerk",
    "svix",
    "shopify",
    "supabase",
    "resend",
    "twilio",
    "slack",
    "discord",
    "linear",
    "vercel",
    "netlify",
    "paddle",
    "lemon_squeezy",
    "lemonsqueezy",
)

_REQUEST_BODY_HINTS = (
    "request.get_json",
    "request.json",
    "request.data",
    "request.body",
    "await request.body",
    "await request.json",
    "json.loads(request.body",
)

_WEBHOOK_VERIFY_WINDOW_CHARS = 4096
_WEBHOOK_VERIFY_MAX_CANDIDATES = 64
_WEBHOOK_CONSTRUCTOR_PATTERN = re.compile(r"\bWebhook\s*\(", re.I)
_WEBHOOK_INSTANCE_VERIFY_PATTERN = re.compile(r"\.verify\s*\(", re.I)

_VERIFY_PATTERNS = (
    re.compile(r"\bconstruct_event\s*\(", re.I),
    re.compile(r"\bconstructevent\s*\(", re.I),
    re.compile(r"\bverify_signature\s*\(", re.I),
    re.compile(r"\bverify_webhook\s*\(", re.I),
    re.compile(r"\bverifywebhook\s*\(", re.I),
    re.compile(r"\bverifysignature\s*\(", re.I),
    re.compile(r"\bvalidate_signature\s*\(", re.I),
    re.compile(r"\bvalidate_webhook\s*\(", re.I),
    re.compile(r"\bvalidatesignature\s*\(", re.I),
    re.compile(r"\bvalidatewebhook\s*\(", re.I),
    re.compile(r"\bhmac\.compare_digest\s*\(", re.I),
    re.compile(r"\bhmac\.new\s*\(", re.I),
    re.compile(r"\bWebhook\.verify\s*\(", re.I),
)

_TEST_PATH_PARTS = {"test", "tests", "fixtures", "fixture"}


def _is_test_path(file_path: str | Path) -> bool:
    normalized = str(file_path).replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    base = Path(normalized).name
    return (
        bool(parts & _TEST_PATH_PARTS)
        or base.startswith("test_")
        or base.endswith("_test.py")
    )


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _string_values(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for item in node.elts:
            values.extend(_string_values(item))
        return values
    return []


def _decorator_route_path(decorator: ast.AST) -> str:
    call = decorator if isinstance(decorator, ast.Call) else None
    if call is None or not call.args:
        return ""
    first_arg = call.args[0]
    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
        return first_arg.value
    return ""


def _decorator_has_post(decorator: ast.AST) -> bool:
    call = decorator if isinstance(decorator, ast.Call) else None
    name = _dotted_name(call.func if call else decorator).lower()
    tail = name.rsplit(".", 1)[-1]
    if tail == "post":
        return True

    if call is None or tail != "route":
        return False

    for keyword in call.keywords:
        if keyword.arg == "methods":
            methods = {value.upper() for value in _string_values(keyword.value)}
            if "POST" in methods:
                return True
    return False


def _function_source(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    if segment is not None:
        return segment
    start = max(getattr(node, "lineno", 1) - 1, 0)
    end = getattr(node, "end_lineno", start + 1)
    return "\n".join(source.splitlines()[start:end])


def _has_provider_hint(text: str) -> bool:
    lower = text.lower()
    return any(provider in lower for provider in _WEBHOOK_PROVIDER_HINTS)


def _uses_request_body(text: str) -> bool:
    lower = text.lower()
    return any(hint in lower for hint in _REQUEST_BODY_HINTS)


def _has_webhook_instance_verification(text: str) -> bool:
    for index, match in enumerate(_WEBHOOK_CONSTRUCTOR_PATTERN.finditer(text)):
        if index >= _WEBHOOK_VERIFY_MAX_CANDIDATES:
            return False
        window = text[match.end() : match.end() + _WEBHOOK_VERIFY_WINDOW_CHARS]
        if _WEBHOOK_INSTANCE_VERIFY_PATTERN.search(window):
            return True
    return False


def _has_signature_verification(text: str) -> bool:
    return any(pattern.search(text) for pattern in _VERIFY_PATTERNS) or (
        _has_webhook_instance_verification(text)
    )


class _WebhookSignatureChecker(ast.NodeVisitor):
    def __init__(self, file_path: str | Path, findings: list[dict], source: str):
        self.file_path = file_path
        self.findings = findings
        self.source = source
        self.path_text = str(file_path).replace("\\", "/")

    def generic_visit(self, node: ast.AST) -> None:
        for _field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def _report(self, node: ast.AST) -> None:
        self.findings.append(
            {
                "rule_id": RULE_ID,
                "severity": "HIGH",
                "message": (
                    "Webhook handler processes inbound events without obvious "
                    "signature verification. Verify provider signatures before "
                    "parsing or trusting the event body."
                ),
                "file": str(self.file_path),
                "line": getattr(node, "lineno", 1),
                "col": getattr(node, "col_offset", 0),
            }
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        function_text = _function_source(self.source, node)
        route_paths = [_decorator_route_path(deco) for deco in node.decorator_list]
        combined = "\n".join([self.path_text, node.name, *route_paths, function_text])
        combined_lower = combined.lower()

        if "webhook" not in combined_lower and "webhooks" not in combined_lower:
            return
        if not _has_provider_hint(combined):
            return

        has_post = any(_decorator_has_post(deco) for deco in node.decorator_list)
        if not has_post and not re.search(
            r"\brequest\.method\s*(?:==|===)\s*['\"]POST['\"]", function_text
        ):
            return

        if not _uses_request_body(function_text):
            return
        if _has_signature_verification(function_text):
            return

        self._report(node)


def scan(tree: ast.AST, file_path, findings, *, source: str | None = None) -> None:
    try:
        if _is_test_path(file_path):
            return
        if source is None:
            source = Path(file_path).read_text(  # skylos: ignore[SKY-D215]
                encoding="utf-8", errors="ignore"
            )
        checker = _WebhookSignatureChecker(file_path, findings, source)
        checker.visit(tree)
    except Exception as e:
        print(
            f"Webhook signature analysis failed for {file_path}: {e}", file=sys.stderr
        )
