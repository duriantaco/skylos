"""
MCP Server Security Scanner — SKY-D240 through SKY-D244.

Detects MCP-specific vulnerabilities in Python MCP server source code:
  D240  Tool description poisoning (prompt injection in tool metadata)
  D241  Unauthenticated network transport (SSE/HTTP without auth)
  D242  Overly permissive resource URI (path traversal via template)
  D243  Network-exposed MCP server without auth (host 0.0.0.0)
  D244  Hardcoded secrets in MCP tool parameter defaults
"""

from __future__ import annotations

import ast
import re
import sys


# ---------------------------------------------------------------------------
# D240: prompt-injection patterns in tool descriptions / docstrings
# ---------------------------------------------------------------------------
_INJECTION_TAG_RE = re.compile(
    r"<\s*/?\s*("
    r"system|instruction|s>|admin|prompt|context|rules|configuration"
    r"|im_start|im_end|endoftext|message"
    r")\b",
    re.IGNORECASE,
)

_INJECTION_PHRASE_RE = re.compile(
    r"("
    r"ignore\s+(all\s+)?previous\s+instructions?"
    r"|disregard\s+(all\s+)?(previous|above|prior)"
    r"|you\s+are\s+now\s+a"
    r"|forget\s+(all\s+)?previous"
    r"|new\s+system\s+prompt"
    r"|override\s+(all\s+)?instructions?"
    r"|do\s+not\s+follow\s+(any\s+)?previous"
    r")",
    re.IGNORECASE,
)

# Hidden Unicode: zero-width chars, RTL overrides, BOM
_HIDDEN_UNICODE_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"
    r"\u2028\u2029\u202a\u202b\u202c\u202d\u202e"
    r"\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\ufff9\ufffa\ufffb]"
)

# ---------------------------------------------------------------------------
# D244: patterns that look like hardcoded secrets
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    re.compile(r"^sk-[a-zA-Z0-9]{20,}$"),  # OpenAI
    re.compile(r"^sk-ant-[a-zA-Z0-9\-]{20,}$"),  # Anthropic
    re.compile(r"^AKIA[A-Z0-9]{16}$"),  # AWS access key
    re.compile(r"^ghp_[a-zA-Z0-9]{36}$"),  # GitHub PAT
    re.compile(r"^gho_[a-zA-Z0-9]{36}$"),  # GitHub OAuth
    re.compile(r"^glpat-[a-zA-Z0-9\-]{20,}$"),  # GitLab PAT
    re.compile(r"^xox[bpsar]-[a-zA-Z0-9\-]{10,}$"),  # Slack
    re.compile(r"^sk_live_[a-zA-Z0-9]{20,}$"),  # Stripe
    re.compile(r"^rk_live_[a-zA-Z0-9]{20,}$"),  # Stripe restricted
    re.compile(r"^Bearer\s+[a-zA-Z0-9\-_.]{20,}$"),  # Bearer tokens
    re.compile(r"^Basic\s+[a-zA-Z0-9+/=]{20,}$"),  # Basic auth
    re.compile(r"^eyJ[a-zA-Z0-9\-_]{20,}"),  # JWT
]

# ---------------------------------------------------------------------------
# MCP library detection
# ---------------------------------------------------------------------------
_MCP_IMPORTS = {
    "mcp",
    "fastmcp",
    "mcp.server",
    "mcp.server.fastmcp",
    "mcp.server.lowlevel",
}

_MCP_SERVER_CLASSES = {"FastMCP", "Server"}

_MCP_TOOL_DECORATORS = {"tool", "resource", "prompt"}

_NETWORK_TRANSPORTS = {"sse", "streamable-http", "streamable_http", "http"}


def _qualified_name(node):
    """Build dotted name from AST attribute chain."""
    func = node.func if isinstance(node, ast.Call) else node
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _get_string_value(node):
    """Extract string from a Constant node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_mcp_file(tree):
    """Check if the file imports any MCP library."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _MCP_IMPORTS or alias.name.startswith("mcp."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (
                node.module in _MCP_IMPORTS or node.module.startswith("mcp.")
            ):
                return True
    return False


def _get_decorator_name(decorator):
    """Get the method name from a decorator (e.g., 'tool' from @server.tool())."""
    if isinstance(decorator, ast.Call):
        if isinstance(decorator.func, ast.Attribute):
            return decorator.func.attr
        if isinstance(decorator.func, ast.Name):
            return decorator.func.id
    elif isinstance(decorator, ast.Attribute):
        return decorator.attr
    elif isinstance(decorator, ast.Name):
        return decorator.id
    return None


def _is_mcp_tool_function(node):
    """Check if a FunctionDef is decorated with @server.tool() or similar."""
    for dec in node.decorator_list:
        name = _get_decorator_name(dec)
        if name in _MCP_TOOL_DECORATORS:
            return True
    return False


def _get_docstring(node):
    """Extract docstring from a function/class definition."""
    if (
        node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    ):
        return node.body[0].value.value
    return None


def _get_decorator_description(decorator):
    """Extract description= kwarg or first positional string arg from decorator."""
    if not isinstance(decorator, ast.Call):
        return None
    for kw in decorator.keywords:
        if kw.arg == "description":
            return _get_string_value(kw.value)
    return None


class _MCPChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self._mcp_server_vars = set()

    def _report(self, rule_id, node, message, severity="HIGH"):
        self.findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
            }
        )

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    # -- Track MCP server variable names --

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            qn = _qualified_name(node.value)
            if qn and any(qn.endswith(cls) for cls in _MCP_SERVER_CLASSES):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._mcp_server_vars.add(target.id)
        self.generic_visit(node)

    # -- D240: Tool description poisoning --

    def _check_text_for_injection(self, text, node, context):
        """Scan a string for prompt injection patterns."""
        if _INJECTION_TAG_RE.search(text):
            self._report(
                "SKY-D240",
                node,
                f"MCP tool poisoning: suspicious injection tag in {context}.",
                severity="CRITICAL",
            )
        if _INJECTION_PHRASE_RE.search(text):
            self._report(
                "SKY-D240",
                node,
                f"MCP tool poisoning: prompt injection phrase in {context}.",
                severity="CRITICAL",
            )
        if _HIDDEN_UNICODE_RE.search(text):
            self._report(
                "SKY-D240",
                node,
                f"MCP tool poisoning: hidden Unicode characters in {context}.",
                severity="HIGH",
            )

    def visit_FunctionDef(self, node):
        self._check_mcp_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_mcp_function(node)
        self.generic_visit(node)

    def _check_mcp_function(self, node):
        if not _is_mcp_tool_function(node):
            return

        # D240: Check docstring
        docstring = _get_docstring(node)
        if docstring:
            self._check_text_for_injection(docstring, node.body[0], "tool docstring")

        # D240: Check description= kwarg in decorator
        for dec in node.decorator_list:
            desc = _get_decorator_description(dec)
            if desc:
                self._check_text_for_injection(desc, dec, "tool description")

        # D242: Check resource URI patterns for path traversal
        for dec in node.decorator_list:
            dec_name = _get_decorator_name(dec)
            if dec_name == "resource" and isinstance(dec, ast.Call):
                for arg in dec.args:
                    uri = _get_string_value(arg)
                    if uri:
                        self._check_resource_uri(uri, dec)
                for kw in dec.keywords:
                    if kw.arg == "uri":
                        uri = _get_string_value(kw.value)
                        if uri:
                            self._check_resource_uri(uri, dec)

        # D244: Check default parameter values for hardcoded secrets
        self._check_param_defaults(node)

    def _check_resource_uri(self, uri, node):
        """D242: Flag resource URIs that allow arbitrary path traversal."""
        # Pattern: file:///{path} or similar with unconstrained path template
        if re.search(r"file://.*\{", uri):
            self._report(
                "SKY-D242",
                node,
                f"MCP permissive resource URI: '{uri}' may allow path traversal.",
                severity="HIGH",
            )
            return
        # Generic: any URI with {path} or {file} template vars
        if re.search(r"\{(path|file|filename|dir|directory|filepath)\}", uri, re.I):
            # Only flag if no fixed prefix constraining the path
            parts = uri.split("://", 1)
            if len(parts) == 2:
                path_part = parts[1]
                # If the template var is at root level or near-root
                if re.match(r"^/?\{", path_part) or re.match(r"^[^/]*/?\{", path_part):
                    self._report(
                        "SKY-D242",
                        node,
                        f"MCP permissive resource URI: '{uri}' allows unconstrained path access.",
                        severity="HIGH",
                    )

    def _check_param_defaults(self, node):
        """D244: Flag hardcoded secrets as default values in MCP tool params."""
        defaults = []
        args_obj = node.args

        # Collect (arg_name, default_node) pairs
        num_args = len(args_obj.args)
        num_defaults = len(args_obj.defaults)
        offset = num_args - num_defaults
        for i, default in enumerate(args_obj.defaults):
            arg = args_obj.args[offset + i]
            defaults.append((arg.arg, default))

        for arg, default in zip(args_obj.kwonlyargs, args_obj.kw_defaults):
            if default is not None:
                defaults.append((arg.arg, default))

        for arg_name, default_node in defaults:
            val = _get_string_value(default_node)
            if not val or len(val) < 10:
                continue
            for pattern in _SECRET_PATTERNS:
                if pattern.search(val):
                    self._report(
                        "SKY-D244",
                        default_node,
                        f"Hardcoded secret in MCP tool parameter default '{arg_name}'.",
                        severity="CRITICAL",
                    )
                    break

    # -- D241 / D243: server.run() checks --

    def visit_Call(self, node):
        qn = _qualified_name(node)
        if not qn:
            self.generic_visit(node)
            return

        # Check if this is server.run() on a known MCP server var
        parts = qn.rsplit(".", 1)
        if len(parts) == 2 and parts[1] == "run":
            obj_name = parts[0]
            if obj_name in self._mcp_server_vars or obj_name in (
                "server",
                "mcp",
                "app",
            ):
                self._check_server_run(node)

        self.generic_visit(node)

    def _check_server_run(self, node):
        """Check server.run() for D241 (unauth transport) and D243 (0.0.0.0)."""
        transport = None
        host = None
        has_auth = False

        for kw in node.keywords:
            if kw.arg == "transport":
                transport = _get_string_value(kw.value)
            elif kw.arg == "host":
                host = _get_string_value(kw.value)
            elif kw.arg in (
                "auth",
                "authenticator",
                "auth_server_provider",
                "middleware",
                "auth_middleware",
            ):
                has_auth = True

        is_network = False
        if transport and transport.lower() in _NETWORK_TRANSPORTS:
            is_network = True
        if host and host != "127.0.0.1" and host != "localhost":
            is_network = True

        # D241: Network transport without auth
        if is_network and not has_auth:
            self._report(
                "SKY-D241",
                node,
                f"MCP server uses network transport"
                f"{' (' + transport + ')' if transport else ''}"
                f" without authentication.",
                severity="HIGH",
            )

        # D243: Bound to 0.0.0.0
        if host == "0.0.0.0" and not has_auth:
            self._report(
                "SKY-D243",
                node,
                "MCP server bound to 0.0.0.0 without authentication — "
                "accessible from any network interface.",
                severity="CRITICAL",
            )


def scan(tree, file_path, findings):
    """Entry point called by danger.py — only runs on MCP server files."""
    if not _is_mcp_file(tree):
        return
    try:
        checker = _MCPChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"MCP analysis failed for {file_path}: {e}", file=sys.stderr)
