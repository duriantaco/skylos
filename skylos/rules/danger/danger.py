from __future__ import annotations
import ast
import os
import sys
from pathlib import Path
from .danger_sql.sql_flow import scan as scan_sql
from .danger_cmd.cmd_flow import scan as scan_cmd
from .danger_sql.sql_raw_flow import scan as scan_sql_raw
from .danger_net.ssrf_flow import scan as scan_ssrf
from .danger_fs.path_flow import scan as scan_path
from .danger_web.xss_flow import scan as scan_xss
from .danger_redirect.redirect_flow import scan as scan_redirect
from .danger_cors.cors_flow import scan as scan_cors
from .danger_jwt.jwt_flow import scan as scan_jwt
from .danger_access.access_flow import scan as scan_access
from .danger_mcp.mcp_flow import scan as scan_mcp
from .danger_webhook.webhook_flow import scan as scan_webhook
from .danger_agent.tool_privilege import scan as scan_agent_tool_privilege
from .danger_llm.consumption import scan as scan_llm_consumption
from .danger_llm.llm_flow import scan as scan_llm
from .danger_ml.model_deserialization import scan as scan_ml_model_load
from .danger_hallucination.dependency_hallucination import (
    scan_python_dependency_hallucinations,
)
from .danger_hallucination.api_signature_hallucination import (
    scan_python_api_signature_hallucinations,
)
from skylos.security.command_guard import (
    findings_for_command,
    is_external_url,
    is_sensitive_path,
)
from .calls import (
    DANGEROUS_CALLS,
    _matches_rule,
    _kw_equals,
    _qualified_name_from_call as qualified_name_from_call,
    _weak_random_has_security_context,
    _yaml_load_without_safeloader,
)


ALLOWED_SUFFIXES = (".py", ".pyi", ".pyw")

_BIDI_CONTROL_CHARS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


class _DangerousCallsChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self._symbol_stack = ["<module>"]
        self.aliases = {}
        self.assigned_calls_stack = [{}]
        self._parents_annotated = False

    def _annotate_parents(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            child.parent = node
            self._annotate_parents(child)

    def _current_symbol(self):
        if self._symbol_stack:
            return self._symbol_stack[-1]
        else:
            return "<module>"

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_FunctionDef(self, node):
        self._symbol_stack.append(node.name)
        self.assigned_calls_stack.append({})
        self.generic_visit(node)
        self.assigned_calls_stack.pop()
        self._symbol_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self._symbol_stack.append(node.name)
        self.assigned_calls_stack.append({})
        self.generic_visit(node)
        self.assigned_calls_stack.pop()
        self._symbol_stack.pop()

    def visit_ClassDef(self, node):
        self._symbol_stack.append(node.name)
        self.assigned_calls_stack.append({})
        self.generic_visit(node)
        self.assigned_calls_stack.pop()
        self._symbol_stack.pop()

    def visit_Module(self, node):
        if not self._parents_annotated:
            self._annotate_parents(node)
            self._parents_annotated = True
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            call_name = qualified_name_from_call(
                node.value, self.aliases, self.assigned_calls_stack[-1]
            )
            if call_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assigned_calls_stack[-1][target.id] = call_name
        self.generic_visit(node)

    def visit_Call(self, node):
        name = qualified_name_from_call(
            node, self.aliases, self.assigned_calls_stack[-1]
        )
        if name:
            for rule_key, tup in DANGEROUS_CALLS.items():
                rule_id, severity, message = tup[0], tup[1], tup[2]
                if len(tup) > 3:
                    opts = tup[3]
                else:
                    opts = None

                if not _matches_rule(name, rule_key):
                    continue

                if rule_key == "yaml.load" and not _yaml_load_without_safeloader(
                    node, self.aliases
                ):
                    continue

                if (
                    opts
                    and "kw_equals" in opts
                    and not _kw_equals(node, opts["kw_equals"])
                ):
                    continue

                if opts and opts.get("weak_random"):
                    if not _weak_random_has_security_context(
                        node, self._current_symbol()
                    ):
                        continue

                self.findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": severity,
                        "message": message,
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
                break

        self.generic_visit(node)

    def _append_shell_command_findings(self, name: str, node: ast.Call) -> None:
        if name == "os.system":
            command_node = node.args[0] if node.args else None
        elif name.startswith("subprocess.") and _call_kw_is_true(node, "shell"):
            command_node = node.args[0] if node.args else None
        else:
            return

        command = _constant_str(command_node)
        if command is None:
            return
        self.findings.extend(
            findings_for_command(
                command,
                self.file_path,
                node.lineno,
                col=node.col_offset,
            )
        )

    def _append_http_exfil_findings(self, name: str, node: ast.Call) -> None:
        if name in _HTTP_REQUEST_CALLS:
            method = _constant_str(node.args[0]) if node.args else None
            if method is None or method.upper() not in {"PATCH", "POST", "PUT"}:
                return
            url_node = node.args[1] if len(node.args) > 1 else None
        elif name in _HTTP_UPLOAD_CALLS:
            url_node = node.args[0] if node.args else None
        else:
            return

        url = _constant_str(url_node)
        if url is not None and not is_external_url(url):
            return
        if not _http_payload_contains_sensitive_data(node, self.aliases):
            return

        self.findings.append(
            {
                "rule_id": "SKY-D327",
                "severity": "CRITICAL",
                "message": (
                    "HTTP request sends environment variables or local secret "
                    "files to an external destination."
                ),
                "file": str(self.file_path),
                "line": node.lineno,
                "col": node.col_offset,
                "symbol": self._current_symbol(),
            }
        )


class _PythonCommandExfilChecker(_DangerousCallsChecker):
    def visit_Call(self, node):
        name = qualified_name_from_call(
            node, self.aliases, self.assigned_calls_stack[-1]
        )
        if name:
            self._append_shell_command_findings(name, node)
            self._append_http_exfil_findings(name, node)
        self.generic_visit(node)


_SQL_TOKENS = (
    ".execute",
    ".executemany",
    ".executescript",
    "execute(",
    "executemany(",
    "executescript(",
    ".text(",
    " text(",
    "read_sql",
    ".raw(",
    "objects.raw",
)
_SQL_RAW_TOKENS = (
    ".text(",
    " text(",
    "read_sql",
    ".raw(",
    "objects.raw",
)
_CMD_TOKENS = (
    "os.system",
    "subprocess",
    "popen",
    "exec_command",
    "shell=true",
    "shell = true",
)
_SSRF_TOKENS = (
    "requests",
    "httpx",
    "aiohttp",
    "urllib",
    "urllib3",
    "urlopen",
    "urljoin",
    "grequests",
    ".get(",
    ".post(",
    ".put(",
    ".patch(",
    ".delete(",
    ".request(",
)
_PATH_TOKENS = (
    "open(",
    "os.open",
    "os.unlink",
    "os.remove",
    "os.mkdir",
    "os.rmdir",
    "os.makedirs",
    "shutil.",
    "path(",
    "pathlib",
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "send_file",
    "send_from_directory",
    "extract(",
    "extractall",
    "tarfile",
    "zipfile",
)
_XSS_TOKENS = (
    "markup",
    "mark_safe",
    "render_template_string",
    "|safe",
    "autoescape false",
    "<",
)
_REDIRECT_TOKENS = ("redirect", "httpresponseredirect")
_CORS_TOKENS = (
    "cors",
    "access-control-allow-origin",
    "access_control_allow_origin",
    "cors_allow_all_origins",
    "origins",
)
_JWT_TOKENS = ("jwt", "verify_signature", "algorithms")
_MCP_TOKENS = ("mcp", "fastmcp")
_WEBHOOK_TOKENS = ("webhook", "webhooks")
_LLM_TOKENS = (
    "openai",
    "anthropic",
    "litellm",
    "chatopenai",
    "llmchain",
    "langchain",
    "llama_index",
    "huggingface_hub",
    "inferenceclient",
    "genai",
    "generativeai",
    "cohere",
    "bedrock",
    "invoke_model",
    "chat.completions.create",
    "responses.create",
    "embeddings.create",
    "messages.create",
    "generate_text",
    "stream_text",
    "generatetext",
    "streamtext",
)
_AGENT_TOOL_TOKENS = (
    "agentexecutor",
    "code_interpreter",
    "computer_use_preview",
    "create_openai_functions_agent",
    "create_openai_tools_agent",
    "create_react_agent",
    "create_structured_chat_agent",
    "crewai",
    "initialize_agent",
    "load_tools",
    "pythonastrepltool",
    "pythonrepltool",
    "shelltool",
    "structuredtool",
    "tool(",
    "tools=",
    "tools =",
)
_ML_MODEL_LOAD_TOKENS = (
    "torch.load",
    "weights_only",
    "joblib.load",
    "numpy.load",
    "allow_pickle",
    "load_model",
    "hf_hub_download",
    "snapshot_download",
    "huggingface_hub",
    "from_pretrained",
    "load_dataset",
    "transformers",
    "datasets",
    ".pt",
    ".pth",
    ".ckpt",
    ".joblib",
    ".pkl",
    ".pickle",
)
_HTTP_UPLOAD_CALLS = {
    "httpx.patch",
    "httpx.post",
    "httpx.put",
    "requests.patch",
    "requests.post",
    "requests.put",
}
_HTTP_REQUEST_CALLS = {"httpx.request", "requests.request"}


def _constant_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    return None


def _call_kw_is_true(node: ast.Call, name: str) -> bool:
    return any(
        kw.arg == name
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in node.keywords
    )


def _http_payload_contains_sensitive_data(
    node: ast.Call, aliases: dict[str, str]
) -> bool:
    for kw in node.keywords:
        if kw.arg in {"data", "json"} and _contains_os_environ(kw.value, aliases):
            return True
        if kw.arg == "files" and _contains_sensitive_file_open(kw.value):
            return True
    return False


def _contains_os_environ(node: ast.AST, aliases: dict[str, str]) -> bool:
    if _is_os_environ_reference(node, aliases):
        return True
    return any(_contains_os_environ(child, aliases) for child in ast.iter_child_nodes(node))


def _is_os_environ_reference(node: ast.AST, aliases: dict[str, str]) -> bool:
    if isinstance(node, ast.Name):
        return aliases.get(node.id) == "os.environ"
    if isinstance(node, ast.Attribute):
        return (
            node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and aliases.get(node.value.id, node.value.id) == "os"
        )
    return False


def _contains_sensitive_file_open(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        call_name = qualified_name_from_call(node)
        if call_name == "open" and node.args:
            path = _constant_str(node.args[0])
            if path and is_sensitive_path(path):
                return True
        return any(_contains_sensitive_file_open(arg) for arg in node.args) or any(
            _contains_sensitive_file_open(kw.value) for kw in node.keywords
        )
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        children = []
        if isinstance(node, ast.Dict):
            children.extend(child for child in node.keys if child is not None)
            children.extend(node.values)
        else:
            children.extend(node.elts)
        return any(_contains_sensitive_file_open(child) for child in children)
    return False


def _has_any(source: str, tokens: tuple[str, ...]) -> bool:
    return any(token in source for token in tokens)


def _scan_trojan_source_text(src: str, file_path: Path, findings: list[dict]) -> None:
    for line_no, line in enumerate(src.splitlines(), start=1):
        for col, char in enumerate(line):
            if char not in _BIDI_CONTROL_CHARS:
                continue
            findings.append(
                {
                    "rule_id": "SKY-D344",
                    "severity": "HIGH",
                    "message": (
                        "Bidirectional Unicode control character can disguise "
                        "source code logic."
                    ),
                    "file": str(file_path),
                    "line": line_no,
                    "col": col,
                    "symbol": "<module>",
                    "metadata": {"unicode_codepoint": f"U+{ord(char):04X}"},
                }
            )
            break


def scan_file_with_tree(tree, file_path, findings, *, source: str | None = None):
    """Run taint-flow scanners on an already-parsed AST (no re-read/re-parse)."""
    if source is None:
        scan_sql(tree, file_path, findings)
        scan_cmd(tree, file_path, findings)
        scan_sql_raw(tree, file_path, findings)
        scan_ssrf(tree, file_path, findings)
        scan_path(tree, file_path, findings)
        scan_xss(tree, file_path, findings)
        scan_redirect(tree, file_path, findings)
        scan_cors(tree, file_path, findings)
        scan_jwt(tree, file_path, findings)
        scan_access(tree, file_path, findings)
        scan_mcp(tree, file_path, findings)
        scan_webhook(tree, file_path, findings)
        scan_agent_tool_privilege(tree, file_path, findings)
        scan_llm_consumption(tree, file_path, findings)
        scan_llm(tree, file_path, findings)
        scan_ml_model_load(tree, file_path, findings)
        _PythonCommandExfilChecker(file_path, findings).visit(tree)
        return

    source_lower = source.lower()
    if _has_any(source_lower, _SQL_TOKENS):
        scan_sql(tree, file_path, findings)
    if _has_any(source_lower, _CMD_TOKENS):
        scan_cmd(tree, file_path, findings)
    if _has_any(source_lower, _SQL_RAW_TOKENS):
        scan_sql_raw(tree, file_path, findings)
    if _has_any(source_lower, _SSRF_TOKENS):
        scan_ssrf(tree, file_path, findings)
    if _has_any(source_lower, _PATH_TOKENS):
        scan_path(tree, file_path, findings)
    if _has_any(source_lower, _XSS_TOKENS):
        scan_xss(tree, file_path, findings)
    if _has_any(source_lower, _REDIRECT_TOKENS):
        scan_redirect(tree, file_path, findings)
    if _has_any(source_lower, _CORS_TOKENS):
        scan_cors(tree, file_path, findings)
    if "jwt" in source_lower and _has_any(source_lower, _JWT_TOKENS):
        scan_jwt(tree, file_path, findings)
    if "fields" in source_lower and "__all__" in source_lower:
        scan_access(tree, file_path, findings)
    if _has_any(source_lower, _MCP_TOKENS):
        scan_mcp(tree, file_path, findings)
    if _has_any(source_lower, _WEBHOOK_TOKENS) or _has_any(
        str(file_path).lower(), _WEBHOOK_TOKENS
    ):
        scan_webhook(tree, file_path, findings, source=source)
    if _has_any(source_lower, _AGENT_TOOL_TOKENS):
        scan_agent_tool_privilege(tree, file_path, findings)
    if _has_any(source_lower, _LLM_TOKENS) or _has_any(
        source_lower, _AGENT_TOOL_TOKENS
    ):
        scan_llm_consumption(tree, file_path, findings)
    if _has_any(source_lower, _LLM_TOKENS):
        scan_llm(tree, file_path, findings)
    if _has_any(source_lower, _ML_MODEL_LOAD_TOKENS):
        scan_ml_model_load(tree, file_path, findings)
    if _has_any(
        source_lower,
        (
            ".env",
            "curl",
            "os.environ",
            "printenv",
            "requests",
            "subprocess",
            "httpx",
        ),
    ):
        _PythonCommandExfilChecker(file_path, findings).visit(tree)


def _scan_file(file_path: Path, findings):
    src = file_path.read_text(encoding="utf-8", errors="ignore")
    _scan_trojan_source_text(src, file_path, findings)
    tree = ast.parse(src)

    scan_file_with_tree(tree, file_path, findings, source=src)

    checker = _DangerousCallsChecker(file_path, findings)
    checker.visit(tree)


def scan_ctx(_, files):
    findings = []
    py_files = []

    for file_path in files:
        if file_path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue

        py_files.append(file_path)

        try:
            _scan_file(file_path, findings)
        except Exception as e:
            print(f"Scan failed for {file_path}: {e}", file=sys.stderr)

    try:
        if py_files:
            repo_root = Path(os.path.commonpath([str(p.resolve()) for p in py_files]))

            if repo_root.is_file():
                repo_root = repo_root.parent

            dep_findings = scan_python_dependency_hallucinations(repo_root, py_files)
            if dep_findings:
                findings.extend(dep_findings)

            api_findings = scan_python_api_signature_hallucinations(repo_root, py_files)
            if api_findings:
                findings.extend(api_findings)

    except Exception as e:
        print(f"Dependency hallucination scan failed: {e}", file=sys.stderr)

    return findings
