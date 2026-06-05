from __future__ import annotations

import ast
import sys

from skylos.rules.danger.taint import TaintVisitor

from .sensitivity import SensitiveExpressionMixin
from .utils import (
    DANGEROUS_EXEC_CALLS,
    DIRECT_LLM_CALLS,
    HTTP_SINKS,
    LLM_CLIENT_CALL_SUFFIXES,
    LLM_CLIENT_CONSTRUCTORS,
    PROMPT_KEYWORDS,
    SQL_SINK_SUFFIXES,
    SUBPROCESS_PREFIX,
    constant_string,
    dict_value,
    is_shell_true,
    iter_child_exprs,
    qualified_name_from_call,
    qualified_name_from_expr,
    root_name,
)

class _LLMFlowChecker(SensitiveExpressionMixin, TaintVisitor):
    def __init__(self, file_path, findings):
        super().__init__(file_path, findings)
        self.aliases: dict[str, str] = {}
        self.llm_clients_stack: list[set[str]] = [set()]
        self.llm_outputs_stack: list[set[str]] = [set()]
        self.sensitive_stack: list[set[str]] = [set()]
        self.static_strings_stack: list[set[str]] = [set()]
        self._emitted: set[tuple[str, int, int]] = set()

    def _push(self):
        super()._push()
        self.llm_clients_stack.append(set())
        self.llm_outputs_stack.append(set())
        self.sensitive_stack.append(set())
        self.static_strings_stack.append(set())

    def _pop(self):
        if len(self.llm_clients_stack) > 1:
            self.llm_clients_stack.pop()
        if len(self.llm_outputs_stack) > 1:
            self.llm_outputs_stack.pop()
        if len(self.sensitive_stack) > 1:
            self.sensitive_stack.pop()
        if len(self.static_strings_stack) > 1:
            self.static_strings_stack.pop()
        super()._pop()

    def _mark_llm_client(self, name: str) -> None:
        self.llm_clients_stack[-1].add(name)

    def _mark_llm_output(self, name: str) -> None:
        self.llm_outputs_stack[-1].add(name)

    def _mark_sensitive(self, name: str) -> None:
        self.sensitive_stack[-1].add(name)

    def _mark_static_string(self, name: str) -> None:
        self.static_strings_stack[-1].add(name)

    def _is_llm_client_name(self, name: str | None) -> bool:
        if not name:
            return False
        return any(name in scope for scope in reversed(self.llm_clients_stack))

    def _is_llm_output_name(self, name: str | None) -> bool:
        if not name:
            return False
        return any(name in scope for scope in reversed(self.llm_outputs_stack))

    def _is_sensitive_marked_name(self, name: str | None) -> bool:
        if not name:
            return False
        return any(name in scope for scope in reversed(self.sensitive_stack))

    def _is_static_string_name(self, name: str | None) -> bool:
        if not name:
            return False
        return any(name in scope for scope in reversed(self.static_strings_stack))

    def _append_finding(
        self,
        *,
        rule_id: str,
        severity: str,
        message: str,
        node: ast.AST,
    ) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        col = int(getattr(node, "col_offset", 0) or 0)
        key = (rule_id, line, col)
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.findings.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "file": str(self.file_path),
                "line": line,
                "col": col,
                "symbol": self._current_symbol(),
                "metadata": {"llm_app_security": True},
            }
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_llm_constructor(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._mark_llm_client(target.id)

        is_output = self._expr_has_llm_output(node.value)
        is_sensitive = self._expr_is_sensitive(node.value)
        is_static_string = isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        )
        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_output:
                    self._mark_llm_output(target.id)
                if is_sensitive:
                    self._mark_sensitive(target.id)
                if is_static_string:
                    self._mark_static_string(target.id)

        super().visit_Assign(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and isinstance(node.target, ast.Name):
            if self._is_llm_constructor(node.value):
                self._mark_llm_client(node.target.id)
            if self._expr_has_llm_output(node.value):
                self._mark_llm_output(node.target.id)
            if self._expr_is_sensitive(node.value):
                self._mark_sensitive(node.target.id)
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                self._mark_static_string(node.target.id)
        super().visit_AnnAssign(node)

    def visit_Call(self, node: ast.Call) -> None:
        qual_name = qualified_name_from_call(node, self.aliases)
        if self._is_llm_call(node, qual_name):
            self._check_llm_prompt_inputs(node)
            self.generic_visit(node)
            return

        self._check_llm_output_sink(node, qual_name)
        self.generic_visit(node)

    def _is_llm_constructor(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        qual_name = qualified_name_from_call(node, self.aliases)
        return bool(qual_name and qual_name in LLM_CLIENT_CONSTRUCTORS)

    def _is_llm_call(self, node: ast.Call, qual_name: str | None) -> bool:
        if not qual_name:
            return False
        if qual_name in DIRECT_LLM_CALLS:
            return True

        root = root_name(node.func)
        if self._is_llm_client_name(root) and qual_name.endswith(
            LLM_CLIENT_CALL_SUFFIXES
        ):
            return True

        if qual_name.endswith(LLM_CLIENT_CALL_SUFFIXES):
            qual_root = qual_name.split(".", 1)[0]
            return qual_root in {
                "openai",
                "anthropic",
                "genai",
                "cohere",
                "bedrock",
                "llm",
                "chain",
            }

        return False

    def _iter_prompt_nodes(self, call: ast.Call) -> list[tuple[ast.AST, str | None]]:
        nodes: list[tuple[ast.AST, str | None]] = []

        for keyword in call.keywords or []:
            if keyword.arg == "messages":
                nodes.extend(self._iter_message_content_nodes(keyword.value))
                continue
            if keyword.arg in PROMPT_KEYWORDS:
                nodes.append((keyword.value, None))

        if not nodes and call.args:
            nodes.append((call.args[0], None))
        return nodes

    def _iter_message_content_nodes(
        self, node: ast.AST
    ) -> list[tuple[ast.AST, str | None]]:
        if isinstance(node, ast.List):
            items = node.elts
        elif isinstance(node, ast.Tuple):
            items = node.elts
        else:
            return [(node, None)]

        results: list[tuple[ast.AST, str | None]] = []
        for item in items:
            if not isinstance(item, ast.Dict):
                results.append((item, None))
                continue
            content = dict_value(item, "content")
            if content is None:
                continue
            role = constant_string(dict_value(item, "role"))
            results.append((content, role))
        return results

    def _has_static_system_prompt(self, call: ast.Call) -> bool:
        for keyword in call.keywords or []:
            if keyword.arg != "messages":
                continue
            value = keyword.value
            if not isinstance(value, (ast.List, ast.Tuple)):
                continue
            for item in value.elts:
                if not isinstance(item, ast.Dict):
                    continue
                if constant_string(dict_value(item, "role")) != "system":
                    continue
                content = dict_value(item, "content")
                if isinstance(content, ast.Constant) and isinstance(content.value, str):
                    return True
                if isinstance(content, ast.Name) and self._is_static_string_name(
                    content.id
                ):
                    return True
        return False

    def _check_llm_prompt_inputs(self, call: ast.Call) -> None:
        prompt_nodes = self._iter_prompt_nodes(call)
        has_static_system = self._has_static_system_prompt(call)
        for prompt_node, role in prompt_nodes:
            if self._expr_is_sensitive(prompt_node):
                self._append_finding(
                    rule_id="SKY-D263",
                    severity="HIGH",
                    message=(
                        "Sensitive data flows into an LLM or embedding API input."
                    ),
                    node=call,
                )

            if not self.is_tainted(prompt_node):
                continue
            if role == "user" and has_static_system:
                continue
            severity = "HIGH" if role in {None, "system", "developer"} else "MEDIUM"
            self._append_finding(
                rule_id="SKY-D261",
                severity=severity,
                message=(
                    "Untrusted input flows into an LLM prompt without a clear "
                    "instruction/data boundary."
                ),
                node=call,
            )

    def _expr_has_llm_output(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            qual_name = qualified_name_from_call(node, self.aliases)
            if self._is_llm_call(node, qual_name):
                return True
        if isinstance(node, ast.Name):
            return self._is_llm_output_name(node.id)
        root = root_name(node)
        if self._is_llm_output_name(root):
            return True
        return any(
            self._expr_has_llm_output(child) for child in iter_child_exprs(node)
        )

    def _is_os_environ_expr(self, node: ast.AST) -> bool:
        qual_name = qualified_name_from_expr(node, self.aliases)
        return qual_name in {"os.environ", "environ"}

    def _check_llm_output_sink(self, node: ast.Call, qual_name: str | None) -> None:
        if not qual_name:
            return

        sink = self._llm_output_sink_label(node, qual_name)
        if sink:
            self._append_llm_output_finding(node, sink)

    def _llm_output_sink_label(self, node: ast.Call, qual_name: str) -> str | None:
        checks = (
            self._exec_sink_label,
            self._subprocess_sink_label,
            self._sql_sink_label,
            self._http_sink_label,
        )
        for check in checks:
            sink = check(node, qual_name)
            if sink:
                return sink
        return None

    def _exec_sink_label(self, node: ast.Call, qual_name: str) -> str | None:
        if qual_name not in DANGEROUS_EXEC_CALLS or not node.args:
            return None
        if self._expr_has_llm_output(node.args[0]):
            return "code execution"
        return None

    def _subprocess_sink_label(self, node: ast.Call, qual_name: str) -> str | None:
        if not qual_name.startswith(SUBPROCESS_PREFIX) or not is_shell_true(node):
            return None
        command = node.args[0] if node.args else node
        if self._expr_has_llm_output(command):
            return "shell command execution"
        return None

    def _sql_sink_label(self, node: ast.Call, qual_name: str) -> str | None:
        if not qual_name.endswith(SQL_SINK_SUFFIXES):
            return None
        query = node.args[0] if node.args else None
        if query is not None and self._expr_has_llm_output(query):
            return "SQL execution"
        return None

    def _http_sink_label(self, node: ast.Call, qual_name: str) -> str | None:
        if qual_name not in HTTP_SINKS:
            return None
        url = node.args[0] if node.args else None
        if qual_name.endswith(".request") and len(node.args) > 1:
            url = node.args[1]
        if url is not None and self._expr_has_llm_output(url):
            return "network request"
        return None

    def _append_llm_output_finding(self, node: ast.Call, sink: str) -> None:
        self._append_finding(
            rule_id="SKY-D262",
            severity="CRITICAL",
            message=f"LLM output flows into {sink} without validation.",
            node=node,
        )


def scan(tree, file_path, findings):
    try:
        checker = _LLMFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(
            f"LLM application flow analysis failed for {file_path}: {e}",
            file=sys.stderr,
        )
