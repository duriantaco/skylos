from __future__ import annotations

import ast
import sys
from dataclasses import dataclass

from .utils import (
    DIRECT_LLM_CALLS,
    LLM_CLIENT_CALL_SUFFIXES,
    LLM_CLIENT_CONSTRUCTORS,
    qualified_name_from_call,
    root_name,
)


TOKEN_LIMIT_KEYWORDS = {
    "max_completion_tokens",
    "max_output_tokens",
    "max_tokens",
    "maxOutputTokens",
}

TIMEOUT_KEYWORDS = {
    "request_timeout",
    "timeout",
    "timeout_seconds",
}

AGENT_ITERATION_KEYWORDS = {
    "max_execution_time",
    "max_iter",
    "max_iterations",
}

AGENT_EXECUTOR_SUFFIXES = (
    ".AgentExecutor",
    ".AgentExecutor.from_agent_and_tools",
    ".initialize_agent",
    "AgentExecutor",
    "AgentExecutor.from_agent_and_tools",
    "initialize_agent",
)

INFINITE_ITERATOR_SUFFIXES = (
    ".count",
    ".cycle",
    "count",
    "cycle",
)

EMBEDDING_CALL_SUFFIXES = (
    ".embeddings.create",
    "embeddings.create",
)


@dataclass(frozen=True)
class _ClientBounds:
    has_token_limit: bool
    has_timeout: bool


class _LLMConsumptionChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.aliases: dict[str, str] = {}
        self._symbol_stack = ["<module>"]
        self._client_bounds_stack: list[dict[str, _ClientBounds]] = [{}]
        self._unbounded_loop_depth = 0
        self._emitted: set[tuple[int, int, str]] = set()

    def _current_symbol(self) -> str:
        if self._symbol_stack:
            return self._symbol_stack[-1]
        return "<module>"

    def _push_scope(self) -> None:
        self._client_bounds_stack.append({})

    def _pop_scope(self) -> None:
        if len(self._client_bounds_stack) > 1:
            self._client_bounds_stack.pop()

    def _mark_client_bounds(self, name: str, bounds: _ClientBounds) -> None:
        self._client_bounds_stack[-1][name] = bounds

    def _client_bounds_for_name(self, name: str | None) -> _ClientBounds | None:
        if not name:
            return None
        for scope in reversed(self._client_bounds_stack):
            bounds = scope.get(name)
            if bounds:
                return bounds
        return None

    def generic_visit(self, node: ast.AST) -> None:
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._symbol_stack.append(node.name)
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()
        self._symbol_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._symbol_stack.append(node.name)
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()
        self._symbol_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._symbol_stack.append(node.name)
        self.generic_visit(node)
        self._symbol_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        bounds = self._constructor_bounds(node.value)
        if bounds:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._mark_client_bounds(target.id, bounds)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        bounds = self._constructor_bounds(node.value)
        if bounds and isinstance(node.target, ast.Name):
            self._mark_client_bounds(node.target.id, bounds)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_loop_body(node, self._is_unbounded_while(node))

    def visit_For(self, node: ast.For) -> None:
        self._visit_loop_body(node, self._is_unbounded_for(node))

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop_body(node, self._is_unbounded_for(node))

    def visit_Call(self, node: ast.Call) -> None:
        call_name = qualified_name_from_call(node, self.aliases)
        if self._is_llm_call(node, call_name):
            self._check_llm_call(node, call_name)
        if self._is_agent_executor_call(call_name):
            self._check_agent_executor(node)
        self.generic_visit(node)

    def _visit_loop_body(self, node: ast.For | ast.AsyncFor | ast.While, active: bool) -> None:
        if active:
            self._unbounded_loop_depth += 1
        for statement in node.body:
            self.visit(statement)
        if active:
            self._unbounded_loop_depth -= 1
        for statement in node.orelse:
            self.visit(statement)

    def _constructor_bounds(self, node: ast.AST | None) -> _ClientBounds | None:
        if not isinstance(node, ast.Call):
            return None
        call_name = qualified_name_from_call(node, self.aliases)
        if not call_name:
            return None
        if call_name not in LLM_CLIENT_CONSTRUCTORS:
            return None
        return _ClientBounds(
            has_token_limit=_has_bound_keyword(node, TOKEN_LIMIT_KEYWORDS),
            has_timeout=_has_bound_keyword(node, TIMEOUT_KEYWORDS),
        )

    def _is_llm_call(self, node: ast.Call, call_name: str | None) -> bool:
        if not call_name:
            return False
        if call_name in DIRECT_LLM_CALLS:
            return True

        root = root_name(node.func)
        if self._client_bounds_for_name(root) and call_name.endswith(
            LLM_CLIENT_CALL_SUFFIXES
        ):
            return True

        if call_name.endswith(LLM_CLIENT_CALL_SUFFIXES):
            qual_root = call_name.split(".", 1)[0]
            return qual_root in {
                "anthropic",
                "bedrock",
                "chain",
                "cohere",
                "genai",
                "llm",
                "openai",
            }

        return False

    def _check_llm_call(self, node: ast.Call, call_name: str | None) -> None:
        issues: list[str] = []
        client_bounds = self._bounds_for_call(node)

        if self._unbounded_loop_depth > 0:
            issues.append("call runs inside an obvious unbounded loop")
        if self._needs_token_limit(node, call_name, client_bounds):
            issues.append("no max token limit")
        if self._needs_timeout(node, client_bounds):
            issues.append("no request timeout")

        if issues:
            self._append_finding(node, issues)

    def _bounds_for_call(self, node: ast.Call) -> _ClientBounds | None:
        root = root_name(node.func)
        return self._client_bounds_for_name(root)

    def _needs_token_limit(
        self,
        node: ast.Call,
        call_name: str | None,
        client_bounds: _ClientBounds | None,
    ) -> bool:
        if self._is_embedding_call(call_name):
            return False
        if _has_bound_keyword(node, TOKEN_LIMIT_KEYWORDS):
            return False
        if client_bounds and client_bounds.has_token_limit:
            return False
        return True

    def _needs_timeout(
        self,
        node: ast.Call,
        client_bounds: _ClientBounds | None,
    ) -> bool:
        if _has_bound_keyword(node, TIMEOUT_KEYWORDS):
            return False
        if client_bounds and client_bounds.has_timeout:
            return False
        return True

    def _is_embedding_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in EMBEDDING_CALL_SUFFIXES)

    def _is_agent_executor_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in AGENT_EXECUTOR_SUFFIXES)

    def _check_agent_executor(self, node: ast.Call) -> None:
        if _has_bound_keyword(node, AGENT_ITERATION_KEYWORDS):
            return
        self._append_finding(node, ["agent executor has no iteration or time cap"])

    def _is_unbounded_while(self, node: ast.While) -> bool:
        return _truthy_constant(node.test)

    def _is_unbounded_for(self, node: ast.For | ast.AsyncFor) -> bool:
        if not isinstance(node.iter, ast.Call):
            return False
        call_name = qualified_name_from_call(node.iter, self.aliases)
        if not call_name:
            return False
        if any(call_name.endswith(suffix) for suffix in INFINITE_ITERATOR_SUFFIXES):
            return True
        return self._is_unbounded_repeat(node.iter, call_name)

    def _is_unbounded_repeat(self, node: ast.Call, call_name: str) -> bool:
        if not call_name.endswith(("itertools.repeat", "repeat")):
            return False
        if len(node.args) >= 2:
            return False
        for keyword in node.keywords:
            if keyword.arg == "times":
                return False
        return True

    def _append_finding(self, node: ast.Call, issues: list[str]) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        col = int(getattr(node, "col_offset", 0) or 0)
        detail = "; ".join(issues)
        key = (line, col, detail)
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.findings.append(
            {
                "rule_id": "SKY-D267",
                "severity": "MEDIUM",
                "message": (
                    f"Unbounded LLM consumption risk: {detail}. "
                    "Set token, timeout, and iteration limits before invoking the model."
                ),
                "file": str(self.file_path),
                "line": line,
                "col": col,
                "symbol": self._current_symbol(),
                "metadata": {"llm_unbounded_consumption": True},
            }
        )


def _has_bound_keyword(node: ast.Call, names: set[str]) -> bool:
    for keyword in node.keywords:
        if keyword.arg not in names:
            continue
        if _is_unbounded_value(keyword.value):
            continue
        return True
    return False


def _is_unbounded_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is None or node.value is False
    return False


def _truthy_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return False


def scan(tree, file_path, findings):
    try:
        checker = _LLMConsumptionChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(
            f"LLM consumption analysis failed for {file_path}: {e}",
            file=sys.stderr,
        )

