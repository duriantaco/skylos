from __future__ import annotations

import ast
import sys

from skylos.rules.danger.calls import _qualified_name_from_call, _resolve_expr_name


DANGEROUS_TOOL_CONSTRUCTORS = {
    "ShellTool": "shell execution tool",
    "PythonREPLTool": "Python REPL tool",
    "PythonAstREPLTool": "Python AST REPL tool",
}

DANGEROUS_FUNCTION_REFS = {
    "compile": "dynamic code compilation",
    "eval": "dynamic eval",
    "exec": "dynamic exec",
    "os.execve": "process replacement",
    "os.execvp": "process replacement",
    "os.popen": "shell command execution",
    "os.system": "shell command execution",
    "shutil.rmtree": "recursive file deletion",
    "subprocess.Popen": "subprocess execution",
    "subprocess.call": "subprocess execution",
    "subprocess.check_call": "subprocess execution",
    "subprocess.check_output": "subprocess execution",
    "subprocess.run": "subprocess execution",
}

DANGEROUS_LOAD_TOOL_NAMES = {
    "file_management": "unrestricted file management tool",
    "python_repl": "Python REPL tool",
    "python_repl_ast": "Python AST REPL tool",
    "requests_all": "unrestricted HTTP request tool",
    "shell": "shell execution tool",
    "terminal": "terminal execution tool",
}

DANGEROUS_OPENAI_TOOL_TYPES = {
    "code_interpreter": "code interpreter tool",
    "computer_use_preview": "computer-use tool",
}

AGENT_CALL_SUFFIXES = (
    ".assistants.create",
    ".create_openai_functions_agent",
    ".create_openai_tools_agent",
    ".create_react_agent",
    ".create_structured_chat_agent",
    ".initialize_agent",
    "Agent",
    "AgentExecutor",
    "AgentExecutor.from_agent_and_tools",
    "create_openai_functions_agent",
    "create_openai_tools_agent",
    "create_react_agent",
    "create_structured_chat_agent",
    "initialize_agent",
)

TOOL_FACTORY_SUFFIXES = (
    ".StructuredTool",
    ".StructuredTool.from_function",
    ".Tool",
    ".Tool.from_function",
    "StructuredTool",
    "StructuredTool.from_function",
    "Tool",
    "Tool.from_function",
)


class _AgentToolPrivilegeChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self.aliases: dict[str, str] = {}
        self._symbol_stack = ["<module>"]
        self._dangerous_tools_stack: list[dict[str, str]] = [{}]
        self._dangerous_functions_stack: list[dict[str, str]] = [{}]
        self._emitted: set[tuple[int, int, str]] = set()

    def _current_symbol(self) -> str:
        if self._symbol_stack:
            return self._symbol_stack[-1]
        return "<module>"

    def _push_scope(self) -> None:
        self._dangerous_tools_stack.append({})
        self._dangerous_functions_stack.append({})

    def _pop_scope(self) -> None:
        if len(self._dangerous_tools_stack) > 1:
            self._dangerous_tools_stack.pop()
        if len(self._dangerous_functions_stack) > 1:
            self._dangerous_functions_stack.pop()

    def _mark_dangerous_tool(self, name: str, detail: str) -> None:
        self._dangerous_tools_stack[-1][name] = detail

    def _mark_dangerous_function(self, name: str, detail: str) -> None:
        self._dangerous_functions_stack[-1][name] = detail

    def _dangerous_tool_detail_for_name(self, name: str) -> str | None:
        for scope in reversed(self._dangerous_tools_stack):
            detail = scope.get(name)
            if detail:
                return detail
        return None

    def _dangerous_function_detail_for_name(self, name: str) -> str | None:
        for scope in reversed(self._dangerous_functions_stack):
            detail = scope.get(name)
            if detail:
                return detail
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
        tool_detail = self._expr_dangerous_tool_detail(node.value)
        function_detail = self._expr_dangerous_function_detail(node.value)
        for target in node.targets:
            self._mark_target(target, tool_detail, function_detail)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            tool_detail = self._expr_dangerous_tool_detail(node.value)
            function_detail = self._expr_dangerous_function_detail(node.value)
            self._mark_target(node.target, tool_detail, function_detail)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _qualified_name_from_call(node, self.aliases)
        if self._is_agent_call(call_name):
            detail = self._agent_tool_detail(node)
            if detail:
                self._append_finding(node, detail)
        self.generic_visit(node)

    def _mark_target(
        self,
        target: ast.AST,
        tool_detail: str | None,
        function_detail: str | None,
    ) -> None:
        if not isinstance(target, ast.Name):
            return
        if tool_detail:
            self._mark_dangerous_tool(target.id, tool_detail)
        if function_detail:
            self._mark_dangerous_function(target.id, function_detail)

    def _is_agent_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in AGENT_CALL_SUFFIXES)

    def _agent_tool_detail(self, node: ast.Call) -> str | None:
        for keyword in node.keywords:
            if keyword.arg in {"tool", "toolkit", "toolkits", "tools"}:
                detail = self._expr_dangerous_tool_detail(keyword.value)
                if detail:
                    return detail

        for arg in node.args:
            detail = self._expr_dangerous_tool_detail(arg)
            if detail:
                return detail
        return None

    def _expr_dangerous_tool_detail(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self._dangerous_tool_detail_for_name(node.id)
        if isinstance(node, ast.Call):
            return self._call_dangerous_tool_detail(node)
        if isinstance(node, ast.Dict):
            return self._dict_dangerous_tool_detail(node)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._iterable_dangerous_tool_detail(node.elts)
        return None

    def _iterable_dangerous_tool_detail(self, nodes: list[ast.AST]) -> str | None:
        for item in nodes:
            detail = self._expr_dangerous_tool_detail(item)
            if detail:
                return detail
        return None

    def _call_dangerous_tool_detail(self, node: ast.Call) -> str | None:
        call_name = _qualified_name_from_call(node, self.aliases)
        short_name = _short_name(call_name)
        if short_name in DANGEROUS_TOOL_CONSTRUCTORS:
            return DANGEROUS_TOOL_CONSTRUCTORS[short_name]

        if call_name and call_name.endswith(".load_tools"):
            return self._load_tools_detail(node)
        if call_name == "load_tools":
            return self._load_tools_detail(node)

        if self._is_tool_factory_call(call_name):
            return self._tool_factory_detail(node)
        return None

    def _is_tool_factory_call(self, call_name: str | None) -> bool:
        if not call_name:
            return False
        return any(call_name.endswith(suffix) for suffix in TOOL_FACTORY_SUFFIXES)

    def _tool_factory_detail(self, node: ast.Call) -> str | None:
        for arg in node.args:
            detail = self._expr_dangerous_function_detail(arg)
            if detail:
                return detail
        for keyword in node.keywords:
            if keyword.arg not in {"coroutine", "func"}:
                continue
            detail = self._expr_dangerous_function_detail(keyword.value)
            if detail:
                return detail
        return None

    def _load_tools_detail(self, node: ast.Call) -> str | None:
        for value in self._iter_string_constants(node.args):
            detail = DANGEROUS_LOAD_TOOL_NAMES.get(value.lower())
            if detail:
                return detail
        return None

    def _dict_dangerous_tool_detail(self, node: ast.Dict) -> str | None:
        tool_type = _dict_string_value(node, "type")
        if tool_type:
            return DANGEROUS_OPENAI_TOOL_TYPES.get(tool_type)
        return None

    def _expr_dangerous_function_detail(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            marked = self._dangerous_function_detail_for_name(node.id)
            if marked:
                return marked
        name = _resolve_expr_name(node, self.aliases)
        if name in DANGEROUS_FUNCTION_REFS:
            return DANGEROUS_FUNCTION_REFS[name]
        return None

    def _iter_string_constants(self, nodes: list[ast.AST]) -> list[str]:
        values: list[str] = []
        for node in nodes:
            values.extend(_string_constants(node))
        return values

    def _append_finding(self, node: ast.Call, detail: str) -> None:
        line = int(getattr(node, "lineno", 1) or 1)
        col = int(getattr(node, "col_offset", 0) or 0)
        key = (line, col, detail)
        if key in self._emitted:
            return
        self._emitted.add(key)
        self.findings.append(
            {
                "rule_id": "SKY-D264",
                "severity": "HIGH",
                "message": (
                    "Agent is granted dangerous tool capability "
                    f"({detail}); restrict tools to allowlisted, scoped "
                    "functions and require human approval for mutating actions."
                ),
                "file": str(self.file_path),
                "line": line,
                "col": col,
                "symbol": self._current_symbol(),
                "metadata": {"agent_tool_privilege": True},
            }
        )


def _short_name(call_name: str | None) -> str | None:
    if not call_name:
        return None
    return call_name.rsplit(".", 1)[-1]


def _dict_string_value(node: ast.Dict, key_name: str) -> str | None:
    for key, value in zip(node.keys, node.values):
        if _constant_string(key) != key_name:
            continue
        return _constant_string(value)
    return None


def _constant_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_constants(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for item in node.elts:
            values.extend(_string_constants(item))
        return values
    return []


def scan(tree, file_path, findings):
    try:
        checker = _AgentToolPrivilegeChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(
            f"Agent tool privilege analysis failed for {file_path}: {e}",
            file=sys.stderr,
        )
