from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TaintFlow:
    source: str
    source_location: str
    sink: str
    sink_location: str
    path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_location": self.source_location,
            "sink": self.sink,
            "sink_location": self.sink_location,
            "path": self.path,
        }


class _TaintVisitor(ast.NodeVisitor):
    def generic_visit(self, node: ast.AST) -> None:
        for _field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    TAINT_SOURCES = {
        "input",
        "request.get_json",
        "request.form.get",
        "request.args.get",
        "request.json.get",
    }

    SANITIZERS = {
        "int",
        "float",
        "bool",
        "json.loads",
        "json.load",
        "ast.literal_eval",
        "html.escape",
        "bleach.clean",
        "markupsafe.escape",
        "urllib.parse.quote",
        "shlex.quote",
    }

    DANGEROUS_SINKS = {
        "eval",
        "exec",
        "compile",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "os.system",
        "os.popen",
    }

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.flows: list[TaintFlow] = []

        self._tainted_vars: dict[str, str] = {}
        self._tainted_sources: dict[str, str] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        prev_tainted = self._tainted_vars.copy()
        prev_sources = self._tainted_sources.copy()
        self._tainted_vars.clear()
        self._tainted_sources.clear()

        for arg in node.args.args:
            if arg.arg in ("request", "req"):
                self._tainted_vars[arg.arg] = "HTTP request"
                self._tainted_sources[arg.arg] = f"{self.filepath}:{node.lineno}"

        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign):
                self._check_taint_assign(stmt)
            elif isinstance(stmt, ast.Call):
                self._check_taint_sink(stmt)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self._check_taint_sink(stmt.value)

        self._tainted_vars = prev_tainted
        self._tainted_sources = prev_sources

    def _check_taint_assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id

            source = self._get_taint_source(node.value)
            if source:
                self._tainted_vars[var_name] = source
                self._tainted_sources[var_name] = f"{self.filepath}:{node.lineno}"
                continue

            used_vars = self._extract_names(node.value)
            for used in used_vars:
                if used in self._tainted_vars:
                    if not self._is_sanitized(node.value):
                        self._tainted_vars[var_name] = self._tainted_vars[used]
                        self._tainted_sources[var_name] = self._tainted_sources.get(
                            used, f"{self.filepath}:{node.lineno}"
                        )
                    break

    def _check_taint_sink(self, node: ast.Call) -> None:
        call_name = self._resolve_call(node.func)
        if call_name not in self.DANGEROUS_SINKS:
            return

        for arg in node.args:
            names = self._extract_names(arg)
            for name in names:
                if name in self._tainted_vars:
                    self.flows.append(
                        TaintFlow(
                            source=self._tainted_vars[name],
                            source_location=self._tainted_sources.get(name, "unknown"),
                            sink=call_name,
                            sink_location=f"{self.filepath}:{node.lineno}",
                            path=[name],
                        )
                    )

        for kw in node.keywords:
            names = self._extract_names(kw.value)
            for name in names:
                if name in self._tainted_vars:
                    self.flows.append(
                        TaintFlow(
                            source=self._tainted_vars[name],
                            source_location=self._tainted_sources.get(name, "unknown"),
                            sink=call_name,
                            sink_location=f"{self.filepath}:{node.lineno}",
                            path=[name],
                        )
                    )

    def _get_taint_source(self, node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Call):
            call_name = self._resolve_call(node.func)
            if call_name in self.TAINT_SOURCES:
                return call_name

            if isinstance(node.func, ast.Attribute):
                obj_name = self._resolve_call(node.func.value)
                if obj_name in self._tainted_vars:
                    return self._tainted_vars[obj_name]
        if isinstance(node, ast.Attribute):
            obj_name = self._resolve_call(node.value)
            if obj_name in self._tainted_vars:
                return self._tainted_vars[obj_name]
        return None

    def _is_sanitized(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Call):
            call_name = self._resolve_call(node.func)
            if call_name in self.SANITIZERS:
                return True
        return False

    def _extract_names(self, node: ast.expr) -> list[str]:
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append(child.id)
        return names

    def _resolve_call(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value = self._resolve_call(node.value)
            if value:
                return f"{value}.{node.attr}"
            return node.attr
        return ""


def analyze_taint_flows(filepath: str, source: str) -> list[TaintFlow]:
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    visitor = _TaintVisitor(filepath)
    visitor.visit(tree)
    return visitor.flows
