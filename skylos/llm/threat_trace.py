from __future__ import annotations

import ast
import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATIC_VALIDATION = "static_unvalidated"
MEDIUM_CONFIDENCE = "medium"
PYTHON_INTRA_PROCEDURAL_LIMITATION = "python_intra_procedural_only"
MAX_CONTEXT_TRACES_PER_FILE = 5
MAX_THREAT_TRACE_SOURCE_BYTES = 1_000_000

_REQUEST_SOURCE_CALLS = {
    "input",
    "request.args.get",
    "request.form.get",
    "request.headers.get",
    "request.query_params.get",
    "request.GET.get",
    "request.POST.get",
    "request.files.get",
    "request.get_json",
    "request.json.get",
}
_REQUEST_SOURCE_OBJECTS = {
    "request.args",
    "request.form",
    "request.headers",
    "request.query_params",
    "request.GET",
    "request.POST",
    "request.files",
    "request.json",
}
_SANITIZER_CALLS = {
    "ast.literal_eval",
    "bleach.clean",
    "html.escape",
    "int",
    "float",
    "bool",
    "json.load",
    "json.loads",
    "markupsafe.escape",
    "os.path.basename",
    "secure_filename",
    "shlex.quote",
    "Path.resolve",
    "urllib.parse.quote",
}
_GUARD_CALLS = {
    "urlparse",
    "urllib.parse.urlparse",
    "html.escape",
    "markupsafe.escape",
    "os.path.basename",
    "secure_filename",
    "Path.resolve",
}
_HTTP_SINKS = {
    "requests.get",
    "requests.post",
    "httpx.get",
    "httpx.post",
    "urllib.request.urlopen",
}
_COMMAND_SINKS = {
    "os.system",
    "os.popen",
}
_SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
}
_PATH_SINKS = {
    "open",
    "Path.open",
    "Path.read_text",
    "Path.write_text",
}
_REDIRECT_SINKS = {"redirect", "flask.redirect"}
_TEMPLATE_SINKS = {"render_template_string", "flask.render_template_string"}
_ROUTE_DECORATOR_SUFFIXES = {
    ".route",
    ".get",
    ".post",
    ".put",
    ".patch",
    ".delete",
    ".head",
    ".options",
    ".websocket",
}


@dataclass(frozen=True)
class ThreatTraceStep:
    kind: str
    name: str
    line: int
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "name": self.name,
            "line": self.line,
        }
        if self.detail:
            data["detail"] = self.detail
        return data


@dataclass(frozen=True)
class ThreatTracePoint:
    file: str
    line: int
    name: str
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "name": self.name,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class ThreatTrace:
    trace_id: str
    file: str
    entrypoint: str
    source: ThreatTracePoint
    sink: ThreatTracePoint
    sink_category: str
    path: tuple[ThreatTraceStep, ...]
    guards: tuple[ThreatTraceStep, ...] = ()
    confidence: str = MEDIUM_CONFIDENCE
    validation: str = STATIC_VALIDATION
    limitations: tuple[str, ...] = (PYTHON_INTRA_PROCEDURAL_LIMITATION,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "file": self.file,
            "entrypoint": self.entrypoint,
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "sink_category": self.sink_category,
            "path": [step.to_dict() for step in self.path],
            "guards": [guard.to_dict() for guard in self.guards],
            "confidence": self.confidence,
            "validation": self.validation,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class _TaintState:
    source: ThreatTracePoint
    path: tuple[ThreatTraceStep, ...]
    guards: tuple[ThreatTraceStep, ...] = ()


def build_static_threat_traces(
    project_root: str | Path, files: list[Path]
) -> list[ThreatTrace]:
    root = Path(project_root).resolve()
    traces: list[ThreatTrace] = []
    for file_path in files:
        path = Path(file_path)
        if path.suffix != ".py":
            continue
        traces.extend(_build_python_file_traces(root, path))
    return sorted(
        traces,
        key=lambda trace: (
            trace.file,
            trace.sink.line,
            trace.source.line,
            trace.sink.name,
        ),
    )


def threat_trace_context_lines(traces: list[ThreatTrace]) -> dict[str, list[str]]:
    by_file: dict[str, list[str]] = {}
    for trace in traces:
        lines = by_file.setdefault(trace.file, [])
        if len(lines) >= MAX_CONTEXT_TRACES_PER_FILE:
            continue
        guard_text = ""
        if trace.guards:
            guard_text = (
                " with guards "
                + ", ".join(f"{guard.name}@L{guard.line}" for guard in trace.guards)
            )
        lines.append(
            "- threat trace: "
            f"{trace.entrypoint} source {trace.source.name}@L{trace.source.line} "
            f"reaches {trace.sink.name}@L{trace.sink.line}{guard_text} "
            f"({trace.validation})"
        )
    return by_file


def attach_threat_traces_to_findings(
    findings: list[Any], traces: list[ThreatTrace]
) -> None:
    by_location: dict[tuple[str, int], list[ThreatTrace]] = {}
    for trace in traces:
        by_location.setdefault((str(Path(trace.file).resolve()), trace.sink.line), [])
        by_location[(str(Path(trace.file).resolve()), trace.sink.line)].append(trace)

    for finding in findings:
        location = _finding_location(finding)
        if location is None:
            continue
        matched = by_location.get(location)
        if not matched:
            continue
        payloads = [trace.to_dict() for trace in matched]
        metadata = _finding_metadata(finding)
        metadata["threat_trace"] = payloads[0]
        if len(payloads) > 1:
            metadata["threat_traces"] = payloads
        _set_finding_metadata(finding, metadata)


def _build_python_file_traces(project_root: Path, file_path: Path) -> list[ThreatTrace]:
    resolved_path, source = _read_trace_source(project_root, file_path)
    if resolved_path is None or source is None:
        return []
    try:
        tree = ast.parse(source, filename=str(resolved_path))
    except SyntaxError:
        return []

    traces: list[ThreatTrace] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            analyzer = _FunctionThreatTraceAnalyzer(project_root, resolved_path, node)
            traces.extend(analyzer.analyze())
    return traces


def _read_trace_source(
    project_root: Path, file_path: Path
) -> tuple[Path | None, str | None]:
    try:
        file_stat = file_path.lstat()
    except OSError:
        return None, None

    if file_path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
        return None, None
    if file_stat.st_size > MAX_THREAT_TRACE_SOURCE_BYTES:
        return None, None

    try:
        resolved_root = project_root.resolve(strict=True)
        resolved_path = file_path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError):
        return None, None

    try:
        return resolved_path, resolved_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, None


class _FunctionThreatTraceAnalyzer:
    def __init__(
        self,
        project_root: Path,
        file_path: Path,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self.project_root = project_root
        self.file_path = str(file_path)
        self.function = node
        self.entrypoint = _entrypoint_name(node)
        self.tainted: dict[str, _TaintState] = {}
        self.active_guards: tuple[ThreatTraceStep, ...] = ()
        self.traces: list[ThreatTrace] = []

    def analyze(self) -> list[ThreatTrace]:
        for arg in self.function.args.args:
            if arg.arg in {"request", "req"}:
                source = ThreatTracePoint(
                    file=self.file_path,
                    line=self.function.lineno,
                    name=f"{arg.arg} parameter",
                    kind="source",
                )
                self.tainted[arg.arg] = _TaintState(
                    source=source,
                    path=(
                        ThreatTraceStep(
                            kind="source",
                            name=f"{arg.arg} parameter",
                            line=self.function.lineno,
                            detail="HTTP request object",
                        ),
                    ),
                )

        for statement in self.function.body:
            self._visit_statement(statement)
        return self.traces

    def _visit_statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(statement, ast.Assign):
            self._record_sinks_in_expr(statement.value)
            self._handle_assign(statement.targets, statement.value, statement.lineno)
            return
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._record_sinks_in_expr(statement.value)
                self._handle_assign([statement.target], statement.value, statement.lineno)
            return
        if isinstance(statement, ast.AugAssign):
            self._record_sinks_in_expr(statement.value)
            self._handle_assign([statement.target], statement.value, statement.lineno)
            return
        if isinstance(statement, ast.If):
            self._visit_if(statement)
            return

        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._record_sinks_in_expr(child)
            elif isinstance(child, ast.stmt):
                self._visit_statement(child)

    def _visit_if(self, statement: ast.If) -> None:
        guards = self._guards_in_expr(statement.test)
        self._record_sinks_in_expr(statement.test)
        previous_guards = self.active_guards
        initial_taint = dict(self.tainted)

        self.active_guards = previous_guards + tuple(guards)
        body_traces_start = len(self.traces)
        for child in statement.body:
            self._visit_statement(child)
        body_result = dict(self.tainted)
        body_traces = self.traces[body_traces_start:]

        self.tainted = dict(initial_taint)
        self.traces = self.traces[:body_traces_start]
        self.active_guards = previous_guards
        for child in statement.orelse:
            self._visit_statement(child)
        else_result = dict(self.tainted)
        else_traces = self.traces[body_traces_start:]

        self.traces = self.traces[:body_traces_start] + body_traces + else_traces
        self.tainted = _intersect_taint_states(body_result, else_result)
        self.active_guards = previous_guards

    def _handle_assign(
        self, targets: list[ast.expr], value: ast.expr, line: int
    ) -> None:
        taint = self._expr_taint(value)
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if taint is not None and not self._is_sanitized_expr(value):
                step = ThreatTraceStep(
                    kind="propagation",
                    name=target.id,
                    line=line,
                    detail="assigned from tainted expression",
                )
                self.tainted[target.id] = _TaintState(
                    source=taint.source,
                    path=taint.path + (step,),
                    guards=taint.guards + self.active_guards,
                )
            else:
                self.tainted.pop(target.id, None)

    def _record_sinks_in_expr(self, expr: ast.expr) -> None:
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call):
                continue
            sink = self._sink_for_call(node)
            if sink is None:
                continue
            for taint in self._call_taints(node):
                self._append_trace(node, sink, taint)

    def _append_trace(
        self, node: ast.Call, sink: tuple[str, str], taint: _TaintState
    ) -> None:
        sink_name, sink_category = sink
        sink_step = ThreatTraceStep(
            kind="sink",
            name=sink_name,
            line=node.lineno,
            detail=f"{sink_category} sink",
        )
        guards = _dedupe_steps(taint.guards + self.active_guards)
        path = _dedupe_steps(taint.path + (sink_step,))
        trace_id = _trace_id(
            self.file_path,
            self.entrypoint,
            taint.source.name,
            taint.source.line,
            sink_name,
            node.lineno,
            [step.name for step in path],
        )
        self.traces.append(
            ThreatTrace(
                trace_id=trace_id,
                file=self.file_path,
                entrypoint=self.entrypoint,
                source=taint.source,
                sink=ThreatTracePoint(
                    file=self.file_path,
                    line=node.lineno,
                    name=sink_name,
                    kind="sink",
                ),
                sink_category=sink_category,
                path=path,
                guards=guards,
            )
        )

    def _call_taints(self, node: ast.Call) -> list[_TaintState]:
        taints: list[_TaintState] = []
        for expr in list(node.args) + [keyword.value for keyword in node.keywords]:
            taint = self._expr_taint(expr)
            if taint is not None and not self._is_sanitized_expr(expr):
                taints.append(taint)
        return _dedupe_taints(taints)

    def _expr_taint(self, expr: ast.expr) -> _TaintState | None:
        source_call = self._source_call(expr)
        if source_call is not None:
            source = ThreatTracePoint(
                file=self.file_path,
                line=getattr(expr, "lineno", self.function.lineno),
                name=source_call,
                kind="source",
            )
            return _TaintState(
                source=source,
                path=(
                    ThreatTraceStep(
                        kind="source",
                        name=source_call,
                        line=getattr(expr, "lineno", self.function.lineno),
                        detail="user-controlled input",
                    ),
                ),
                guards=self.active_guards,
            )

        if isinstance(expr, ast.Name):
            return self.tainted.get(expr.id)

        child_taints = []
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                taint = self._expr_taint(child)
                if taint is not None:
                    child_taints.append(taint)
        return child_taints[0] if child_taints else None

    def _source_call(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Call):
            call_name = _call_name(expr)
            if call_name in _REQUEST_SOURCE_CALLS:
                return call_name
        if isinstance(expr, ast.Subscript):
            object_name = _dotted_name(expr.value)
            if object_name in _REQUEST_SOURCE_OBJECTS:
                return f"{object_name}[]"
        return None

    def _sink_for_call(self, node: ast.Call) -> tuple[str, str] | None:
        call_name = _call_name(node)
        if call_name in _HTTP_SINKS:
            return call_name, "ssrf"
        if call_name in _COMMAND_SINKS:
            return call_name, "command_execution"
        if call_name in _SUBPROCESS_SINKS and _shell_true(node):
            return f"{call_name}(shell=True)", "command_execution"
        if call_name in _PATH_SINKS:
            return call_name, "filesystem"
        if call_name.endswith(".execute") or call_name.endswith(".executemany"):
            return call_name, "sql"
        if call_name in _REDIRECT_SINKS:
            return call_name, "redirect"
        if call_name in _TEMPLATE_SINKS:
            return call_name, "template"
        return None

    def _is_sanitized_expr(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Call) and _call_name(expr) in _SANITIZER_CALLS:
            return True
        return any(
            isinstance(child, ast.Call) and _call_name(child) in _SANITIZER_CALLS
            for child in ast.walk(expr)
        )

    def _guards_in_expr(self, expr: ast.expr) -> list[ThreatTraceStep]:
        guards = []
        for child in ast.walk(expr):
            if isinstance(child, ast.Call):
                call_name = _call_name(child)
                if call_name in _GUARD_CALLS:
                    guards.append(
                        ThreatTraceStep(
                            kind="guard",
                            name=call_name,
                            line=child.lineno,
                            detail="guard or sanitizer check",
                        )
                    )
        return guards


def _entrypoint_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for decorator in node.decorator_list:
        decorator_name = _dotted_name(decorator)
        if _is_route_decorator(decorator_name):
            return f"{node.name} [{decorator_name}]"
    return node.name


def _is_route_decorator(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in _ROUTE_DECORATOR_SUFFIXES)


def _call_name(node: ast.Call) -> str:
    return _dotted_name(node.func)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _shell_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _trace_id(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts)
    return "trace-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _dedupe_steps(steps: tuple[ThreatTraceStep, ...]) -> tuple[ThreatTraceStep, ...]:
    seen = set()
    deduped = []
    for step in steps:
        key = (step.kind, step.name, step.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(step)
    return tuple(deduped)


def _dedupe_taints(taints: list[_TaintState]) -> list[_TaintState]:
    seen = set()
    deduped = []
    for taint in taints:
        key = (taint.source.name, taint.source.line, tuple(step.name for step in taint.path))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(taint)
    return deduped


def _intersect_taint_states(
    left: dict[str, _TaintState], right: dict[str, _TaintState]
) -> dict[str, _TaintState]:
    return {
        name: state
        for name, state in left.items()
        if name in right
        and state.source.name == right[name].source.name
        and state.source.line == right[name].source.line
    }


def _finding_location(finding: Any) -> tuple[str, int] | None:
    try:
        if isinstance(finding, dict):
            location = finding.get("location") or {}
            file_path = str(finding.get("file") or location.get("file") or "")
            line = int(finding.get("line") or location.get("line") or 0)
        else:
            file_path = str(finding.location.file)
            line = int(finding.location.line)
    except (AttributeError, TypeError, ValueError):
        return None
    if not file_path or line <= 0:
        return None
    return str(Path(file_path).resolve()), line


def _finding_metadata(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return dict(finding.get("metadata") or {})
    return dict(getattr(finding, "metadata", None) or {})


def _set_finding_metadata(finding: Any, metadata: dict[str, Any]) -> None:
    if isinstance(finding, dict):
        finding["metadata"] = metadata
    else:
        finding.metadata = metadata
