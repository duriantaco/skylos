"""Explain reported security candidates using bounded static source evidence.

This layer never evaluates target code and never suppresses findings, changes
severity, or rewrites the existing ``security_evidence`` packet.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
import re

from skylos.security.static_trace_graph import TraceGraph
from skylos.security.static_trace_index import TraceLimits, build_index
from skylos.security.static_trace_walk import PredecessorWalker, observed_guards


__all__ = ["attach_security_traces", "build_index", "TraceLimits"]


def _sink_call(unit, finding):
    line = finding.get("line")
    if type(line) is not int or line < 1:
        return None
    rule = finding.get("rule_id")
    if rule in {"SKY-D211", "SKY-D217"}:
        names = {
            "execute",
            "executemany",
            "executescript",
            "text",
            "read_sql",
            "read_sql_query",
            "raw",
            "RawSQL",
        }
    elif rule in {"SKY-D215", "SKY-D324", "SKY-D325"}:
        names = {
            "open",
            "read_text",
            "write_text",
            "read_bytes",
            "write_bytes",
            "FileResponse",
            "send_file",
        }
    else:
        return None
    source_calls = unit.calls_by_line.get(line, [])
    column = finding.get("col", finding.get("column"))
    if type(column) is int:
        exact = []
        for node in source_calls:
            if node.col_offset == column:
                exact.append(node)
        if len(exact) == 1:
            return exact[0]
        # Chained calls share their starting column. SQL findings identify a
        # SQL operation, so an outer fetch/result call must not obscure the
        # unique SQL call at that location. Arbitrary path calls still need an
        # unambiguous exact match; a method name alone cannot select them.
        if rule not in {"SKY-D211", "SKY-D217"}:
            return None
        source_calls = exact
    calls = []
    for node in source_calls:
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name in names:
            calls.append(node)
    if not calls:
        return None
    if len(calls) == 1:
        return calls[0]
    return None


def _receiver(index, unit, call, graph):
    proof = index.receiver_proof(unit, call)
    output = {}
    for key in (
        "status",
        "qualified_name",
        "kind",
        "effects",
        "receiver_is_path",
        "receiver_is_non_path",
        "path_argument_index",
        "bound_method",
        "line",
    ):
        if key in proof:
            output[key] = proof[key]
    if "path_argument_name" in proof:
        output["path_argument_name"] = proof["path_argument_name"]
    output.setdefault("status", "unknown")
    output["limitations"] = list(proof.get("limitations") or [])
    output["steps"] = []
    if proof.get("file"):
        output["file"] = index.relative_path(proof["file"])
        if output["file"] not in index.units:
            output["status"] = "unknown"
            output["limitations"].append(
                "Receiver source is outside the selected source snapshot."
            )
    for original in proof.get("steps") or []:
        path = index.relative_path(original.get("file") or unit.path)
        location = index.units.get(path)
        if location is None:
            continue
        message = original.get("description") or "Source receiver binding."
        line = original.get("line") or call.lineno
        step = graph.add("receiver", location, None, message, line=line)
        graph.connect(step, graph.sink_id, "receiver")
        output["steps"].append(
            {
                "kind": original.get("kind", "source_binding"),
                "file": path,
                "line": line,
                "description": message,
                "source_sha256": location.digest,
            }
        )
    if output["status"] != "resolved":
        graph.limit(
            "Sink receiver/provider is unresolved; its name does not prove sink identity."
        )
    for limitation in output["limitations"]:
        graph.limit(str(limitation))
    return output


def _arguments(call, finding, receiver, graph):
    rule = finding.get("rule_id")
    arguments = []
    if rule in {"SKY-D211", "SKY-D217"}:
        if call.args:
            return [call.args[0]]
        for keyword in call.keywords:
            if keyword.arg in {"sql", "query", "statement"}:
                return [keyword.value]
        return []
    if rule in {"SKY-D215", "SKY-D324", "SKY-D325"}:
        if (
            isinstance(call.func, ast.Attribute)
            and receiver.get("receiver_is_path") is True
        ):
            return [call.func.value]
        position = receiver.get("path_argument_index")
        if type(position) is int and 0 <= position < len(call.args):
            return [call.args[position]]
        name = receiver.get("path_argument_name")
        if isinstance(name, str):
            for keyword in call.keywords:
                if keyword.arg == name:
                    return [keyword.value]
        qualified = receiver.get("qualified_name")
        if isinstance(call.func, ast.Attribute):
            if qualified not in {"builtins.open", "io.open", "os.open"}:
                graph.limit(
                    "Method receiver is only an alleged path; content arguments are not substituted for its unknown path identity."
                )
                return [call.func.value]
        if call.args:
            return [call.args[0]]
        for keyword in call.keywords:
            if keyword.arg in {"file", "filename", "path"}:
                return [keyword.value]
        return []
    for argument in call.args:
        arguments.append(argument)
    for keyword in call.keywords:
        arguments.append(keyword.value)
    return arguments


def trace_finding(finding, index):
    graph = TraceGraph(index, finding)
    path = index.relative_path(finding.get("file") or finding.get("file_path") or ".")
    unit = index.units.get(path)
    if unit is not None:
        call = _sink_call(unit, finding)
    else:
        call = None
    document = index.documents.get(path)
    rule = str(finding.get("rule_id") or "")
    if re.fullmatch(r"SKY-[A-Z0-9]+", rule) is None:
        rule = "reported finding"
    if unit is not None:
        location = unit
    else:
        location = document
    graph.sink_id = graph.add(
        "sink", location, call, "Static finding location: " + rule
    )
    receiver = {
        "status": "unknown",
        "qualified_name": None,
        "limitations": ["No source-resolved Python sink call."],
    }
    if unit is None:
        graph.limit(
            "Finding source is outside the selected readable Python snapshot; config/other languages are not interpreted as Python."
        )
    elif call is None:
        graph.limit(
            "No unambiguous Python call at the reported location; the original finding is retained."
        )
    else:
        receiver = _receiver(index, unit, call, graph)
        observed_guards(unit, call, graph, graph.sink_id)
        walker = PredecessorWalker(index, graph)
        scope = unit.scope_for(call)
        arguments = _arguments(call, finding, receiver, graph)
        if not arguments:
            graph.limit(
                "No modeled sink data argument; receiver/property state is unknown."
            )
        for argument in arguments:
            walker.walk(unit, scope, argument, graph.sink_id)
    return graph.finish(receiver)


def attach_security_traces(findings, *, project_root, files=None, limits=None):
    """Attach deterministic explanatory metadata; preserve every original field."""
    failure = None
    findings = list(findings)
    if not findings:
        return
    selected_files = None
    if files is not None:
        selected_files = list(files)
    priority_files = []
    for finding in findings:
        if isinstance(finding, Mapping):
            path = finding.get("file") or finding.get("file_path")
            if path:
                priority_files.append(path)
    try:
        index = build_index(
            project_root, selected_files, limits=limits, priority_files=priority_files
        )
    except Exception as error:
        from skylos.security.static_trace_index import ProjectTraceIndex

        index = ProjectTraceIndex(project_root, (), limits)
        failure = type(error).__name__
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        metadata = finding.get("metadata")
        if metadata is not None and not isinstance(metadata, Mapping):
            continue
        updated = dict(metadata or {})
        if failure is None:
            try:
                trace = trace_finding(finding, index)
            except Exception as error:
                trace = _failed_trace(finding, index, type(error).__name__)
        else:
            trace = _failed_trace(finding, index, failure)
        updated["security_trace"] = trace
        finding["metadata"] = updated


def _failed_trace(finding, index, error_class):
    graph = TraceGraph(index, finding)
    path = index.relative_path(finding.get("file") or finding.get("file_path") or ".")
    unit = index.units.get(path)
    location = unit
    if location is None:
        location = index.documents.get(path)
    graph.sink_id = graph.add(
        "sink",
        location,
        None,
        "Original security candidate retained; optional static explanation is unavailable.",
    )
    graph.limit(
        "Static trace unavailable (" + error_class + "); original finding retained."
    )
    receiver = {"status": "unknown", "qualified_name": None, "limitations": []}
    trace = graph.finish(receiver)
    trace["error"] = error_class
    return trace
