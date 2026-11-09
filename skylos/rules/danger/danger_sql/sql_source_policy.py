"""Keep SQL injection claims distinct from unresolved query provenance.

The local detector discovers candidate query construction. This project pass
requires an identified input source before presenting a candidate as SQL
injection. Unknown values remain diagnostics; they are never declared safe.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys

from ..danger_fs import path_provenance as graph
from ..project_source import project_source_snapshot


UNKNOWN_REASON = (
    "SQL query sources remain unresolved; attacker control has not been "
    "established. This diagnostic is not proof that the query is safe "
    "(see metadata.sql_provenance)."
)


_SPECS = {
    "SKY-D211": {
        "operand": "sql_operand",
        "digest": "sql_source_ast_sha256",
        "provenance": "sql_provenance",
        "sink": "sql_sink",
        "evidence": "python_sql_source_to_sink",
        "missing": "SQL values must use bound parameters",
        "message": "Possible SQL injection: identified input reaches SQL query text.",
        "reason": UNKNOWN_REASON,
    },
    "SKY-D230": {
        "operand": "redirect_operand",
        "digest": "redirect_source_ast_sha256",
        "provenance": "redirect_provenance",
        "sink": "redirect_sink",
        "evidence": "python_redirect_source_to_sink",
        "missing": "redirect origin allowlist",
        "message": "Possible open redirect: identified input reaches a redirect target.",
        "reason": "Redirect target sources remain unresolved; attacker control has not been established. This diagnostic is not proof that the target is safe (see metadata.redirect_provenance).",
    },
}


class RedirectSourceTracer(graph._Tracer):
    def __init__(self, project):
        super().__init__(project, "SKY-D230")

    def _guarded(self, site, expr):
        return None


class SqlSourceTracer(graph._Tracer):
    """Use the bounded call graph without filesystem safety assumptions."""

    def __init__(self, project):
        super().__init__(project, "SKY-D211")

    def _guarded(self, site, expr):
        # Path containment is unrelated to SQL syntax. SQL-specific literal
        # and bound-parameter proofs run in the local SQL detector instead.
        return None

    @staticmethod
    def _input_facts(facts):
        return facts.moved(
            graph.OPERATOR,
            graph.UNTRUSTED,
            "operator-supplied data is an identified SQL input source",
        )

    def _call_source(self, unit, scope, node, names):
        facts = super()._call_source(unit, scope, node, names)
        if facts is not None and names.intersection(
            graph._STDIN_CALLS | graph._ENV_CALLS
        ):
            return self._input_facts(facts)
        return facts

    def _environment(self, unit, node, key):
        return self._input_facts(super()._environment(unit, node, key))

    def _param(self, unit, owner, param, env):
        facts = super()._param(unit, owner, param, env)
        entry = self.project.parameter_entry(unit, owner.node, param)
        if entry is not None and entry[0] == graph.OPERATOR:
            return self._input_facts(facts)
        return facts


def _candidate(finding):
    metadata = finding.get("metadata") or {}
    spec = _SPECS.get(finding.get("rule_id"))
    return (
        spec is not None
        and isinstance(metadata.get(spec["operand"]), dict)
        and (
            finding.get("rule_id") == "SKY-D230"
            or not metadata.get("security_evidence")
        )
    )


def _record(status, finding, facts=None, *, complete=False, limits=()):
    record = {
        "version": 1,
        "status": status,
        "function": finding.get("symbol", "<module>"),
        "complete_project": complete,
        "safety_proven": False,
    }
    if facts is not None:
        for kind in (graph.UNTRUSTED, graph.UNKNOWN, graph.INCOMPLETE, graph.OPERATOR):
            if facts.chains[kind]:
                record[kind] = [list(chain) for chain in facts.chains[kind]]
    if limits:
        record["limits"] = list(limits)
    return record


def _incomplete(findings, reason):
    result = []
    for finding in findings:
        if _candidate(finding):
            finding = {**finding, "metadata": dict(finding["metadata"])}
            finding["metadata"][_SPECS[finding["rule_id"]]["provenance"]] = _record(
                graph.INCOMPLETE, finding, limits=[reason]
            )
        result.append(finding)
    return result


def resolve_source_required_findings(findings, *, scan_path, project_root, suppressed):
    retained = []
    for finding in findings:
        metadata = finding.get("metadata") or {}
        if finding.get("rule_id") == "SKY-D218" and metadata.get("audit_only") is True:
            metadata = {**metadata, "source_status": "unknown"}
            metadata["url_scheme_provenance"] = _record(graph.UNKNOWN, finding)
            suppressed.append(
                {
                    **finding,
                    "metadata": metadata,
                    "category": "danger",
                    "reason": "URL scheme audit does not establish attacker control. This diagnostic is not proof that the URL is safe.",
                }
            )
        else:
            retained.append(finding)
    findings = retained
    if not any(_candidate(finding) for finding in findings):
        return findings
    root, files, complete = graph._scan_root(scan_path, project_root)
    if root is None:
        return _incomplete(findings, "SQL project root could not be established")
    trees, snapshot_complete = project_source_snapshot(root)
    if not snapshot_complete:
        return _incomplete(findings, "SQL source snapshot is incomplete")
    old_limit = sys.getrecursionlimit()
    if old_limit < graph._RECURSION_LIMIT:
        sys.setrecursionlimit(graph._RECURSION_LIMIT)
    try:
        try:
            project = graph._Project.load(root, files, complete)
        except (OSError, RuntimeError, ValueError, RecursionError, MemoryError):
            return _incomplete(findings, "SQL caller indexing could not complete")
        tracers = {
            "SKY-D211": SqlSourceTracer(project),
            "SKY-D230": RedirectSourceTracer(project),
        }
        result = []
        source_digests = {}
        for finding in findings:
            if not _candidate(finding):
                result.append(finding)
                continue
            updated = {**finding, "metadata": dict(finding["metadata"])}
            metadata = updated["metadata"]
            spec = _SPECS[finding["rule_id"]]
            tracer = tracers[finding["rule_id"]]
            try:
                path = Path(str(finding["file"])).resolve()
                unit = project.by_path.get(path)
                captured = trees.get(path)
                if (
                    path not in source_digests
                    and unit is not None
                    and captured is not None
                ):
                    source_digests[path] = (
                        hashlib.sha256(ast.dump(unit.tree).encode()).hexdigest(),
                        hashlib.sha256(ast.dump(captured).encode()).hexdigest(),
                    )
                digests = source_digests.get(path)
                if (
                    unit is None
                    or captured is None
                    or digests is None
                    or digests[0] != digests[1]
                    or digests[1] != metadata.get(spec["digest"])
                ):
                    raise ValueError("SQL source is absent or changed during indexing")
                operand = graph._locate_operand(unit, metadata[spec["operand"]])
                if operand is None:
                    raise ValueError("SQL query expression could not be located")
                tracer.work = 0
                facts = tracer.trace(unit, unit.scope_of(operand), operand)
                if facts.chains[graph.UNTRUSTED]:
                    status = graph.UNTRUSTED
                elif facts.chains[graph.INCOMPLETE] or project.truncated:
                    status = graph.INCOMPLETE
                else:
                    status = graph.UNKNOWN
                metadata[spec["provenance"]] = _record(
                    status,
                    finding,
                    facts,
                    complete=project.complete,
                    limits=project.limits,
                )
                if status == graph.UNTRUSTED:
                    chain = list(facts.chains[graph.UNTRUSTED][0])
                    source = graph._strip_location(chain[0])
                    sink = metadata.get(spec["sink"], "security-sensitive operation")
                    metadata["security_evidence"] = {
                        "evidence_kind": spec["evidence"],
                        "source": source,
                        "sources": [source],
                        "sink": sink,
                        "path": [*map(graph._strip_location, chain), f"reaches {sink}"],
                        "guards_seen": [],
                        "guards_missing": [spec["missing"]],
                        "analysis_complete": False,
                    }
                    metadata["source_status"] = "untrusted"
                    metadata.pop("audit_only", None)
                    updated["message"] = spec["message"]
                    result.append(updated)
                elif status == graph.INCOMPLETE:
                    result.append(updated)
                else:
                    if metadata.get("security_evidence"):
                        metadata["candidate_security_evidence"] = metadata.pop(
                            "security_evidence"
                        )
                    metadata["source_status"] = "unknown"
                    metadata["audit_only"] = True
                    updated["category"] = "danger"
                    updated["reason"] = spec["reason"]
                    suppressed.append(updated)
            except (
                OSError,
                RuntimeError,
                ValueError,
                TypeError,
                RecursionError,
                MemoryError,
                AttributeError,
                KeyError,
            ):
                metadata[spec["provenance"]] = _record(
                    graph.INCOMPLETE,
                    finding,
                    limits=["SQL source analysis could not complete"],
                )
                result.append(updated)
        return result
    finally:
        sys.setrecursionlimit(old_limit)


resolve_sql_source_findings = resolve_source_required_findings
