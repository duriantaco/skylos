"""Deterministic, credential-free source locations and predecessor edges."""

from __future__ import annotations

import hashlib
import json


def stable_id(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:24]


class TraceGraph:
    def __init__(self, index, finding):
        self.index = index
        self.finding = finding
        self.trace_id = stable_id(
            [
                "static-security-trace-v1",
                index.snapshot_id(),
                finding.get("rule_id"),
                index.relative_path(
                    finding.get("file") or finding.get("file_path") or "."
                ),
                finding.get("line"),
                finding.get("col", finding.get("column")),
            ]
        )
        self.steps = {}
        self.edges = set()
        self.limitations = set(index.limitations)
        self.incomplete = bool(index.limitations)
        self.found_source = False
        self.file_digests = {}
        self.sink_id = None

    def limit(self, message):
        self.limitations.add(message)
        self.incomplete = True

    def add(self, kind, unit, node, message, *, token="", line=None):
        path = None
        digest = None
        if unit is not None:
            path = unit.path
            digest = unit.digest
            self.file_digests[path] = digest
        else:
            path = self.index.relative_path(
                self.finding.get("file") or self.finding.get("file_path") or "."
            )
        if line is None:
            line = getattr(node, "lineno", self.finding.get("line", 1))
        column = getattr(node, "col_offset", 0)
        step_id = stable_id([self.trace_id, kind, path, line, column, message, token])
        if step_id in self.steps:
            return step_id
        if len(self.steps) >= max(1, self.index.limits.max_steps):
            self.limit(
                "Trace step budget reached; unexpanded predecessors are unknown."
            )
            return None
        step = {
            "id": step_id,
            "kind": kind,
            "message": message,
            "file": path,
            "line": line,
            "column": column,
        }
        if digest:
            step["source_sha256"] = digest
        self.steps[step_id] = step
        return step_id

    def connect(self, predecessor, successor, kind="data"):
        if predecessor and successor and predecessor != successor:
            self.edges.add((predecessor, successor, kind))

    def unknown(self, unit, node, destination, message, *, token=""):
        self.limit(message)
        step = self.add("unknown", unit, node, message, token=token)
        self.connect(step, destination)

    def finish(self, receiver):
        incoming = {}
        outgoing = {}
        for step_id in self.steps:
            incoming[step_id] = []
            outgoing[step_id] = []
        for start, end, kind in sorted(self.edges):
            if start in self.steps and end in self.steps:
                incoming[end].append(start)
                outgoing[start].append(end)
        ready = []
        for step_id in self.steps:
            if not incoming[step_id]:
                ready.append(step_id)
        ordered = []
        remaining = {}
        for step_id, parents in incoming.items():
            remaining[step_id] = len(parents)
        while ready:
            ready.sort(key=self._sort_key)
            step_id = ready.pop(0)
            ordered.append(step_id)
            for successor in sorted(outgoing[step_id], key=self._sort_key):
                remaining[successor] -= 1
                if remaining[successor] == 0:
                    ready.append(successor)
        if len(ordered) != len(self.steps):
            self.limit("Cyclic explanatory edges could not be ordered.")
            for step_id in sorted(self.steps, key=self._sort_key):
                if step_id not in ordered:
                    ordered.append(step_id)
        output_steps = []
        for step_id in ordered:
            step = dict(self.steps[step_id])
            parents = sorted(incoming[step_id], key=self._sort_key)
            if parents:
                step["parent_id"] = parents[0]
            output_steps.append(step)
        output_edges = []
        for start, end, kind in sorted(self.edges):
            output_edges.append({"from": start, "to": end, "kind": kind})
        if self.found_source and not self.incomplete:
            status = "source_to_sink"
        elif len(self.steps) > 1:
            status = "partial"
        else:
            status = "unknown"
        self.limitations.add(
            "Static source/call evidence does not prove runtime reachability, guard effectiveness or complete external callers."
        )
        return {
            "version": 1,
            "trace_id": self.trace_id,
            "status": status,
            "context": self.index.context(),
            "steps": output_steps,
            "edges": output_edges,
            "receiver": receiver,
            "file_digests": dict(sorted(self.file_digests.items())),
            "limitations": sorted(self.limitations),
        }

    def _sort_key(self, step_id):
        step = self.steps[step_id]
        if step["kind"] == "sink":
            sink_order = 1
        else:
            sink_order = 0
        return (
            sink_order,
            step.get("file") or "",
            step.get("line") or 0,
            step.get("column") or 0,
            step["kind"],
            step_id,
        )
