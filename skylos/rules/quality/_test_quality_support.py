"""Shared reporting for bounded, static Python test-quality checks."""

from __future__ import annotations

import ast
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.quality._test_subjects import test_subjects


class TestQualityRule(SkylosRule):
    kind = "logic"
    severity = "LOW"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None
        context["_test_quality_module"] = node
        findings = []
        for subject in test_subjects(node, context):
            findings.extend(self.check(subject, context))
        return findings or None

    def check(self, subject, context):
        raise NotImplementedError

    def _finding(self, node, context, *, subject, pattern, message, evidence=None):
        filename = context.get("filename")
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "severity": self.severity,
            "type": "test_quality",
            "name": subject.name,
            "simple_name": subject.node.name,
            "file": filename,
            "basename": Path(filename or "").name,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "col": node.col_offset,
            "value": pattern,
            "message": message,
            "evidence": {"pattern": pattern, "test": subject.name, **(evidence or {})},
        }
