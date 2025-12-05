from __future__ import annotations
import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


class PerformanceRule(SkylosRule):
    rule_id = "SKY-P401"
    name = "Performance Checks"

    def __init__(self, ignore_list=None):
        self.ignore_list = ignore_list or []

    def _is_pandas_read(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read_csv":
            return True
        return False

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "read",
                "readlines",
            ):
                if "SKY-P401" not in self.ignore_list:
                    findings.append(
                        {
                            "rule_id": "SKY-P401",
                            "kind": "performance",
                            "severity": "MEDIUM",
                            "type": "function",
                            "name": node.func.attr,
                            "simple_name": node.func.attr,
                            "value": "memory_load",
                            "threshold": 0,
                            "message": f"Potential Memory Risk: '{node.func.attr}()' loads entire file into RAM. Consider iterating line-by-line.",
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": node.lineno,
                            "col": node.col_offset,
                        }
                    )

            if self._is_pandas_read(node):
                if "SKY-P402" not in self.ignore_list:
                    has_chunk = False
                    for kw in node.keywords:
                        if kw.arg == "chunksize":
                            has_chunk = True
                            break

                    if not has_chunk:
                        findings.append(
                            {
                                "rule_id": "SKY-P402",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": "read_csv",
                                "simple_name": "read_csv",
                                "value": "no_chunk",
                                "threshold": 0,
                                "message": "Pandas Memory Risk: read_csv used without 'chunksize'. Large files may crash RAM.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if isinstance(node, ast.For):
            if "SKY-P403" not in self.ignore_list:
                for child in node.body:
                    if isinstance(child, ast.For):
                        findings.append(
                            {
                                "rule_id": "SKY-P403",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "loop",
                                "name": "nested_loop",
                                "simple_name": "for",
                                "value": "O(N^2)",
                                "threshold": 0,
                                "message": "Performance Warning: Nested loop detected (O(N^2) complexity).",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": child.lineno,
                                "col": child.col_offset,
                            }
                        )

        return findings if findings else None
