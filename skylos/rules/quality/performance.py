from __future__ import annotations
import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


def _get_loop_target_name(node: ast.For) -> str | None:
    if isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _inner_iterates_over_outer(outer: ast.For, inner: ast.For) -> bool:
    outer_name = _get_loop_target_name(outer)
    if outer_name is None:
        return False

    inner_iter = inner.iter

    if isinstance(inner_iter, ast.Attribute):
        if isinstance(inner_iter.value, ast.Name) and inner_iter.value.id == outer_name:
            return True

    if isinstance(inner_iter, ast.Subscript):
        if isinstance(inner_iter.value, ast.Name) and inner_iter.value.id == outer_name:
            return True

    if isinstance(inner_iter, ast.Call):
        for arg in inner_iter.args:
            if isinstance(arg, ast.Name) and arg.id == outer_name:
                return True
            if isinstance(arg, ast.Attribute):
                if isinstance(arg.value, ast.Name) and arg.value.id == outer_name:
                    return True

    return False


def _is_file_read_context(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return True

    receiver = node.func.value

    if isinstance(receiver, ast.Name):
        name = receiver.id.lower()

        non_file_hints = (
            "response", "resp", "reply", "buf", "buffer",
            "stringio", "bytesio", "stream", "bio", "sio",
            "stdin", "stdout", "stderr",
        )
        if any(hint in name for hint in non_file_hints):
            return False

    return True


class PerformanceRule(SkylosRule):
    rule_id = "SKY-P401"
    name = "Performance Checks"

    def __init__(self, ignore_list=None):
        self.ignore_list = ignore_list or []

    def _is_pandas_read(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read_csv":
            return True
        return False

    def _find_nested_loops(self, outer: ast.For, body: list[ast.stmt]) -> list[dict]:
        findings_list = []
        for child in body:
            if isinstance(child, ast.For):
                if not _inner_iterates_over_outer(outer, child):
                    findings_list.append(child)
            elif isinstance(child, ast.If):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
            elif isinstance(child, ast.With):
                findings_list.extend(self._find_nested_loops(outer, child.body))
            elif isinstance(child, ast.Try):
                findings_list.extend(self._find_nested_loops(outer, child.body))
                for handler in child.handlers:
                    findings_list.extend(self._find_nested_loops(outer, handler.body))
                if child.orelse:
                    findings_list.extend(self._find_nested_loops(outer, child.orelse))
                if child.finalbody:
                    findings_list.extend(self._find_nested_loops(outer, child.finalbody))
        return findings_list

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "read",
                "readlines",
            ):
                if "SKY-P401" not in self.ignore_list:
                    if _is_file_read_context(node):
                        findings.append(
                            {
                                "rule_id": "SKY-P401",
                                "kind": "performance",
                                "severity": "LOW",
                                "type": "function",
                                "name": node.func.attr,
                                "simple_name": node.func.attr,
                                "value": "memory_load",
                                "threshold": 0,
                                "message": f"Potential Memory Risk: '{node.func.attr}()' loads entire file into RAM. Consider iterating line-by-line for large files.",
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
                suspect_loops = self._find_nested_loops(node, node.body)
                for inner_loop in suspect_loops:
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
                            "message": "Performance Warning: Nested loop detected — may be O(N²). Consider using a dict lookup or itertools.",
                            "file": context.get("filename"),
                            "basename": Path(context.get("filename", "")).name,
                            "line": inner_loop.lineno,
                            "col": inner_loop.col_offset,
                        }
                    )

        return findings if findings else None