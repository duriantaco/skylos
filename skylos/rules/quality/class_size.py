import ast
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.quality._test_code import is_collected_test_class, is_python_test_file
from skylos.rules.quality._code_lines import code_lines
from skylos.rules.quality._receivers import (
    class_method_nodes,
    context_method_kinds,
    method_receiver,
    receiver_usage,
    resolve_method_kinds,
)
from skylos.rules.quality._scope import (
    is_non_production_python,
    is_sample_or_build_python,
)

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BLOCKS = (ast.stmt, ast.excepthandler, ast.match_case)


def _read_source(filename: str) -> str | None:
    if not filename:
        return None

    try:
        return Path(filename).read_text(
            encoding="utf-8", errors="ignore"
        )  # skylos: ignore[SKY-D215] analyzer reads discovered source files
    except OSError:
        return None


def _module_definitions(module: ast.Module) -> tuple[int, int]:
    """Classes, and functions or methods, defined outside any function body.

    A function's nested helpers and local classes belong to that function,
    not to the file's surface.
    """
    classes = functions = 0
    pending = list(module.body)
    while pending:
        child = pending.pop()
        if isinstance(child, _FUNCTIONS):
            functions += 1
        elif isinstance(child, ast.ClassDef):
            classes += 1
            pending.extend(child.body)
        else:
            pending.extend(
                item for item in ast.iter_child_nodes(child) if isinstance(item, _BLOCKS)
            )
    return classes, functions


def _is_dunder(name: str) -> bool:
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_test_class(node: ast.ClassDef) -> bool:
    return is_collected_test_class(
        node.name,
        [_base_name(base) for base in node.bases],
        method_names=[
            item.name
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        ],
        opted_out=_opts_out_of_collection(node),
    )


def _opts_out_of_collection(node: ast.ClassDef) -> bool:
    """``__test__ = False`` in the class body."""
    for item in node.body:
        targets = item.targets if isinstance(item, ast.Assign) else [getattr(item, "target", None)]
        value = getattr(item, "value", None)
        if (
            isinstance(item, (ast.Assign, ast.AnnAssign))
            and any(isinstance(t, ast.Name) and t.id == "__test__" for t in targets)
            and isinstance(value, ast.Constant)
            and value.value is False
        ):
            return True
    return False


class GodFileRule(SkylosRule):
    rule_id = "SKY-Q502"
    name = "God File"

    def __init__(
        self,
        max_lines=500,
        max_definitions=40,
        max_top_level_definitions=25,
    ):
        self.max_lines = max_lines
        self.max_definitions = max_definitions
        self.max_top_level_definitions = max_top_level_definitions

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        if is_non_production_python(filename, context.get("project_root")):
            return None
        source = context.get("source")
        if not isinstance(source, str):
            source = _read_source(filename)
        code_line_count = len(code_lines(node, source))

        top_level_definitions = sum(
            1
            for item in node.body
            if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        )
        class_count, function_count = _module_definitions(node)
        total_definitions = class_count + function_count

        metrics = [
            (
                "code_lines",
                code_line_count,
                self.max_lines,
                "code lines, not counting blank, comment or docstring lines",
            ),
            (
                "total_definitions",
                total_definitions,
                self.max_definitions,
                "classes, functions and methods outside function bodies",
            ),
            (
                "top_level_definitions",
                top_level_definitions,
                self.max_top_level_definitions,
                "top-level definitions",
            ),
        ]
        violations = [
            metric for metric in metrics if metric[2] > 0 and metric[1] > metric[2]
        ]
        if not violations:
            return None

        primary_metric, value, threshold, _label = max(
            violations,
            key=lambda metric: metric[1] / metric[2],
        )
        worst_ratio = value / threshold if threshold else 1.0
        severity = "HIGH" if worst_ratio >= 1.5 or len(violations) >= 2 else "MEDIUM"

        basename = Path(filename).name if filename else "<module>"
        module_name = context.get("mod") or basename
        violation_summary = ", ".join(
            f"{actual} {label} (limit: {limit})"
            for _metric, actual, limit, label in violations
        )

        return [
            {
                "rule_id": self.rule_id,
                "kind": "quality",
                "severity": severity,
                "type": "module",
                "name": module_name,
                "simple_name": basename,
                "value": value,
                "threshold": threshold,
                "metric": primary_metric,
                "code_lines": code_line_count,
                "total_definitions": total_definitions,
                "top_level_definitions": top_level_definitions,
                "class_count": class_count,
                "function_count": function_count,
                "message": (
                    f"File '{basename}' is a god file candidate: {violation_summary}. "
                    "Consider splitting it by responsibility."
                ),
                "file": filename,
                "basename": basename,
                "line": 1,
                "col": 0,
            }
        ]


class GodClassRule(SkylosRule):
    """Too many methods or instance attributes for one class.

    Dunder methods implement protocols (``__len__``, ``__getitem__``, ...);
    a mapping or sequence type needs them all, so they are not counted
    toward the method limit.
    """

    rule_id = "SKY-Q501"
    name = "God Class"

    def __init__(self, max_methods=20, max_attributes=15):
        self.max_methods = max_methods
        self.max_attributes = max_attributes
        self._method_kinds = {}
        self._skip_file = False

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._skip_file = is_sample_or_build_python(
                context.get("filename"), context.get("project_root")
            )
            self._method_kinds = (
                {} if self._skip_file else context_method_kinds(node, context)
            )
            return None
        if self._skip_file or not isinstance(node, ast.ClassDef):
            return None

        # A test class groups many cases (and their fixtures) by design;
        # its size is not a design defect.
        if _is_test_class(node) and is_python_test_file(
            context.get("filename", ""),
            context.get("project_root"),
            context.get("source"),
        ):
            return None

        method_count = 0
        dunder_count = 0
        attributes = set()

        kinds = self._method_kinds or resolve_method_kinds(node)
        for item in class_method_nodes(node):
            if _is_dunder(item.name):
                dunder_count += 1
            else:
                method_count += 1

            if method_receiver(item, instance_only=True, kinds=kinds) is not None:
                attributes.update(receiver_usage(item, kinds=kinds).writes)

        findings = []

        if method_count > self.max_methods:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": method_count,
                    "threshold": self.max_methods,
                    "dunder_methods": dunder_count,
                    "message": (
                        f"Class '{node.name}' has {method_count} methods "
                        f"(limit: {self.max_methods}); dunder protocol methods "
                        "are not counted. Consider splitting into smaller classes."
                    ),
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        if len(attributes) > self.max_attributes:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": "MEDIUM",
                    "type": "class",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": len(attributes),
                    "threshold": self.max_attributes,
                    "message": f"Class '{node.name}' has {len(attributes)} attributes (limit: {self.max_attributes}). Consider splitting into smaller classes.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        return findings if findings else None
