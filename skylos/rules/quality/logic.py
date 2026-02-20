import ast
from pathlib import Path
from skylos.rules.base import SkylosRule


MUTABLE_CONSTRUCTORS = {
    "list",
    "dict",
    "set",
    "defaultdict",
    "OrderedDict",
    "Counter",
    "deque",
    "array",
}


class MutableDefaultRule(SkylosRule):
    rule_id = "SKY-L001"
    name = "Mutable Default Argument"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        findings = []

        kw_defaults_filtered = []
        for d in node.args.kw_defaults:
            if d:
                kw_defaults_filtered.append(d)

        for default in node.args.defaults + kw_defaults_filtered:
            is_mutable = False

            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                is_mutable = True

            elif isinstance(default, (ast.ListComp, ast.DictComp, ast.SetComp)):
                is_mutable = True

            elif isinstance(default, ast.Call):
                if isinstance(default.func, ast.Name):
                    if default.func.id in MUTABLE_CONSTRUCTORS:
                        is_mutable = True

            if is_mutable:
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "function",
                        "name": node.name,
                        "simple_name": node.name,
                        "value": "mutable",
                        "threshold": 0,
                        "message": "Mutable default argument detected. This causes state leaks between calls.",
                        "file": context.get("filename"),
                        "basename": Path(context.get("filename", "")).name,
                        "line": default.lineno,
                        "col": default.col_offset,
                    }
                )

        if findings:
            return findings
        return None


class BareExceptRule(SkylosRule):
    rule_id = "SKY-L002"
    name = "Bare Except Block"

    def visit_node(self, node, context):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "block",
                    "name": "except",
                    "simple_name": "except",
                    "value": "bare",
                    "threshold": 0,
                    "message": "Bare 'except:' block swallows SystemExit and other critical errors.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


class DangerousComparisonRule(SkylosRule):
    rule_id = "SKY-L003"
    name = "Dangerous Comparison"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Compare):
            return None

        findings = []
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(comparator, ast.Constant):
                    val = comparator.value
                    if val is True or val is False or val is None:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "LOW",
                                "type": "comparison",
                                "name": "==",
                                "simple_name": "==",
                                "value": str(comparator.value),
                                "threshold": 0,
                                "message": f"Comparison to {comparator.value} should use 'is' or 'is not'.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if findings:
            return findings
        return None


def _walk_scope(nodes):
    stack = []

    if isinstance(nodes, list):
        for n in nodes:
            stack.append(n)
    else:
        stack.append(nodes)

    while stack:
        node = stack.pop()

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        yield node

        for child in ast.iter_child_nodes(node):
            stack.append(child)


def _is_function_level_try(node: ast.Try, parent_body: list[ast.stmt]) -> bool:
    if len(parent_body) == 1 and parent_body[0] is node:
        return True
    if (
        len(parent_body) == 2
        and isinstance(parent_body[0], ast.Expr)
        and isinstance(parent_body[0].value, ast.Constant)
        and isinstance(parent_body[0].value.value, str)
        and parent_body[1] is node
    ):
        return True
    return False


class TryBlockPatternsRule(SkylosRule):
    rule_id = "SKY-L004"
    name = "Anti-Pattern Try Block"

    def __init__(self, max_lines=15, max_control_flow=3):
        self.max_lines = max_lines
        self.max_control_flow = max_control_flow

    def visit_node(self, node, context):
        if not isinstance(node, ast.Try):
            return None

        parent_body = context.get("_parent_body")
        is_func_level = (
            parent_body is not None
            and _is_function_level_try(node, parent_body)
        )

        findings = []

        if node.body and not is_func_level:
            start = node.body[0].lineno
            end = getattr(node.body[-1], "end_lineno", start)
            length = end - start + 1

            if length > self.max_lines:
                findings.append(
                    self._create_finding(
                        node,
                        context,
                        severity="LOW",
                        value=length,
                        msg=f"Try block covers {length} lines (limit: {self.max_lines}). Reduce scope to the risky operation only.",
                    )
                )

        control_flow_count = 0
        has_nested_try = False

        for stmt in node.body:
            for child in _walk_scope([stmt]):
                if child is stmt:
                    continue
                if isinstance(child, ast.Try):
                    has_nested_try = True
                if isinstance(child, (ast.If, ast.For, ast.While)):
                    control_flow_count += 1

        if has_nested_try:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="MEDIUM",
                    value="nested",
                    msg="Nested 'try' block detected. Flatten logic or move inner try to a helper function.",
                )
            )

        if control_flow_count > self.max_control_flow:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="HIGH",
                    value=control_flow_count,
                    msg=f"Try block contains {control_flow_count} control flow statements. Don't wrap complex logic in error handling.",
                )
            )

        if findings:
            return findings
        return None

    def _create_finding(self, node, context, severity, value, msg):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": severity,
            "type": "block",
            "name": "try",
            "simple_name": "try",
            "value": value,
            "threshold": 0,
            "message": msg,
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


class UnusedExceptVarRule(SkylosRule):
    rule_id = "SKY-L005"
    name = "Unused Exception Variable"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None
        if not node.name:
            return None

        use_count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == node.name:
                use_count += 1

        if use_count == 0:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "LOW",
                    "type": "variable",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "unused",
                    "threshold": 0,
                    "message": f"Exception variable '{node.name}' is captured but never used. Use '_' or remove it.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


def _annotation_allows_none(annotation) -> bool:
    if annotation is None:
        return False

    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True

    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        if _annotation_allows_none(annotation.left):
            return True
        if _annotation_allows_none(annotation.right):
            return True

    if isinstance(annotation, ast.Subscript):
        func = annotation.value
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ("Optional",):
            return True

        if name in ("Union",):
            slice_node = annotation.slice
            if isinstance(slice_node, ast.Tuple):
                for elt in slice_node.elts:
                    if isinstance(elt, ast.Constant) and elt.value is None:
                        return True
                    if isinstance(elt, ast.Name) and elt.id == "None":
                        return True

    if isinstance(annotation, ast.Name) and annotation.id == "None":
        return True

    return False


class ReturnConsistencyRule(SkylosRule):
    rule_id = "SKY-L006"
    name = "Inconsistent Return"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        if _annotation_allows_none(node.returns):
            return None

        returns_value = False
        returns_none = False

        for child in _walk_scope(node.body):
            if isinstance(child, ast.Return):
                if child.value is None:
                    returns_none = True
                elif (
                    isinstance(child.value, ast.Constant) and child.value.value is None
                ):
                    returns_none = True
                else:
                    returns_value = True

        if returns_value and returns_none:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "function",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "inconsistent",
                    "threshold": 0,
                    "message": f"Function '{node.name}' has inconsistent returns: some paths return a value, others return None.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None