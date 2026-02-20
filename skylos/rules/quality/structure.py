import ast
from skylos.rules.base import SkylosRule
from pathlib import Path


class ArgCountRule(SkylosRule):
    rule_id = "SKY-C303"
    name = "Too Many Arguments"

    def __init__(self, max_args=5, max_required=5, max_total=10):
        self.max_required = max_required if max_required != 5 else max_args
        self.max_total = max_total

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        args = node.args

        positional = [a for a in args.args if a.arg not in ("self", "cls")]
        if args.posonlyargs:
            pos_only = list(args.posonlyargs)
        else:
            pos_only = []

        all_positional = pos_only + positional
        num_defaults = len(args.defaults)
        num_required = len(all_positional) - num_defaults

        total_count = len(all_positional) + len(args.kwonlyargs)

        exceeds_required = num_required > self.max_required
        exceeds_total = total_count > self.max_total

        if not exceeds_required and not exceeds_total:
            return None

        mod = context.get("mod", "")
        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        findings = []

        if exceeds_required:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "structure",
                    "type": "function",
                    "name": func_name,
                    "simple_name": node.name,
                    "value": num_required,
                    "threshold": self.max_required,
                    "severity": "MEDIUM",
                    "message": (
                        f"Function has {num_required} required arguments "
                        f"(limit: {self.max_required}). Consider using a "
                        f"config object or keyword arguments with defaults."
                    ),
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )
        elif exceeds_total:
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "structure",
                    "type": "function",
                    "name": func_name,
                    "simple_name": node.name,
                    "value": total_count,
                    "threshold": self.max_total,
                    "severity": "LOW",
                    "message": (
                        f"Function has {total_count} total parameters "
                        f"(limit: {self.max_total}). "
                        f"({num_required} required, "
                        f"{total_count - num_required} optional)."
                    ),
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            )

        return findings


class FunctionLengthRule(SkylosRule):
    rule_id = "SKY-C304"
    name = "Function Too Long"

    def __init__(self, max_lines=50):
        self.max_lines = max_lines

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        start = getattr(node, "lineno", 0)
        end = getattr(node, "end_lineno", start)
        physical_length = max(end - start + 1, 0)

        if physical_length <= self.max_lines:
            return None

        if physical_length < 100:
            severity = "MEDIUM"
        else:
            severity = "HIGH"

        mod = context.get("mod", "")

        if mod:
            func_name = f"{mod}.{node.name}"
        else:
            func_name = node.name

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "type": "function",
                "name": func_name,
                "simple_name": node.name,
                "value": physical_length,
                "threshold": self.max_lines,
                "severity": severity,
                "message": f"Function is {physical_length} lines long (limit: {self.max_lines}).",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
