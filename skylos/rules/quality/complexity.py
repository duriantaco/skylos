import ast
from pathlib import Path

"""
Rule ID: SKY-Q301
Trigger: Cyclomatic complexity > threshold (default 10)
Why: Too many branches/paths can increase bug risk
Fix: Use guard clauses / early returns, extract helpers, simplify boolean logic
"""

RULE_ID = "SKY-Q301" 

_COMPLEX_NODES = (
    ast.If,
    ast.For,
    ast.While,
    ast.Try,
    ast.With,
    ast.ExceptHandler,
    ast.BoolOp,
    ast.IfExp,
    ast.comprehension,
)

def _func_complexity(node):
    c = 1
    for child in ast.walk(node):
        if isinstance(child, _COMPLEX_NODES):
            c += 1
    return c

def _func_length(node):
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)

    if start is None:
        return 0

    if end is None:
        end = start
        for child in ast.walk(node):
            ln = getattr(child, "lineno", None)
            if ln is not None and ln > end:
                end = ln

    return max(end - start + 1, 0)

def scan_complex_functions(ctx, threshold=10):
    src = ctx.get("source") or ""
    file_path = ctx.get("file") or "?"
    mod = ctx.get("mod") or ""

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []

    items = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = _func_complexity(node)

            if complexity < threshold:
                continue

            length = _func_length(node)

            items.append({
                "rule_id": RULE_ID,
                "kind": "complexity",
                "type": "function",
                "name": f"{mod}.{node.name}" if mod else node.name,
                "simple_name": node.name,
                "file": str(file_path),
                "basename": Path(file_path).name,
                "line": int(getattr(node, "lineno", 1)),
                "metric": "mccabe",
                "value": int(complexity),
                "threshold": int(threshold),
                "length": int(length),
                "severity": (
                    "OK" if complexity < 10 else
                    "WARN" if complexity < 15 else
                    "HIGH" if complexity < 25 else
                    "CRITICAL"
                ),

                "message": f"Function is complex (McCabe={complexity} ≥ {threshold}). "
                        f"Consider splitting loops/branches or extracting helpers.",
            })

    return items
