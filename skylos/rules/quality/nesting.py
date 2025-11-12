from __future__ import annotations
import ast
from pathlib import Path

"""
Rule ID: SKY-Q302
Trigger: max nesting depth > threshold (default 3)
Why: Deep nesting hurts readability/testability
Fix: Use guard clauses / early returns / extract helpers / invert conditions
"""

RULE_ID = "SKY-Q302"

NEST_NODES = (ast.If, ast.For, ast.While, ast.Try, ast.With)

def _max_depth(nodes, depth=0):
    max_depth = depth
    
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        if isinstance(node, NEST_NODES):
            branches = []
            
            if isinstance(node, ast.If):
                branches.append(node.body)
                if node.orelse:
                    branches.append(node.orelse)
            
            elif isinstance(node, (ast.For, ast.While)):
                branches.append(node.body)
                if node.orelse:
                    branches.append(node.orelse)
            
            elif isinstance(node, ast.With):
                branches.append(node.body)
            
            elif isinstance(node, ast.Try):
                branches.append(node.body)
                for handler in node.handlers:
                    branches.append(handler.body)
                if node.orelse:
                    branches.append(node.orelse)
                if node.finalbody:
                    branches.append(node.finalbody)
            
            for branch in branches:
                max_depth = max(max_depth, _max_depth(branch, depth + 1))
    
    return max_depth

def _function_lengths(source, node):
    start = node.lineno
    end = node.end_lineno
    lines = source.splitlines()[start - 1:end]
    
    physical = len(lines)
    logical = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            logical += 1
    
    return physical, logical

def scan_nesting(ctx, threshold=3):
    source = ctx["source"]
    file_path = ctx["file"]
    module_name = ctx.get("mod")
    tree = ast.parse(source)

    functions = [
        node for node in ast.walk(tree) 
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for func in functions:
        depth = _max_depth(func.body, 0)
        
        if depth > threshold:
            physical, logical = _function_lengths(source, func)
            
            if module_name:
                full_name = f"{module_name}.{func.name}"
            else:
                full_name = func.name
            
            if depth <= threshold + 2:
                severity = "MEDIUM"
            elif depth <= threshold + 5:
                severity = "HIGH"
            else:
                severity = "CRITICAL"
            
            yield {
                "rule_id": RULE_ID,
                "kind": "nesting",
                "type": "function",
                "name": full_name,
                "simple_name": func.name,
                "file": str(file_path),
                "basename": Path(file_path).name,
                "line": func.lineno,
                "metric": "max_nesting",
                "value": depth,
                "threshold": threshold,
                "length": physical,
                "logical_length": logical,
                "severity": severity,
                "message": f"Nesting depth of {depth} exceeds threshold of {threshold}. "
                           f"Consider using early returns or extracting logic.",
            }