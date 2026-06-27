import ast
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


class PhantomCallRule(SkylosRule):
    rule_id = "SKY-L012"
    name = "Phantom Function Call"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._defined_names = None
        self._current_file = None

    def visit_node(self, node, context):
        filename = context.get("filename", "")

        if isinstance(node, ast.Module):
            self._current_file = filename
            self._defined_names = set()
            self._imported_names = set()
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._defined_names.add(child.name)
                elif isinstance(child, ast.ClassDef):
                    self._defined_names.add(child.name)
                    for item in child.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self._defined_names.add(item.name)
                elif isinstance(child, ast.ImportFrom):
                    if child.names:
                        for alias in child.names:
                            name = alias.asname if alias.asname else alias.name
                            self._imported_names.add(name)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        name = alias.asname if alias.asname else alias.name
                        self._imported_names.add(name.split(".")[0])
            return None

        if self._defined_names is None:
            return None

        if not isinstance(node, ast.Call):
            return None

        func = node.func
        func_name = None

        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            return None

        if not func_name:
            return None

        if func_name not in self.vibe_dictionary.phantom_security_names:
            return None

        if func_name in self._defined_names:
            return None
        if func_name in self._imported_names:
            return None

        basename = Path(filename).name
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "CRITICAL",
                "type": "call",
                "name": func_name,
                "simple_name": func_name,
                "value": "phantom",
                "threshold": 0,
                "message": (
                    f"Call to '{func_name}()' but this function is never defined or imported. "
                    f"AI-generated code often hallucinates security functions."
                ),
                "file": filename,
                "basename": basename,
                "line": node.lineno,
                "col": node.col_offset,
                "category": "ai_defect",
                "defect_type": "hallucinated_reference",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
            }
        ]
