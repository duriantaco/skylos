import ast
from pathlib import Path

from skylos.rules.base import SkylosRule
from skylos.rules.vibe_dictionary import DEFAULT_VIBE_DICTIONARY


class PhantomDecoratorRule(SkylosRule):
    rule_id = "SKY-L023"
    name = "Phantom Decorator"

    def __init__(self, vibe_dictionary=None):
        self.vibe_dictionary = vibe_dictionary or DEFAULT_VIBE_DICTIONARY
        self._defined_names = None
        self._imported_names = None
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

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return None

        findings = []
        for deco in node.decorator_list:
            deco_name = self._extract_decorator_name(deco)
            if not deco_name:
                continue
            if deco_name not in self.vibe_dictionary.phantom_security_decorators:
                continue
            if deco_name in self._defined_names:
                continue
            if deco_name in self._imported_names:
                continue

            basename = Path(filename).name
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "CRITICAL",
                    "type": "decorator",
                    "name": deco_name,
                    "simple_name": deco_name,
                    "value": "phantom",
                    "threshold": 0,
                    "message": (
                        f"Decorator '@{deco_name}' is used but never defined or imported. "
                        f"AI-generated code often hallucinates security decorators."
                    ),
                    "file": filename,
                    "basename": basename,
                    "line": deco.lineno,
                    "col": deco.col_offset,
                    "category": "ai_defect",
                    "defect_type": "hallucinated_reference",
                    "vibe_category": "hallucinated_reference",
                    "ai_likelihood": "high",
                }
            )

        return findings if findings else None

    @staticmethod
    def _extract_decorator_name(deco):
        if isinstance(deco, ast.Call):
            return PhantomDecoratorRule._extract_decorator_name(deco.func)
        if isinstance(deco, ast.Name):
            return deco.id
        if isinstance(deco, ast.Attribute):
            return None
        return None
