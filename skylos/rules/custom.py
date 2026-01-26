from __future__ import annotations
import ast
import fnmatch
from pathlib import Path
from skylos.rules.base import SkylosRule


class YAMLRule(SkylosRule):
    def __init__(self, config):
        self._rule_id = config["rule_id"]
        self._name = config["name"]
        self.severity = config.get("severity", "MEDIUM")
        self.category = config.get("category", "custom")
        self.pattern = config.get("yaml_config", {}).get("pattern", {})
        self.message = config.get("yaml_config", {}).get(
            "message", "Custom rule violation"
        )

    @property
    def rule_id(self):
        return self._rule_id

    @property
    def name(self):
        return self._name

    def visit_node(self, node, context):
        pattern_type = self.pattern.get("type")

        if pattern_type == "function":
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return self._check_function_pattern(node, context)

        elif pattern_type == "class":
            if isinstance(node, ast.ClassDef):
                return self._check_class_pattern(node, context)

        elif pattern_type == "call":
            if isinstance(node, ast.Call):
                return self._check_call_pattern(node, context)

        return None

    def _check_function_pattern(self, node, context):
        decorators = self.pattern.get("decorators", {})
        has_any = decorators.get("has_any", [])
        must_also_have_any = decorators.get("must_also_have_any", [])

        if not has_any:
            return None

        found = set()
        for deco in node.decorator_list:
            found.add(self._get_decorator_name(deco))

        triggered = False
        for trigger in has_any:
            for f in found:
                if trigger in f:
                    triggered = True
                    break
            if triggered:
                break

        if not triggered:
            return None

        if must_also_have_any:
            has_required = False
            for required in must_also_have_any:
                for f in found:
                    if required in f:
                        has_required = True
                        break
                if has_required:
                    break

            if not has_required:
                return [self._make_finding(node, context)]

        return None

    def _check_class_pattern(self, node, context):
        name_pattern = self.pattern.get("name_pattern", "*")
        must_inherit_any = self.pattern.get("must_inherit_any", [])

        if not fnmatch.fnmatch(node.name, name_pattern):
            return None

        if must_inherit_any:
            base_names = set()
            for base in node.bases:
                base_names.add(self._get_base_name(base))

            if not (set(must_inherit_any) & base_names):
                return [self._make_finding(node, context)]

        return None

    def _check_call_pattern(self, node, context):
        function_match = self.pattern.get("function_match", [])
        args_config = self.pattern.get("args", {})

        func_name = self._get_call_name(node)
        if not func_name:
            return None

        matched = any(p in func_name for p in function_match)
        if not matched:
            return None

        if args_config.get("is_dynamic"):
            pos = args_config.get("position", 0)
            if len(node.args) > pos:
                if self._is_dynamic_string(node.args[pos]):
                    return [self._make_finding(node, context)]

        return None

    def _get_decorator_name(self, deco):
        if isinstance(deco, ast.Name):
            return deco.id
        elif isinstance(deco, ast.Attribute):
            parent = self._get_decorator_name(deco.value)
            return f"{parent}.{deco.attr}" if parent else deco.attr
        elif isinstance(deco, ast.Call):
            return self._get_decorator_name(deco.func)
        return ""

    def _get_base_name(self, base):
        if isinstance(base, ast.Name):
            return base.id
        elif isinstance(base, ast.Attribute):
            return base.attr
        return ""

    def _get_call_name(self, node):
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
            parts.reverse()
            return ".".join(parts)
        return None

    def _is_dynamic_string(self, node):
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _make_finding(self, node, context):
        name = None

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = getattr(node, "name", None)

        if name is None and isinstance(node, ast.Call):
            name = self._get_call_name(node) or "<call>"

        return {
            "rule_id": self.rule_id,
            "kind": "custom",
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "name": name or "<custom>",
            "simple_name": name or "<custom>",
            "value": "-",
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", 0),
        }


def load_custom_rules(rules_data):
    rules = []
    for config in rules_data:
        if not config.get("enabled", True):
            continue
        if config.get("rule_type") != "yaml":
            continue
        try:
            rules.append(YAMLRule(config))
        except Exception as e:
            print(f"Warning: Failed to load rule {config.get('rule_id')}: {e}")
    return rules
