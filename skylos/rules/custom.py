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
        # Taint tracking state: maps variable names to taint status within function scope
        self._taint_state: dict[str, bool] = {}

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

        elif pattern_type == "taint_flow":
            return self._check_taint_flow(node, context)

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

    def _check_taint_flow(self, node, context):
        """Check for tainted data flowing from sources to sinks without sanitization."""
        sources = self.pattern.get("sources", [])
        sinks = self.pattern.get("sinks", [])
        sanitizers = self.pattern.get("sanitizers", [])

        # Reset taint state at function scope boundaries
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._taint_state = {}

        # Track assignments: var = source(...)  or  var = request.form[...]
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if self._expr_matches_sources(node.value, sources):
                        self._taint_state[var_name] = True
                    elif self._expr_is_sanitizer_call(node.value, sanitizers):
                        # Sanitizer call removes taint
                        self._taint_state[var_name] = False
                    elif self._expr_contains_tainted(node.value, sources):
                        # Taint propagates through expressions containing tainted vars
                        self._taint_state[var_name] = True

        # Check sink calls for tainted arguments
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            if call_name and any(s in call_name for s in sinks):
                # Check if any argument is tainted
                for arg in node.args:
                    if self._arg_is_tainted(arg, sources):
                        return [self._make_finding(node, context)]
                # Check keyword arguments too
                for kw in node.keywords:
                    if kw.value and self._arg_is_tainted(kw.value, sources):
                        return [self._make_finding(node, context)]

        return None

    def _expr_matches_sources(self, node, sources):
        """Check if an expression references any source pattern."""
        expr_str = self._node_to_str(node)
        if expr_str and any(s in expr_str for s in sources):
            return True
        # Check subscript access like request.form["key"]
        if isinstance(node, ast.Subscript):
            return self._expr_matches_sources(node.value, sources)
        # Check call like request.get_json()
        if isinstance(node, ast.Call):
            return self._expr_matches_sources(node.func, sources)
        return False

    def _expr_is_sanitizer_call(self, node, sanitizers):
        """Check if an expression is a sanitizer call wrapping a tainted variable."""
        if not isinstance(node, ast.Call):
            return False
        call_name = self._get_call_name(node)
        if call_name and any(s in call_name for s in sanitizers):
            # Check that it wraps a tainted variable
            for arg in node.args:
                if isinstance(arg, ast.Name) and self._taint_state.get(arg.id):
                    return True
        return False

    def _expr_contains_tainted(self, node, sources):
        """Check if an expression contains any tainted variable reference."""
        if isinstance(node, ast.Name) and self._taint_state.get(node.id):
            return True
        if isinstance(node, ast.BinOp):
            return self._expr_contains_tainted(
                node.left, sources
            ) or self._expr_contains_tainted(node.right, sources)
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._expr_contains_tainted(val.value, sources):
                        return True
            return False
        if isinstance(node, ast.Call):
            # .format(tainted_var) or func(tainted_var)
            for arg in node.args:
                if self._expr_contains_tainted(arg, sources):
                    return True
            for kw in node.keywords:
                if kw.value and self._expr_contains_tainted(kw.value, sources):
                    return True
        return False

    def _arg_is_tainted(self, node, sources):
        """Check if a call argument contains tainted data."""
        # Direct variable reference
        if isinstance(node, ast.Name) and self._taint_state.get(node.id):
            return True
        # f-string or format string containing tainted variable
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if isinstance(val.value, ast.Name) and self._taint_state.get(
                        val.value.id
                    ):
                        return True
        # String concatenation/formatting with tainted variable
        if isinstance(node, ast.BinOp):
            if self._arg_is_tainted(node.left, sources) or self._arg_is_tainted(
                node.right, sources
            ):
                return True
        # .format() call with tainted arg
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for arg in node.args:
                    if self._arg_is_tainted(arg, sources):
                        return True
            # Direct source call as argument to sink
            call_name = self._get_call_name(node)
            if call_name and any(s in call_name for s in sources):
                return True
        # % formatting: "..." % (var,)
        if isinstance(node, ast.Tuple):
            for elt in node.elts:
                if self._arg_is_tainted(elt, sources):
                    return True
        # Subscript access like request.form["key"] as direct argument
        if isinstance(node, ast.Subscript):
            sub_str = self._node_to_str(node.value)
            if sub_str and any(s in sub_str for s in sources):
                return True
        # Direct source attribute access as argument
        expr_str = self._node_to_str(node)
        if expr_str and any(s in expr_str for s in sources):
            return True
        return False

    def _node_to_str(self, node):
        """Convert a simple AST node to a dotted string representation."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._node_to_str(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
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


def load_community_rules() -> list[dict]:
    """Load all installed community rules from ~/.skylos/rules/"""
    rules_dir = Path.home() / ".skylos" / "rules"
    if not rules_dir.exists():
        return []
    all_rules = []
    for f in sorted(rules_dir.glob("*.yml")):
        try:
            import yaml

            data = yaml.safe_load(f.read_text())
            if data and "rules" in data:
                for rule_def in data["rules"]:
                    all_rules.append(
                        {
                            "rule_id": rule_def["id"],
                            "name": rule_def["name"],
                            "rule_type": "yaml",
                            "enabled": True,
                            "severity": rule_def.get("severity", "MEDIUM"),
                            "category": rule_def.get("category", "community"),
                            "yaml_config": {
                                "pattern": rule_def.get("pattern", {}),
                                "message": rule_def.get(
                                    "message", "Community rule violation"
                                ),
                            },
                        }
                    )
        except Exception:
            continue
    return all_rules
