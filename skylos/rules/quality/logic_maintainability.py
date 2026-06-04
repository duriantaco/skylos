import ast
import math
import re
from pathlib import Path

from skylos.audit.redaction import REDACTION, redact_text
from skylos.rules.base import SkylosRule
from skylos.rules.quality.logic_foundation import (
    _exception_type_names,
    _handler_body_is_trivial,
    _handler_has_real_work,
)
from skylos.rules.quality.logic_security import _qualified_call_name


_SENSITIVE_LITERAL_KEYWORDS = (
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
)


def _string_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_sensitive_literal(value: str) -> bool:
    if redact_text(value) != value:
        return True

    lowered = value.lower()
    if any(keyword in lowered for keyword in _SENSITIVE_LITERAL_KEYWORDS):
        return True

    if len(value) < 24:
        return False

    has_upper = any(char.isupper() for char in value)
    has_lower = any(char.islower() for char in value)
    has_digit = any(char.isdigit() for char in value)
    has_symbol = any(char in "_-./+=" for char in value)
    return (
        sum((has_upper, has_lower, has_digit, has_symbol)) >= 3
        and _string_entropy(value) >= 3.5
    )


def _duplicate_string_display(value: str) -> str:
    if _looks_sensitive_literal(value):
        return REDACTION
    return value if len(value) <= 40 else value[:37] + "..."


_DUPLICATE_STRING_PATH_PREFIXES = (
    "benchmarks/",
    "corpus/",
    "docs/",
    "editors/",
    "scripts/",
    "skylos/",
    "test/",
    "tests/",
)

_DUPLICATE_STRING_PATH_SUFFIXES = (
    ".cfg",
    ".css",
    ".go",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".md",
    ".php",
    ".py",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
)

_DUPLICATE_STRING_SCHEMA_VALUES = frozenset(
    {
        "ai",
        "ai_agent",
        "ai_authored",
        "basename",
        "category",
        "col",
        "confidence",
        "CRITICAL",
        "cwe",
        "dead_code",
        "debt",
        "dismissed",
        "error",
        "failed",
        "FAIL",
        "file",
        "findings",
        "fingerprint",
        "HIGH",
        "INFO",
        "kind",
        "line",
        "LOW",
        "MEDIUM",
        "message",
        "name",
        "PASS",
        "passed",
        "primary_dimension",
        "priority_score",
        "quality",
        "rule_id",
        "security",
        "secrets",
        "severity",
        "signal_count",
        "signals",
        "simple_name",
        "snoozed",
        "snoozed_until",
        "standard_refs",
        "success",
        "system",
        "threshold",
        "triage",
        "type",
        "value",
        "WARN",
    }
)


def _is_rule_identifier_literal(value: str) -> bool:
    return re.fullmatch(r"(?:SKY-[A-Z]\d{3,4}|CUSTOM-[A-Z0-9_-]+)", value) is not None


def _looks_like_filesystem_path_literal(value: str) -> bool:
    stripped = value.strip()
    normalized = stripped.replace("\\", "/")

    if "/" not in normalized:
        return False

    if normalized.startswith(("http://", "https://")):
        return False

    if normalized.startswith("/"):
        return normalized.endswith(_DUPLICATE_STRING_PATH_SUFFIXES)

    if normalized.endswith("/"):
        return True

    if normalized.startswith(_DUPLICATE_STRING_PATH_PREFIXES):
        return True

    last_segment = normalized.rsplit("/", 1)[-1]
    return last_segment.endswith(_DUPLICATE_STRING_PATH_SUFFIXES)


def _looks_like_markup_fragment(value: str) -> bool:
    stripped = value.strip()
    if re.search(r"</?[A-Za-z][^>]*>", stripped):
        return True
    return bool(re.search(r"\sdata-[A-Za-z0-9_-]+\s*=", stripped))


def _is_duplicate_string_noise(value: str) -> bool:
    stripped = value.strip()

    if stripped in _DUPLICATE_STRING_SCHEMA_VALUES:
        return True

    if _is_rule_identifier_literal(stripped):
        return True

    if _looks_like_filesystem_path_literal(stripped):
        return True

    return _looks_like_markup_fragment(value)


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}

    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_target_names(element))
        return names

    return set()


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr

    return ""


def _is_container_literal(node: ast.AST) -> bool:
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return True

    if isinstance(node, ast.Call):
        call_name = _call_name(node.func)
        return call_name in {"dict", "frozenset", "list", "set", "tuple"}

    return False


def _target_names_are_constant_like(target_names: set[str]) -> bool:
    return any(name.isupper() or name.startswith("_") for name in target_names)


def _is_module_level_assignment(parent: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    grandparent = parent_map.get(id(parent))
    return isinstance(grandparent, ast.Module)


def _assignment_targets(parent: ast.Assign | ast.AnnAssign) -> set[str]:
    if isinstance(parent, ast.Assign):
        target_names: set[str] = set()
        for target in parent.targets:
            target_names.update(_target_names(target))
        return target_names

    return _target_names(parent.target)


def _assignment_value(parent: ast.Assign | ast.AnnAssign) -> ast.AST | None:
    return parent.value


def _is_declarative_assignment(parent: ast.Assign | ast.AnnAssign) -> bool:
    value = _assignment_value(parent)
    if value is None:
        return False

    if _is_container_literal(value):
        return True

    return _target_names_are_constant_like(_assignment_targets(parent))


def _is_local_scope_node(node: ast.AST) -> bool:
    return isinstance(
        node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
    )


class DuplicateStringLiteralRule(SkylosRule):
    rule_id = "SKY-L027"
    name = "Duplicate String Literal"

    def __init__(self, threshold=3):
        self.threshold = threshold

    def _is_docstring(self, node, parent_map):
        parent = parent_map.get(id(node))
        if parent is None:
            return False
        if isinstance(parent, ast.Expr):
            grandparent = parent_map.get(id(parent))
            if grandparent is not None and isinstance(
                grandparent,
                (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                body = grandparent.body
                if body and body[0] is parent:
                    return True
        return False

    def _is_structural_key_literal(self, node, parent_map):
        parent = parent_map.get(id(node))
        if isinstance(parent, ast.Subscript) and parent.slice is node:
            return True
        if isinstance(parent, ast.Dict) and node in parent.keys:
            return True
        return False

    def _is_annotation_literal(self, node, parent_map):
        current = node
        type_alias_node = getattr(ast, "TypeAlias", None)

        while True:
            parent = parent_map.get(id(current))
            if parent is None:
                return False

            if isinstance(parent, ast.arg) and parent.annotation is current:
                return True

            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if parent.returns is current:
                    return True

            if isinstance(parent, ast.AnnAssign) and parent.annotation is current:
                return True

            if (
                type_alias_node is not None
                and isinstance(parent, type_alias_node)
                and parent.value is current
            ):
                return True

            current = parent

    def _is_module_level_declarative_literal(self, node, parent_map):
        current = node

        while True:
            parent = parent_map.get(id(current))
            if parent is None:
                return False

            if _is_local_scope_node(parent):
                return False

            if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                if not _is_module_level_assignment(parent, parent_map):
                    return False
                return _is_declarative_assignment(parent)

            current = parent

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename", "")
        basename = Path(filename).name

        if basename.startswith("test_") or basename.endswith("_test.py"):
            return None

        parent_map = {}
        for parent in ast.walk(node):
            for child in ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent

        string_occurrences = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) < 5:
                    continue
                if self._is_docstring(child, parent_map):
                    continue
                if self._is_structural_key_literal(child, parent_map):
                    continue
                if self._is_annotation_literal(child, parent_map):
                    continue
                if self._is_module_level_declarative_literal(child, parent_map):
                    continue
                if _is_duplicate_string_noise(child.value):
                    continue
                key = child.value
                if key not in string_occurrences:
                    string_occurrences[key] = []
                string_occurrences[key].append(child)

        findings = []
        for value, nodes in string_occurrences.items():
            count = len(nodes)
            if count < self.threshold:
                continue
            severity = "MEDIUM" if count >= 6 else "LOW"
            display = _duplicate_string_display(value)
            findings.append(
                {
                    "rule_id": self.rule_id,
                    "kind": "quality",
                    "severity": severity,
                    "type": "string",
                    "name": display,
                    "simple_name": display,
                    "value": count,
                    "threshold": self.threshold,
                    "message": f"String literal '{display}' repeated {count} times (threshold: {self.threshold}).",
                    "file": filename,
                    "basename": basename,
                    "line": nodes[0].lineno,
                    "col": nodes[0].col_offset,
                }
            )

        return findings if findings else None


class TooManyReturnsRule(SkylosRule):
    rule_id = "SKY-L028"
    name = "Too Many Returns"

    def __init__(self, threshold=5):
        self.threshold = threshold

    def _count_returns(self, func_node):
        count = 0
        stack = list(func_node.body)
        while stack:
            child = stack.pop()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Return):
                count += 1
            for attr in ("body", "orelse", "finalbody", "handlers"):
                block = getattr(child, attr, None)
                if block and isinstance(block, list):
                    stack.extend(block)
        return count

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        count = self._count_returns(node)
        if count < self.threshold:
            return None

        severity = "MEDIUM" if count >= 9 else "LOW"
        filename = context.get("filename", "")

        return [
            {
                "rule_id": self.rule_id,
                "kind": "structure",
                "severity": severity,
                "type": "function",
                "name": node.name,
                "simple_name": node.name,
                "value": count,
                "threshold": self.threshold,
                "message": f"Function has {count} return statements (limit: {self.threshold}). Consider simplifying control flow.",
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_BOOLEAN_TRAP_ALLOWED_NAMES = {
    "inplace",
    "reverse",
    "recursive",
    "verbose",
    "debug",
    "force",
    "dry_run",
    "strict",
}


class BooleanTrapRule(SkylosRule):
    rule_id = "SKY-L029"
    name = "Boolean Trap"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        func_name = node.name
        if func_name.startswith("__") and func_name.endswith("__"):
            return None

        args = node.args
        positional_args = args.args

        num_defaults = len(args.defaults)
        num_positional = len(positional_args)

        findings = []
        filename = context.get("filename", "")

        for i, arg in enumerate(positional_args):
            arg_name = arg.arg
            if arg_name in ("self", "cls"):
                continue
            if arg_name in _BOOLEAN_TRAP_ALLOWED_NAMES:
                continue

            is_bool_trap = False

            if arg.annotation is not None:
                if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "bool":
                    is_bool_trap = True
                elif (
                    isinstance(arg.annotation, ast.Constant)
                    and arg.annotation.value == "bool"
                ):
                    is_bool_trap = True

            if not is_bool_trap and num_defaults > 0:
                default_index = i - (num_positional - num_defaults)
                if 0 <= default_index < num_defaults:
                    default = args.defaults[default_index]
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, bool
                    ):
                        is_bool_trap = True

            if is_bool_trap:
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "quality",
                        "severity": "LOW",
                        "type": "function",
                        "name": f"{func_name}.{arg_name}",
                        "simple_name": arg_name,
                        "value": arg_name,
                        "threshold": 0,
                        "message": f"Boolean positional parameter '{arg_name}' is a readability trap. Use keyword-only arguments instead.",
                        "file": filename,
                        "basename": Path(filename).name,
                        "line": arg.lineno if hasattr(arg, "lineno") else node.lineno,
                        "col": arg.col_offset
                        if hasattr(arg, "col_offset")
                        else node.col_offset,
                    }
                )

        return findings if findings else None


class BroadExceptionRule(SkylosRule):
    rule_id = "SKY-L030"
    name = "Broad Exception with Trivial Handler"

    _BROAD_EXCEPTION_TYPES = {"Exception", "BaseException"}

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler) or node.type is None:
            return None

        broad_types = [
            exc_name
            for exc_name in _exception_type_names(node.type)
            if exc_name in self._BROAD_EXCEPTION_TYPES
        ]
        if not broad_types:
            return None
        if _handler_has_real_work(node.body):
            return None
        if not _handler_body_is_trivial(node.body):
            return None

        exc_name = ", ".join(sorted(set(broad_types)))

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "block",
                "name": "except",
                "simple_name": "except",
                "value": "broad",
                "threshold": 0,
                "message": f"Catching broad '{exc_name}' with a trivial handler silently hides bugs. Narrow the exception type or add logging/re-raise.",
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


_NO_EFFECT_EXPR_TYPES = (
    ast.BinOp,
    ast.BoolOp,
    ast.Compare,
    ast.Dict,
    ast.IfExp,
    ast.List,
    ast.Name,
    ast.Set,
    ast.Tuple,
    ast.UnaryOp,
)

_PURE_DISCARDED_CALLS = {
    "uuid.uuid1",
    "uuid.uuid3",
    "uuid.uuid4",
    "uuid.uuid5",
}


def _contains_possible_effect(node):
    return any(
        isinstance(
            child, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr)
        )
        for child in ast.walk(node)
    )


class NoEffectStatementRule(SkylosRule):
    rule_id = "SKY-L033"
    name = "No-Effect Statement"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Expr):
            return None

        value = node.value
        issue_name = "expression"
        issue_value = "no_effect"
        message = (
            "Expression statement has no effect because its result is discarded. "
            "Assign/use the result or remove the statement."
        )

        if isinstance(value, ast.Constant):
            if isinstance(value.value, str) or value.value is ...:
                return None
            if value.value is None:
                return None
        elif isinstance(value, (ast.Await, ast.Yield, ast.YieldFrom)):
            return None
        elif isinstance(value, ast.Call):
            call_name = _qualified_call_name(value.func)
            if call_name not in _PURE_DISCARDED_CALLS:
                return None
            issue_name = call_name
            issue_value = "discarded_result"
            message = (
                f"Return value from '{call_name}()' is discarded. "
                "Assign/use the result or remove the call."
            )
        elif not isinstance(value, _NO_EFFECT_EXPR_TYPES):
            return None
        elif _contains_possible_effect(value):
            return None

        filename = context.get("filename", "")
        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "LOW",
                "type": "statement",
                "name": issue_name,
                "simple_name": issue_name,
                "value": issue_value,
                "threshold": 0,
                "message": message,
                "file": filename,
                "basename": Path(filename).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]
