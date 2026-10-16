import ast
import math
import operator
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
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


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


def _is_module_level_assignment(
    parent: ast.AST, parent_map: dict[int, ast.AST]
) -> bool:
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


def _receiver_shape(node: ast.AST) -> tuple | None:
    if isinstance(node, ast.Name):
        return ("name", node.id)
    if isinstance(node, ast.Attribute):
        base = _receiver_shape(node.value)
        if base is not None:
            return ("attribute", base, node.attr)
    return None


def _receiver_scope(node: ast.AST, parent_map: dict[int, ast.AST]) -> int | None:
    class_field = (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"self", "cls"}
    )
    current = node
    while parent := parent_map.get(id(current)):
        if class_field and isinstance(parent, ast.ClassDef):
            return id(parent)
        if not class_field and isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            return id(parent)
        if isinstance(parent, ast.Module):
            return id(parent)
        current = parent
    return None


def _mapping_receiver_key(
    node: ast.AST, parent_map: dict[int, ast.AST]
) -> tuple[int | None, tuple] | None:
    shape = _receiver_shape(node)
    if shape is None:
        return None
    return (_receiver_scope(node, parent_map), shape)


def _is_mapping_annotation(node: ast.AST) -> bool:
    if isinstance(node, ast.Subscript):
        return _is_mapping_annotation(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_mapping_annotation(node.left) or _is_mapping_annotation(node.right)
    if isinstance(node, ast.Name):
        return node.id in {"dict", "Dict", "Mapping", "MutableMapping"}
    return isinstance(node, ast.Attribute) and node.attr in {
        "Dict",
        "Mapping",
        "MutableMapping",
    }


def _bound_receiver_keys(
    target: ast.AST, parent_map: dict[int, ast.AST]
) -> set[tuple[int | None, tuple]]:
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            key
            for element in target.elts
            for key in _bound_receiver_keys(element, parent_map)
        }
    if isinstance(target, ast.Starred):
        return _bound_receiver_keys(target.value, parent_map)
    key = _mapping_receiver_key(target, parent_map)
    return {key} if key is not None else set()


def _mapping_receiver_evidence(
    tree: ast.Module, parent_map: dict[int, ast.AST]
) -> set[tuple[int | None, tuple]]:
    receivers: set[tuple[int | None, tuple]] = set()
    rebound: set[tuple[int | None, tuple]] = set()
    for node in ast.walk(tree):
        candidate: ast.AST | None = None
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if isinstance(node.slice.value, str):
                candidate = node.value
        elif isinstance(node, ast.AnnAssign):
            if _is_mapping_annotation(node.annotation):
                candidate = node.target
            if node.value is not None and not isinstance(node.value, ast.Dict):
                rebound.update(_bound_receiver_keys(node.target, parent_map))
        elif isinstance(node, ast.arg) and node.annotation is not None:
            if _is_mapping_annotation(node.annotation):
                candidate = node
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                keys = _bound_receiver_keys(target, parent_map)
                if isinstance(node.value, ast.Dict):
                    receivers.update(keys)
                else:
                    rebound.update(keys)
        elif isinstance(
            node,
            (ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor, ast.comprehension),
        ):
            rebound.update(_bound_receiver_keys(node.target, parent_map))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope = _receiver_scope(node, parent_map)
            if scope is not None:
                rebound.add((scope, ("name", node.name)))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    rebound.update(_bound_receiver_keys(item.optional_vars, parent_map))
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                rebound.update(_bound_receiver_keys(target, parent_map))
        if isinstance(candidate, ast.arg):
            # A parameter's annotation belongs to its containing function.
            scope = _receiver_scope(node, parent_map)
            if scope is not None:
                receivers.add((scope, ("name", node.arg)))
            continue
        if candidate is not None:
            key = _mapping_receiver_key(candidate, parent_map)
            if key is not None:
                receivers.add(key)
    return receivers - rebound


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

    def _is_mapping_lookup_key(self, node, parent_map, mapping_receivers):
        parent = parent_map.get(id(node))
        if (
            not isinstance(parent, ast.Call)
            or not parent.args
            or parent.args[0] is not node
        ):
            return False
        func = parent.func
        if not isinstance(func, ast.Attribute) or func.attr not in {
            "get",
            "setdefault",
            "pop",
        }:
            return False
        return _mapping_receiver_key(func.value, parent_map) in mapping_receivers

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
        mapping_receivers = _mapping_receiver_evidence(node, parent_map)

        string_occurrences = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) < 5:
                    continue
                if self._is_docstring(child, parent_map):
                    continue
                if self._is_structural_key_literal(child, parent_map):
                    continue
                if self._is_mapping_lookup_key(child, parent_map, mapping_receivers):
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
        if count <= self.threshold:
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


def _property_setter_value_arg(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    positional_args: list[ast.arg],
) -> ast.arg | None:
    setter_decorators = (
        decorator
        for decorator in node.decorator_list
        if isinstance(decorator, ast.Attribute) and decorator.attr == "setter"
    )
    is_matching_setter = any(
        (isinstance(decorator.value, ast.Name) and decorator.value.id == node.name)
        or (
            isinstance(decorator.value, ast.Attribute)
            and decorator.value.attr == node.name
        )
        for decorator in setter_decorators
    )
    if not is_matching_setter:
        return None

    if len(positional_args) < 2:
        return None

    return positional_args[1]


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
        positional_args = [*args.posonlyargs, *args.args]
        setter_value_arg = _property_setter_value_arg(node, positional_args)

        num_defaults = len(args.defaults)
        num_positional = len(positional_args)

        findings = []
        filename = context.get("filename", "")

        for i, arg in enumerate(positional_args):
            arg_name = arg.arg
            if arg_name in ("self", "cls"):
                continue
            if arg is setter_value_arg:
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
        # Empty handlers are already reported by SKY-L007. A placeholder
        # return is a separate broad-exception fallback worth reporting here.
        if not any(isinstance(stmt, ast.Return) for stmt in node.body):
            return None

        exc_name = ", ".join(sorted(set(broad_types)))

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "HIGH",
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

_UNKNOWN_EXPRESSION = object()
_RAISING_EXPRESSION = object()
_LITERAL_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}
_LITERAL_COMPARISONS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}


def _bounded_literal(value):
    if isinstance(value, int):
        return value.bit_length() <= 256
    if isinstance(value, (str, bytes, list, tuple, set, dict)):
        return len(value) <= 256
    return True


def _literal_expression_value(node, budget=None):
    """Evaluate only small built-in literals, never target objects or calls."""
    if budget is None:
        budget = [128]
    budget[0] -= 1
    if budget[0] < 0:
        return _UNKNOWN_EXPRESSION
    if isinstance(node, ast.Constant):
        return node.value if _bounded_literal(node.value) else _UNKNOWN_EXPRESSION
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [_literal_expression_value(child, budget) for child in node.elts]
        if any(value is _RAISING_EXPRESSION for value in values):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in values):
            return _UNKNOWN_EXPRESSION
        constructor = {ast.List: list, ast.Tuple: tuple, ast.Set: set}[type(node)]
        try:
            return constructor(values)
        except TypeError:
            return _RAISING_EXPRESSION
    if isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            return _UNKNOWN_EXPRESSION
        keys = [_literal_expression_value(child, budget) for child in node.keys]
        values = [_literal_expression_value(child, budget) for child in node.values]
        if any(value is _RAISING_EXPRESSION for value in [*keys, *values]):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in [*keys, *values]):
            return _UNKNOWN_EXPRESSION
        try:
            return dict(zip(keys, values))
        except TypeError:
            return _RAISING_EXPRESSION
    if isinstance(node, ast.UnaryOp):
        operand = _literal_expression_value(node.operand, budget)
        if operand is _UNKNOWN_EXPRESSION or operand is _RAISING_EXPRESSION:
            return operand
        operation = {
            ast.UAdd: operator.pos,
            ast.USub: operator.neg,
            ast.Invert: operator.invert,
            ast.Not: operator.not_,
        }.get(type(node.op))
        operands = [operand]
    elif isinstance(node, ast.BinOp):
        operands = [
            _literal_expression_value(node.left, budget),
            _literal_expression_value(node.right, budget),
        ]
        if any(value is _RAISING_EXPRESSION for value in operands):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in operands):
            return _UNKNOWN_EXPRESSION
        operation = _LITERAL_BINARY_OPERATORS.get(type(node.op))
        if isinstance(node.op, ast.Mod) and isinstance(operands[0], (str, bytes)):
            # A short format string can request an arbitrarily large allocation.
            return _UNKNOWN_EXPRESSION
        if isinstance(node.op, ast.Mult):
            for sequence, count in (operands, operands[::-1]):
                if isinstance(sequence, (str, bytes, list, tuple)) and isinstance(
                    count, int
                ):
                    if len(sequence) * max(0, count) > 256:
                        return _UNKNOWN_EXPRESSION
    elif isinstance(node, ast.Compare):
        if len(node.ops) != 1:
            return _UNKNOWN_EXPRESSION
        operands = [
            _literal_expression_value(node.left, budget),
            _literal_expression_value(node.comparators[0], budget),
        ]
        if any(value is _RAISING_EXPRESSION for value in operands):
            return _RAISING_EXPRESSION
        if any(value is _UNKNOWN_EXPRESSION for value in operands):
            return _UNKNOWN_EXPRESSION
        operation = _LITERAL_COMPARISONS.get(type(node.ops[0]))
    else:
        return _UNKNOWN_EXPRESSION
    if operation is None:
        return _UNKNOWN_EXPRESSION
    try:
        result = operation(*operands)
    except (ArithmeticError, TypeError, ValueError):
        return _RAISING_EXPRESSION
    return result if _bounded_literal(result) else _UNKNOWN_EXPRESSION


def _scope_import_bindings(scope):
    bindings = {}

    def record(name, target=None):
        if name in bindings and bindings[name] != target:
            bindings[name] = None
        else:
            bindings[name] = target

    class Bindings(ast.NodeVisitor):
        def visit_Name(self, node):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                record(node.id)

        def visit_Import(self, node):
            for alias in node.names:
                record(alias.asname or alias.name.split(".")[0], alias.name)

        def visit_ImportFrom(self, node):
            for alias in node.names:
                record(
                    alias.asname or alias.name,
                    f"{node.module}.{alias.name}" if not node.level else None,
                )

        def visit_FunctionDef(self, node):
            record(node.name)
            for expression in [
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ]:
                if expression is not None:
                    self.visit(expression)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            record(node.name)
            for expression in [*node.bases, *node.keywords, *node.decorator_list]:
                self.visit(expression)

        def visit_Lambda(self, node):
            for expression in [*node.args.defaults, *node.args.kw_defaults]:
                if expression is not None:
                    self.visit(expression)

        def visit_ListComp(self, node):
            # Targets are comprehension-local; walruses in evaluated expressions
            # can bind in the containing scope.
            for generator in node.generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)

        visit_SetComp = visit_ListComp
        visit_DictComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

        def visit_ExceptHandler(self, node):
            if node.name:
                record(node.name)
            self.generic_visit(node)

    visitor = Bindings()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for argument in [
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            scope.args.vararg,
            scope.args.kwarg,
        ]:
            if argument is not None:
                record(argument.arg)
    for statement in scope.body:
        visitor.visit(statement)
    return bindings


def _exception_probe_expressions(module):
    parents = {
        child: parent
        for parent in ast.walk(module)
        for child in ast.iter_child_nodes(parent)
    }
    bindings = {}
    global_writes = set()
    for function in ast.walk(module):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        declared_globals = set()
        stack = list(function.body)
        while stack:
            child = stack.pop()
            if isinstance(child, ast.Global):
                declared_globals.update(child.names)
            elif not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                stack.extend(ast.iter_child_nodes(child))
        global_writes.update(declared_globals & _scope_import_bindings(function).keys())

    def resolve_import(name, node):
        in_function = False
        while node is not None:
            if isinstance(
                node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                if not (in_function and isinstance(node, ast.ClassDef)):
                    if isinstance(node, ast.Module) and name in global_writes:
                        return None
                    if node not in bindings:
                        bindings[node] = _scope_import_bindings(node)
                    scope_bindings = bindings[node]
                    if "*" in scope_bindings:
                        return None
                    if name in scope_bindings:
                        return scope_bindings[name]
                in_function |= isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            node = parents.get(node)
        return None

    helper_overwritten = False
    for node in ast.walk(module):
        if not (
            isinstance(node, ast.Attribute)
            and node.attr == "raises"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            continue
        receiver = _qualified_call_name(node.value)
        if not receiver:
            continue
        root, _, suffix = receiver.partition(".")
        target = resolve_import(root, node)
        if target and ".".join(filter(None, (target, suffix))) == "pytest":
            helper_overwritten = True
            break

    probes = set()
    for node in ast.walk(module):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            call = item.context_expr
            if not isinstance(call, ast.Call):
                continue
            name = _qualified_call_name(call.func)
            if not name:
                continue
            root, _, suffix = name.partition(".")
            target = resolve_import(root, node)
            if (
                helper_overwritten
                or not target
                or ".".join(filter(None, (target, suffix))) != "pytest.raises"
            ):
                continue
            stack = list(node.body)
            while stack:
                child = stack.pop()
                if isinstance(
                    child,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
                ):
                    continue
                if isinstance(child, ast.Expr):
                    probes.add(id(child))
                stack.extend(ast.iter_child_nodes(child))
    return probes


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

    def __init__(self):
        self._exception_probes = set()

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            self._exception_probes = _exception_probe_expressions(node)
            return None
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
            if id(node) in self._exception_probes:
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
        else:
            literal_value = _literal_expression_value(value)
            if literal_value is _RAISING_EXPRESSION:
                return None
            if literal_value is _UNKNOWN_EXPRESSION:
                if id(node) in self._exception_probes:
                    return None
                if not isinstance(value, ast.Compare):
                    return None
                issue_value = "discarded_comparison"
                message = (
                    "Comparison result is discarded. Check whether an assignment "
                    "or assertion was intended."
                )

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
