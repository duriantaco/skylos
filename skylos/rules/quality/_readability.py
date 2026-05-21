from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from skylos.rules.base import SkylosRule


_IDENT_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_ACCEPTED_SHORT_NAMES = {
    "i",
    "j",
    "k",
    "n",
    "m",
    "e",
    "f",
    "fp",
    "fd",
    "fh",
    "db",
    "id",
    "pk",
    "q",
}

_STRONG_OPAQUE_NAMES = {
    "tmp",
    "temp",
    "var",
    "val",
    "obj",
    "thing",
    "stuff",
    "out",
    "ret",
}

_WEAK_OPAQUE_NAMES = {
    "data",
    "result",
    "results",
    "value",
    "item",
    "items",
    "info",
}

_STOP_TOKENS = {
    "a",
    "an",
    "and",
    "api",
    "arg",
    "args",
    "as",
    "bool",
    "build",
    "by",
    "call",
    "client",
    "cls",
    "create",
    "dict",
    "do",
    "fetch",
    "for",
    "format",
    "from",
    "get",
    "handle",
    "helper",
    "http",
    "https",
    "int",
    "json",
    "kwargs",
    "list",
    "load",
    "make",
    "manager",
    "none",
    "object",
    "of",
    "parse",
    "process",
    "read",
    "repo",
    "repository",
    "request",
    "run",
    "self",
    "service",
    "set",
    "str",
    "to",
    "util",
    "utils",
    "with",
    "write",
}

_DOMAIN_TOKENS = {
    "account",
    "admin",
    "auth",
    "authorization",
    "bucket",
    "cmd",
    "command",
    "config",
    "cookie",
    "email",
    "file",
    "filename",
    "header",
    "headers",
    "host",
    "invoice",
    "order",
    "org",
    "password",
    "path",
    "payment",
    "permission",
    "project",
    "query",
    "role",
    "secret",
    "session",
    "sql",
    "tenant",
    "token",
    "url",
    "user",
}

_MATH_TOKENS = {
    "abs",
    "acos",
    "asin",
    "atan",
    "ceil",
    "cos",
    "floor",
    "height",
    "hypot",
    "len",
    "log",
    "max",
    "min",
    "pow",
    "sin",
    "sqrt",
    "tan",
    "vector",
    "width",
}

_COORD_NAMES = {"x", "y", "z"}


@dataclass(frozen=True)
class _AssignmentCandidate:
    name: str
    line: int
    col: int
    rhs: ast.AST


@dataclass(frozen=True)
class _UsageProfile:
    use_count: int
    span: int
    contexts: frozenset[str]


@dataclass(frozen=True)
class _RhsEvidence:
    tokens: tuple[str, ...]
    key_tokens: tuple[str, ...]
    semantic_tokens: tuple[str, ...]
    suggested_name: str
    score: int
    has_domain_token: bool


def _basename(filename: str | None) -> str:
    return Path(filename or "").name


def _is_non_production_path(filename: str | None) -> bool:
    normalized = str(filename or "").replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    base = Path(normalized).name
    return (
        "test" in parts
        or "tests" in parts
        or "corpus" in parts
        or base.startswith("test_")
        or base.endswith("_test.py")
    )


def _split_identifier(value: str) -> list[str]:
    spaced = _CAMEL_BOUNDARY_RE.sub("_", str(value))
    tokens: list[str] = []
    for part in _IDENT_SPLIT_RE.split(spaced):
        part = part.strip("_").lower()
        if not part:
            continue
        tokens.append(part)
    return tokens


def _ordered_unique(tokens: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for token in tokens:
        if token and token not in seen:
            seen.add(token)
            ordered.append(token)
    return tuple(ordered)


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _subscript_key(node: ast.Subscript) -> str | None:
    key = node.slice
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    return None


def _semantic_subset(tokens: Iterable[str]) -> tuple[str, ...]:
    return _ordered_unique(
        token for token in tokens if len(token) > 1 and token not in _STOP_TOKENS
    )


def _direct_key_tokens(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Call):
        call_name = _dotted_name(node.func)
        if call_name.rsplit(".", 1)[-1] == "get" and node.args:
            key_value = _string_constant(node.args[0])
            if key_value:
                return _split_identifier(key_value)
        if isinstance(node.func, ast.Attribute):
            return _direct_key_tokens(node.func.value)
        return []
    if isinstance(node, ast.Attribute):
        return _direct_key_tokens(node.value)
    if isinstance(node, ast.Subscript):
        tokens: list[str] = []
        key_value = _subscript_key(node)
        if key_value:
            tokens.extend(_split_identifier(key_value))
        tokens.extend(_direct_key_tokens(node.value))
        return tokens
    return []


def _rhs_evidence(node: ast.AST) -> _RhsEvidence:
    raw_tokens: list[str] = []
    key_tokens = _direct_key_tokens(node)
    has_structural_hint = bool(key_tokens)

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            call_name = _dotted_name(child.func)
            raw_tokens.extend(_split_identifier(call_name))
        elif isinstance(child, ast.Subscript):
            raw_tokens.extend(_split_identifier(_dotted_name(child.value)))
        elif isinstance(child, ast.Attribute):
            raw_tokens.extend(_split_identifier(child.attr))
        elif isinstance(child, ast.Name):
            raw_tokens.extend(_split_identifier(child.id))

    key_semantics = _semantic_subset(key_tokens)
    all_semantics = _semantic_subset([*key_tokens, *raw_tokens])
    suggested_tokens = key_semantics or all_semantics[:3]
    suggested_name = "_".join(suggested_tokens[:3])

    has_domain_token = bool(set(all_semantics) & _DOMAIN_TOKENS)
    score = 0
    if key_semantics:
        score += 2
    if all_semantics:
        score += 1
    if has_domain_token:
        score += 1
    if has_structural_hint:
        score += 1

    return _RhsEvidence(
        tokens=_ordered_unique(raw_tokens),
        key_tokens=key_semantics,
        semantic_tokens=all_semantics,
        suggested_name=suggested_name,
        score=score,
        has_domain_token=has_domain_token,
    )


def _name_opacity_strength(name: str) -> int:
    normalized = name.lower()
    if not normalized or normalized.startswith("_") or normalized.isupper():
        return 0
    if normalized in _ACCEPTED_SHORT_NAMES:
        return 0
    if len(normalized) == 1 and normalized.isalpha():
        return 2
    if normalized in _STRONG_OPAQUE_NAMES:
        return 2
    if normalized in _WEAK_OPAQUE_NAMES:
        return 1
    return 0


def _is_numeric_or_math_shape(node: ast.AST, evidence: _RhsEvidence) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, complex)):
        return True
    if isinstance(node, ast.UnaryOp):
        return _is_numeric_or_math_shape(node.operand, evidence)
    if isinstance(node, ast.BinOp):
        return _is_numeric_or_math_shape(node.left, evidence) or _is_numeric_or_math_shape(
            node.right, evidence
        )
    if isinstance(node, ast.Call):
        return bool(set(evidence.semantic_tokens) & _MATH_TOKENS)
    return False


def _rhs_already_names_target(name: str, evidence: _RhsEvidence) -> bool:
    normalized = name.lower()
    if evidence.suggested_name == normalized:
        return True
    return normalized in evidence.key_tokens and len(evidence.key_tokens) <= 2


def _names_loaded_in(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


class _ScopeFactCollector(ast.NodeVisitor):
    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef):
        self.root = root
        self.assignments: list[_AssignmentCandidate] = []
        self.uses: dict[str, list[int]] = defaultdict(list)
        self.contexts: dict[str, list[tuple[int, str]]] = defaultdict(list)

    def collect(self) -> None:
        for stmt in self.root.body:
            self.visit(stmt)

    def _visit_children(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def generic_visit(self, node: ast.AST) -> None:
        self._visit_children(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            self._visit_children(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            self._visit_children(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments.append(
                    _AssignmentCandidate(
                        name=target.id,
                        line=getattr(target, "lineno", node.lineno),
                        col=getattr(target, "col_offset", node.col_offset),
                        rhs=node.value,
                    )
                )
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.assignments.append(
                _AssignmentCandidate(
                    name=node.target.id,
                    line=getattr(node.target, "lineno", node.lineno),
                    col=getattr(node.target, "col_offset", node.col_offset),
                    rhs=node.value,
                )
            )
        if node.value is not None:
            self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:
        for name in _names_loaded_in(node.test):
            self.contexts[name].append((node.lineno, "branch"))
        self._visit_children(node)

    def visit_While(self, node: ast.While) -> None:
        for name in _names_loaded_in(node.test):
            self.contexts[name].append((node.lineno, "branch"))
        self._visit_children(node)

    def visit_Return(self, node: ast.Return) -> None:
        for name in _names_loaded_in(node.value):
            self.contexts[name].append((node.lineno, "returned"))
        self._visit_children(node)

    def visit_Call(self, node: ast.Call) -> None:
        for arg in node.args:
            for name in _names_loaded_in(arg):
                self.contexts[name].append((node.lineno, "passed"))
        for keyword in node.keywords:
            for name in _names_loaded_in(keyword.value):
                self.contexts[name].append((node.lineno, "passed"))
        self._visit_children(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.uses[node.id].append(node.lineno)


def _iter_function_scopes(module: ast.Module):
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _usage_profile(
    assignment: _AssignmentCandidate,
    assignments: list[_AssignmentCandidate],
    uses: dict[str, list[int]],
    contexts: dict[str, list[tuple[int, str]]],
) -> _UsageProfile:
    next_assignment_line = min(
        (
            other.line
            for other in assignments
            if other.name == assignment.name and other.line > assignment.line
        ),
        default=None,
    )

    def in_assignment_window(line: int) -> bool:
        return line > assignment.line and (
            next_assignment_line is None or line < next_assignment_line
        )

    use_lines = [line for line in uses.get(assignment.name, []) if in_assignment_window(line)]
    context_values = {
        context
        for line, context in contexts.get(assignment.name, [])
        if in_assignment_window(line)
    }
    span = max(use_lines) - assignment.line if use_lines else 0
    return _UsageProfile(
        use_count=len(use_lines),
        span=span,
        contexts=frozenset(context_values),
    )


def _usage_score(profile: _UsageProfile) -> int:
    score = 0
    if profile.span >= 8:
        score += 2
    elif profile.span >= 5:
        score += 1
    if profile.use_count >= 3:
        score += 1
    if profile.contexts & {"branch", "passed", "returned"}:
        score += 1
    return score


def _should_report(
    assignment: _AssignmentCandidate,
    profile: _UsageProfile,
    evidence: _RhsEvidence,
) -> bool:
    strength = _name_opacity_strength(assignment.name)
    if strength == 0 or profile.use_count == 0:
        return False
    if not evidence.key_tokens:
        return False
    if evidence.score < 2 or not evidence.suggested_name:
        return False
    if _rhs_already_names_target(assignment.name, evidence):
        return False
    if assignment.name.lower() in _COORD_NAMES and _is_numeric_or_math_shape(
        assignment.rhs, evidence
    ):
        return False
    if profile.span < 5:
        return False

    total_score = strength + evidence.score + _usage_score(profile)
    threshold = 7 if strength == 1 else 6
    return total_score >= threshold


class OpaqueIdentifierRule(SkylosRule):
    rule_id = "SKY-Q806"
    name = "Opaque Identifier"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename")
        if _is_non_production_path(filename):
            return None

        findings: list[dict] = []
        reported: set[tuple[str, int, int]] = set()

        for scope in _iter_function_scopes(node):
            collector = _ScopeFactCollector(scope)
            collector.collect()

            for assignment in collector.assignments:
                evidence = _rhs_evidence(assignment.rhs)
                profile = _usage_profile(
                    assignment,
                    collector.assignments,
                    collector.uses,
                    collector.contexts,
                )
                if not _should_report(assignment, profile, evidence):
                    continue

                key = (assignment.name, assignment.line, assignment.col)
                if key in reported:
                    continue
                reported.add(key)

                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "readability",
                        "severity": "LOW",
                        "type": "variable",
                        "name": assignment.name,
                        "simple_name": assignment.name,
                        "value": evidence.suggested_name,
                        "threshold": 6,
                        "metric": "identifier_opacity",
                        "message": (
                            f"Opaque variable '{assignment.name}' hides semantic "
                            f"RHS evidence; consider a name like "
                            f"'{evidence.suggested_name}'."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": assignment.line,
                        "col": assignment.col,
                        "span": profile.span,
                        "use_count": profile.use_count,
                    }
                )

        return findings or None
