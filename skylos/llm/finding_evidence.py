from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from ._grounding import read_bounded_bytes
from .liveness import SymbolLiveness, build_liveness_index
from .schemas import Finding, IssueType


MAX_SOURCE_BYTES = 1_000_000
COMMAND_TERMS = (
    "command injection",
    "shell injection",
    "subprocess",
    "shell=true",
    "os.system",
    "popen",
    "exec",
)
SQL_TERMS = ("sql", "query", "injection")


def filter_findings_with_evidence(
    findings: list[Finding],
    files: list[str | Path],
    *,
    project_root: str | Path | None = None,
) -> list[Finding]:
    """Drop LLM security findings refuted by deterministic source evidence.

    The filter is intentionally conservative. It does not try to prove safety in
    general; it only removes findings for dead non-test symbols when the file set
    includes entrypoints, plus a few source-local patterns that are commonly
    hallucinated as exploitable.
    """

    if not findings:
        return findings

    py_files = [Path(path) for path in files if Path(path).suffix == ".py"]
    if not py_files:
        return findings

    root = Path(project_root).resolve() if project_root else _common_root(py_files)
    liveness = build_liveness_index(root, py_files)
    multi_file_project = _non_test_file_count(py_files) >= 2
    source_cache: dict[str, str | None] = {}

    filtered: list[Finding] = []
    for finding in findings:
        if not _is_filterable_security_finding(finding):
            filtered.append(finding)
            continue

        resolved = liveness.resolve_symbol(
            finding.symbol, finding.location.file, finding.location.line
        )
        owner_source = _owner_source(resolved, source_cache, root)

        if _safe_sink_refutes(finding, owner_source):
            continue

        if (
            multi_file_project
            and liveness.has_entrypoints
            and resolved
            and not resolved.reachable
            and not _is_test_path(resolved.symbol.path)
        ):
            continue

        filtered.append(finding)

    return filtered


def _is_filterable_security_finding(finding: Finding) -> bool:
    if finding.issue_type != IssueType.SECURITY:
        return False
    explanation = str(finding.explanation or "").lower()
    if "static analysis" in explanation:
        return False
    return True


def _safe_sink_refutes(finding: Finding, owner_source: str | None) -> bool:
    if not owner_source:
        return False
    evidence_text = _finding_text(finding)
    return _is_safe_subprocess_finding(
        evidence_text, owner_source
    ) or _is_parameterized_sql_finding(evidence_text, owner_source)


def _finding_text(finding: Finding) -> str:
    parts = [
        finding.rule_id,
        finding.message,
        finding.explanation,
        finding.suggestion,
        finding.code_snippet,
    ]
    return " ".join(str(part or "") for part in parts).lower()


def _is_safe_subprocess_finding(evidence_text: str, owner_source: str) -> bool:
    if not any(term in evidence_text for term in COMMAND_TERMS):
        return False
    if "subprocess." not in owner_source:
        return False

    return _ast_proves_safe_subprocess(owner_source)


def _ast_proves_safe_subprocess(owner_source: str) -> bool:
    try:
        tree = ast.parse(owner_source)
    except SyntaxError:
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _dotted_name(node.func).split(".")[:1] != ["subprocess"]:
            continue
        if _call_has_shell_true(node):
            return False
        if not node.args:
            continue
        argv = node.args[0]
        if isinstance(argv, (ast.List, ast.Tuple)):
            return _literal_sequence(argv)
        allowlist = _subscript_name(argv)
        if allowlist and allowlist.isupper():
            return _allowlist_is_not_mutated(tree, allowlist)
    return False


def _call_has_shell_true(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True
    return False


def _literal_sequence(node: ast.List | ast.Tuple) -> bool:
    return all(isinstance(item, ast.Constant) for item in node.elts)


def _subscript_name(node: ast.AST) -> str:
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        return node.value.id
    return ""


def _allowlist_is_not_mutated(tree: ast.AST, name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]
            for target in targets:
                if _is_mutation_target(target, name):
                    return False
        if isinstance(node, ast.Call):
            receiver = ""
            if isinstance(node.func, ast.Attribute):
                receiver = _dotted_name(node.func.value)
            if receiver == name and node.func.attr in {
                "append",
                "clear",
                "extend",
                "insert",
                "pop",
                "remove",
                "setdefault",
                "update",
            }:
                return False
    return True


def _is_mutation_target(target: ast.AST, name: str) -> bool:
    if isinstance(target, ast.Subscript) and _dotted_name(target.value) == name:
        return True
    if isinstance(target, ast.Attribute) and _dotted_name(target.value) == name:
        return True
    return False


def _is_parameterized_sql_finding(evidence_text: str, owner_source: str) -> bool:
    if not any(term in evidence_text for term in SQL_TERMS):
        return False
    lower_source = owner_source.lower()
    if "select " not in lower_source and "query" not in lower_source:
        return False
    if 'f"' in owner_source or "f'" in owner_source:
        return False
    if ".format(" in owner_source or " % " in owner_source:
        return False
    if "?" not in owner_source and "%s" not in owner_source:
        return False
    return bool(
        re.search(r"\bexecute\(\s*\w+\s*,\s*[\[(]", owner_source)
        or re.search(r"\bfetch_\w+\(\s*\w+\s*,\s*[\[(]", owner_source)
        or re.search(r"\bquery_\w+\(\s*\w+\s*,\s*[\[(]", owner_source)
    )


def _owner_source(
    resolved: SymbolLiveness | None, cache: dict[str, str | None], root: Path
) -> str | None:
    if not resolved:
        return None
    symbol = resolved.symbol
    source = _read_source(symbol.path, cache, root)
    if source is None:
        return None
    lines = source.splitlines()
    start = max(symbol.line - 1, 0)
    end = max(symbol.end_line, symbol.line)
    return "\n".join(lines[start:end])


def _read_source(path: str, cache: dict[str, str | None], root: Path) -> str | None:
    source_path = Path(path)
    try:
        norm = str(source_path.resolve(strict=True))
    except OSError:
        norm = str(source_path)
    if norm in cache:
        return cache[norm]
    source_bytes = read_bounded_bytes(source_path, MAX_SOURCE_BYTES, root=root)
    cache[norm] = _decode_source(source_bytes)
    return cache[norm]


def _decode_source(source: bytes | None) -> str | None:
    if source is None:
        return None
    try:
        return source.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _common_root(files: list[Path]) -> Path:
    parents = [str(path.resolve().parent) for path in files]
    if not parents:
        return Path.cwd().resolve()
    return Path(os.path.commonpath(parents)).resolve()


def _non_test_file_count(files: list[Path]) -> int:
    return sum(1 for path in files if not _is_test_path(path))


def _is_test_path(path: str | Path) -> bool:
    path = Path(path)
    name = path.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in path.parts
    )


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""
