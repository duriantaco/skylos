from __future__ import annotations
import ast
import os
import sys
from pathlib import Path
from .danger_sql.sql_flow import scan as scan_sql
from .danger_cmd.cmd_flow import scan as scan_cmd
from .danger_sql.sql_raw_flow import scan as scan_sql_raw
from .danger_net.ssrf_flow import scan as scan_ssrf
from .danger_fs.path_flow import scan as scan_path
from .danger_web.xss_flow import scan as scan_xss
from .danger_redirect.redirect_flow import scan as scan_redirect
from .danger_cors.cors_flow import scan as scan_cors
from .danger_jwt.jwt_flow import scan as scan_jwt
from .danger_access.access_flow import scan as scan_access
from .danger_mcp.mcp_flow import scan as scan_mcp
from .danger_hallucination.dependency_hallucination import (
    scan_python_dependency_hallucinations,
)
from .calls import (
    DANGEROUS_CALLS,
    _matches_rule,
    _kw_equals,
    _qualified_name_from_call as qualified_name_from_call,
    _yaml_load_without_safeloader,
)


ALLOWED_SUFFIXES = (".py", ".pyi", ".pyw")


class _DangerousCallsChecker(ast.NodeVisitor):
    def __init__(self, file_path, findings):
        self.file_path = file_path
        self.findings = findings
        self._symbol_stack = ["<module>"]

    def _current_symbol(self):
        if self._symbol_stack:
            return self._symbol_stack[-1]
        else:
            return "<module>"

    def generic_visit(self, node):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def visit_FunctionDef(self, node):
        self._symbol_stack.append(node.name)
        self.generic_visit(node)
        self._symbol_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self._symbol_stack.append(node.name)
        self.generic_visit(node)
        self._symbol_stack.pop()

    def visit_ClassDef(self, node):
        self._symbol_stack.append(node.name)
        self.generic_visit(node)
        self._symbol_stack.pop()

    def visit_Call(self, node):
        name = qualified_name_from_call(node)
        if name:
            for rule_key, tup in DANGEROUS_CALLS.items():
                rule_id, severity, message = tup[0], tup[1], tup[2]
                if len(tup) > 3:
                    opts = tup[3]
                else:
                    opts = None

                if not _matches_rule(name, rule_key):
                    continue

                if rule_key == "yaml.load" and not _yaml_load_without_safeloader(node):
                    continue

                if (
                    opts
                    and "kw_equals" in opts
                    and not _kw_equals(node, opts["kw_equals"])
                ):
                    continue

                self.findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": severity,
                        "message": message,
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
                break

        self.generic_visit(node)


def scan_file_with_tree(tree, file_path, findings):
    """Run taint-flow scanners on an already-parsed AST (no re-read/re-parse)."""
    scan_sql(tree, file_path, findings)
    scan_cmd(tree, file_path, findings)
    scan_sql_raw(tree, file_path, findings)
    scan_ssrf(tree, file_path, findings)
    scan_path(tree, file_path, findings)
    scan_xss(tree, file_path, findings)
    scan_redirect(tree, file_path, findings)
    scan_cors(tree, file_path, findings)
    scan_jwt(tree, file_path, findings)
    scan_access(tree, file_path, findings)
    scan_mcp(tree, file_path, findings)


def _scan_file(file_path: Path, findings):
    src = file_path.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(src)

    scan_file_with_tree(tree, file_path, findings)

    checker = _DangerousCallsChecker(file_path, findings)
    checker.visit(tree)


def scan_ctx(_, files):
    findings = []
    py_files = []

    for file_path in files:
        if file_path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue

        py_files.append(file_path)

        try:
            _scan_file(file_path, findings)
        except Exception as e:
            print(f"Scan failed for {file_path}: {e}", file=sys.stderr)

    try:
        if py_files:
            repo_root = Path(os.path.commonpath([str(p.resolve()) for p in py_files]))

            if repo_root.is_file():
                repo_root = repo_root.parent

            dep_findings = scan_python_dependency_hallucinations(repo_root, py_files)
            if dep_findings:
                findings.extend(dep_findings)

    except Exception as e:
        print(f"Dependency hallucination scan failed: {e}", file=sys.stderr)

    return findings
