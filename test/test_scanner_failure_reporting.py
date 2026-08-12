"""A taint scanner that fails must not leave the file looking clean.

These tests are structural on purpose. They enumerate the scanners rather than
listing them, so a scanner added later that swallows its own exceptions fails
here instead of silently dropping findings in the field.
"""

import ast
import importlib
import json
import pkgutil

import pytest

import skylos.rules.danger as danger_package
from skylos.analyzer import analyze
from skylos.cli import _analysis_incomplete_exit_code
from skylos.rules.danger._incomplete import RULE_ID as INCOMPLETE_RULE_ID


def _scanner_modules():
    modules = []
    for info in pkgutil.walk_packages(
        danger_package.__path__, danger_package.__name__ + "."
    ):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # pragma: no cover - optional dependency
            continue
        if callable(getattr(module, "scan", None)):
            modules.append(module)
    return sorted(modules, key=lambda module: module.__name__)


SCANNER_MODULES = _scanner_modules()


def test_scanner_modules_are_discovered():
    assert len(SCANNER_MODULES) >= 16


@pytest.mark.parametrize(
    "module",
    SCANNER_MODULES,
    ids=[m.__name__.rsplit(".", 1)[-1] for m in SCANNER_MODULES],
)
def test_scanner_records_incomplete_analysis_instead_of_swallowing(module):
    """An unusable tree forces the scanner into its own failure path."""
    findings = []

    module.scan(object(), "app.py", findings)

    assert [finding["rule_id"] for finding in findings] == [INCOMPLETE_RULE_ID], (
        f"{module.__name__}.scan() dropped its failure instead of recording it"
    )
    payload = findings[0]
    assert payload["kind"] == "processing_error"
    assert payload["severity"] == "HIGH"
    assert payload["file"] == "app.py"
    assert payload["scanner"]
    assert payload["error_type"]
    # Reports render "Python ?" without this; it is set independently of
    # _analysis_error_payload, so it needs its own assertion.
    assert payload["python_version"].count(".") == 2


def test_taint_dispatcher_failure_reaches_analysis_errors(tmp_path, monkeypatch):
    """The net around scan_file_with_tree must fail closed, not logger.debug."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\n\n"
        "def get_user(user_id):\n"
        '    cur = sqlite3.connect("d").cursor()\n'
        '    cur.execute("SELECT * FROM t WHERE id = \'" + user_id + "\'")\n'
        "    return cur.fetchall()\n",
        encoding="utf-8",
    )

    import skylos.rules.danger.danger as danger_module

    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated dispatcher failure")

    monkeypatch.setattr(danger_module, "scan_file_with_tree", boom)

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_danger=True, grep_verify=False)
    )

    recorded = [
        entry
        for entry in result.get("analysis_errors", [])
        if entry.get("rule_id") == INCOMPLETE_RULE_ID
    ]
    assert recorded, "a failed taint dispatch was reported as a clean scan"
    assert recorded[0]["error_type"] == "RuntimeError"
    assert _analysis_incomplete_exit_code(result) == 2


def test_scanner_failures_are_not_reported_as_security_findings(tmp_path, monkeypatch):
    """The incomplete marker belongs in analysis_errors, not in the findings list."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    import skylos.rules.danger.danger_sql.sql_flow as sql_flow

    class Boom(sql_flow._SQLFlowChecker):
        def visit(self, node):
            raise RuntimeError("simulated scanner failure")

    monkeypatch.setattr(sql_flow, "_SQLFlowChecker", Boom)

    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_danger=True, grep_verify=False)
    )

    for key, value in result.items():
        if key == "analysis_errors" or not isinstance(value, list):
            continue
        assert not [
            item
            for item in value
            if isinstance(item, dict) and item.get("rule_id") == INCOMPLETE_RULE_ID
        ], f"incomplete-analysis marker leaked into {key}"


def test_every_scanner_guards_its_whole_body():
    """The failure handler must cover the scanner's early gates too.

    mcp_flow once evaluated its "is this an MCP file" gate outside the try, so
    a failure there escaped the handler entirely.
    """
    offenders = []
    for module in SCANNER_MODULES:
        source = ast.parse(open(module.__file__, encoding="utf-8").read())
        for node in ast.walk(source):
            if not isinstance(node, ast.FunctionDef) or node.name != "scan":
                continue
            body = [
                statement
                for statement in node.body
                if not (
                    isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Constant)
                )
            ]
            if len(body) != 1 or not isinstance(body[0], ast.Try):
                offenders.append(module.__name__)
    assert not offenders, f"scan() body not fully guarded in: {offenders}"
