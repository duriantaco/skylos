"""A failed analysis subsystem must not be reported as a clean result.

The structural test is the important one: it enumerates the exception handlers
in analyze() rather than listing them, so a feature block added later that only
logs its failure fails here instead of silently reporting nothing in the field.
"""

import ast
import inspect
import json
import textwrap

import pytest

import skylos.analyzer as analyzer_module
from skylos.analyzer import analyze
from skylos.cli import _analysis_incomplete_exit_code


SECRET_SOURCE = 'GITHUB_PAT = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\n'


def _boom(*_args, **_kwargs):
    raise RuntimeError("simulated subsystem failure")


def test_secret_scan_failure_is_not_reported_as_no_secrets(tmp_path, monkeypatch):
    """The worst case: a crashed secret scanner asserting the repo is clean."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "config.py").write_text(SECRET_SOURCE, encoding="utf-8")

    baseline = json.loads(
        analyze(str(tmp_path), conf=0, enable_secrets=True, grep_verify=False)
    )
    baseline_ids = {
        finding["rule_id"]
        for value in baseline.values()
        if isinstance(value, list)
        for finding in value
        if isinstance(finding, dict) and finding.get("rule_id")
    }
    assert "SKY-S101" in baseline_ids, "fixture no longer produces a secret finding"

    monkeypatch.setattr(analyzer_module, "_secrets_scan_ctx", _boom)
    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_secrets=True, grep_verify=False)
    )

    recorded = [
        entry
        for entry in result.get("analysis_errors", [])
        if entry.get("subsystem") == "Secret scan"
    ]
    assert recorded, "a crashed secret scan was reported as a clean repository"
    assert recorded[0]["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert recorded[0]["error_type"] == "RuntimeError"
    assert _analysis_incomplete_exit_code(result) == 2


def test_subsystem_payload_names_the_subsystem():
    payload = analyzer_module._subsystem_error_payload(
        "/repo", "Secret scan", RuntimeError("boom")
    )
    assert payload["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert payload["severity"] == "HIGH"
    assert payload["subsystem"] == "Secret scan"
    assert payload["message"].startswith("Secret scan did not complete:")


def _analyze_handlers():
    """Broad handlers in analyze() that wrap subsystem work."""
    source = textwrap.dedent(inspect.getsource(analyzer_module.Skylos.analyze))
    tree = ast.parse(source)
    subsystem_markers = ("scan", "detect", "analyze", "hallucination", "policy")
    handlers = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        called = {
            call.func.attr
            if isinstance(call.func, ast.Attribute)
            else getattr(call.func, "id", "")
            for call in ast.walk(ast.Module(body=node.body, type_ignores=[]))
            if isinstance(call, ast.Call)
        }
        if not any(
            marker in name.lower()
            for name in called
            if name
            for marker in subsystem_markers
        ):
            continue
        for handler in node.handlers:
            exc_type = handler.type
            broad = exc_type is None or any(
                isinstance(name, ast.Name) and name.id in ("Exception", "BaseException")
                for name in ast.walk(exc_type)
            )
            if broad:
                handlers.append((handler, sorted(name for name in called if name)))
    return handlers


def test_analyze_has_subsystem_handlers_to_check():
    assert len(_analyze_handlers()) >= 15


@pytest.mark.parametrize("index", range(len(_analyze_handlers())))
def test_no_analyze_subsystem_handler_swallows_its_failure(index):
    """Every broad handler around subsystem work must leave a trace in the output.

    Recording an analysis error, an existing _analysis_error_payload, or a
    failed_*_api_check all count. Only logging does not: the subsystem's
    findings are then simply absent, which reads as "found nothing".
    """
    handler, called = _analyze_handlers()[index]
    body = ast.dump(ast.Module(body=handler.body, type_ignores=[]))
    records = (
        "analysis_errors" in body
        or "_analysis_error_payload" in body
        or ("failed_" in body and "_api_check" in body)
    )
    assert records, (
        f"handler at line {handler.lineno} of analyze() wrapping {called} "
        "only logs its failure; the run would report a clean result"
    )
