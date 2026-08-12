"""A failed analysis subsystem must not be reported as a clean result.

The structural test is the important one: it enumerates the exception handlers
in analyze() rather than listing them, so a feature block added later that only
logs its failure fails here instead of silently reporting nothing in the field.
"""

import ast
import inspect
import json
import textwrap
from pathlib import Path

import pytest

import skylos.analyzer as analyzer_module
from skylos.analyzer import analyze
from skylos.cli import _analysis_incomplete_exit_code


GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
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


def test_config_only_secret_scan_failure_is_recorded(tmp_path, monkeypatch):
    """The config-file path is a separate helper from the per-file loop."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / ".env").write_text(f"GITHUB_TOKEN={GITHUB_TOKEN}\n", encoding="utf-8")

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
    assert recorded, "a crashed config secret scan was reported as a clean repository"
    assert recorded[0]["file"].endswith(".env")
    assert _analysis_incomplete_exit_code(result) == 2


def test_secret_failure_names_the_file_not_the_repository(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(
            f'TOKEN_{name[0]} = "{GITHUB_TOKEN}"\n', encoding="utf-8"
        )

    monkeypatch.setattr(analyzer_module, "_secrets_scan_ctx", _boom)
    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_secrets=True, grep_verify=False)
    )

    recorded = [
        entry
        for entry in result.get("analysis_errors", [])
        if entry.get("subsystem") == "Secret scan"
    ]
    assert recorded
    assert {Path(entry["file"]).name for entry in recorded} == {"a.py", "b.py"}, (
        "a per-file failure must name the file, not the scan root"
    )


def test_no_source_result_reports_its_own_error_count(tmp_path, monkeypatch):
    """Optional no-source subsystems append after the earlier count was taken."""
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"left-pad": "1.0.0"}}', encoding="utf-8"
    )

    import skylos.rules.sca.vulnerability_scanner as vulnerability_scanner

    monkeypatch.setattr(vulnerability_scanner, "scan_dependencies", _boom)
    result = json.loads(
        analyze(str(tmp_path), conf=0, enable_sca=True, grep_verify=False)
    )

    assert result["analysis_summary"]["analysis_error_count"] == len(
        result["analysis_errors"]
    )
    assert result["analysis_errors"]


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
    subsystem_markers = (
        "scan",
        "detect",
        "analyze",
        "hallucination",
        "policy",
        "rule",
        "visitor",
        "linter",
    )
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
    """Pinned near the real count so coverage cannot quietly shrink.

    Raise this when a subsystem is added; a drop means handlers stopped
    matching the markers and are no longer being checked.
    """
    assert len(_analyze_handlers()) >= 22


def _worker_handlers():
    """Broad handlers in proc_file(), which runs per file in the workers."""
    source = textwrap.dedent(inspect.getsource(analyzer_module.proc_file))
    tree = ast.parse(source)
    handlers = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            exc_type = handler.type
            broad = exc_type is None or any(
                isinstance(name, ast.Name) and name.id in ("Exception", "BaseException")
                for name in ast.walk(exc_type)
            )
            if broad:
                handlers.append(handler)
    return handlers


@pytest.mark.parametrize("index", range(len(_worker_handlers())))
def test_no_worker_handler_swallows_its_failure(index):
    """proc_file's per-file handlers must record too.

    Clone extraction and architecture metrics once logged and continued, so
    a crash there dropped SKY-C401 with an empty analysis_errors list.
    """
    handler = _worker_handlers()[index]
    body = ast.dump(ast.Module(body=handler.body, type_ignores=[]))
    records = (
        "scanner_errors" in body
        or "scanner_failure_finding" in body
        or "_analysis_error_payload" in body
        or "_subsystem_error_payload" in body
    )
    assert records, (
        f"handler at line {handler.lineno} of proc_file() only logs its failure; "
        "the file would be reported as fully analyzed"
    )


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
