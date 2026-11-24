"""Keep report optimization separate from JSON normalization and upload state."""

import copy
import json
from types import SimpleNamespace

import pytest

import skylos.cli as cli
from skylos.commands.scan_cmd import _build_ci_json_payload
from skylos.core.gate_incomplete import analysis_coverage, coverage_record
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.finding_types import (
    annotate_finding_types,
    summarize_finding_types,
)


@pytest.fixture(autouse=True)
def _placeholder_scan_paths(monkeypatch):
    """These tests mock the analyzer and pass placeholder paths such as
    ``test_path``; the missing-path check has its own tests."""
    import skylos.commands.scan_cmd as scan_cmd

    monkeypatch.setattr(
        scan_cmd, "_exit_on_missing_scan_paths", lambda args, *, cli_module: None
    )


def _report():
    return {
        "definitions": {"app.unused": {"name": "app.unused", "type": "function"}},
        "dead_code_evidence": {
            "symbols": [
                {"qualified_name": "app.unused", "classification": "likely_dead"}
            ]
        },
        "unused_functions": [
            {
                "name": "unused",
                "full_name": "app.unused",
                "file": "app.py",
                "line": 1,
                "confidence": 100,
                "type": "function",
                "dead_code_evidence": [
                    {"kind": "no_static_references", "role": "supports_dead"}
                ],
            }
        ],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
        "analysis_errors": [],
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
    }


def _configure(monkeypatch, tmp_path, output_format, *, upload=False):
    monkeypatch.chdir(tmp_path)
    if upload:
        monkeypatch.setenv("SKYLOS_TOKEN", "fixture-project-token")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert write_text_no_symlink(
        tmp_path / "app.py", "def unused():\n    return 1\n", encoding="utf-8"
    )
    argv = [
        "skylos",
        str(tmp_path),
        "--format",
        output_format,
        "--no-provenance",
        "--no-clipboard",
    ]
    argv.append("--upload" if upload else "--no-upload")
    monkeypatch.setattr(cli.sys, "argv", argv)
    monkeypatch.setattr(
        cli, "run_analyze", lambda *_args, **_kwargs: json.dumps(_report())
    )
    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(cli, "print_badge", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "skylos.cloud.sync.load_custom_rules",
        lambda: {"status": "complete", "rules": []},
    )


@pytest.mark.parametrize(
    "output_format", ["rich", "pretty", "concise", "llm", "github", "gitlab", "tui"]
)
def test_non_json_formats_do_not_encode_an_unused_whole_report(
    monkeypatch, capsys, tmp_path, output_format
):
    # A complete report encode is particularly expensive because it includes
    # every symbol's ledger, even when the consumer is a terminal renderer.
    _configure(
        monkeypatch, tmp_path, "rich" if output_format == "tui" else output_format
    )
    seen = []

    def encode(payload, *args, **kwargs):
        if isinstance(payload, dict) and "definitions" in payload:
            seen.append(payload)
        return json.dumps(payload, *args, **kwargs)

    monkeypatch.setattr(cli, "json", SimpleNamespace(loads=json.loads, dumps=encode))
    if output_format == "tui":
        monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--tui"])
        monkeypatch.setattr(cli, "_is_tty", lambda: True)
        monkeypatch.setattr("skylos.ui.tui.run_tui", lambda *_args, **_kwargs: None)
    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == (1 if output_format == "concise" else 0)
    capsys.readouterr()
    assert seen == []


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
@pytest.mark.parametrize("filtered", [False, True])
def test_json_bytes_normalization_and_upload_isolation(
    monkeypatch, capsys, tmp_path, output_format, filtered
):
    _configure(monkeypatch, tmp_path, output_format, upload=True)
    # CLI enrichments can introduce tuples or non-string keys after the
    # analyzer's public JSON return. Keep the existing normalization, including
    # colliding keys, rather than replacing its snapshot with a shallow copy.
    expected = _report()
    expected["metadata"] = {
        "tuple": ("雪", "é"),
        "keys": {1: "first", "1": "last", False: "false"},
    }
    expected["provenance"] = None
    expected["analysis_summary"]["custom_rules_coverage"] = {
        "status": "complete",
        "rule_count": 0,
    }
    expected["analysis_summary"]["analysis_coverage"] = coverage_record(
        analysis_coverage(expected)
    )
    expected["provenance_status"] = {
        "ran": False,
        "reason": "skipped with --no-provenance",
    }
    annotate_finding_types(expected)
    expected["analysis_summary"]["finding_type_counts"] = summarize_finding_types(
        expected
    )
    original_expected = copy.deepcopy(expected)

    def enrich(result, *_args, **_kwargs):
        result["metadata"] = copy.deepcopy(expected["metadata"])
        return result

    monkeypatch.setattr(
        "skylos.core.review_decisions.apply_trusted_review_decisions", enrich
    )
    monkeypatch.setattr(cli, "_attach_upload_project_context", lambda *_args: None)
    uploaded = []

    def upload(result, **_kwargs):
        uploaded.append(copy.deepcopy(result))
        result["unused_functions"][0]["name"] = "upload mutated the finding"
        result["dead_code_evidence"]["symbols"].clear()
        result["metadata"]["tuple"] = ("changed",)
        return {"success": True}

    monkeypatch.setattr(cli, "upload_report", upload)
    if filtered:
        monkeypatch.setattr(
            cli.sys, "argv", [*cli.sys.argv, "--file-filter", "elsewhere.py"]
        )

    public = dict(expected)
    public.pop("provenance_status")
    public.pop("provenance")
    normalized = json.loads(json.dumps(public))
    if filtered:
        normalized = cli._apply_display_filters(normalized, file_filter="elsewhere.py")
    from skylos.reporting.top_risks import add_report_guidance

    add_report_guidance(normalized, config={})
    if output_format == "json-ci":
        normalized = _build_ci_json_payload(normalized)
    normalized["upload"] = {
        "status": "uploaded",
        "upload_trust": "unknown",
        "verification": {
            "status": "unknown",
            "message": "Your scan is saved. Cloud did not report its upload verification status.",
        },
    }
    expected_bytes = json.dumps(normalized) + "\n"

    cli.main()

    assert capsys.readouterr().out == expected_bytes
    assert uploaded == [original_expected]
    assert len(uploaded[0]["dead_code_evidence"]["symbols"]) == 1
    assert uploaded[0]["metadata"]["tuple"] == ("雪", "é")


@pytest.mark.parametrize(
    "output_format",
    ["json", "json-ci", "rich", "pretty", "concise", "llm", "github", "gitlab"],
)
def test_output_format_does_not_filter_the_result_used_by_a_strict_gate(
    monkeypatch, capsys, tmp_path, output_format
):
    _configure(monkeypatch, tmp_path, output_format)
    monkeypatch.setattr(
        cli.sys, "argv", [*cli.sys.argv, "--strict", "--file-filter", "elsewhere.py"]
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    capsys.readouterr()


@pytest.fixture
def aws_identifier_finding():
    return {
        "file": "app.py",
        "line": 1,
        "rule_id": "SKY-S101",
        "severity": "CRITICAL",
        "provider": "aws_access_key_id",
        "message": "Potential AWS access-key identifier detected",
    }


@pytest.mark.parametrize("secret_flag", ["--secrets", "--all", "--select=SKY-S101"])
def test_default_credential_material_view_keeps_signers_and_the_full_upload(
    monkeypatch, capsys, tmp_path, aws_identifier_finding, secret_flag
):
    _configure(monkeypatch, tmp_path, "json", upload=True)
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, secret_flag])
    raw = _report()
    evidence = {"credential_record": "aws_pair", "validation": "structural"}
    related_identifier = {
        **aws_identifier_finding,
        "line": 2,
        "structured_credential": evidence,
    }
    signing_material = {
        **related_identifier,
        "line": 3,
        "provider": "aws_secret_access_key",
        "message": "Potential AWS signing material detected",
    }
    raw["secrets"] = [aws_identifier_finding, related_identifier, signing_material]
    raw["analysis_summary"].update(
        secrets_count=3,
        dead_code_evidence={"record_count": 1},
        grep_verify={"complete": True, "verified": 1},
    )
    monkeypatch.setattr(cli, "run_analyze", lambda *_args, **_kwargs: json.dumps(raw))
    monkeypatch.setattr(cli, "_attach_upload_project_context", lambda *_args: None)
    uploaded = []

    def upload(result, **_kwargs):
        uploaded.append(copy.deepcopy(result))
        return {"success": True}

    monkeypatch.setattr(cli, "upload_report", upload)
    cli.main()

    display = json.loads(capsys.readouterr().out)
    assert [finding["line"] for finding in display["secrets"]] == [2, 3]
    assert display["analysis_summary"]["secrets_count"] == 2
    assert (
        display["analysis_summary"]["secrets_display_scope"]
        == "credential_material_only"
    )
    assert display["analysis_summary"]["aws_access_key_identifiers_hidden"] == 1

    monkeypatch.setattr(
        cli.sys, "argv", [*cli.sys.argv, "--secrets-include-aws-key-ids"]
    )
    cli.main()

    raw_display = json.loads(capsys.readouterr().out)
    assert [finding["line"] for finding in raw_display["secrets"]] == [1, 2, 3]
    assert raw_display["analysis_summary"]["secrets_count"] == 3
    assert "aws_access_key_identifiers_hidden" not in raw_display["analysis_summary"]
    for field in ("dead_code_evidence", "grep_verify"):
        assert (
            display["analysis_summary"].get(field)
            == raw_display["analysis_summary"].get(field)
        )
    assert uploaded[0]["secrets"] == uploaded[1]["secrets"]
    assert [finding["line"] for finding in uploaded[0]["secrets"]] == [1, 2, 3]
    assert uploaded[0]["analysis_summary"]["secrets_count"] == 3
    assert "aws_access_key_identifiers_hidden" not in uploaded[0]["analysis_summary"]


@pytest.mark.parametrize(
    "output_format,gate_options",
    [
        ("json", ["--strict"]),
        ("json", ["--gate", "--strict"]),
        ("json", ["--strict", "--secrets-credential-material-only"]),
        ("pretty", ["--strict"]),
        ("concise", ["--strict"]),
    ],
)
def test_default_credential_material_view_keeps_the_identifier_blocking(
    monkeypatch, capsys, tmp_path, aws_identifier_finding, output_format, gate_options
):
    _configure(monkeypatch, tmp_path, output_format)
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    raw = _report()
    raw["unused_functions"] = []
    raw["secrets"] = [aws_identifier_finding]
    raw["analysis_summary"]["secrets_count"] = 1
    monkeypatch.setattr(cli, "run_analyze", lambda *_args, **_kwargs: json.dumps(raw))
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--secrets", *gate_options])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    if output_format == "json":
        output = json.loads(captured.out)
        assert output["gate"]["passed"] is False
        assert output["secrets"] == []
        assert output["analysis_summary"]["aws_access_key_identifiers_hidden"] == 1
    elif output_format == "pretty":
        assert "Credential material view hides 1 standalone" in captured.out
        assert "No findings to display." in captured.out
        assert "Quality Gate: FAILED" in captured.out
    else:
        assert aws_identifier_finding["message"] not in captured.out


def test_secret_scan_without_standalone_identifiers_preserves_report_shape(
    monkeypatch, capsys, tmp_path
):
    _configure(monkeypatch, tmp_path, "json")
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--secrets"])

    cli.main()

    output = json.loads(capsys.readouterr().out)
    assert output["dead_code_evidence"] == _report()["dead_code_evidence"]
    assert "secrets_display_scope" not in output["analysis_summary"]


@pytest.mark.parametrize(
    "output_format", ["json-in-ci", "json-ci", "github", "gitlab", "sarif"]
)
def test_credential_material_view_preserves_ci_reports(
    monkeypatch, capsys, tmp_path, aws_identifier_finding, output_format
):
    cli_format = {"json-in-ci": "json", "sarif": "rich"}.get(
        output_format, output_format
    )
    _configure(monkeypatch, tmp_path, cli_format)
    monkeypatch.setattr(cli, "_is_ci", lambda: output_format == "json-in-ci")
    raw = _report()
    raw["unused_functions"] = []
    raw["secrets"] = [aws_identifier_finding]
    raw["analysis_summary"]["secrets_count"] = 1
    monkeypatch.setattr(cli, "run_analyze", lambda *_args, **_kwargs: json.dumps(raw))
    argv = [*cli.sys.argv, "--secrets", "--strict"]
    sarif = tmp_path / "result.sarif"
    if output_format == "sarif":
        argv.extend(["--sarif", str(sarif)])
    monkeypatch.setattr(cli.sys, "argv", argv)

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 1
    output = capsys.readouterr().out
    if output_format in {"json-in-ci", "json-ci"}:
        result = json.loads(output)
        assert [item["provider"] for item in result["secrets"]] == ["aws_access_key_id"]
        assert "secrets_display_scope" not in result["analysis_summary"]
    elif output_format == "github":
        assert aws_identifier_finding["message"] in output
    elif output_format == "gitlab":
        assert [item["check_name"] for item in json.loads(output)] == ["SKY-S101"]
    else:
        results = json.loads(sarif.read_text())["runs"][0]["results"]
        assert [item["ruleId"] for item in results] == ["SKY-S101"]
