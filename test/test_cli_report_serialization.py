"""Keep report optimization separate from JSON normalization and upload state."""

import copy
import json
from types import SimpleNamespace

import pytest

import skylos.cli as cli
from skylos.commands.scan_cmd import _build_ci_json_payload
from skylos.core.safe_cache_io import write_text_no_symlink


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
    expected["provenance_status"] = {
        "ran": False,
        "reason": "skipped with --no-provenance",
    }
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
    if output_format == "json-ci":
        normalized = _build_ci_json_payload(normalized)
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
