"""Offline CLI guards for the opt-in hosted Jev benchmark."""

import json

import pytest

from scripts import jev_dead_code_benchmark as cli


def test_failed_checkpoint_replace_preserves_prior_report(monkeypatch, tmp_path):
    output = tmp_path / "jev-result.json"
    previous = {"status": "incomplete", "completed_request_count": 1}
    cli._write_report(output, previous)
    saved = output.read_bytes()

    def failed_replace(*_args, **_kwargs):
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(cli.os, "replace", failed_replace)
    with pytest.raises(OSError, match="simulated replacement failure"):
        cli._write_report(output, {"status": "complete"})

    assert output.read_bytes() == saved
    assert json.loads(output.read_text(encoding="utf-8")) == previous
    assert list(tmp_path.iterdir()) == [output]


def test_plan_does_not_need_key_or_call_live_runner(monkeypatch, capsys):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr(
        cli,
        "run_jev_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live call")),
    )

    assert cli.main(["--case", "basic-unused-symbols", "--json"]) == 0

    plan = json.loads(capsys.readouterr().out)
    assert plan["network_used"] is False
    assert plan["request_count"] == 2


def test_live_refuses_to_replace_existing_report_without_resume(
    monkeypatch, tmp_path, capsys
):
    report = tmp_path / "existing.json"
    report.write_text('{"do_not_replace": true}', encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-key")
    monkeypatch.setattr(
        cli,
        "run_jev_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live call")),
    )

    assert cli.main(["--live", "--output", str(report)]) == 2
    assert "output already exists" in capsys.readouterr().err
    assert report.read_text(encoding="utf-8") == '{"do_not_replace": true}'


def test_live_requires_existing_output_parent_before_paid_call(
    monkeypatch, tmp_path, capsys
):
    output = tmp_path / "missing" / "report.json"
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-key")
    monkeypatch.setattr(
        cli,
        "run_jev_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live call")),
    )

    assert cli.main(["--live", "--output", str(output)]) == 2
    assert "output parent" in capsys.readouterr().err


def test_resume_passes_existing_report_to_runner(monkeypatch, tmp_path):
    report = tmp_path / "resume.json"
    report.write_text('{"status": "incomplete"}', encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-key")
    observed = {}

    def fake_runner(_manifest, **kwargs):
        observed.update(kwargs)
        result = {"status": "complete"}
        kwargs["checkpoint"](result)
        return result

    monkeypatch.setattr(cli, "run_jev_manifest", fake_runner)
    monkeypatch.setattr(cli, "format_report", lambda _report: "done")

    assert (
        cli.main(["--live", "--resume", "--max-requests", "2", "--output", str(report)])
        == 0
    )
    assert observed["resume_report"] == {"status": "incomplete"}
    assert observed["max_new_requests"] == 2
    assert report.read_text(encoding="utf-8").strip() == '{\n  "status": "complete"\n}'


def test_resume_rejects_symlink_without_live_call(monkeypatch, tmp_path, capsys):
    target = tmp_path / "target.json"
    target.write_text('{"status": "incomplete"}', encoding="utf-8")
    link = tmp_path / "resume.json"
    link.symlink_to(target)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-key")
    monkeypatch.setattr(
        cli,
        "run_jev_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live call")),
    )

    assert cli.main(["--live", "--resume", "--output", str(link)]) == 2
    assert "safely read" in capsys.readouterr().err


def test_resume_rejects_complete_report_without_live_call(
    monkeypatch, tmp_path, capsys
):
    report = tmp_path / "complete.json"
    report.write_text('{"status": "complete"}', encoding="utf-8")
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-key")
    monkeypatch.setattr(
        cli,
        "run_jev_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("live call")),
    )

    assert cli.main(["--live", "--resume", "--output", str(report)]) == 2
    assert "incomplete report" in capsys.readouterr().err
