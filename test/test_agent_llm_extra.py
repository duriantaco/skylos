from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from skylos import cli
from skylos.audit.types import AuditScanSummary

INSTALL_HINT = 'pip install "skylos[llm]"'


@pytest.fixture
def no_llm_extra(monkeypatch):
    monkeypatch.setattr(cli, "SkylosLLM", None)
    monkeypatch.setattr("skylos.llm.runtime.llm_extra_importable", lambda: False)

    def no_key_lookup(**_kwargs):
        raise AssertionError("the provider key must not be resolved without the extra")

    monkeypatch.setattr(cli, "resolve_llm_runtime", no_key_lookup)


def _run_agent(monkeypatch, *argv):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "agent", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def _source_file(tmp_path: Path) -> Path:
    source = tmp_path / "db.py"
    source.write_text(
        "def find(conn, name):\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        encoding="utf-8",
    )
    return source


def test_ensure_llm_support_requires_litellm_not_just_the_analyzer(monkeypatch):
    monkeypatch.setattr(cli, "SkylosLLM", None)
    monkeypatch.setattr(cli, "LLM_AVAILABLE", True)
    monkeypatch.setattr("skylos.llm.runtime.llm_extra_importable", lambda: False)

    import skylos.llm.analyzer  # noqa: F401

    assert cli._ensure_llm_support() is False
    assert cli.LLM_AVAILABLE is False


def test_security_quick_without_litellm_fails_without_a_clean_result(
    no_llm_extra, monkeypatch, capsys, tmp_path
):
    source = _source_file(tmp_path)
    analyze_files = MagicMock()
    monkeypatch.setattr("skylos.llm.analyzer.SkylosLLM.analyze_files", analyze_files)

    code = _run_agent(
        monkeypatch,
        "security-quick",
        str(source),
        "--provider",
        "ollama",
        "--model",
        "ollama/none",
        "--base-url",
        "http://127.0.0.1:9",
        "--format",
        "json",
    )
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert INSTALL_HINT in " ".join(captured.err.split())
    assert "No issues found" not in captured.err
    analyze_files.assert_not_called()
    assert cli.SkylosLLM is None


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "{path}"],
        ["scan", "{path}", "--security"],
        ["verify", "{path}"],
        ["remediate", "{path}"],
        ["remediate", "{path}", "--dry-run", "--standards"],
    ],
)
def test_llm_agent_commands_without_litellm_exit_2(
    no_llm_extra, monkeypatch, capsys, tmp_path, argv
):
    _source_file(tmp_path)
    args = [part.replace("{path}", str(tmp_path)) for part in argv]

    code = _run_agent(monkeypatch, *args)

    assert code == 2
    assert INSTALL_HINT in " ".join(capsys.readouterr().err.split())


def test_deep_audit_processing_without_litellm_exits_2(
    no_llm_extra, monkeypatch, capsys, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_scan(path, **_kwargs):
        return (
            AuditScanSummary(
                project_id="default",
                project_root=str(repo),
                files_scanned=1,
                records_written=1,
                candidate_count=1,
                redacted_candidates=0,
                pending_files=1,
                not_analyzed_files=0,
            ),
            SimpleNamespace(
                project_dir=repo / ".skylos" / "audit" / "projects" / "default"
            ),
        )

    monkeypatch.setattr("skylos.audit.candidates.scan_deep_audit_candidates", fake_scan)

    code = _run_agent(monkeypatch, "audit", str(repo), "--deep")

    assert code == 2
    assert INSTALL_HINT in " ".join(capsys.readouterr().err.split())


def test_remediation_plan_does_not_need_the_llm_extra(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "SkylosLLM", None)
    monkeypatch.setattr("skylos.llm.runtime.llm_extra_importable", lambda: False)
    monkeypatch.setattr(
        cli,
        "resolve_llm_runtime",
        lambda **_kwargs: ("openai", "test-key", None, False),
    )
    agent_cls = MagicMock()
    agent_cls.return_value.run.return_value = {"total_findings": 0}
    monkeypatch.setattr("skylos.llm.orchestrator.RemediationAgent", agent_cls)

    code = _run_agent(monkeypatch, "remediate", str(tmp_path), "--dry-run")

    assert code == 0
    assert agent_cls.return_value.run.call_args.kwargs["dry_run"] is True
    assert INSTALL_HINT not in capsys.readouterr().err
