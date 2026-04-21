from pathlib import Path
from unittest.mock import patch

from skylos.llm.analyzer import AnalyzerConfig
from skylos.llm.schemas import (
    AnalysisResult,
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)
from skylos.llm.security_taskflow import (
    AUDIT_STAGE,
    ENTRY_POINTS_STAGE,
    FINALIZE_STAGE,
    REPO_MAP_STAGE,
    VERIFY_STAGE,
    DEFAULT_CANDIDATE_STATE,
    run_security_taskflow,
)
from skylos.llm.security_verifier import annotate_security_finding


class _FakeAnalyzer:
    def __init__(self, result: AnalysisResult):
        self.config = AnalyzerConfig(quiet=True)
        self._result = result
        self.seen_files = None
        self.seen_issue_types = None

    def analyze_files(self, files, issue_types=None):
        self.seen_files = list(files)
        self.seen_issue_types = list(issue_types or [])
        return self._result

    def _generate_summary(self, result):
        return f"{len(result.findings)} findings"


def _security_finding(file_path: str, line: int, rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        issue_type=IssueType.SECURITY,
        severity=Severity.HIGH,
        message=f"{rule_id} issue",
        location=CodeLocation(file=file_path, line=line),
        confidence=Confidence.HIGH,
    )


def test_run_security_taskflow_builds_repo_context_and_entry_points(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        "from flask import Flask, request\n"
        "import requests\n"
        "app = Flask(__name__)\n"
        "@app.route('/proxy')\n"
        "def proxy():\n"
        "    url = request.args.get('url')\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    helper = tmp_path / "helper.py"
    helper.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    analyzer = _FakeAnalyzer(AnalysisResult(findings=[], files_analyzed=2))
    run = run_security_taskflow(
        path=tmp_path,
        files=[app, helper],
        analyzer=analyzer,
        model="gpt-4.1",
        api_key="k",
    )

    app_key = str(app.resolve())
    assert analyzer.seen_issue_types == ["security_audit"]
    assert app_key in analyzer.config.repo_context_map
    assert "conventional entry file `app.py`" in analyzer.config.repo_context_map[app_key]
    assert "network boundary" in analyzer.config.repo_context_map[app_key]
    assert any(item.path == app_key for item in run.entry_points)
    assert any(item.path == app_key for item in run.trust_boundaries)
    assert run.preferred_audit_targets
    assert [stage.name for stage in run.stages] == [
        REPO_MAP_STAGE,
        ENTRY_POINTS_STAGE,
        AUDIT_STAGE,
        VERIFY_STAGE,
        FINALIZE_STAGE,
    ]
    assert run.candidate_ledger == []


def test_run_security_taskflow_records_review_counts_and_filters_refuted_findings(
    tmp_path,
):
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    findings = [
        _security_finding(str(app), 1, "SKY-L001"),
        _security_finding(str(app), 2, "SKY-L002"),
    ]
    analyzer = _FakeAnalyzer(AnalysisResult(findings=findings, files_analyzed=1))

    def _review(found):
        annotate_security_finding(
            found[0],
            evidence="review_supported",
            review_verdict="SUPPORTED",
            review_reason="confirmed",
            needs_review=True,
            ci_blocking=False,
        )
        annotate_security_finding(
            found[1],
            evidence="refuted",
            review_verdict="REFUTED",
            review_reason="guarded path",
            needs_review=True,
            ci_blocking=False,
        )
        return {
            "supported": 1,
            "refuted": 1,
            "undecided": 0,
            "refuted_findings": [found[1]],
        }

    with patch(
        "skylos.llm.security_taskflow.SecurityVerifier.review_findings",
        side_effect=_review,
    ):
        run = run_security_taskflow(
            path=tmp_path,
            files=[app],
            analyzer=analyzer,
            model="gpt-4.1",
            api_key="k",
        )

    assert run.candidate_count == 2
    assert run.supported_count == 1
    assert run.refuted_count == 1
    assert run.hypothesis_count == 0
    assert run.final_finding_count == 1
    assert len(run.result.findings) == 1
    assert run.result.findings[0].metadata["review_verdict"] == "SUPPORTED"
    assert len(run.candidate_ledger) == 2

    supported = next(
        candidate for candidate in run.candidate_ledger if candidate.rule_id == "SKY-L001"
    )
    refuted = next(
        candidate for candidate in run.candidate_ledger if candidate.rule_id == "SKY-L002"
    )
    assert supported.state == "review_supported"
    assert supported.evidence == "review_supported"
    assert supported.review_verdict == "SUPPORTED"
    assert [event.stage for event in supported.history] == [AUDIT_STAGE, VERIFY_STAGE]
    assert supported.history[0].state == DEFAULT_CANDIDATE_STATE
    assert supported.history[0].evidence == "hypothesis"
    assert refuted.state == "refuted"
    assert refuted.evidence == "refuted"
    assert refuted.review_verdict == "REFUTED"
    assert [event.stage for event in refuted.history] == [AUDIT_STAGE, VERIFY_STAGE]


def test_run_security_taskflow_ledger_ids_are_stable_and_serialized(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    findings = [
        _security_finding(str(app), 1, "SKY-L001"),
        _security_finding(str(app), 2, "SKY-L002"),
    ]

    run_one = run_security_taskflow(
        path=tmp_path,
        files=[app],
        analyzer=_FakeAnalyzer(AnalysisResult(findings=findings, files_analyzed=1)),
        model="gpt-4.1",
        api_key="k",
    )
    run_two = run_security_taskflow(
        path=tmp_path,
        files=[app],
        analyzer=_FakeAnalyzer(
            AnalysisResult(
                findings=[
                    _security_finding(str(app), 1, "SKY-L001"),
                    _security_finding(str(app), 2, "SKY-L002"),
                ],
                files_analyzed=1,
            )
        ),
        model="gpt-4.1",
        api_key="k",
    )

    ids_one = [candidate.candidate_id for candidate in run_one.candidate_ledger]
    ids_two = [candidate.candidate_id for candidate in run_two.candidate_ledger]
    assert ids_one == ids_two

    serialized = run_one.to_dict()
    assert [item["candidate_id"] for item in serialized["candidate_ledger"]] == ids_one
    assert serialized["candidate_ledger"][0]["history"][0]["stage"] == AUDIT_STAGE
