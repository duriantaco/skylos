import json
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
    CHALLENGE_STAGE,
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
    assert (
        "conventional entry file `app.py`" in analyzer.config.repo_context_map[app_key]
    )
    assert "network boundary" in analyzer.config.repo_context_map[app_key]
    assert "framework: flask" in analyzer.config.repo_context_map[app_key]
    assert (
        "user-controlled sources: request.args.get"
        in analyzer.config.repo_context_map[app_key]
    )
    assert "dangerous sinks: requests.get" in analyzer.config.repo_context_map[app_key]
    assert any(item.path == app_key for item in run.entry_points)
    assert any(item.path == app_key for item in run.trust_boundaries)
    assert run.preferred_audit_targets
    repo_node = next(item for item in run.repo_map if item.path == app_key)
    assert repo_node.framework == "flask"
    assert "request.args.get" in repo_node.sources
    assert "requests.get" in repo_node.sinks
    assert [stage.name for stage in run.stages] == [
        REPO_MAP_STAGE,
        ENTRY_POINTS_STAGE,
        AUDIT_STAGE,
        VERIFY_STAGE,
        CHALLENGE_STAGE,
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
        candidate
        for candidate in run.candidate_ledger
        if candidate.rule_id == "SKY-L001"
    )
    refuted = next(
        candidate
        for candidate in run.candidate_ledger
        if candidate.rule_id == "SKY-L002"
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


def test_run_security_taskflow_extracts_fastapi_facts_and_guards(tmp_path):
    app = tmp_path / "api.py"
    app.write_text(
        "from fastapi import FastAPI, Request\n"
        "from urllib.parse import urlparse\n"
        "import httpx\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/proxy')\n"
        "async def proxy(request: Request):\n"
        "    target = request.query_params.get('url')\n"
        "    if urlparse(target).netloc not in {'internal.local'}:\n"
        "        target = 'https://internal.local/health'\n"
        "    return httpx.get(target).text\n",
        encoding="utf-8",
    )

    analyzer = _FakeAnalyzer(AnalysisResult(findings=[], files_analyzed=1))
    run = run_security_taskflow(
        path=tmp_path,
        files=[app],
        analyzer=analyzer,
        model="gpt-4.1",
        api_key="k",
    )

    app_key = str(app.resolve())
    context = analyzer.config.repo_context_map[app_key]
    assert "framework: fastapi" in context
    assert "user-controlled sources: request.query_params.get" in context
    assert "dangerous sinks: httpx.get" in context
    assert "guards/sanitizers: urlparse" in context


def test_run_security_taskflow_writes_run_artifacts(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    findings = [_security_finding(str(app), 1, "SKY-L001")]
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
        return {
            "supported": 1,
            "refuted": 0,
            "undecided": 0,
            "refuted_findings": [],
        }

    with (
        patch(
            "skylos.llm.security_taskflow._generate_run_id",
            return_value="run-test-123",
        ),
        patch(
            "skylos.llm.security_taskflow.SecurityVerifier.review_findings",
            side_effect=_review,
        ),
    ):
        run = run_security_taskflow(
            path=tmp_path,
            files=[app],
            analyzer=analyzer,
            model="gpt-4.1",
            api_key="k",
        )

    artifacts_dir = tmp_path / ".skylos" / "runs" / "run-test-123"
    assert run.run_id == "run-test-123"
    assert Path(run.artifacts_dir) == artifacts_dir

    repo_map_payload = json.loads((artifacts_dir / "repo_map.json").read_text())
    candidates_payload = json.loads((artifacts_dir / "candidates.json").read_text())
    verified_payload = json.loads((artifacts_dir / "verified.json").read_text())
    summary_payload = json.loads((artifacts_dir / "summary.json").read_text())

    assert repo_map_payload["run_id"] == "run-test-123"
    assert repo_map_payload["project_root"] == str(tmp_path.resolve())
    assert repo_map_payload["repo_map"][0]["path"] == str(app.resolve())

    assert candidates_payload["run_id"] == "run-test-123"
    assert candidates_payload["candidate_count"] == 1
    assert candidates_payload["candidates"][0]["rule_id"] == "SKY-L001"
    assert candidates_payload["candidates"][0]["history"][1]["stage"] == VERIFY_STAGE

    assert verified_payload["run_id"] == "run-test-123"
    assert verified_payload["supported_count"] == 1
    assert verified_payload["final_finding_count"] == 1
    assert (
        verified_payload["result"]["findings"][0]["metadata"]["review_verdict"]
        == "SUPPORTED"
    )

    assert summary_payload["run_id"] == "run-test-123"
    assert summary_payload["artifacts_dir"] == str(artifacts_dir)
    assert summary_payload["candidate_count"] == 1
    assert summary_payload["supported_count"] == 1
    assert summary_payload["final_finding_count"] == 1
    assert summary_payload["stages"][-1]["name"] == FINALIZE_STAGE
    assert summary_payload["artifact_write_error"] is None


def test_run_security_taskflow_challenges_uncertain_findings(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("print('hi')\n", encoding="utf-8")
    findings = [_security_finding(str(app), 1, "SKY-L001")]
    analyzer = _FakeAnalyzer(AnalysisResult(findings=findings, files_analyzed=1))

    def _review(found):
        annotate_security_finding(
            found[0],
            evidence="hypothesis",
            review_verdict="UNCERTAIN",
            review_reason="not enough local context",
            needs_review=True,
            ci_blocking=False,
        )
        return {
            "supported": 0,
            "refuted": 0,
            "undecided": 1,
            "refuted_findings": [],
        }

    def _challenge(found):
        annotate_security_finding(
            found[0],
            evidence="review_supported",
            review_verdict="SUPPORTED",
            review_reason="challenge found enough local evidence",
            needs_review=True,
            ci_blocking=False,
        )
        return {
            "supported": 1,
            "refuted": 0,
            "undecided": 0,
            "refuted_findings": [],
        }

    with (
        patch(
            "skylos.llm.security_taskflow.SecurityVerifier.review_findings",
            side_effect=_review,
        ),
        patch(
            "skylos.llm.security_taskflow.SecurityVerifier.challenge_findings",
            side_effect=_challenge,
        ),
    ):
        run = run_security_taskflow(
            path=tmp_path,
            files=[app],
            analyzer=analyzer,
            model="gpt-4.1",
            api_key="k",
        )

    assert run.supported_count == 1
    assert run.refuted_count == 0
    assert run.hypothesis_count == 0
    candidate = run.candidate_ledger[0]
    assert candidate.state == "review_supported"
    assert candidate.review_verdict == "SUPPORTED"
    assert [event.stage for event in candidate.history] == [
        AUDIT_STAGE,
        VERIFY_STAGE,
        CHALLENGE_STAGE,
    ]
    assert candidate.history[1].evidence == "hypothesis"
    assert candidate.history[2].evidence == "review_supported"
    assert run.stages[-2].name == CHALLENGE_STAGE
    assert run.stages[-2].details["challenged"] == 1
    assert run.stages[-2].details["supported"] == 1
