"""`skylos cicd review` composes the brief at the top of the pull request
comment from the Done receipt, the change map and the risk review that the
workflow jobs saved, and keeps the old tables under Details."""

from __future__ import annotations

import contextlib
import copy
import json
from unittest.mock import Mock, patch

from skylos.cicd import review
from skylos.cicd.pr_summary import (
    MAX_BLOCKING_FINDINGS,
    MAX_READ_FIRST,
    MAX_UNCHECKED,
    SummaryInputs,
    run_url_from_env,
)
from skylos.cicd.review import _post_summary_comment
from skylos.commands import cicd_cmd
from test.test_cicd_review_sticky import FakeGitHub, _finding

SHA_A = "a" * 40
SHA_B = "b" * 40
RUN_URL = "https://github.com/acme/app/actions/runs/123"
WAITING = "Earlier required checks failed or were incomplete"


def _check(check_id, status, summary, *, mode="block", rule=None, findings=()):
    return {
        "id": check_id,
        "rule": rule,
        "mode": mode,
        "status": status,
        "evidence": {"summary": summary},
        "findings": list(findings),
    }


def _found(file, line, message, rule=None):
    return {"rule": rule, "file": file, "line": line, "message": message}


RECEIPT = {
    "schema": "skylos.done-receipt/v1",
    "skylos_version": "5.4.0",
    "base": {"sha": SHA_A, "source": "merge_base"},
    "head": {"sha": SHA_B, "dirty": False},
    "agent": {"client": "unknown", "model": None, "session_id": None},
    "config_digest": None,
    "verdict": "fail",
    "stop_blocks": None,
    "checks": [
        _check(
            "tests_pass",
            "fail",
            "2 of 40 tests failed",
            findings=[
                _found("tests/test_refund.py", 41, "test_partial_refund failed"),
                _found("tests/test_refund.py", 58, "test_full_refund failed"),
            ],
        ),
        _check(
            "test_tampering",
            "pass",
            "no test deleted, skipped or weakened",
            rule="SKY-A110",
        ),
        _check(
            "changed_lines_checked",
            "fail",
            "2 changed lines no test checks",
            mode="advise",
            rule="SKY-A120",
            findings=[
                _found(
                    "app/refund.py",
                    12,
                    "No test fails if app/refund.py:12 returns early. "
                    "Add an assertion that would.",
                    "SKY-A120",
                ),
            ],
        ),
        _check("secrets", "incomplete", WAITING, rule="SKY-S101"),
    ],
    "unverified": [
        {"file": "app/refund.py", "line": 12},
        {"file": "app/refund.py", "line": 30},
    ],
}


def _symbol(entry_id, file, name, start, bucket, why, *, is_test=False, verdict_text="Logic changed."):
    return {
        "id": entry_id,
        "file": file,
        "name": name,
        "full_name": name,
        "kind": "function",
        "status": "modified",
        "is_test": is_test,
        "before": {"start": start, "end": start + 8, "code": "..."},
        "after": {"start": start, "end": start + 10, "code": "..."},
        "review": bucket,
        "review_why": why,
        "verdict": "changed",
        "verdict_text": verdict_text,
        "callers": [],
        "lines_changed": 6,
    }


CHANGE_MAP = {
    "schema_version": 1,
    "base_commit": SHA_A,
    "head": "working_tree",
    "symbols": [
        _symbol(
            "app/refund.py::refund",
            "app/refund.py",
            "refund",
            10,
            "read_first",
            "Flagged: removed auth check `require_admin`.",
        ),
        _symbol("app/refund.py::audit", "app/refund.py", "audit", 30, "read", None),
        _symbol(
            "app/util.py::fmt",
            "app/util.py",
            "fmt",
            3,
            "skip",
            None,
            verdict_text="Same logic. Only the docstring changed.",
        ),
        _symbol(
            "tests/test_refund.py::test_full_refund",
            "tests/test_refund.py",
            "test_full_refund",
            50,
            None,
            None,
            is_test=True,
        ),
    ],
    "read_first": ["app/refund.py::refund"],
    "flagged": ["app/refund.py::refund"],
    "groups": [],
    "review": {
        "buckets": {
            "read_first": ["app/refund.py::refund"],
            "read": ["app/refund.py::audit"],
            "skim": [],
            "skip": ["app/util.py::fmt"],
        },
        "counts": {"read_first": 1, "read": 1, "skim": 0, "skip": 1},
        "lines": {"read_first": 6, "read": 6, "skim": 0, "skip": 6},
        "total": 3,
        "total_lines": 18,
        "test_edits": {},
    },
    "module_changes": [],
    "coverage": {
        "languages": ["python"],
        "not_mapped": ["config/refund.yaml"],
        "unparsed": [],
        "caller_depth": 3,
        "reach_is_lower_bound": False,
        "notes": [],
    },
}

RISK = {
    "approval": {
        "schema": "skylos.approval/v1",
        "check": "Skylos risk review",
        "verdict": "needs_human_approval",
        "passed": False,
        "eligible": False,
        "complete": True,
        "needs_human_approval": ["auth_removed"],
        "human_approval": {
            "status": "missing",
            "login": None,
            "review_id": None,
            "detail": "no person with write access approved the head commit",
            "ignored": [],
        },
        "vetoes": [
            {
                "class": "auth_removed",
                "rule_id": "SKY-A130",
                "file": "app/refund.py",
                "line": 14,
                "reason": "the require_admin check was removed",
            }
        ],
        "advisories": [],
        "classes_checked": ["tests_weakened", "auth_removed"],
        "classes_incomplete": [],
        "classes_disabled": [],
        "base": SHA_A,
        "base_ref": "origin/main",
        "head": SHA_B,
        "head_dirty": False,
        "diff": {"files": 3, "lines": 52},
        "excluded": 0,
        "settings": {
            "configured": False,
            "large_diff_lines": 800,
            "large_diff_files": 40,
            "problems": [],
        },
        "exit_code": 1,
        "skylos_version": "5.4.0",
    }
}

FULL = SummaryInputs(
    gate_result="failure",
    gate_reasons=("1 critical security issue",),
    done_requested=True,
    done_receipt=RECEIPT,
    change_map=CHANGE_MAP,
    risk_requested=True,
    risk_review=RISK,
    run_url=RUN_URL,
)

EXPECTED = """<!-- skylos-review -->
## Skylos Analysis Summary

**Gate:** failed · **Done:** failed · **Risk review:** needs a person

**0** issue(s) on changed lines | **0** total

**Blocking**
- 1 critical security issue
- Tests pass when Skylos runs them: 2 of 40 tests failed
  - `tests/test_refund.py:41` test_partial_refund failed
  - `tests/test_refund.py:58` test_full_refund failed
  - Fix: Fix the failing tests, or the code they test.

**Read first**
- `app/refund.py:10` · `refund` · Flagged: removed auth check require_admin.
- 1 more to read, 1 proven unchanged, 1 file(s) not mapped

**Not checked by tests**
- `app/refund.py:12` · No test fails if app/refund.py:12 returns early
- `app/refund.py:30` · no test checks this line
- not traced: `config/refund.yaml`

**Needs a person**
- `auth_removed` (1) · `app/refund.py:14` · the require_admin check was removed

A person with write access approving the head commit turns this check green; bot approvals and approvals of older commits do not.

[Full receipt and change map](https://github.com/acme/app/actions/runs/123)

<details><summary>Details</summary>

| Severity | Count |
|----------|-------|

</details>

---
_Skylos edits this comment on each push instead of adding a new one. Inline comments from earlier runs stay on the PR._
<!-- skylos-review-state: changed=0 max=0 -->"""


def _post(inputs, findings=(), **kwargs):
    gh = FakeGitHub()
    findings = list(findings)
    with patch("skylos.cicd.review.subprocess.run", side_effect=gh):
        _post_summary_comment(
            findings, findings, 7, "acme/app", summary_inputs=inputs, **kwargs
        )
    return gh.issue_comments[-1]["body"]


def _visible(body):
    return body.split("<details>", 1)[0].rstrip("\n").splitlines()


def test_full_brief_is_exactly_the_expected_comment():
    assert _post(FULL) == EXPECTED
    assert len(_visible(EXPECTED)) == 29


def test_absent_inputs_drop_their_sections():
    body = _post(None)
    for marker in (
        "**Gate:**",
        "**Blocking**",
        "**Read first**",
        "**Not checked by tests**",
        "**Needs a person**",
        "Full receipt",
    ):
        assert marker not in body
    assert "<details><summary>Details</summary>" in body

    body = _post(SummaryInputs(gate_result="success"))
    assert "\n**Gate:** passed\n" in body
    assert "**Blocking**" not in body

    body = _post(SummaryInputs(gate_result="cancelled", done_requested=True, risk_requested=True))
    assert "**Gate:** not run · **Done:** not run · **Risk review:** not run" in body
    for marker in ("**Blocking**", "**Not checked by tests**", "**Needs a person**"):
        assert marker not in body

    body = _post(SummaryInputs(done_requested=True, done_receipt=RECEIPT))
    assert "**Done:** failed" in body
    assert "**Read first**" not in body
    assert "not traced" not in body
    assert "- `app/refund.py:30` · no test checks this line" in body

    eligible = copy.deepcopy(RISK)
    eligible["approval"].update(
        verdict="eligible", needs_human_approval=[], vetoes=[], passed=True, eligible=True
    )
    body = _post(SummaryInputs(risk_requested=True, risk_review=eligible))
    assert "**Risk review:** passed" in body
    assert "**Needs a person**" not in body

    approved = copy.deepcopy(RISK)
    approved["approval"]["verdict"] = "human_approved"
    approved["approval"]["human_approval"] = {"status": "approved", "login": "alice"}
    body = _post(SummaryInputs(risk_requested=True, risk_review=approved))
    assert "**Risk review:** approved by alice" in body
    assert "**Needs a person**" not in body

    broken = copy.deepcopy(RISK)
    broken["approval"]["verdict"] = "error"
    broken["approval"]["error"] = "cannot find base origin/main"
    body = _post(SummaryInputs(risk_requested=True, risk_review=broken))
    assert "**Risk review:** could not check" in body
    assert "- Could not decide: cannot find base origin/main" in body


def test_gate_failure_without_reasons_points_at_the_job_log():
    body = _post(SummaryInputs(gate_result="failure"))
    assert "**Gate:** failed" in body
    assert "**Blocking**\n- The Skylos Quality Gate job failed; its log says why." in body


def test_passport_and_tables_sit_under_details_after_the_brief():
    passport = {
        "recommendation": "BLOCK",
        "changed_line_evidence": {},
        "reasons": ["Changed-line security regression: auth"],
        "warnings": [],
    }
    body = _post(FULL, findings=[_finding(3)], risk_passport=passport)
    head, details = body.split("<details><summary>Details</summary>", 1)
    assert "**Gate:** failed" in head
    assert "**Read first**" in head
    assert "**1** issue(s) on changed lines | **1** total" in head
    assert "### AI PR Risk Passport" in details
    assert "| HIGH | 1 |" in details
    assert "| danger | 1 |" in details
    assert "### Top Issues" in details
    assert details.index("</details>") < details.index("<!-- skylos-review-state:")


def test_blocking_findings_are_capped_at_ten_across_checks():
    receipt = copy.deepcopy(RECEIPT)
    receipt["checks"][0]["findings"] = [
        _found("tests/test_a.py", n, f"test_{n} failed") for n in range(1, 15)
    ]
    receipt["checks"].append(
        _check(
            "unknown_imports",
            "fail",
            "1 import does not exist",
            rule="SKY-L012",
            findings=[_found("app/x.py", 2, "ghostlib is not a package")],
        )
    )
    body = _post(SummaryInputs(done_requested=True, done_receipt=receipt))
    assert body.count("  - `tests/test_a.py:") == MAX_BLOCKING_FINDINGS
    assert "  - … and 4 more\n  - Fix: Fix the failing tests, or the code they test." in body
    assert (
        "- Every package and import is real: 1 import does not exist\n"
        "  - … and 1 more\n"
        "  - Fix: Remove the made-up import, or declare the real package that provides it."
    ) in body
    assert len(_visible(body)) < 60


def test_read_first_and_unchecked_lines_are_capped_with_counts():
    change_map = copy.deepcopy(CHANGE_MAP)
    many = [
        _symbol(f"app/m.py::f{n}", "app/m.py", f"f{n}", n * 10, "read_first", "Flagged.")
        for n in range(1, 12)
    ]
    change_map["symbols"] = many
    change_map["read_first"] = [s["id"] for s in many]
    change_map["review"]["counts"] = {"read_first": 11, "read": 2, "skim": 1, "skip": 4}
    change_map["coverage"]["not_mapped"] = []
    receipt = copy.deepcopy(RECEIPT)
    receipt["unverified"] = [{"file": "app/m.py", "line": n} for n in range(1, 14)]
    body = _post(
        SummaryInputs(done_requested=True, done_receipt=receipt, change_map=change_map)
    )
    assert body.count("- `app/m.py:") == MAX_READ_FIRST + MAX_UNCHECKED
    assert "- 5 more to read, 1 to skim, 4 proven unchanged, 0 file(s) not mapped" in body
    assert "- … and 3 more lines" in body
    assert "not traced" not in body


def test_run_url_needs_a_well_formed_repository_and_run_id():
    env = {
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "acme/app",
        "GITHUB_RUN_ID": "123",
    }
    assert run_url_from_env(env) == RUN_URL
    assert run_url_from_env({**env, "GITHUB_REPOSITORY": "acme/app/../evil"}) is None
    assert run_url_from_env({**env, "GITHUB_RUN_ID": ""}) is None
    assert run_url_from_env({**env, "GITHUB_SERVER_URL": "javascript:alert(1)"}) is None
    assert run_url_from_env({"GITHUB_REPOSITORY": "acme/app", "GITHUB_RUN_ID": "9"}) == (
        "https://github.com/acme/app/actions/runs/9"
    )


def _run_review(tmp_path, monkeypatch, argv):
    seen = {}
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    monkeypatch.setattr(
        review, "run_pr_review", lambda results, **kwargs: seen.update(results=results, **kwargs)
    )
    console = Mock()
    code = cicd_cmd.run_cicd_command(
        ["review", *argv],
        console_factory=lambda: console,
        load_config_func=lambda path: {},
        run_gate_interaction_func=Mock(),
        emit_github_annotations_func=Mock(),
    )
    printed = " ".join(str(call.args[0]) for call in console.print.call_args_list if call.args)
    return code, seen, printed


def test_review_reads_the_saved_files_and_tolerates_missing_ones(tmp_path, monkeypatch):
    (tmp_path / "receipt.json").write_text(json.dumps(RECEIPT))
    (tmp_path / "change-map.json").write_text(json.dumps(CHANGE_MAP))
    code, seen, printed = _run_review(
        tmp_path,
        monkeypatch,
        [
            "--input", str(tmp_path / "skylos-results.json"),
            "--gate-result", "failure",
            "--done-receipt", str(tmp_path / "receipt.json"),
            "--change-map", str(tmp_path / "change-map.json"),
            "--risk-review", str(tmp_path / "risk-review.json"),
        ],
    )
    assert code == 0
    assert seen["results"] == {}
    assert "No scan results" in printed
    inputs = seen["summary_inputs"]
    assert inputs.gate_result == "failure"
    assert inputs.gate_reasons == ()
    assert inputs.done_requested and inputs.done_receipt == RECEIPT
    assert inputs.change_map == CHANGE_MAP
    assert inputs.risk_requested and inputs.risk_review is None
    assert inputs.run_url is None

    code, seen, _ = _run_review(tmp_path, monkeypatch, ["--input", str(tmp_path / "missing.json")])
    assert code == 1
    assert "results" not in seen


def test_review_takes_the_gate_reasons_from_the_gate_itself(tmp_path, monkeypatch):
    import skylos.cicd.policy as policy
    import skylos.security.regression_gate as regression_gate

    results = {
        "project_root": str(tmp_path),
        "danger": [
            {
                "severity": "CRITICAL",
                "rule_id": "SKY-D212",
                "file": str(tmp_path / "app.py"),
                "line": 3,
                "message": "subprocess call with shell=True",
            }
        ],
    }
    (tmp_path / "skylos-results.json").write_text(json.dumps(results))
    monkeypatch.setattr(
        regression_gate, "recheck_control_regressions", lambda result, path, config: result
    )
    monkeypatch.setattr(policy, "base_policy_context", lambda path, ref: contextlib.nullcontext())
    code, seen, _ = _run_review(
        tmp_path,
        monkeypatch,
        ["--input", str(tmp_path / "skylos-results.json"), "--gate-result", "failure"],
    )
    assert code == 0
    assert seen["summary_inputs"].gate_reasons == ("1 critical security issue",)

    code, seen, _ = _run_review(
        tmp_path,
        monkeypatch,
        ["--input", str(tmp_path / "skylos-results.json"), "--gate-result", "success"],
    )
    assert seen["summary_inputs"].gate_reasons == ()
