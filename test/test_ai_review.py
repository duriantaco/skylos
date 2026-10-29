from types import SimpleNamespace
from unittest.mock import MagicMock

import skylos.api as api
from skylos.commands import scan_cmd
from skylos.llm import ai_review


def _votes(supported, refuted, uncertain):
    return {"supported": supported, "refuted": refuted, "uncertain": uncertain}


def _verdict(reviewer):
    return (reviewer or {}).get("verdict")


def test_every_reviewer_maps_to_one_verdict():
    def verdict(record):
        return _verdict(ai_review.reviewer_from_verification(record))

    assert (
        verdict({"level": "ai_verified", "runs": 3, "votes": _votes(2, 0, 1)}) == "real"
    )
    assert (
        verdict({"level": "refuted", "runs": 3, "votes": _votes(0, 3, 0)})
        == "false_positive"
    )
    assert (
        verdict({"level": "unverified", "runs": 3, "votes": _votes(1, 1, 1)})
        == "unsure"
    )
    assert (
        verdict(
            {"level": "traced", "runs": 3, "votes": _votes(0, 3, 0), "disputed": True}
        )
        == "false_positive"
    )
    assert verdict({"level": "traced", "runs": 3, "votes": _votes(3, 0, 0)}) == "real"
    assert verdict({"level": "made_up"}) is None

    def llm(value, **extra):
        return _verdict(
            ai_review.reviewer_from_llm({"_llm_verdict": value, **extra}, "gpt-4.1")
        )

    assert llm("TRUE_POSITIVE") == "real"
    assert llm("FALSE_POSITIVE") == "false_positive"
    assert llm("UNCERTAIN") == "unsure"
    assert llm("FALSE_POSITIVE", _verified_by_llm=False) is None

    def jev(**fields):
        return _verdict(ai_review.reviewer_from_jev(fields))

    assert jev(_jev_agreed=True, _jev_confidence=0.93) == "real"
    assert jev(_jev_judged_retained=True) == "false_positive"
    assert jev(_jev_status="disagreed") == "false_positive"
    assert jev(_jev_status="uncertain") == "unsure"
    assert jev(_jev_status="unavailable") is None


def test_dead_code_review_keeps_every_issue_and_only_adds_the_ai_review():
    used = {
        "name": "used_helper",
        "full_name": "app.used_helper",
        "file": "app.py",
        "line": 3,
    }
    dead = {
        "name": "old_report",
        "full_name": "app.old_report",
        "file": "app.py",
        "line": 9,
    }
    result = {"unused_functions": [used, dead], "definitions": {"app.used_helper": {}}}
    calls = []

    def fake_harness(**kwargs):
        calls.append(kwargs)
        first, second = kwargs["findings"]
        first.update(
            _llm_verdict="FALSE_POSITIVE",
            _llm_rationale="Called from a template",
            _suppressed=True,
        )
        second.update(
            _llm_verdict="TRUE_POSITIVE", _jev_agreed=True, _jev_confidence=0.9
        )
        return SimpleNamespace(
            output={
                "verified_findings": [first, second],
                "new_dead_code": [{"name": "extra"}],
            }
        )

    reviewed = ai_review.review_dead_code(
        result,
        project_root=".",
        model="gpt-4.1",
        api_key="k",
        provider="openai",
        base_url=None,
        use_llm=True,
        use_jev=True,
        run_harness=fake_harness,
    )

    assert reviewed == 2
    assert result["unused_functions"] == [used, dead]
    assert len(result["unused_functions"]) == 2
    assert used["metadata"]["ai_review"]["reviewers"] == [
        {
            "name": "llm",
            "verdict": "false_positive",
            "model": "gpt-4.1",
            "reason": "Called from a template",
        }
    ]
    assert [r["name"] for r in dead["metadata"]["ai_review"]["reviewers"]] == [
        "jev",
        "llm",
    ]
    for finding in (used, dead):
        assert not any(key.startswith("_") for key in finding)
    assert calls[0]["enable_survivor_challenge"] is False
    assert calls[0]["jev_precheck"] is True and calls[0]["jev_only"] is False
    assert ai_review.summarize_ai_reviews(result) == {
        "confirmed": 1,
        "disputed": 1,
        "unsure": 0,
    }


def test_ai_review_reaches_the_upload(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "get_git_info", lambda: ("0" * 40, "main", "tester", None))
    monkeypatch.setattr(api, "detect_ai_code", lambda *a, **k: {"detected": False})
    (tmp_path / "app.py").write_text("def old_report():\n    return 1\n")
    review = {
        "reviewers": [
            {"name": "jev", "verdict": "real", "model": "jev-1.13.0", "confidence": 0.9}
        ]
    }
    result = {
        "provenance": None,
        "project_root": "",
        "analysis_summary": {"project_root": ""},
        "unused_functions": [
            {
                "name": "old_report",
                "full_name": "app.old_report",
                "file": str(tmp_path / "app.py"),
                "line": 1,
                "confidence": 90,
                "metadata": {"ai_review": review},
            }
        ],
    }
    prepared = api._prepare_report_upload(result)
    sarif_results = prepared.core_payload["runs"][0]["results"]
    assert sarif_results[0]["properties"]["skylos_metadata"]["ai_review"] == review


def test_without_any_key_the_scan_is_untouched(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("skylos.llm.runtime.llm_extra_installed", lambda: True)
    monkeypatch.setattr(
        "skylos.llm.runtime.resolve_llm_runtime",
        lambda **kwargs: ("openai", None, None, False),
    )
    verify = MagicMock()
    monkeypatch.setattr(scan_cmd, "_verify_security_findings", verify)
    console = MagicMock()
    result = {
        "danger": [{"rule_id": "SKY-D211", "file": "a.py", "line": 1}],
        "unused_functions": [{"name": "f", "file": "a.py", "line": 2}],
    }
    before = repr(result)
    scan_cmd._run_ai_review(
        result,
        SimpleNamespace(model=None, verify_model=None, api_base=None),
        console,
        project_root=".",
        machine_output=False,
    )
    assert repr(result) == before
    verify.assert_not_called()
    assert "AI review skipped" in console.print.call_args[0][0]
