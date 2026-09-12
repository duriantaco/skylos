from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from skylos.agents import center
from skylos.commands import review_cmd
from skylos.core import review_decisions


def test_watch_projects_reviewed_findings_before_building_actions(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def orphan():\n    return 1\n", encoding="utf-8")
    raw_result = {
        "unused_functions": [
            {
                "rule_id": "SKY-U001",
                "name": "orphan",
                "file": str(source),
                "line": 1,
                "confidence": 100,
            }
        ]
    }
    projected_result = {
        **raw_result,
        "unused_functions": [],
        "reviewed_findings": raw_result["unused_functions"],
    }

    with (
        patch(
            "skylos.agents.center.run_analyze",
            return_value=json.dumps(raw_result),
        ) as run_analyze,
        patch(
            "skylos.core.review_decisions.review_scan_requirements",
            return_value=(True, True),
        ),
        patch(
            "skylos.core.review_decisions.apply_trusted_review_decisions",
            return_value=projected_result,
        ) as apply_reviews,
        patch("skylos.agents.center.collect_debt_signals", return_value=[]),
    ):
        findings = center._run_refresh_analysis(
            tmp_path,
            conf=60,
            enable_secrets=True,
            enable_danger=True,
            enable_quality=True,
            enable_ai_defects=True,
            include_dead_code=True,
            use_baseline=False,
            changed_files=[],
        )

    assert findings == []
    assert run_analyze.call_args.kwargs["include_review_proofs"] is True
    apply_reviews.assert_called_once_with(raw_result, tmp_path)


def test_watch_rescans_when_only_review_state_changes(tmp_path):
    project = tmp_path / "repo"
    project.mkdir()
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")

    with (
        patch(
            "skylos.agents.center._current_review_state_revision",
            side_effect=["review:one", "review:two", "review:two"],
        ),
        patch(
            "skylos.agents.center._run_refresh_analysis",
            side_effect=[[], []],
        ) as analyze,
        patch(
            "skylos.agents.center._load_refresh_baselines",
            return_value=(None, None, set(), set()),
        ),
    ):
        first, first_updated = center.refresh_agent_state(
            project,
            force=True,
            use_baseline=False,
        )
        second, second_updated = center.refresh_agent_state(
            project,
            use_baseline=False,
        )
        reused, third_updated = center.refresh_agent_state(
            project,
            use_baseline=False,
        )

    assert first_updated is True
    assert first["review_state_revision"] == "review:one"
    assert second_updated is True
    assert second["review_state_revision"] == "review:two"
    assert third_updated is False
    assert reused == second
    assert analyze.call_count == 2


def test_triage_only_rebuild_preserves_review_state_revision(tmp_path):
    state = center.compose_agent_state(
        tmp_path,
        signatures={},
        findings=[],
        changed_files=[],
        baseline_present=False,
        review_state_revision="review:one",
    )

    rebuilt = center.rebuild_agent_state_from_existing(state, triage={})

    assert rebuilt["review_state_revision"] == "review:one"


def test_new_review_decision_invalidates_watch_without_a_source_change(
    tmp_path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    source = repo / "app.py"
    source.write_text("def orphan():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=skylos-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    cloud_cache = tmp_path / "reviewed-findings"
    local_cache = tmp_path / "local-review-decisions"
    monkeypatch.setattr(
        review_decisions,
        "_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else cloud_cache
        ),
    )
    monkeypatch.setattr(
        review_decisions,
        "_local_cache_root",
        lambda value=None: (
            Path(value).expanduser() if value is not None else local_cache
        ),
    )
    monkeypatch.delenv("CI", raising=False)
    for _provider, key in review_decisions._CI_RUN_KEYS:
        monkeypatch.delenv(key, raising=False)

    first, first_updated = center.refresh_agent_state(
        repo,
        conf=60,
        force=True,
        use_baseline=False,
    )
    first_signatures = first["file_signatures"]
    assert first_updated is True
    assert any(
        finding.get("message") == "Unused function: orphan"
        for finding in first["findings"]
    )
    assert first["review_state_revision"] is None

    def choose_dead(_console, findings, _input_fn):
        return next(
            finding
            for finding in findings
            if finding.get("_review_category") == "DEAD_CODE"
            and finding.get("symbol") == "orphan"
        )

    monkeypatch.setattr(review_cmd, "_choose_finding", choose_dead)
    answers = iter(["1", "registered runtime callback"])
    assert (
        review_cmd.run_review_command(
            [str(repo)],
            input_fn=lambda _prompt: next(answers),
            environ={},
        )
        == 0
    )

    second, second_updated = center.refresh_agent_state(
        repo,
        conf=60,
        use_baseline=False,
    )
    reused, third_updated = center.refresh_agent_state(
        repo,
        conf=60,
        use_baseline=False,
    )

    assert second_updated is True
    assert second["file_signatures"] == first_signatures
    assert second["review_state_revision"] is not None
    assert all(
        finding.get("message") != "Unused function: orphan"
        for finding in second["findings"]
    )
    assert all(
        action.get("message") != "Unused function: orphan"
        for action in second["actions"]
    )
    assert third_updated is False
    assert reused == second
    assert source.read_text(encoding="utf-8") == "def orphan():\n    return 1\n"
