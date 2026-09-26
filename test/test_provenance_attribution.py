"""Attribution rules: only explicit agent signals count as AI; bots are automation."""

import shutil
import subprocess
from unittest.mock import patch

import pytest

from skylos.api._ai_detection import detect_ai_code
from skylos.reporting.provenance import (
    ATTRIBUTION_AI,
    ATTRIBUTION_AUTOMATION,
    analyze_provenance,
    classify_commit,
)


def _cat(result):
    return None if result is None else result["category"]


# --- classify_commit ---------------------------------------------------------


def test_human_named_claude_is_not_ai():
    assert classify_commit("Claude Monet", "claude@monet.fr", "Paint", "") is None
    assert (
        classify_commit("Claudette", "claudette.dev@gmail.com", "Fix claude bug", "")
        is None
    )


def test_human_named_claude_coauthor_trailer_is_not_ai():
    trailers = "Co-authored-by: Claude Dupont <claude.dupont@example.org>"
    assert classify_commit("Alice", "alice@example.com", "Pair", trailers) is None


def test_dependabot_is_automation_not_ai():
    r = classify_commit(
        "dependabot[bot]",
        "49699333+dependabot[bot]@users.noreply.github.com",
        "Bump requests from 2.31.0 to 2.32.0",
        "Signed-off-by: dependabot[bot] <support@github.com>",
    )
    assert _cat(r) == ATTRIBUTION_AUTOMATION
    assert r["agent_name"] == "dependabot"


def test_renovate_is_automation_not_ai():
    r = classify_commit(
        "renovate[bot]",
        "29139614+renovate[bot]@users.noreply.github.com",
        "chore(deps): update dependency ruff to v0.6",
        "",
    )
    assert _cat(r) == ATTRIBUTION_AUTOMATION
    assert r["agent_name"] == "renovate"
    r = classify_commit("Renovate Bot", "bot@renovateapp.com", "Update deps", "")
    assert _cat(r) == ATTRIBUTION_AUTOMATION


def test_github_actions_is_automation_not_ai():
    r = classify_commit(
        "github-actions[bot]",
        "41898282+github-actions[bot]@users.noreply.github.com",
        "chore(main): release 1.2.3",
        "",
    )
    assert _cat(r) == ATTRIBUTION_AUTOMATION
    assert r["agent_name"] == "github-actions"
    r = classify_commit("GitHub Action", "action@github.com", "Update docs", "")
    assert _cat(r) == ATTRIBUTION_AUTOMATION


def test_github_actions_coauthor_trailer_is_not_ai():
    trailers = (
        "Co-authored-by: github-actions[bot] "
        "<41898282+github-actions[bot]@users.noreply.github.com>"
    )
    assert classify_commit("Alice", "alice@example.com", "Merge", trailers) is None


def test_noreply_github_web_commit_is_human():
    # Web-UI commits: author is the user's noreply, committer noreply@github.com.
    assert (
        classify_commit(
            "Jane Dev", "1234567+janedev@users.noreply.github.com", "Update README", ""
        )
        is None
    )
    assert classify_commit("Jane Dev", "noreply@github.com", "Edit file", "") is None


def test_claude_code_trailer_is_ai():
    trailers = "Co-authored-by: Claude Opus 4.5 <noreply@anthropic.com>"
    r = classify_commit("Alice", "alice@example.com", "Add feature", trailers)
    assert _cat(r) == ATTRIBUTION_AI
    assert r["agent_name"] == "claude"
    assert r["type"] == "co-author"


def test_claude_code_trailer_among_other_trailers():
    trailers = (
        "Signed-off-by: Alice <alice@example.com>\x1f"
        "Co-Authored-By: Claude <noreply@anthropic.com>"
    )
    r = classify_commit("Alice", "alice@example.com", "Add feature", trailers)
    assert r["agent_name"] == "claude"


def test_legacy_value_only_trailer_still_supported():
    r = classify_commit(
        "Alice", "alice@example.com", "x", "Claude <noreply@anthropic.com>"
    )
    assert r["agent_name"] == "claude"


def test_copilot_agent_bot_is_ai():
    r = classify_commit(
        "copilot-swe-agent[bot]",
        "198982749+Copilot@users.noreply.github.com",
        "Fix flaky test",
        "",
    )
    assert _cat(r) == ATTRIBUTION_AI
    assert r["agent_name"] == "copilot"
    r = classify_commit(
        "Alice",
        "alice@example.com",
        "Fix",
        "Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>",
    )
    assert r["agent_name"] == "copilot"


def test_cursor_trailer_is_ai():
    r = classify_commit(
        "Alice",
        "alice@example.com",
        "Refactor",
        "Co-authored-by: Cursor Agent <cursoragent@cursor.com>",
    )
    assert _cat(r) == ATTRIBUTION_AI
    assert r["agent_name"] == "cursor"


def test_devin_bot_and_aider_are_ai():
    r = classify_commit(
        "devin-ai-integration[bot]",
        "158243242+devin-ai-integration[bot]@users.noreply.github.com",
        "Implement",
        "",
    )
    assert r["agent_name"] == "devin"
    r = classify_commit(
        "Alice",
        "alice@example.com",
        "x",
        "Co-authored-by: aider (gpt-4o) <noreply@aider.chat>",
    )
    assert r["agent_name"] == "aider"
    r = classify_commit("Alice (aider)", "alice@example.com", "x", "")
    assert r["agent_name"] == "aider"


def test_explicit_ai_declaration_trailer_is_ai():
    r = classify_commit(
        "Alice", "alice@example.com", "x", "Assisted-by: Claude:claude-opus-4-5"
    )
    assert _cat(r) == ATTRIBUTION_AI
    assert r["type"] == "ai-trailer"
    assert r["agent_name"] == "claude"


def test_employee_email_at_agent_vendor_is_not_ai():
    assert classify_commit("Bob", "bob@anthropic.com", "Fix", "") is None
    assert classify_commit("Eve", "eve@cursor.com", "Fix", "") is None


def test_generic_ai_generated_subject_is_not_ai():
    assert classify_commit("A", "a@x.io", "Remove AI-generated boilerplate", "") is None
    r = classify_commit("A", "a@x.io", "Generated with Claude Code", "")
    assert r["agent_name"] == "claude"


# --- analyze_provenance end to end (mocked git) ------------------------------


def _mock_git(log_output, diffs, names):
    def _mock(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return b"base\n"
        if " log " in cmd_str:
            return log_output.encode()
        if "diff-tree" in cmd_str:
            for sha, diff in diffs.items():
                if sha in cmd_str:
                    return diff.encode()
            return b""
        if "--name-only" in cmd_str:
            return names.encode()
        return b""

    return _mock


def _diff(path, start=1, count=2):
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        f"@@ -{start},1 +{start},{count} @@\n+x\n"
    )


def test_analyze_provenance_separates_automation_from_ai():
    log = (
        "aaa1111full|dependabot[bot]|49699333+dependabot[bot]@users.noreply.github.com"
        "|Bump x|\n"
        "bbb2222full|Claude Smith|claude.smith@corp.com|Human work|\n"
        "ccc3333full|Alice|alice@corp.com|Agent work|"
        "Co-authored-by: Claude <noreply@anthropic.com>\n"
    )
    diffs = {
        "aaa1111full": _diff("requirements.txt"),
        "ccc3333full": _diff("app.py", 5, 3),
    }
    names = "requirements.txt\napp.py\nhuman.py\n"
    with patch("subprocess.check_output", side_effect=_mock_git(log, diffs, names)):
        report = analyze_provenance("/fake", base_ref="origin/main")

    assert report.agent_files == ["app.py"]
    assert report.summary["agents_seen"] == ["claude"]
    assert report.automation_files == ["requirements.txt"]
    assert report.summary["automation_seen"] == ["dependabot"]
    # Human, AI and automation buckets are disjoint.
    assert report.human_files == ["human.py"]
    assert report.summary["human_count"] == 1
    assert report.summary["agent_count"] == 1
    assert report.summary["automation_count"] == 1
    assert (
        report.summary["human_count"]
        + report.summary["agent_count"]
        + report.summary["automation_count"]
        == report.summary["total_files"]
    )
    assert report.files["requirements.txt"].agent_authored is False
    assert report.files["requirements.txt"].automation_name == "dependabot"
    d = report.to_dict()
    assert d["automation_files"] == ["requirements.txt"]
    assert d["files"]["requirements.txt"]["automation_authored"] is True
    # Backwards-compatible keys still present.
    for key in ("files", "agent_files", "human_files", "summary", "confidence"):
        assert key in d


def test_detect_ai_code_ignores_bots_and_claude_named_humans():
    log = (
        "aaa1111full|renovate[bot]|29139614+renovate[bot]@users.noreply.github.com"
        "|Update deps|\n"
        "bbb2222full|Claude Smith|claude@smith.dev|Work|\n"
        "ccc3333full|Web|noreply@github.com|Edit|\n"
    )
    with patch("subprocess.check_output", return_value=log.encode()):
        result = detect_ai_code("/fake")
    assert result["detected"] is False
    assert result["indicators"] == []


# --- real git: verify the trailer format string works -----------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_real_git_trailer_parsing(tmp_path):
    def git(*args, env=None):
        subprocess.run(
            ["git", *args], cwd=tmp_path, check=True, capture_output=True, env=env
        )

    import os

    base_env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }

    def commit(path, msg, name, email):
        (tmp_path / path).write_text(msg + "\n")
        env = {
            **base_env,
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
        }
        git("add", path, env=env)
        git("commit", "-q", "-m", msg, env=env)

    git("init", "-q", "-b", "main", env=base_env)
    commit("base.txt", "base", "Alice", "alice@example.com")
    git("branch", "base", env=base_env)
    commit(
        "agent.py",
        "Add agent code\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>",
        "Alice",
        "alice@example.com",
    )
    commit(
        "deps.txt",
        "Bump deps",
        "dependabot[bot]",
        "49699333+dependabot[bot]@users.noreply.github.com",
    )
    commit("human.py", "Human change", "Claude Monet", "claude@monet.fr")

    report = analyze_provenance(str(tmp_path), base_ref="base")
    assert report.agent_files == ["agent.py"]
    assert report.automation_files == ["deps.txt"]
    assert report.human_files == ["human.py"]
    assert "deps.txt" not in report.human_files
    assert report.summary["human_count"] == 1
    assert report.summary["agents_seen"] == ["claude"]


def test_declaration_trailers_need_agent_unless_ai_key():
    assert classify_commit("A", "a@x.io", "x", "Assisted-by: Bob <bob@x.io>") is None
    assert classify_commit("A", "a@x.io", "x", "Generated-by: protoc 3.21") is None
    r = classify_commit("A", "a@x.io", "x", "AI-Agent: in-house-bot")
    assert r["category"] == ATTRIBUTION_AI and r["agent_name"] is None
