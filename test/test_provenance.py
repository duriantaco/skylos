import subprocess
from unittest.mock import patch

from skylos.provenance import (
    FileProvenance,
    ProvenanceReport,
    RiskIntersection,
    _detect_agent_name,
    _merge_ranges,
    _parse_diff_hunks,
    _resolve_base_ref,
    analyze_provenance,
    compute_risk_intersections,
)


def test_detect_agent_name_claude():
    assert _detect_agent_name("Claude <noreply@anthropic.com>") == "claude"


def test_detect_agent_name_copilot():
    assert _detect_agent_name("GitHub Copilot") == "copilot"


def test_detect_agent_name_cursor():
    assert _detect_agent_name("cursor-ai[bot]") == "cursor"


def test_detect_agent_name_devin():
    assert _detect_agent_name("Devin AI <devin@cognition.ai>") == "devin"


def test_detect_agent_name_unknown():
    assert _detect_agent_name("John Doe <john@example.com>") is None


def test_detect_agent_name_anthropic_maps_to_claude():
    assert _detect_agent_name("noreply@anthropic.com") == "claude"


def test_merge_ranges_empty():
    assert _merge_ranges([]) == []


def test_merge_ranges_single():
    assert _merge_ranges([(1, 10)]) == [(1, 10)]


def test_merge_ranges_non_overlapping():
    assert _merge_ranges([(1, 5), (10, 15)]) == [(1, 5), (10, 15)]


def test_merge_ranges_overlapping():
    assert _merge_ranges([(1, 10), (5, 15)]) == [(1, 15)]


def test_merge_ranges_adjacent():
    assert _merge_ranges([(1, 5), (6, 10)]) == [(1, 10)]


def test_merge_ranges_unsorted():
    assert _merge_ranges([(10, 20), (1, 5), (3, 12)]) == [(1, 20)]


def test_merge_ranges_contained():
    assert _merge_ranges([(1, 20), (5, 10)]) == [(1, 20)]


def test_parse_diff_hunks_basic():
    diff = """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,5 @@
 line1
+new_line
+another
 line3
"""
    result = _parse_diff_hunks(diff)
    assert "foo.py" in result
    assert result["foo.py"] == [(1, 5)]


def test_parse_diff_hunks_multiple_files():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -10,3 +10,7 @@
 old
+new
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1,2 +1,4 @@
 x
+y
"""
    result = _parse_diff_hunks(diff)
    assert "a.py" in result
    assert "b.py" in result
    assert result["a.py"] == [(10, 16)]
    assert result["b.py"] == [(1, 4)]


def test_parse_diff_hunks_multiple_hunks_same_file():
    diff = """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,5 @@
 line
+added
@@ -20,3 +22,6 @@
 old
+new
"""
    result = _parse_diff_hunks(diff)
    assert "foo.py" in result
    assert len(result["foo.py"]) == 2
    assert result["foo.py"][0] == (1, 5)
    assert result["foo.py"][1] == (22, 27)


def test_parse_diff_hunks_new_file():
    diff = """\
diff --git a/new.py b/new.py
--- /dev/null
+++ b/new.py
@@ -0,0 +1,10 @@
+line1
+line2
"""
    result = _parse_diff_hunks(diff)
    assert "new.py" in result
    assert result["new.py"] == [(1, 10)]


def test_parse_diff_hunks_deleted_file():
    diff = """\
diff --git a/old.py b/old.py
--- a/old.py
+++ /dev/null
@@ -1,5 +0,0 @@
-line1
-line2
"""
    result = _parse_diff_hunks(diff)
    assert "old.py" not in result


def test_parse_diff_hunks_single_line_hunk():
    diff = """\
diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -5,1 +5 @@
 unchanged
"""
    result = _parse_diff_hunks(diff)
    assert result["x.py"] == [(5, 5)]


def test_resolve_base_ref_explicit():
    assert _resolve_base_ref("origin/develop") == "origin/develop"


def test_resolve_base_ref_github_env(monkeypatch):
    monkeypatch.setenv("GITHUB_BASE_REF", "develop")
    assert _resolve_base_ref() == "origin/develop"


def test_resolve_base_ref_default(monkeypatch):
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    assert _resolve_base_ref() == "origin/main"


def test_file_provenance_defaults():
    fp = FileProvenance(file_path="foo.py")
    assert fp.agent_authored is False
    assert fp.agent_lines == []
    assert fp.indicators == []
    assert fp.agent_name is None


def test_provenance_report_to_dict():
    fp = FileProvenance(
        file_path="foo.py",
        agent_authored=True,
        agent_lines=[(1, 10)],
        indicators=[
            {
                "type": "co-author",
                "commit": "abc1234",
                "detail": "Claude",
                "agent_name": "claude",
            }
        ],
        agent_name="claude",
    )
    report = ProvenanceReport(
        files={"foo.py": fp},
        agent_files=["foo.py"],
        human_files=["bar.py"],
        summary={
            "total_files": 2,
            "agent_count": 1,
            "human_count": 1,
            "agents_seen": ["claude"],
        },
        confidence="medium",
    )
    d = report.to_dict()
    assert d["agent_files"] == ["foo.py"]
    assert d["human_files"] == ["bar.py"]
    assert d["confidence"] == "medium"
    assert d["files"]["foo.py"]["agent_authored"] is True
    assert d["files"]["foo.py"]["agent_lines"] == [(1, 10)]
    assert d["files"]["foo.py"]["agent_name"] == "claude"
    assert d["summary"]["agents_seen"] == ["claude"]


def test_provenance_report_empty_to_dict():
    report = ProvenanceReport()
    d = report.to_dict()
    assert d["files"] == {}
    assert d["agent_files"] == []
    assert d["human_files"] == []
    assert d["confidence"] == "low"


def test_analyze_provenance_no_git_root():
    report = analyze_provenance(None)
    assert report.agent_files == []
    assert report.confidence == "low"


GIT_LOG_OUTPUT = (
    "abc1234full|Alice|alice@example.com|Add feature|"
    "Claude <noreply@anthropic.com>\n"
    "def5678full|Bob|bob@example.com|Fix bug|\n"
)

DIFF_TREE_OUTPUT = """\
diff --git a/src/main.py b/src/main.py
--- a/src/main.py
+++ b/src/main.py
@@ -10,3 +10,8 @@
 old_line
+new_ai_line
"""

DIFF_NAME_ONLY = "src/main.py\nREADME.md\n"

MERGE_BASE = "merge_base_sha\n"


def _mock_check_output(cmd, **kwargs):
    cmd_str = " ".join(cmd)
    if "merge-base" in cmd_str:
        return MERGE_BASE.encode()
    if "git log" in cmd_str:
        return GIT_LOG_OUTPUT.encode()
    if "diff-tree" in cmd_str:
        return DIFF_TREE_OUTPUT.encode()
    if "diff" in cmd_str and "--name-only" in cmd_str:
        return DIFF_NAME_ONLY.encode()
    return b""


def test_analyze_provenance_detects_ai_commit():
    with patch("subprocess.check_output", side_effect=_mock_check_output):
        report = analyze_provenance("/fake/repo", base_ref="origin/main")

    assert "src/main.py" in report.agent_files
    assert "README.md" in report.human_files
    assert report.confidence == "medium"
    assert "claude" in report.summary["agents_seen"]
    assert report.files["src/main.py"].agent_authored is True
    assert report.files["src/main.py"].agent_name == "claude"
    assert report.files["src/main.py"].agent_lines == [(10, 17)]


def test_analyze_provenance_no_ai_commits():
    log_no_ai = "abc1234full|Alice|alice@example.com|Normal commit|\n"
    diff_names = "foo.py\n"

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            return log_no_ai.encode()
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return diff_names.encode()
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert report.agent_files == []
    assert "foo.py" in report.human_files
    assert report.confidence == "low"


def test_analyze_provenance_email_detection():
    log = "abc1234full|copilot[bot]|copilot[bot]@users.noreply.github.com|Auto-fix|\n"
    diff_tree = """\
diff --git a/fix.py b/fix.py
--- a/fix.py
+++ b/fix.py
@@ -1,1 +1,3 @@
+autofix
"""
    diff_names = "fix.py\n"

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            return log.encode()
        if "diff-tree" in cmd_str:
            return diff_tree.encode()
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return diff_names.encode()
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert "fix.py" in report.agent_files
    assert report.files["fix.py"].agent_name == "copilot"


def test_analyze_provenance_message_detection():
    log = "abc1234full|Dev|dev@co.com|AI-generated code for module|\n"
    diff_tree = """\
diff --git a/gen.py b/gen.py
--- a/gen.py
+++ b/gen.py
@@ -1,1 +1,5 @@
+generated
"""
    diff_names = "gen.py\n"

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            return log.encode()
        if "diff-tree" in cmd_str:
            return diff_tree.encode()
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return diff_names.encode()
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert "gen.py" in report.agent_files


def test_analyze_provenance_merge_base_fallback():
    """When merge-base fails, falls back to HEAD~10."""

    call_log = []

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        call_log.append(cmd_str)
        if "merge-base" in cmd_str:
            raise subprocess.CalledProcessError(1, cmd)
        if "git log" in cmd_str:
            assert "HEAD~10..HEAD" in cmd_str
            return b""
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return b""
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert report.agent_files == []


def test_analyze_provenance_git_log_failure():
    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            raise subprocess.CalledProcessError(1, cmd)
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert report.agent_files == []
    assert report.confidence == "low"


def test_analyze_provenance_multiple_agents():
    log = (
        "abc1234full|Dev|dev@co.com|Add feature|Claude <noreply@anthropic.com>\n"
        "def5678full|copilot[bot]|copilot[bot]@noreply.github.com|Auto fix|\n"
    )
    diff_tree_abc = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,1 +1,3 @@
+code
"""
    diff_tree_def = """\
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,1 +5,4 @@
+fix
"""
    diff_names = "a.py\nb.py\n"

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            return log.encode()
        if "diff-tree" in cmd_str:
            if "abc1234full" in cmd_str:
                return diff_tree_abc.encode()
            if "def5678full" in cmd_str:
                return diff_tree_def.encode()
            return b""
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return diff_names.encode()
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert sorted(report.agent_files) == ["a.py", "b.py"]
    assert "claude" in report.summary["agents_seen"]
    assert "copilot" in report.summary["agents_seen"]
    assert report.files["a.py"].agent_name == "claude"
    assert report.files["b.py"].agent_name == "copilot"


def test_analyze_provenance_high_confidence():
    """Many indicators should produce high confidence."""
    lines = []
    for i in range(10):
        sha = f"sha{i:04d}full"
        lines.append(f"{sha}|Dev|dev@co.com|Change {i}|Claude <noreply@anthropic.com>")
    log = "\n".join(lines) + "\n"

    diff_template = """\
diff --git a/f{i}.py b/f{i}.py
--- a/f{i}.py
+++ b/f{i}.py
@@ -1,1 +1,2 @@
+code
"""
    diff_names = "\n".join(f"f{i}.py" for i in range(10)) + "\n"

    def mock_output(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "merge-base" in cmd_str:
            return MERGE_BASE.encode()
        if "git log" in cmd_str:
            return log.encode()
        if "diff-tree" in cmd_str:
            for i in range(10):
                sha = f"sha{i:04d}full"
                if sha in cmd_str:
                    return diff_template.format(i=i).encode()
            return b""
        if "diff" in cmd_str and "--name-only" in cmd_str:
            return diff_names.encode()
        return b""

    with patch("subprocess.check_output", side_effect=mock_output):
        report = analyze_provenance("/fake/repo")

    assert report.confidence == "high"


def test_risk_intersection_to_dict():
    ri = RiskIntersection(
        high_risk=[
            {
                "file_path": "a.py",
                "agent_name": "claude",
                "reasons": [
                    "ai_authored",
                    "has_llm_integration",
                    "failed_defense_check",
                ],
            }
        ],
        medium_risk=[
            {
                "file_path": "b.py",
                "agent_name": "copilot",
                "reasons": ["ai_authored", "has_llm_integration"],
            }
        ],
        summary={"high": 1, "medium": 1, "total_ai_files": 3},
    )
    d = ri.to_dict()
    assert len(d["high_risk"]) == 1
    assert len(d["medium_risk"]) == 1
    assert d["summary"]["high"] == 1


def test_risk_intersection_empty():
    ri = RiskIntersection(summary={"high": 0, "medium": 0, "total_ai_files": 0})
    d = ri.to_dict()
    assert d["high_risk"] == []
    assert d["medium_risk"] == []


def _make_provenance_report(agent_files_dict):
    files = {}
    agent_files = []
    for fpath, agent_name in agent_files_dict.items():
        files[fpath] = FileProvenance(
            file_path=fpath,
            agent_authored=True,
            agent_lines=[(1, 10)],
            indicators=[],
            agent_name=agent_name,
        )
        agent_files.append(fpath)
    return ProvenanceReport(
        files=files,
        agent_files=sorted(agent_files),
        human_files=[],
        summary={
            "total_files": len(agent_files),
            "agent_count": len(agent_files),
            "human_count": 0,
            "agents_seen": [],
        },
        confidence="medium",
    )


def test_compute_risk_no_ai_files():
    report = ProvenanceReport()
    result = compute_risk_intersections("/fake", report)
    assert result.high_risk == []
    assert result.medium_risk == []
    assert result.summary["total_ai_files"] == 0


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_compute_risk_no_overlap(mock_detect, mock_defense):
    """AI files exist but no LLM integrations or defense failures → no risk."""
    from skylos.defend.result import DefenseScore, OpsScore

    mock_detect.return_value = ([], None)
    mock_defense.return_value = (
        [],
        DefenseScore(
            weighted_score=0,
            weighted_max=0,
            passed=0,
            total=0,
            score_pct=100,
            risk_rating="minimal",
        ),
        OpsScore(passed=0, total=0, score_pct=100, rating="good"),
    )

    report = _make_provenance_report({"src/clean.py": "claude"})
    result = compute_risk_intersections("/fake", report)

    assert result.high_risk == []
    assert result.medium_risk == []
    assert result.summary["total_ai_files"] == 1


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_compute_risk_medium_integration_only(mock_detect, mock_defense):
    """AI file has LLM integration but defense passes → medium risk."""
    from skylos.discover.integration import LLMIntegration
    from skylos.defend.result import DefenseScore, OpsScore

    integration = LLMIntegration(
        provider="openai", location="/fake/src/api.py:10", integration_type="chat"
    )
    mock_detect.return_value = ([integration], None)
    mock_defense.return_value = (
        [],
        DefenseScore(
            weighted_score=10,
            weighted_max=10,
            passed=5,
            total=5,
            score_pct=100,
            risk_rating="minimal",
        ),
        OpsScore(passed=0, total=0, score_pct=100, rating="good"),
    )

    report = _make_provenance_report({"src/api.py": "claude"})
    result = compute_risk_intersections("/fake", report)

    assert result.high_risk == []
    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/api.py"
    assert "has_llm_integration" in result.medium_risk[0]["reasons"]


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_compute_risk_medium_defense_only(mock_detect, mock_defense):
    """AI file has failed defense but no integration → medium risk."""
    from skylos.defend.result import DefenseResult, DefenseScore, OpsScore

    mock_detect.return_value = ([], None)
    failed = DefenseResult(
        plugin_id="input-validation",
        passed=False,
        integration_location="/fake/src/handler.py:5",
        location="/fake/src/handler.py:5",
        message="No input validation",
        severity="high",
        weight=3,
        category="defense",
    )
    mock_defense.return_value = (
        [failed],
        DefenseScore(
            weighted_score=0,
            weighted_max=3,
            passed=0,
            total=1,
            score_pct=0,
            risk_rating="critical",
        ),
        OpsScore(passed=0, total=0, score_pct=100, rating="good"),
    )

    report = _make_provenance_report({"src/handler.py": "copilot"})
    result = compute_risk_intersections("/fake", report)

    assert result.high_risk == []
    assert len(result.medium_risk) == 1
    assert "failed_defense_check" in result.medium_risk[0]["reasons"]


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_compute_risk_high(mock_detect, mock_defense):
    """AI file has both integration AND failed defense → high risk."""
    from skylos.discover.integration import LLMIntegration
    from skylos.defend.result import DefenseResult, DefenseScore, OpsScore

    integration = LLMIntegration(
        provider="openai", location="/fake/src/agent.py:20", integration_type="chat"
    )
    failed = DefenseResult(
        plugin_id="input-validation",
        passed=False,
        integration_location="/fake/src/agent.py:20",
        location="/fake/src/agent.py:20",
        message="No input validation",
        severity="high",
        weight=3,
        category="defense",
    )
    mock_detect.return_value = ([integration], None)
    mock_defense.return_value = (
        [failed],
        DefenseScore(
            weighted_score=0,
            weighted_max=3,
            passed=0,
            total=1,
            score_pct=0,
            risk_rating="critical",
        ),
        OpsScore(passed=0, total=0, score_pct=100, rating="good"),
    )

    report = _make_provenance_report({"src/agent.py": "claude"})
    result = compute_risk_intersections("/fake", report)

    assert len(result.high_risk) == 1
    assert result.high_risk[0]["file_path"] == "src/agent.py"
    assert result.high_risk[0]["agent_name"] == "claude"
    assert "has_llm_integration" in result.high_risk[0]["reasons"]
    assert "failed_defense_check" in result.high_risk[0]["reasons"]
    assert result.medium_risk == []
    assert result.summary["high"] == 1


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_compute_risk_mixed(mock_detect, mock_defense):
    """Multiple AI files: one high, one medium, one clean."""
    from skylos.discover.integration import LLMIntegration
    from skylos.defend.result import DefenseResult, DefenseScore, OpsScore

    integrations = [
        LLMIntegration(
            provider="openai", location="/fake/src/a.py:10", integration_type="chat"
        ),
        LLMIntegration(
            provider="anthropic",
            location="/fake/src/b.py:5",
            integration_type="completion",
        ),
    ]
    failed = DefenseResult(
        plugin_id="input-validation",
        passed=False,
        integration_location="/fake/src/a.py:10",
        location="/fake/src/a.py:10",
        message="Missing validation",
        severity="high",
        weight=3,
        category="defense",
    )
    mock_detect.return_value = (integrations, None)
    mock_defense.return_value = (
        [failed],
        DefenseScore(
            weighted_score=0,
            weighted_max=3,
            passed=0,
            total=1,
            score_pct=0,
            risk_rating="critical",
        ),
        OpsScore(passed=0, total=0, score_pct=100, rating="good"),
    )

    report = _make_provenance_report(
        {
            "src/a.py": "claude",
            "src/b.py": "copilot",
            "src/c.py": "cursor",
        }
    )
    result = compute_risk_intersections("/fake", report)

    assert len(result.high_risk) == 1
    assert result.high_risk[0]["file_path"] == "src/a.py"
    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/b.py"
    assert result.summary["high"] == 1
    assert result.summary["medium"] == 1
    assert result.summary["total_ai_files"] == 3
