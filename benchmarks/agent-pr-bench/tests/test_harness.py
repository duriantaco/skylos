"""Offline tests for the agent-pr-bench harness (no tools, no network).

Run: python3 -m pytest benchmarks/agent-pr-bench/tests -q
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from harness import corpus, score, tools  # noqa: E402


def test_unified_zero_parser_handles_additions_and_pure_deletions():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -3,0 +4,2 @@\n+x\n+y\n"
        "@@ -10 +11,0 @@\n-gone\n"
        "diff --git a/b.py b/b.py\ndeleted file mode 100644\n--- a/b.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-z\n"
    )
    changed = corpus.parse_unified_zero(diff)
    assert changed == {"a.py": {4, 5, 11, 12}}


def test_changed_new_lines_marks_insertions_and_deletion_neighbours():
    before = ["a", "b", "c", "d"]
    after = ["a", "NEW", "b", "d"]
    lines, added = corpus.changed_new_lines(before, after)
    assert 2 in lines  # inserted
    assert {3, 4} & lines  # neighbours of deleted "c"
    assert added == 1


def test_every_seeded_case_is_well_formed():
    bases = corpus.load_bases()
    for case in corpus.load_cases():
        assert case["base"] in bases, case["id"]
        assert case["language"] in {"python", "typescript"}, case["id"]
        assert case.get("story"), case["id"]
        if case.get("clean"):
            assert not case.get("defects"), case["id"]
        else:
            assert case["defects"], case["id"]
            for d in case["defects"]:
                assert d["category"] in {
                    "auth_removed", "dead_code", "hallucinated_api", "hallucinated_import",
                    "hallucinated_package", "injection", "insecure_config", "secret", "weakened_test",
                }, (case["id"], d["category"])
                assert d["locations"] and all(loc.get("anchor") for loc in d["locations"])


def test_materialized_secrets_are_not_stored_verbatim():
    for path in sorted((corpus.SEEDED_DIR / "cases").glob("*.toml")):
        case = tomllib.loads(path.read_text())
        for parts in (case.get("materialize") or {}).values():
            assert "".join(parts) not in path.read_text()


def test_sonar_payload_normalization():
    # Hand-written to the documented api/issues/search and api/hotspots/search
    # response shapes (not captured from a live server).
    payload = {
        "issues": [
            {"rule": "pythonsecurity:S3649", "component": "k:app/db.py", "line": 12,
             "textRange": {"startLine": 12, "endLine": 13}, "severity": "BLOCKER",
             "type": "VULNERABILITY", "message": "Change this code to not construct SQL queries directly from user-controlled data."},
            {"rule": "secrets:S6290", "component": "k:config.py", "line": 3, "type": "VULNERABILITY",
             "severity": "BLOCKER", "message": "Make sure this AWS Secret Access Key gets revoked."},
            {"rule": "python:S1481", "component": "k:app/x.py", "textRange": {"startLine": 7, "endLine": 7},
             "type": "CODE_SMELL", "impacts": [{"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}],
             "message": "Remove the unused local variable \"a\"."},
        ],
        "hotspots": [
            {"ruleKey": "python:S4507", "component": "k:app/__init__.py", "line": 5,
             "vulnerabilityProbability": "LOW", "message": "Make sure this debug feature is deactivated before delivering the code in production."},
        ],
    }
    out = tools.Sonar.normalize_payload(payload)
    assert [(f["file"], f["line"], f["category"]) for f in out] == [
        ("app/db.py", 12, "security"),
        ("config.py", 3, "secret"),
        ("app/x.py", 7, "quality"),
        ("app/__init__.py", 5, "security"),
    ]
    assert out[0]["end_line"] == 13
    assert out[2]["severity"] == "MAINTAINABILITY:LOW"


def test_wilson_interval_bounds():
    lo, hi = score.wilson(0, 10)
    assert lo == 0.0 and 0.25 < hi < 0.35
    assert score.wilson(0, 0) is None


def test_semgrep_category_mapping():
    assert tools._short_semgrep_id("tmp.x.semgrep-rules.python.lang.a.b") == "python.lang.a.b"
    assert tools.Semgrep._category("generic.secrets.security.detected-aws-access-key-id-value", {}) == "secret"
    assert tools.Semgrep._category("python.lang.security.audit.eval-detected", {"category": "security"}) == "security"
    assert tools.Semgrep._category("python.lang.correctness.useless-eqeq", {"category": "correctness"}) == "quality"


def test_skylos_hook_normalize_keeps_only_blocking_findings(tmp_path):
    import json

    raw = tmp_path / "ws.json"
    raw.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": "app.py",
                        "status": "checked",
                        "exit_code": 0,
                        "wall_s": 2.5,
                        "seconds": 2.1,
                        "findings": [
                            {"rule_id": "SKY-S101", "line": 3, "severity": "CRITICAL", "message": "key",
                             "category": "secret", "blocking": True, "why": "secret"},
                            {"rule_id": "SKY-D211", "line": 9, "severity": "HIGH", "message": "path",
                             "category": "security", "blocking": False, "why": "note"},
                            {"rule_id": "SKY-L021", "line": 9, "severity": "HIGH", "message": "guard removed",
                             "category": "quality", "blocking": True, "why": "security-regression",
                             "file_level": True},
                        ],
                    },
                    {"file": "notes.md", "status": "skipped", "exit_code": 0, "wall_s": 0.4, "seconds": 0.1,
                     "findings": []},
                ]
            }
        )
    )
    ws = corpus.Workspace(
        id="w", kind="real", language="python", path=tmp_path, diff_base="HEAD~1",
        changed_lines={"app.py": {3, 9}}, changed_files=["app.py", "notes.md"], added_source_lines=2,
    )
    rec = tools.RunRecord("skylos-hook", "w", "ok", 0, 2.9, [], str(raw))
    findings, signals = tools.SkylosHook(HERE.parents[1]).normalize(rec, ws)
    assert [(f["rule"], f["file"], f["line"], f["category"]) for f in findings] == [
        ("SKY-S101", "app.py", 3, "secret"),
        ("SKY-L021", "app.py", 9, "quality"),
    ]
    assert signals["notes"] == 1
    assert (signals["files_checked"], signals["files_skipped"]) == (1, 1)
    assert signals["wall_s"] == [2.5]


def test_hook_ranges_spec_merges_consecutive_lines():
    assert tools.SkylosHook.ranges_spec({3, 4, 5, 9, 11, 12}) == "3-5,9-9,11-12"


def test_hook_findings_reuse_the_scan_labels():
    ws = corpus.Workspace(
        id="w", kind="real", language="python", path=Path("/nonexistent"), diff_base="x",
        changed_lines={"app.py": {3}}, changed_files=["app.py"], added_source_lines=1,
    )
    finding = {"tool": "skylos-hook", "rule": "SKY-S101", "file": "app.py", "line": 3, "end_line": 3,
               "severity": "CRITICAL", "category": "secret", "message": "key"}
    labels = {score.fingerprint("w", {**finding, "tool": "skylos"}): {"verdict": "tp", "reason": "real key"}}
    report = score.build_report(
        [ws], {("skylos-hook", "w"): {"status": "ok", "wall_s": 2.0}},
        {("skylos-hook", "w"): ([finding], {})}, labels, ["skylos-hook"],
    )
    precision = report["real"]["precision"]["skylos-hook"]["ALL"]
    assert (precision["total"], precision["unlabeled"]) == (1, 0)
    unaliased = score.build_report(
        [ws], {("skylos-hook", "w"): {"status": "ok", "wall_s": 2.0}},
        {("skylos-hook", "w"): ([{**finding, "rule": "SKY-S102"}], {})}, labels, ["skylos-hook"],
    )
    assert unaliased["real"]["precision"]["skylos-hook"]["ALL"]["unlabeled"] == 1
