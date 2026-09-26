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
