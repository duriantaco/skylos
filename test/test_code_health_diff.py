"""Diff-scoped scans report size/complexity/style metrics as code health.

Plan 3.8b: on real agent commits most quality findings were metrics that the
change did not cause. In --diff/--diff-base scans they move to ``code_health``
(never counted, never gating); only metrics the change introduced or made
worse are listed. Full-repository scans are unchanged.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.rules.quality.code_health import (
    CODE_HEALTH_RULES,
    partition_code_health,
    resolve_merge_base,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _long_function(name, lines):
    body = "".join(f"    x{i} = {i}\n" for i in range(lines))
    return f"def {name}():\n{body}    return 0\n"


def _git(cwd, *args):
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        },
    )


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "app.py").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path
        _long_function("legacy", 70) + "\n\n" + _long_function("grows", 55),
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    # The change touches every function: legacy unchanged in size, grows gets
    # longer, fresh is new and long.
    (root / "app.py").write_text(  # skylos: ignore[SKY-D324] pytest tmp_path
        "# edited\n"
        + _long_function("legacy", 70)
        + "\n\n"
        + _long_function("grows", 80)
        + "\n\n"
        + _long_function("fresh", 60),
        encoding="utf-8",
    )
    return root


def _metric(name, value, file):
    return {
        "rule_id": "SKY-C304",
        "name": name,
        "value": value,
        "file": str(file),
        "line": 1,
    }


def test_partition_keeps_only_introduced_or_worsened(repo):
    result = {
        "quality": [
            _metric("legacy", 72, repo / "app.py"),
            _metric("grows", 82, repo / "app.py"),
            _metric("fresh", 62, repo / "app.py"),
            {"rule_id": "SKY-L007", "name": "x", "file": str(repo / "app.py"), "line": 3},
        ],
        "analysis_summary": {"quality_count": 4},
    }
    base = resolve_merge_base("HEAD", repo)
    out = partition_code_health(result, git_root=repo, base_commit=base)

    assert [f["rule_id"] for f in out["quality"]] == ["SKY-L007"]
    changes = {f["name"]: f["code_health_change"] for f in out["code_health"]}
    assert changes == {"grows": "worsened", "fresh": "introduced"}
    assert out["analysis_summary"]["code_health_preexisting_count"] == 1
    assert out["analysis_summary"]["quality_count"] == 1


def test_partition_without_base_marks_unverified(tmp_path):
    result = {"quality": [_metric("f", 60, tmp_path / "a.ts")]}
    out = partition_code_health(result, git_root=tmp_path, base_commit=None)
    assert out["quality"] == []
    assert out["code_health"][0]["code_health_change"] == "unverified"


def test_metric_rules_are_style_not_defect_rules():
    assert "SKY-C304" in CODE_HEALTH_RULES and "SKY-Q301" in CODE_HEALTH_RULES
    # Defect-class quality rules stay findings.
    assert not {"SKY-L007", "SKY-L009", "SKY-P401", "SKY-L006"} & CODE_HEALTH_RULES


def _scan(repo, *extra):
    proc = subprocess.run(
        [sys.executable, "-m", "skylos.entry", ".", "--quality", "--format", "json",
         "--no-upload", *extra],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT), "SKYLOS_NO_UPLOAD": "1"},
        timeout=300,
    )
    return proc, json.loads(proc.stdout)


def test_diff_base_scan_moves_metrics_and_does_not_gate(repo):
    proc, data = _scan(repo, "--diff-base", "HEAD")
    quality_rules = {f.get("rule_id") for f in data.get("quality", [])}
    assert not quality_rules & CODE_HEALTH_RULES
    names = {f.get("name") for f in data.get("code_health", []) if f["rule_id"] == "SKY-C304"}
    assert "legacy" not in names
    assert {"grows", "fresh"} <= names


def test_full_scan_still_reports_metrics_as_quality(repo):
    _proc, data = _scan(repo)
    rules = {f.get("rule_id") for f in data.get("quality", [])}
    assert "SKY-C304" in rules
    assert not data.get("code_health")


def test_diff_base_gate_is_not_failed_by_code_health(repo):
    proc, data = _scan(repo, "--diff-base", "HEAD", "--gate")
    assert data.get("code_health")
    assert proc.returncode == 0, proc.stderr[-2000:]
