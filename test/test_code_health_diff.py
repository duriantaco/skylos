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

from skylos.core.safe_cache_io import write_text_no_symlink
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
    # strict needs a selection: mypy with neither targets nor files checks
    # nothing, so without files = [...] the annotation scope is unknown.
    assert write_text_no_symlink(
        root / "pyproject.toml",
        '[tool.mypy]\nstrict = true\nfiles = ["app.py"]\n', encoding="utf-8"
    )
    assert write_text_no_symlink(
        root / "app.py",
        _long_function("legacy", 70) + "\n\n" + _long_function("grows", 55),
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    # The change touches every function: legacy unchanged in size, grows gets
    # longer, fresh is new and long.
    assert write_text_no_symlink(
        root / "app.py",
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
            {"rule_id": "SKY-T102", "name": "legacy", "value": 1,
             "file": str(repo / "app.py"), "line": 2},
            {"rule_id": "SKY-L007", "name": "x", "file": str(repo / "app.py"), "line": 3},
        ],
        "analysis_summary": {"quality_count": 5},
    }
    base = resolve_merge_base("HEAD", repo)
    out = partition_code_health(result, git_root=repo, base_commit=base)

    assert [f["rule_id"] for f in out["quality"]] == ["SKY-L007"]
    changes = {f["name"]: f["code_health_change"] for f in out["code_health"]}
    assert changes == {"grows": "worsened", "fresh": "introduced"}
    assert out["analysis_summary"]["code_health_preexisting_count"] == 2
    assert out["analysis_summary"]["quality_count"] == 1


def test_partition_without_base_marks_unverified(tmp_path):
    result = {"quality": [_metric("f", 60, tmp_path / "a.ts")]}
    out = partition_code_health(result, git_root=tmp_path, base_commit=None)
    assert out["quality"] == []
    assert out["code_health"][0]["code_health_change"] == "unverified"


def test_diff_partition_omits_full_project_architecture_advisories(tmp_path):
    result = {
        "quality": [],
        "architecture_metrics": {
            "module_metrics": {"shared": {"distance": 1.0}},
            "advisories": [
                {
                    "name": "shared",
                    "rule_ids": ["SKY-Q802", "SKY-Q803"],
                    "signals": [{"rule_id": "SKY-Q802"}, {"rule_id": "SKY-Q803"}],
                }
            ],
            "advisory_count": 1,
            "advisory_signal_count": 2,
        },
        "analysis_summary": {"architecture_advisory_count": 1},
    }

    out = partition_code_health(result, git_root=tmp_path, base_commit=None)

    assert out["architecture_metrics"]["module_metrics"] == {
        "shared": {"distance": 1.0}
    }
    assert out["architecture_metrics"]["advisories"] == []
    assert out["architecture_metrics"]["advisory_count"] == 0
    assert out["architecture_metrics"]["advisory_signal_count"] == 0
    assert out["analysis_summary"]["architecture_advisory_count"] == 0


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
    # Code-health routing covers every metric, so ask for every check.
    proc, data = _scan(repo, "--diff-base", "HEAD", "--all-advice")
    quality_rules = {f.get("rule_id") for f in data.get("quality", [])}
    assert not quality_rules & CODE_HEALTH_RULES
    names = {f.get("name") for f in data.get("code_health", []) if f["rule_id"] == "SKY-C304"}
    assert "legacy" not in names
    assert {"grows", "fresh"} <= names


def test_full_scan_still_reports_metrics_as_quality(repo):
    _proc, data = _scan(repo, "--all-advice")
    rules = {f.get("rule_id") for f in data.get("quality", [])}
    assert "SKY-C304" in rules
    assert not data.get("code_health")


def test_diff_base_gate_is_not_failed_by_code_health(repo):
    proc, data = _scan(repo, "--diff-base", "HEAD", "--gate")
    assert data.get("code_health")
    assert proc.returncode == 0, proc.stderr[-2000:]


def test_base_scan_uses_head_project_root_below_git_root(tmp_path):
    # Monorepo: the analyzer roots the head scan at the nearest pyproject,
    # services/api. The base side must read the same policy from the base
    # revision, or a pre-existing T101/T102 is misreported as introduced.
    repo = tmp_path / "repo"
    service = repo / "services" / "api"
    (service / "svc").mkdir(parents=True)
    _git(repo, "init", "-q")
    assert write_text_no_symlink(
        service / "pyproject.toml",
        '[tool.mypy]\ndisallow_untyped_defs = true\nfiles = ["svc"]\n',
        encoding="utf-8",
    )
    assert write_text_no_symlink(service / "svc" / "__init__.py", "", encoding="utf-8")
    core = service / "svc" / "core.py"
    assert write_text_no_symlink(core, "def legacy(x):\n    return x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    assert write_text_no_symlink(
        core,
        "def legacy(x):\n    return x\n\n\ndef fresh(y):\n    return y\n",
        encoding="utf-8",
    )

    def typing(name, rule):
        return {"rule_id": rule, "name": name, "value": "x", "file": str(core), "line": 1}

    def result():
        return {
            "quality": [
                typing("legacy", "SKY-T101"),
                typing("legacy", "SKY-T102"),
                typing("fresh", "SKY-T101"),
            ],
            "analysis_summary": {
                "comparison_scope": {"repository_root": str(service.resolve())}
            },
        }

    base = resolve_merge_base("HEAD", repo)
    out = partition_code_health(result(), git_root=repo, base_commit=base)

    assert {(f["name"], f["code_health_change"]) for f in out["code_health"]} == {
        ("fresh", "introduced")
    }
    assert out["analysis_summary"]["code_health_preexisting_count"] == 2
