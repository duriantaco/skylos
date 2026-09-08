"""Keep the dependency bump advisory visible in change verification."""

import json
import os
import shutil
import socket
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect.dependency_version_bump import (
    detect_mirrored_dependency_bumps,
)
from skylos.verify_change import build_verify_change_response, verify_change_path


_GIT_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
)


def _manifest(version):
    return (
        '[project]\nname = "example-app"\n'
        f'version = "{version}"\n'
        f'dependencies = ["example-library>={version}"]\n'
    )


def _git(repo, *args):
    env = dict(os.environ)
    for key in _GIT_ENV:
        env.pop(key, None)
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()


@pytest.fixture
def version_change_repo(tmp_path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git is required")
    for key in (*_GIT_ENV, "SKYLOS_DIFF_BASE", "GITHUB_BASE_REF"):
        monkeypatch.delenv(key, raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("Dependency bump verification must not use the network")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    repo = tmp_path / "version change"
    repo.mkdir()
    _git(repo, "init", "-q")
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.3"))
    _git(repo, "add", "pyproject.toml")
    _git(
        repo,
        "-c",
        "user.name=Skylos Test",
        "-c",
        "user.email=skylos-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "initial version",
    )
    assert write_text_no_symlink(repo / "pyproject.toml", _manifest("1.2.4"))
    return repo


@pytest.mark.parametrize("with_source", [False, True])
def test_real_analyzer_dependency_bump_survives_verify_change(
    version_change_repo, with_source
):
    repo = version_change_repo
    if with_source:
        assert write_text_no_symlink(repo / "app.py", "answer = 42\n")
    analysis = json.loads(
        analyze(
            str(repo),
            enable_ai_defects=True,
            enable_dependency_hallucinations=False,
            trace_file=False,
        )
    )
    analyzer_findings = [
        finding
        for finding in analysis.get("ai_defects", [])
        if finding["rule_id"] == "SKY-A106"
    ]
    assert len(analyzer_findings) == 1

    result = verify_change_path(
        repo,
        include_dependency_hallucinations=False,
        contract_enabled=False,
    )

    findings = [
        finding for finding in result["findings"] if finding["rule_id"] == "SKY-A106"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "ai_defect"
    assert finding["vibe_category"] == "mirrored_dependency_bump"
    assert finding["severity"] == "LOW"
    assert finding["ai_likelihood"] == "low"
    assert finding["confidence"] == 50
    assert finding["range"]["file"] == "pyproject.toml"
    assert finding["range"]["start_line"] == 4
    assert finding["metadata"] == analyzer_findings[0]["metadata"]
    assert finding["metadata"]["signal_only"] is True
    assert finding["metadata"]["blocking_recommended"] is False
    assert finding["suggested_fix"] == (
        "Review whether the dependency change was intentional; restore its previous "
        "version only if the change was accidental."
    )
    # The existing verify schema reports findings with status fail, including
    # LOW advisories. The rule metadata still recommends review, not blocking.
    assert result["status"] == "fail"


@pytest.mark.parametrize(
    ("target_file", "line_range", "expected"),
    [
        ("pyproject.toml", "4:4", 1),
        ("pyproject.toml", "1:3", 0),
        ("requirements.txt", None, 0),
    ],
)
def test_dependency_bump_preserves_verify_target_and_range_filters(
    tmp_path, target_file, line_range, expected
):
    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": _manifest("1.2.3")},
        {"pyproject.toml": _manifest("1.2.4")},
    )

    result = build_verify_change_response(
        {"ai_defects": findings},
        project_root=tmp_path,
        target_file=target_file,
        line_range=line_range,
    )

    assert len(result["findings"]) == expected


def test_dependency_bump_registration_does_not_admit_unrelated_findings(tmp_path):
    result = build_verify_change_response(
        {
            "ai_defects": [
                {
                    "rule_id": "TEST-UNREGISTERED",
                    "category": "ai_defect",
                    "severity": "LOW",
                    "file": "pyproject.toml",
                    "line": 4,
                    "metadata": {"signal_only": True, "blocking_recommended": False},
                }
            ]
        },
        project_root=tmp_path,
    )

    assert result["findings"] == []


def _split_dependency_findings():
    before = """from setuptools import setup
setup(
    name="example", version="1.2.3",
    install_requires=[
        "library>="
        "1."
        "2.3",
    ],
)
"""
    after = before.replace("1.2.3", "1.2.4").replace('"2.3"', '"2.4"')
    return detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after})


@pytest.mark.parametrize(
    ("line_range", "expected"),
    [("5:5", 1), ("6:6", 1), ("7:7", 1), ("4:4", 0), ("8:8", 0)],
)
def test_verify_range_covers_the_actual_split_dependency_literal(
    tmp_path, line_range, expected
):
    findings = _split_dependency_findings()
    assert len(findings) == 1
    assert findings[0]["line"] == 6
    assert findings[0]["related_locations"] == [
        {"file": "setup.py", "start_line": 5, "end_line": 7}
    ]

    result = build_verify_change_response(
        {"ai_defects": findings},
        project_root=tmp_path,
        target_file="setup.py",
        line_range=line_range,
    )

    assert len(result["findings"]) == expected
    if expected:
        assert result["findings"][0]["range"] == {
            "file": "setup.py",
            "start_line": 5,
            "start_col": 0,
            "end_line": 7,
            "end_col": 0,
        }


@pytest.mark.parametrize(
    "location",
    [
        {"file": "other.py", "start_line": 5, "end_line": 7},
        {"file": "setup.py", "start_line": 0, "end_line": 7},
        {"file": "setup.py", "start_line": -1, "end_line": 7},
        {"file": "setup.py", "start_line": 7, "end_line": 5},
        {"file": "setup.py", "start_line": True, "end_line": 7},
        {"file": "setup.py", "start_line": "5", "end_line": 7},
        {"file": "setup.py", "start_line": 5, "end_line": 2_000_001},
        {"file": "setup.py", "start_line": 7, "end_line": 8},
    ],
)
def test_verify_dependency_span_rejects_unrelated_or_invalid_locations(
    tmp_path, location
):
    findings = _split_dependency_findings()
    findings[0]["related_locations"] = [location]

    result = build_verify_change_response(
        {"ai_defects": findings},
        project_root=tmp_path,
        target_file="setup.py",
        line_range="7:7",
    )

    assert result["findings"] == []


def test_verify_dependency_span_does_not_change_other_rule_ranges(tmp_path):
    findings = _split_dependency_findings()
    findings[0]["rule_id"] = "SKY-A102"

    result = build_verify_change_response(
        {"ai_defects": findings},
        project_root=tmp_path,
        target_file="setup.py",
        line_range="7:7",
    )

    assert result["findings"] == []
