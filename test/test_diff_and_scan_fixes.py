"""Scan fixes found by the rule handbook: CI permission changes in a repository
without source, the line of a test-impact gap, unrendered Helm templates, the
dependency-confusion message, mirrored version bumps in a ``--diff HEAD`` scan
and the upgrade lookup for machine output."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.analyzer import analyze

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.delenv("SKYLOS_POLICY_BASE", raising=False)
    monkeypatch.delenv("SKYLOS_DIFF_BASE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")


def _write(root: Path, files: dict) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _git(root: Path, *args) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **_GIT_ENV},
    )
    return result.stdout.strip()


def _committed(root: Path, files: dict) -> str:
    _write(root, files)
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return _git(root, "rev-parse", "HEAD")


def _run(root: Path, **kwargs) -> dict:
    return json.loads(analyze(str(root), conf=0, **kwargs))


def _rows(result: dict, key: str, rule: str) -> list[tuple[str, int]]:
    rows = []
    for finding in result.get(key) or []:
        if finding.get("rule_id") != rule:
            continue
        file = Path(str(finding.get("file")))
        rows.append((file.name, finding.get("line")))
    return sorted(rows)


def _suppressed(result: dict, rule: str) -> list[tuple[str, int, str]]:
    return sorted(
        (Path(str(item.get("file"))).name, item.get("line"), item.get("reason"))
        for item in result.get("suppressed") or []
        if item.get("rule_id") == rule
    )


WORKFLOW_BASE = (
    "name: release\n"
    "on:\n"
    "  push:\n"
    '    tags: ["v*"]\n'
    "permissions:\n"
    "  contents: read\n"
    "jobs:\n"
    "  publish:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: make release\n"
)


@needs_git
def test_ci_permission_expansion_runs_in_a_repository_without_source(tmp_path):
    workflow = ".github/workflows/release.yml"
    _committed(tmp_path, {workflow: WORKFLOW_BASE})
    _write(
        tmp_path,
        {workflow: WORKFLOW_BASE.replace("contents: read", "contents: write")},
    )

    result = _run(
        tmp_path, enable_ai_defects=True, enable_dependency_hallucinations=False
    )

    assert _rows(result, "ai_defects", "SKY-A103") == [("release.yml", 6)]


PAYMENTS_BASE = (
    "def charge(amount, card):\n"
    "    fee = 30\n"
    "    total = amount + fee\n"
    "    return card.charge(total)\n"
)


@needs_git
def test_test_impact_gap_is_reported_on_the_first_changed_line(tmp_path):
    _committed(tmp_path, {"billing/payment.py": PAYMENTS_BASE})
    _write(
        tmp_path, {"billing/payment.py": PAYMENTS_BASE.replace("fee = 30", "fee = 35")}
    )

    result = _run(
        tmp_path, enable_ai_defects=True, enable_dependency_hallucinations=False
    )

    assert _rows(result, "ai_defects", "SKY-A102") == [("payment.py", 2)]


@needs_git
def test_test_impact_gap_marker_on_the_changed_line_is_read(tmp_path):
    _committed(tmp_path, {"billing/payment.py": PAYMENTS_BASE})
    _write(
        tmp_path,
        {
            "billing/payment.py": PAYMENTS_BASE.replace(
                "fee = 30", "fee = 35  # skylos: ignore[SKY-A102] rate change only"
            )
        },
    )

    result = _run(
        tmp_path, enable_ai_defects=True, enable_dependency_hallucinations=False
    )

    assert _rows(result, "ai_defects", "SKY-A102") == []
    assert _suppressed(result, "SKY-A102") == [
        ("payment.py", 2, "inline ignore comment")
    ]


HELM_TEMPLATE = (
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n"
    '  name: {{ include "web.fullname" . }}\n'
    "  labels:\n"
    '    {{- include "web.labels" . | nindent 4 }}\n'
    "spec:\n"
    "  replicas: {{ .Values.replicaCount }}\n"
)


def test_unrendered_helm_template_is_a_coverage_note_not_an_analysis_error(tmp_path):
    _write(
        tmp_path,
        {
            "chart/Chart.yaml": "apiVersion: v2\nname: web\nversion: 0.1.0\n",
            "chart/templates/deployment.yaml": HELM_TEMPLATE,
            "app.py": "def main():\n    return 1\n",
        },
    )

    result = _run(tmp_path, enable_danger=True)

    assert result["analysis_errors"] == []
    kubernetes = result["analysis_summary"]["configuration_coverage"]["kubernetes"]
    assert [error["kind"] for error in kubernetes["discovery_errors"]] == [
        "kubernetes_template_not_rendered"
    ]
    assert kubernetes["status"] == "incomplete"


def test_malformed_manifest_outside_a_chart_is_still_an_analysis_error(tmp_path):
    _write(
        tmp_path,
        {
            "deploy/templates/deployment.yaml": HELM_TEMPLATE,
            "app.py": "def main():\n    return 1\n",
        },
    )

    result = _run(tmp_path, enable_danger=True)

    assert [error["kind"] for error in result["analysis_errors"]] == [
        "kubernetes_parse_error"
    ]


def test_confusion_message_names_the_registries_instead_of_none():
    from skylos.rules.sca import supply_chain

    record = {
        "name": "acme-billing",
        "version": "2.0.0",
        "registry": None,
        "registry_mode": "merged",
        "registries": ["https://pypi.org/simple", "https://pypi.acme.example/simple"],
    }

    message = supply_chain._message(
        supply_chain.RULE_CONFUSION, record, {"internal_pattern": "acme-*"}, None
    )

    assert "None" not in message
    assert (
        "resolves from any of https://pypi.org/simple, https://pypi.acme.example/simple"
        in message
    )


PYPROJECT_BUMP = (
    "[project]\n"
    'name = "acme-billing"\n'
    'version = "{version}"\n'
    'requires-python = ">=3.10"\n'
    "dependencies = [\n"
    '    "httpx>=0.27",\n'
    '    "pydantic-settings=={version}",\n'
    "]\n"
)


@needs_git
def test_mirrored_dependency_bump_is_found_in_a_diff_head_scan(tmp_path):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    _committed(tmp_path, {"pyproject.toml": PYPROJECT_BUMP.format(version="2.3.0")})
    _write(tmp_path, {"pyproject.toml": PYPROJECT_BUMP.format(version="2.4.0")})

    against_head = scan_mirrored_dependency_bumps(
        tmp_path,
        scan_paths=tmp_path,
        changed_files={str(tmp_path / "pyproject.toml")},
        diff_base="HEAD",
    )

    assert [(item["rule_id"], item["line"]) for item in against_head] == [
        ("SKY-A106", 7)
    ]


@needs_git
def test_mirrored_dependency_bump_against_an_older_base_still_compares_commits(
    tmp_path,
):
    from skylos.rules.ai_defect.dependency_bump_scan import (
        scan_mirrored_dependency_bumps,
    )

    base = _committed(
        tmp_path, {"pyproject.toml": PYPROJECT_BUMP.format(version="2.3.0")}
    )
    _write(tmp_path, {"pyproject.toml": PYPROJECT_BUMP.format(version="2.4.0")})
    _git(tmp_path, "commit", "-qam", "bump")
    _write(tmp_path, {"pyproject.toml": PYPROJECT_BUMP.format(version="2.5.0")})

    committed = scan_mirrored_dependency_bumps(
        tmp_path,
        scan_paths=tmp_path,
        changed_files={str(tmp_path / "pyproject.toml")},
        diff_base=base,
    )

    assert [item["metadata"]["dependency_new_version"] for item in committed] == [
        "2.4.0"
    ]


def test_machine_output_on_a_terminal_never_starts_the_upgrade_lookup(
    tmp_path, monkeypatch
):
    from skylos import cli
    from skylos.commands import scan_cmd
    from skylos.core import update_check

    calls = []
    monkeypatch.setattr(scan_cmd, "_terminal_output", lambda: True)
    monkeypatch.setattr(update_check, "refresh_in_background", lambda: calls.append(1))
    for name in update_check._CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("SKYLOS_NO_TELEMETRY", raising=False)
    _write(tmp_path, {"app.py": "def main():\n    return 1\n"})

    def scan(*flags):
        calls.clear()
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "skylos",
                str(tmp_path),
                *flags,
                "--no-upload",
                "-o",
                str(tmp_path / "out"),
            ],
        )
        try:
            cli.main()
        except SystemExit:
            pass
        return len(calls)

    assert scan("--format", "json") == 0
    assert scan("--json") == 0
    assert scan("--format", "rich") == 1
