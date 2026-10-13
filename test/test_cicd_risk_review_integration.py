"""skylos cicd risk-review with the rules that ship beside it: AI-reviewer
settings and scanner markers (SKY-A122, SKY-A125), AI agents in CI workflows
(SKY-D350 to SKY-D354) and code left without callers (SKY-A135 to SKY-A137)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from skylos.cicd import approval
from skylos.cicd.approval import analyze_change
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import checks as done_checks

BASE_FILES = {
    "app/__init__.py": "",
    "app/calc.py": "def add(a, b):\n    return a + b\n",
    "util.ts": "export function double(x: number): number {\n  return x * 2;\n}\n",
    ".coderabbit.yaml": 'reviews:\n  path_filters:\n    - "!dist/**"\n',
    "pyproject.toml": '[project]\nname = "demo"\nversion = "0.1.0"\n',
}
AGENT_WORKFLOW = """\
name: Claude
on:
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: "--allowedTools Bash"
"""
GATED_WORKFLOW = """\
name: Claude
on:
  issue_comment:
    types: [created]
jobs:
  claude:
    if: contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
"""


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)


def _analyze(tmp_path: Path, head: dict, *, base: dict | None = None):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, {**BASE_FILES, **(base or {})})
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "switch", "-qc", "feature")
    _write(root, head)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "head", "--allow-empty")
    return analyze_change(str(root), "main")


def _risks(risks) -> list[tuple[str, str | None, str | None]]:
    return [(r.cls, r.rule_id, r.file) for r in risks]


# -- SKY-A122 / SKY-A125 from the guardrail_tampering done check ---------------


def test_ai_reviewer_settings_change_needs_a_human(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            ".coderabbit.yaml": 'reviews:\n  path_filters:\n    - "!dist/**"\n    - "!src/auth/**"\n'
        },
    )
    assert _risks(result.vetoes) == [
        ("guardrail_config_changed", "SKY-A122", ".coderabbit.yaml")
    ]
    assert "src/auth" in result.vetoes[0].reason
    assert not result.eligible


def test_one_line_scanner_marker_naming_a_rule_is_advice(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            "util.ts": "export function double(x: number): number {\n"
            "  // skipcq: JS-0002\n  return x * 2;\n}\n"
        },
    )
    assert result.vetoes == []
    assert _risks(result.advisories) == [("checks_silenced", "SKY-A125", "util.ts")]
    assert result.eligible


@pytest.mark.parametrize(
    "path, text",
    [
        ("k8s/deploy.yaml", "# kics-scan ignore\nkind: Pod\n"),
        (
            "src/A.java",
            "class A {\n  // @codescene(disable-all)\n  void f() {}\n}\n",
        ),
    ],
)
def test_scanner_marker_for_every_rule_over_a_wide_scope_needs_a_human(
    tmp_path: Path, path, text
):
    result = _analyze(tmp_path, {path: text})
    assert _risks(result.vetoes) == [("checks_silenced", "SKY-A125", path)]
    # The same marker is not listed again as advice.
    assert all(a.rule_id != "SKY-A125" for a in result.advisories)


def test_guardrail_check_that_cannot_finish_leaves_both_classes_unchecked(
    tmp_path: Path, monkeypatch
):
    def broken(ctx):
        raise RuntimeError("boom")

    rule = done_checks.CHECKS["guardrail_tampering"][1]
    monkeypatch.setitem(done_checks.CHECKS, "guardrail_tampering", (broken, rule))
    monkeypatch.setattr(approval, "_broad_scanner_marker_risks", lambda c: [])
    result = _analyze(tmp_path, {"app/calc.py": "def add(a, b):\n    return b + a\n"})
    assert set(result.classes_incomplete) == {
        "guardrail_config_changed",
        "checks_silenced",
    }
    assert not result.eligible


# -- SKY-D350 to SKY-D354: AI agents in CI workflows ---------------------------


def test_new_critical_agent_workflow_needs_a_human_without_permission_changes(
    tmp_path: Path,
):
    result = _analyze(tmp_path, {".github/workflows/claude.yml": AGENT_WORKFLOW})
    rules = {r.rule_id for r in result.vetoes if r.cls == "ci_weakened"}
    assert "SKY-D351" in rules
    assert all(
        r.file == ".github/workflows/claude.yml"
        for r in result.vetoes
        if r.rule_id.startswith("SKY-D35")
    )
    assert "ci_weakened" in result.classes_found


def test_widening_an_existing_agent_workflow_needs_a_human(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {
            ".github/workflows/claude.yml": GATED_WORKFLOW.replace(
                '    if: contains(fromJSON(\'["OWNER","MEMBER","COLLABORATOR"]\'), '
                "github.event.comment.author_association)\n",
                "",
            )
            + "          github_token: ${{ secrets.GITHUB_TOKEN }}\n"
            + '          allowed_non_write_users: "*"\n'
        },
        base={".github/workflows/claude.yml": GATED_WORKFLOW},
    )
    assert "SKY-D351" in {r.rule_id for r in result.vetoes}


def test_agent_findings_already_on_the_base_are_not_new(tmp_path: Path):
    result = _analyze(
        tmp_path,
        {".github/workflows/claude.yml": "# reviewed\n" + AGENT_WORKFLOW},
        base={".github/workflows/claude.yml": AGENT_WORKFLOW},
    )
    assert not [r for r in result.vetoes if (r.rule_id or "").startswith("SKY-D35")]


def test_gated_agent_workflow_is_not_a_risk(tmp_path: Path):
    result = _analyze(tmp_path, {".github/workflows/claude.yml": GATED_WORKFLOW})
    assert not [r for r in result.vetoes if (r.rule_id or "").startswith("SKY-D35")]


# -- SKY-A135 to SKY-A137: no risk class reads them -----------------------------


def test_branch_orphans_check_is_not_run(tmp_path: Path, monkeypatch):
    def must_not_run(ctx):
        raise AssertionError("branch_orphans ran")

    rule = done_checks.CHECKS["branch_orphans"][1]
    monkeypatch.setitem(done_checks.CHECKS, "branch_orphans", (must_not_run, rule))
    result = _analyze(tmp_path, {"app/calc.py": "def add(a, b):\n    return b + a\n"})
    assert result.complete
    assert result.classes_incomplete == {}
