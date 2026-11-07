"""Same-commit workflow calls retain caller privilege and input provenance."""

import json
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.ai_agents import local_workflow_callers
from skylos.rules.config.cicd.github_actions import _load_yaml, scan_github_actions


def _write(root, name, source):
    path = root / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _signatures(root, rules):
    return sorted(
        (
            finding["rule_id"],
            Path(finding["file"]).name,
            finding["line"],
            finding["severity"],
        )
        for finding in scan_github_actions(root)
        if finding["rule_id"] in rules
    )


@pytest.mark.parametrize("prefix", ["./", "$/"])
@pytest.mark.parametrize("gated", [False, True], ids=["outsider", "actor-gated"])
@pytest.mark.parametrize("filename", ["called.yml", "called name.yaml", "処理.yml"])
def test_same_commit_agent_call_preserves_caller_privilege(
    tmp_path, prefix, gated, filename
):
    guard = (
        '    if: contains(fromJSON(\'["OWNER","MEMBER","COLLABORATOR"]\'), '
        "github.event.comment.author_association)\n"
        if gated
        else ""
    )
    _write(
        tmp_path,
        "caller.yml",
        "name: Dispatch\non: issue_comment\npermissions: {}\njobs:\n"
        "  invoke:\n"
        + guard
        + "    uses: "
        + json.dumps(prefix + ".github/workflows/" + filename)
        + "\n    secrets: inherit\n",
    )
    _write(
        tmp_path,
        filename,
        "name: Gemini invoke\non: workflow_call\nenv:\n"
        "  GEMINI_CLI_TRUST_WORKSPACE: 'true'\njobs:\n"
        "  invoke:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: google-github-actions/run-gemini-cli@v0\n"
        "        with:\n          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}\n"
        "          prompt: '/gemini-invoke'\n",
    )

    expected = (
        [("SKY-D352", filename, 9, "MEDIUM")]
        if gated
        else [
            ("SKY-D350", filename, 9, "CRITICAL"),
            ("SKY-D352", filename, 9, "HIGH"),
        ]
    )
    assert _signatures(tmp_path, {"SKY-D350", "SKY-D352"}) == expected


@pytest.mark.parametrize("prefix", ["./", "$/"])
@pytest.mark.parametrize(
    "tainted", [False, True], ids=["fixed-input", "attacker-input"]
)
def test_same_commit_workflow_inputs_keep_expression_provenance(
    tmp_path, prefix, tainted
):
    command = "${{ needs.prepare.outputs.code }}" if tainted else "echo fixed"
    _write(
        tmp_path,
        "caller.yml",
        "name: caller\non: issue_comment\npermissions: {}\njobs:\n"
        "  prepare:\n    runs-on: ubuntu-latest\n"
        "    outputs:\n      code: ${{ steps.stage.outputs.code }}\n      fixed: ok\n"
        "    steps:\n      - id: stage\n"
        "        env:\n          TEXT: ${{ github.event.comment.body }}\n"
        '        run: echo "code=$TEXT" >> "$GITHUB_OUTPUT"\n'
        "  invoke:\n    needs: prepare\n    uses: "
        + prefix
        + ".github/workflows/called.yml\n"
        "    with:\n      command: "
        + json.dumps(command)
        + "\n      other: ${{ needs.prepare.outputs.fixed }}\n",
    )
    _write(
        tmp_path,
        "called.yml",
        "name: reusable\non:\n  workflow_call:\n    inputs:\n"
        "      command:\n        type: string\n      other:\n        type: string\n"
        "jobs:\n  demo:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: ${{ inputs.command }}\n      - run: ${{ inputs.other }}\n",
    )

    expected = [("SKY-D294", "called.yml", 13, "HIGH")] if tainted else []
    assert _signatures(tmp_path, {"SKY-D294"}) == expected


@pytest.mark.parametrize(
    "reference, expected",
    [
        ("./.github/workflows/called.yml", True),
        ("$/.github/workflows/called.yml", True),
        (".github/workflows/called.yml", True),
        ("./.github/workflows/called.yml@main", True),
        ("$/.github/workflows/called.yml@main", False),
        ("$/.github/workflows/nested/called.yml", False),
        ("$/.github/workflows/../called.yml", False),
        ("$/.github/workflows/${{ inputs.file }}.yml", False),
        ("owner/repo/.github/workflows/called.yml@main", False),
    ],
)
def test_dollar_callers_do_not_rewrite_legacy_or_unrelated_references(
    tmp_path, reference, expected
):
    _write(
        tmp_path,
        "caller.yml",
        "name: caller\non: issue_comment\njobs:\n  call:\n    uses: "
        + json.dumps(reference)
        + "\n",
    )
    called = _write(
        tmp_path,
        "called.yml",
        "name: called\non: workflow_call\njobs:\n  run:\n"
        "    runs-on: ubuntu-latest\n    steps:\n      - run: echo safe\n",
    )
    loaded = _load_yaml(called, root=tmp_path)
    assert loaded is not None
    callers = local_workflow_callers(loaded[0], called, tmp_path)
    assert [entry[0].name for entry in callers] == (["caller.yml"] if expected else [])
