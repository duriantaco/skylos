"""Persisted credentials require their actual token and artifact value flow."""

import pytest
import yaml

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions_file


def _findings(tmp_path, checkout=None, later=None, permissions=None):
    folder = tmp_path / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "ci.yml"
    first = {"uses": "actions/checkout@v4"}
    if checkout:
        first["with"] = checkout
    steps = [first]
    if later:
        steps.append(later)
    workflow = {
        "name": "CI",
        "on": "push",
        "permissions": permissions or {},
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": steps}},
    }
    assert write_text_no_symlink(path, yaml.safe_dump(workflow), encoding="utf-8")
    return [
        finding
        for finding in scan_github_actions_file(path, root=tmp_path)
        if finding["rule_id"] == "SKY-D293"
    ]


_THIRD_PARTY = {"uses": "vendor/action@0123456789012345678901234567890123456789"}


@pytest.mark.parametrize("credential", ["token", "ssh-key"])
@pytest.mark.parametrize("permissions", [{}, {"contents": "read"}])
def test_custom_checkout_credential_is_not_limited_by_github_permissions(
    tmp_path, credential, permissions
):
    findings = _findings(
        tmp_path,
        {credential: "${{ secrets.REPO_CREDENTIAL }}"},
        _THIRD_PARTY,
        permissions,
    )
    assert len(findings) == 1
    expected = "SSH key" if credential == "ssh-key" else "checkout token"
    assert expected in findings[0]["message"]
    assert "not limited by GITHUB_TOKEN permissions" in findings[0]["message"]


@pytest.mark.parametrize("credential", ["token", "ssh-key"])
def test_custom_credential_without_an_exposure_path_is_not_reported(
    tmp_path, credential
):
    checkout = {credential: "${{ secrets.REPO_CREDENTIAL }}"}
    assert _findings(tmp_path, checkout) == []
    assert _findings(tmp_path, checkout, {"uses": "./local-action"}) == []
    checkout["persist-credentials"] = False
    assert _findings(tmp_path, checkout, _THIRD_PARTY) == []


@pytest.mark.parametrize("persist", [False, "${{ false }}", "${{ 'false' }}"])
def test_nonpersisting_custom_token_does_not_expose_credentials(tmp_path, persist):
    checkout = {"token": "${{ secrets.REPO_PAT }}", "persist-credentials": persist}
    assert _findings(tmp_path, checkout, _THIRD_PARTY, {"contents": "read"}) == []


@pytest.mark.parametrize("persist", [True, "${{ true }}", "${{ inputs.persist }}"])
def test_unknown_or_enabled_persistence_does_not_hide_a_custom_token(tmp_path, persist):
    checkout = {"token": "${{ secrets.REPO_PAT }}", "persist-credentials": persist}
    assert len(_findings(tmp_path, checkout, _THIRD_PARTY, {"contents": "read"})) == 1


@pytest.mark.parametrize("ssh_key", ["", "${{ '' }}", "${{ null }}"])
def test_empty_ssh_input_does_not_invent_a_custom_credential(tmp_path, ssh_key):
    assert (
        _findings(tmp_path, {"ssh-key": ssh_key}, _THIRD_PARTY, {"contents": "read"})
        == []
    )


@pytest.mark.parametrize("ssh_key", ["${{ secrets.SSH_KEY }}", "${{ inputs.ssh_key }}"])
def test_unknown_ssh_key_remains_independent_of_github_token_scope(tmp_path, ssh_key):
    assert (
        len(
            _findings(
                tmp_path, {"ssh-key": ssh_key}, _THIRD_PARTY, {"contents": "read"}
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    ("credential", "reference", "spelling"),
    [
        ("token", "${{ secrets.REPO_PAT }}", "secrets.REPO_PAT"),
        ("token", "${{ secrets['REPO_PAT'] }}", "secrets.REPO_PAT"),
        ("token", "${{ env.TOKEN }}", "env.TOKEN"),
        (
            "token",
            "${{ steps.issue_token.outputs.token }}",
            "steps.issue_token.outputs.token",
        ),
        ("ssh-key", "${{ secrets.SSH_KEY }}", "secrets.SSH_KEY"),
    ],
)
def test_checkout_credential_evidence_names_only_the_reference(
    tmp_path, credential, reference, spelling
):
    findings = _findings(tmp_path, {credential: reference}, _THIRD_PARTY)
    assert spelling in findings[0]["message"]


def test_literal_credential_values_are_never_copied_into_evidence(tmp_path):
    literal = "private credential bytes"
    findings = _findings(tmp_path, {"token": literal}, _THIRD_PARTY)
    assert len(findings) == 1
    assert literal not in findings[0]["message"]


@pytest.mark.parametrize(
    "token",
    [
        None,
        "${{ github.token }}",
        "${{ secrets.GITHUB_TOKEN }}",
        "${{ github['token'] }}",
        "${{ secrets['GITHUB_TOKEN'] }}",
    ],
)
def test_known_github_token_keeps_its_actual_scope(tmp_path, token):
    checkout = {"token": token} if token is not None else {}
    assert _findings(tmp_path, checkout, _THIRD_PARTY, {"contents": "read"}) == []
    assert len(_findings(tmp_path, checkout, _THIRD_PARTY, {"contents": "write"})) == 1


def _upload(path=".", hidden=None, ref="v4"):
    config = {"path": path}
    if hidden is not None:
        config["include-hidden-files"] = hidden
    return {"uses": f"actions/upload-artifact@{ref}", "with": config}


@pytest.mark.parametrize(
    ("hidden", "reported"),
    [
        (None, False),
        (False, False),
        (True, True),
        ("${{ true }}", True),
        ("${{ false }}", False),
        ("${{ inputs.hidden }}", True),
        ("${{ matrix.hidden }}", True),
        ("${{ inputs.hidden && true || false }}", True),
    ],
)
def test_hidden_file_upload_states_are_conservative(tmp_path, hidden, reported):
    assert bool(_findings(tmp_path, later=_upload(hidden=hidden))) is reported


def test_hidden_file_proof_still_needs_an_upload_of_the_checkout(tmp_path):
    assert _findings(tmp_path, later=_upload("dist/", "${{ true }}")) == []
    assert _findings(tmp_path, later=_upload("dist/", "${{ inputs.hidden }}")) == []
    assert _findings(tmp_path, later={"run": "echo done"}) == []


@pytest.mark.parametrize(
    ("path", "checkout", "reported"),
    [
        ("src/**", {"path": "src"}, True),
        ("src/**/*", {"path": "src"}, True),
        ("src/*", {"path": "src"}, True),
        ("src/dist/**", {"path": "src"}, False),
        (".\n!.git/**", {}, False),
        (".\n!.git/config", {}, False),
        (".\n!.gitignore", {}, True),
        (".\n!.git/config.backup", {}, True),
        (".\n!.git/config/", {}, True),
        (".\n!.git/", {}, False),
        ("src/**\n!src/.git/**", {"path": "src"}, False),
        ("src/**\n!src2/.git/**", {"path": "src"}, True),
        ("src/**\n!/src/.git/config", {"path": "src"}, True),
        ("src/**\n! /src/.git/config", {"path": "src"}, True),
        ("src/**\n!${{ github.workspace }}/src/.git/config", {"path": "src"}, False),
        ("!.git/**\n.", {}, True),
        (".\n!${{ inputs.excluded }}", {}, True),
        (".\n!.git/**\n.git/config", {}, True),
        (".\n!.git/**\n!!.git/config", {}, True),
        (".\n!!!.git/config", {}, False),
    ],
)
def test_artifact_globs_and_exclusions_follow_the_credential_file(
    tmp_path, path, checkout, reported
):
    assert bool(_findings(tmp_path, checkout, _upload(path, True))) is reported


def test_ssh_configuration_does_not_remove_the_persisted_http_token(tmp_path):
    findings = _findings(
        tmp_path, {"ssh-key": "${{ secrets.SSH_KEY }}"}, _upload(hidden=True)
    )
    assert len(findings) == 1
    assert "GITHUB_TOKEN" in findings[0]["message"]


def test_unknown_action_ref_cannot_prove_hidden_files_are_excluded(tmp_path):
    assert len(_findings(tmp_path, later=_upload(ref="v4.4-custom"))) == 1


def test_legacy_upload_does_not_honor_a_newer_hidden_files_input(tmp_path):
    assert len(_findings(tmp_path, later=_upload(hidden=False, ref="v4.3.6"))) == 1
