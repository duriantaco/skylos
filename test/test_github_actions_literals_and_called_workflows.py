"""SKY-D300 literal writes, SKY-D309 identifier secrets and SKY-D291 scopes
that a called workflow drops, each beside the shape that stays reported."""

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.config.cicd.github_actions import scan_github_actions


def _scan(tmp_path, files, rule_id):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for name, text in files.items():
        assert write_text_no_symlink(workflows / name, text, encoding="utf-8")
    return [
        finding
        for finding in scan_github_actions(tmp_path)
        if finding["rule_id"] == rule_id
    ]


def _steps(*runs):
    body = "".join(f"      - run: {run}\n" for run in runs)
    return (
        "name: build\non: [pull_request]\npermissions: {}\njobs:\n  build:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + body
    )


def test_literal_path_and_env_writes_are_not_dynamic(tmp_path):
    workflow = _steps(
        "echo 'C:\\Tools\\Assembler' >> \"$GITHUB_PATH\"",
        "echo /opt/tool/bin >> $GITHUB_PATH",
        'echo "TOOL_MODE=release" >> "$GITHUB_ENV"',
    )
    assert _scan(tmp_path, {"ci.yml": workflow}, "SKY-D300") == []


def test_expanded_values_written_to_the_env_files_stay_reported(tmp_path):
    workflow = _steps(
        'echo "$HOME/tools/bin" >> $GITHUB_PATH',
        'echo "TITLE=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"',
        'echo "EXTRA=$(make print-path)" >> "$GITHUB_ENV"',
        "echo '${{ github.head_ref }}' >> $GITHUB_PATH",
    )
    lines = [f["line"] for f in _scan(tmp_path, {"ci.yml": workflow}, "SKY-D300")]
    assert lines == [8, 9, 10, 11]


def _job_env(name, secret):
    return (
        f"  {name.lower()}:\n    runs-on: ubuntu-latest\n    env:\n"
        f"      {name}: ${{{{ secrets.{secret} }}}}\n    steps:\n      - run: ./publish.sh\n"
    )


def test_identifier_named_secret_is_low_risk_and_credentials_are_not(tmp_path):
    workflow = (
        "name: publish\non: [push]\npermissions: {}\njobs:\n"
        + _job_env("RECORD", "ARCHIVE_RECORD_ID")
        + _job_env("TOKEN", "ARCHIVE_TOKEN")
        + _job_env("KEYID", "SIGNING_KEY_ID")
    )
    findings = _scan(tmp_path, {"publish.yml": workflow}, "SKY-D309")
    reasons = {
        finding["value"]: (finding.get("low_risk_context") or {}).get("reason")
        for finding in findings
    }
    assert reasons == {
        "job record:RECORD": "non-credential-secret",
        "job token:TOKEN": None,
        "job keyid:KEYID": None,
    }


CALLER = (
    "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n"
    "  contents: read\n  id-token: write\njobs:\n  checks:\n"
    "    uses: ./.github/workflows/checks.yml\n  publish:\n    needs: checks\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - run: ./publish.sh\n"
)
CALLED_JOB = "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
CALLED_STEPS = "    steps:\n      - run: make test\n"


def _reaching(tmp_path, called):
    findings = _scan(
        tmp_path, {"release.yml": CALLER, "checks.yml": called}, "SKY-D291"
    )
    return [f["message"] for f in findings if "id-token: write reaches" in f["message"]]


def test_called_workflow_with_its_own_read_scope_does_not_receive_the_write(tmp_path):
    called = (
        "name: checks\non:\n  workflow_call:\npermissions:\n  contents: read\n"
        + CALLED_JOB
        + CALLED_STEPS
    )
    assert _reaching(tmp_path, called) == []


def test_called_workflow_without_permissions_receives_the_write(tmp_path):
    called = "name: checks\non:\n  workflow_call:\n" + CALLED_JOB + CALLED_STEPS
    assert len(_reaching(tmp_path, called)) == 1


def test_called_workflow_job_that_takes_the_scope_receives_the_write(tmp_path):
    called = (
        "name: checks\non:\n  workflow_call:\npermissions:\n  contents: read\n"
        + CALLED_JOB
        + "    permissions:\n      id-token: write\n"
        + CALLED_STEPS
    )
    assert len(_reaching(tmp_path, called)) == 1
