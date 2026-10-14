"""Every gate run ends with one verdict line and the reasons behind it.

Covers pass, fail and could-not-decide (exit 2) in rich, line-oriented and
JSON output, `skylos cicd gate`, and runs that stop early (missing diff base,
unreadable input, analyzer crash). Analysis is real; OSV HTTP is replaced by
an offline transport and nothing uploads.
"""

import json

import pytest

import skylos.cli as cli
import skylos.rules.sca.vulnerability_scanner as sca
from skylos.core.gate_incomplete import (
    OSV_HINT,
    PARSE_ERROR_HINT,
    SCA_REQUIRED_HINT,
    SCANNER_EXCEPTION_HINT,
    incomplete_analysis_reasons,
)
from skylos.core.gatekeeper import (
    INCOMPLETE_VERDICT,
    build_summary_markdown,
    run_gate_interaction,
)

PNPM_PACKAGE_JSON = json.dumps(
    {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}}
)
# The importer declares left-pad, but no package or snapshot records it.
PNPM_LOCK_MISSING_ENTRY = (
    "lockfileVersion: '9.0'\n"
    "importers:\n"
    "  .:\n"
    "    dependencies:\n"
    "      left-pad:\n"
    "        specifier: ^1.3.0\n"
    "        version: 1.3.0\n"
    "packages: {}\n"
    "snapshots: {}\n"
)
CLEAN_APP = "def main():\n    return 1\n\n\nif __name__ == '__main__':\n    main()\n"
LOCKFILE_REASON = (
    "Dependency vulnerability scan incomplete (status: incomplete): "
    "1 lockfile entry could not be resolved"
)


class _OfflineOSV:
    """OSV.dev is unreachable: every request fails like a dropped connection."""

    def __init__(self):
        self.calls = 0

    def post(self, *args, **kwargs):
        self.calls += 1
        raise ConnectionError("network unavailable")

    def get(self, *args, **kwargs):
        self.calls += 1
        raise ConnectionError("network unavailable")


@pytest.fixture
def project(tmp_path, monkeypatch):
    path = tmp_path / "project"
    path.mkdir()
    (path / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    monkeypatch.chdir(path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # This non-Git fixture tests local verdicts. The runner's PR base and
    # policy belong to its checkout, not this temporary project.
    for name in (
        "SKYLOS_CONFIG_FILE",
        "SKYLOS_DIFF_BASE",
        "SKYLOS_POLICY_BASE",
        "GITHUB_BASE_REF",
        "GITHUB_STEP_SUMMARY",
        "BITBUCKET_BUILD_NUMBER",
        "BITBUCKET_COMMIT",
        "BITBUCKET_PR_DESTINATION_BRANCH",
        "TF_BUILD",
        "SYSTEM_PULLREQUEST_PULLREQUESTID",
        "SYSTEM_PULLREQUEST_TARGETBRANCH",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)

    def no_upload(*args, **kwargs):
        pytest.fail("gate output tests must not upload anything")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    return path


@pytest.fixture
def offline_osv(monkeypatch):
    transport = _OfflineOSV()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


def _write_pnpm_gap(project):
    (project / "package.json").write_text(PNPM_PACKAGE_JSON, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    (project / "pnpm-lock.yaml").write_text(PNPM_LOCK_MISSING_ENTRY, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path


def _run(monkeypatch, capsys, *args):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", *args])
    capsys.readouterr()
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _scan(monkeypatch, capsys, *args):
    return _run(
        monkeypatch,
        capsys,
        ".",
        "--no-provenance",
        "--no-grep-verify",
        "--no-clipboard",
        *args,
    )


def _tail(text, count):
    return [line.rstrip() for line in text.strip().splitlines()[-count:]]


def _verdict_block(text, verdict):
    """The lines from the last verdict line to the end of the output."""
    lines = [line.rstrip() for line in text.rstrip().splitlines()]
    starts = [i for i, line in enumerate(lines) if line.strip().startswith(verdict)]
    assert starts, f"no {verdict!r} line in:\n{text}"
    return lines[starts[-1] :]


# Reasons built from analysis receipts ------------------------------------


def _sca_result(**coverage):
    return {"analysis_summary": {"sca_coverage": {"status": "incomplete", **coverage}}}


def test_unresolved_lockfile_entries_name_files_lines_and_the_override():
    issues = [
        {
            "file": "pnpm-lock.yaml",
            "line": 6 + index,
            "dependency": f"dep-{index}",
            "reason": "missing_locked_dependency",
        }
        for index in range(25)
    ]

    (reason,) = incomplete_analysis_reasons(
        _sca_result(unresolved_lockfile_dependency_count=98, lockfile_issues=issues)
    )

    assert reason.text == (
        "Dependency vulnerability scan incomplete (status: incomplete): "
        "98 lockfile entries could not be resolved"
    )
    assert reason.details[0] == "pnpm-lock.yaml:6  missing locked dependency: dep-0"
    assert len(reason.details) == 11
    assert reason.details[-1] == "and 88 more"
    assert reason.hint == SCA_REQUIRED_HINT
    assert "run without --sca" in reason.hint


def test_osv_failure_names_failed_batches_and_network_hint():
    (reason,) = incomplete_analysis_reasons(
        _sca_result(
            query={
                "status": "incomplete",
                "complete": False,
                "requested_batches": 3,
                "failed_batches": 2,
                "advisory_details": {
                    "complete": False,
                    "failed_count": 4,
                    "unique_id_count": 9,
                    "deadline_exceeded": True,
                },
            }
        )
    )

    assert "OSV.dev queries failed for 2 of 3 batches" in reason.text
    assert (
        "details for 4 of 9 advisories could not be fetched before the time limit"
        in (reason.text)
    )
    assert reason.hint == f"{OSV_HINT} {SCA_REQUIRED_HINT}"


def test_parse_errors_and_scanner_crashes_say_how_to_see_the_cause():
    (parse,) = incomplete_analysis_reasons(_sca_result(parse_error_count=2))
    (crash,) = incomplete_analysis_reasons(
        _sca_result(reason="scanner_exception", error_type="ValueError")
    )

    assert parse.text.endswith(": 2 dependency files could not be read or parsed")
    assert parse.hint.startswith(PARSE_ERROR_HINT)
    assert crash.text.endswith(": the dependency scanner raised ValueError")
    assert crash.hint.startswith(SCANNER_EXCEPTION_HINT)


def test_inventory_limits_and_unavailable_scanner_are_named():
    (limits,) = incomplete_analysis_reasons(
        _sca_result(limit_reasons=["manifest_count_limit_exceeded"])
    )
    (unavailable,) = incomplete_analysis_reasons(
        {
            "analysis_summary": {
                "sca_coverage": {
                    "status": "unavailable",
                    "reason": "requests_dependency_unavailable",
                }
            }
        }
    )

    assert limits.text.endswith(": more than 1,000 manifests and lockfiles were found")
    assert unavailable.text == (
        "Dependency vulnerability scan incomplete (status: unavailable): the "
        "requests package is not installed, so OSV.dev could not be queried"
    )
    assert "pip install requests" in unavailable.hint


def test_untrusted_receipt_values_never_reach_the_reason_text():
    (reason,) = incomplete_analysis_reasons(
        _sca_result(
            reason="scanner_exception",
            error_type="Boom](https://evil.example)",
            parse_error_count="7",
            unresolved_lockfile_dependency_count=True,
            lockfile_issues="pnpm-lock.yaml",
            query=["not", "a", "receipt"],
        )
    )

    assert reason.text == (
        "Dependency vulnerability scan incomplete (status: incomplete): "
        "the dependency scanner raised an error"
    )
    assert reason.details == ()


def test_analysis_errors_list_files_and_keep_the_engine_suggestion():
    result = {
        "analysis_errors": [
            {
                "file": "broken.py",
                "line": 3,
                "kind": "syntax_error",
                "message": "invalid syntax",
            },
            {
                "file": "main.go",
                "line": 1,
                "kind": "language_engine_unavailable",
                "message": "Go analysis incomplete.",
                "affected_file_count": 4,
                "suggestion": "Set SKYLOS_GO_BIN.",
            },
        ]
    }

    (reason,) = incomplete_analysis_reasons(result)

    assert reason.text == (
        "Analysis incomplete: 2 analysis error(s) prevented a complete scan"
    )
    assert reason.details == (
        "broken.py:3  syntax error: invalid syntax",
        "main.go:1  language engine unavailable: Go analysis incomplete. (4 files)",
    )
    assert reason.hint.startswith("Set SKYLOS_GO_BIN. Fix the files listed above")
    assert "--exclude <folder>" in reason.hint


# Gatekeeper rendering ------------------------------------------------------


def test_incomplete_gate_prints_verdict_then_reasons_details_and_hint(capsys):
    result = _sca_result(
        unresolved_lockfile_dependency_count=1,
        lockfile_issues=[
            {
                "file": "pnpm-lock.yaml",
                "line": 6,
                "dependency": "left-pad",
                "reason": "missing_locked_dependency",
            }
        ],
    )

    assert run_gate_interaction(result=result, config={}, force=True) == 2

    block = _verdict_block(capsys.readouterr().out, INCOMPLETE_VERDICT)
    assert block[0] == INCOMPLETE_VERDICT
    assert block[2] == f"   • {LOCKFILE_REASON}"
    assert block[3] == "       pnpm-lock.yaml:6  missing locked dependency: left-pad"
    assert block[4] == f"       {SCA_REQUIRED_HINT}"
    assert len(block) == 5


def test_incomplete_step_summary_says_could_not_decide():
    result = _sca_result(parse_error_count=1)
    reasons = cli._gate_outcome(result, {}, cli.argparse.Namespace()).reasons

    markdown = build_summary_markdown(result, False, reasons, incomplete=True)

    assert "**Result: ⚠️ INCOMPLETE - COULD NOT DECIDE**" in markdown
    assert "### Incomplete Analysis" in markdown
    assert "1 dependency file could not be read or parsed" in markdown
    assert f"  - {PARSE_ERROR_HINT}" in markdown


# `skylos <path> --gate`, every output mode ------------------------------------


def test_rich_gate_on_unresolved_pnpm_lockfile_ends_with_verdict(
    project, monkeypatch, capsys, offline_osv
):
    _write_pnpm_gap(project)

    exit_code, out, _err = _scan(monkeypatch, capsys, "--sca", "--gate")

    assert exit_code == 2
    block = _verdict_block(out, INCOMPLETE_VERDICT)
    assert block[2] == f"   • {LOCKFILE_REASON}"
    assert block[3] == "       pnpm-lock.yaml:5  missing locked dependency: left-pad"
    assert block[-1] == f"       {SCA_REQUIRED_HINT}"


def test_json_gate_carries_verdict_and_reasons_without_stderr(
    project, monkeypatch, capsys, offline_osv
):
    _write_pnpm_gap(project)

    exit_code, out, err = _scan(
        monkeypatch, capsys, "--sca", "--gate", "--format", "json"
    )

    assert exit_code == 2
    # One gate object: the assessment fields, then the verdict fields.
    assert json.loads(out)["gate"] == {
        "passed": False,
        "reasons": [LOCKFILE_REASON],
        "scope": "local_configured_policy",
        "status": "incomplete",
        "forced": False,
        "verdict": "incomplete",
        "exit_code": 2,
        "strict": False,
        "headline": INCOMPLETE_VERDICT,
        "hint": None,
        "reason_details": [
            {
                "message": LOCKFILE_REASON,
                "details": ["pnpm-lock.yaml:5  missing locked dependency: left-pad"],
                "hint": SCA_REQUIRED_HINT,
            }
        ],
        "coverage_status": "incomplete",
        "coverage_warnings": [],
        "coverage_warning_details": [],
    }
    assert "Quality Gate" not in err


def test_strict_force_without_gate_records_no_gate_but_still_states_it(
    project, monkeypatch, capsys
):
    (project / "app.py").write_text("import os\n" + CLEAN_APP, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    report = project.parent / "report.json"

    exit_code, out, err = _scan(
        monkeypatch,
        capsys,
        "--strict",
        "--force",
        "--format",
        "json",
        "-o",
        str(report),
    )

    assert exit_code == 0
    assert out == ""
    # --strict --force skips the policy record; the run still ends with
    # the verdict it was forced past.
    assert "gate" not in json.loads(report.read_text())
    block = _verdict_block(err, "Quality Gate: FAILED")
    assert block[1] == "   • Strict mode: 1 issue found"
    assert block[-1] == "   Forced pass (local only)"


def test_json_report_file_still_prints_the_verdict(
    project, monkeypatch, capsys, offline_osv
):
    _write_pnpm_gap(project)
    report = project.parent / "report.json"

    exit_code, out, err = _scan(
        monkeypatch, capsys, "--sca", "--gate", "--format", "json", "-o", str(report)
    )

    assert exit_code == 2
    assert out == ""
    assert json.loads(report.read_text())["gate"]["verdict"] == "incomplete"
    assert _verdict_block(err, INCOMPLETE_VERDICT)[2] == f"   • {LOCKFILE_REASON}"


def test_concise_gate_keeps_stdout_findings_only_and_verdict_on_stderr(
    project, monkeypatch, capsys, offline_osv
):
    _write_pnpm_gap(project)

    exit_code, out, err = _scan(
        monkeypatch, capsys, "--sca", "--gate", "--format", "concise"
    )

    assert exit_code == 2
    assert "Quality Gate" not in out
    block = _verdict_block(err, INCOMPLETE_VERDICT)
    assert block[2] == f"   • {LOCKFILE_REASON}"
    assert block[-1] == f"       {SCA_REQUIRED_HINT}"


def test_offline_osv_gate_names_the_failed_query(
    project, monkeypatch, capsys, offline_osv
):
    (project / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path

    exit_code, out, _err = _scan(monkeypatch, capsys, "--sca", "--gate")

    assert exit_code == 2
    assert offline_osv.calls
    block = _verdict_block(out, INCOMPLETE_VERDICT)
    assert block[2] == (
        "   • Dependency vulnerability scan incomplete (status: incomplete): "
        "OSV.dev queries failed for 1 of 1 batch"
    )
    assert block[-1] == f"       {OSV_HINT} {SCA_REQUIRED_HINT}"


def test_lockfile_parse_failure_gate_says_how_to_find_the_file(
    project, monkeypatch, capsys, offline_osv
):
    (project / "pnpm-lock.yaml").write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        'lockfileVersion: "9.0"\nimporters: [not: valid\n', encoding="utf-8"
    )

    exit_code, out, _err = _scan(monkeypatch, capsys, "--sca", "--gate")

    assert exit_code == 2
    block = _verdict_block(out, INCOMPLETE_VERDICT)
    assert block[2].endswith(": 1 dependency file could not be read or parsed")
    assert block[-1].strip().startswith(PARSE_ERROR_HINT)


def test_source_parse_failure_gate_lists_the_file(project, monkeypatch, capsys):
    (project / "broken.py").write_text("def broken(:\n    return 2\n", encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path

    # One of two files did not parse: the gate is decided on app.py and the
    # unanalysed file is a coverage warning under the verdict.
    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate")

    assert exit_code == 0
    assert "Quality Gate: PASSED" in out
    block = _verdict_block(out, "Coverage: INCOMPLETE")
    assert block[1] == (
        "   • Incomplete coverage: 1 of 2 source files could not be analysed"
    )
    assert block[2] == "       broken.py:1  syntax error: invalid syntax"
    assert "--exclude <folder>" in block[3]
    assert "--strict" in block[-1]

    # --strict asks for complete coverage: the gate cannot decide.
    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate", "--strict")

    assert exit_code == 2
    block = _verdict_block(out, INCOMPLETE_VERDICT)
    assert block[2] == (
        "   • Incomplete coverage: 1 of 2 source files could not be analysed"
    )
    assert block[3] == "       broken.py:1  syntax error: invalid syntax"
    assert "--exclude <folder>" in block[-1]


def test_concise_gate_pass_and_fail_end_with_a_verdict(project, monkeypatch, capsys):
    exit_code, out, err = _scan(monkeypatch, capsys, "--gate", "--format", "concise")

    assert exit_code == 0
    assert out == ""
    assert _tail(err, 1)[0].startswith("Quality Gate: PASSED")

    (project / "app.py").write_text("import os\n" + CLEAN_APP, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
    exit_code, out, err = _scan(
        monkeypatch, capsys, "--gate", "--strict", "--format", "concise"
    )

    assert exit_code == 1
    assert "Quality Gate" not in out
    block = _verdict_block(err, "Quality Gate: FAILED")
    assert block[1] == "   • Strict mode: 1 issue found"
    assert "app.py:1" in block[2]


def test_plain_scan_exit_two_explains_itself_without_a_gate(
    project, monkeypatch, capsys, offline_osv
):
    _write_pnpm_gap(project)

    exit_code, out, _err = _scan(monkeypatch, capsys, "--sca")

    assert exit_code == 2
    block = _verdict_block(out, "Scan: INCOMPLETE")
    assert block[0] == "Scan: INCOMPLETE — required analysis did not finish (exit 2)"
    assert f"   • {LOCKFILE_REASON}" in block
    assert "Quality Gate" not in out


def test_strict_without_gate_ends_with_its_verdict(project, monkeypatch, capsys):
    (project / "app.py").write_text("import os\n" + CLEAN_APP, encoding="utf-8")  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path

    exit_code, out, _err = _scan(monkeypatch, capsys, "--strict")

    assert exit_code == 1
    block = _verdict_block(out, "Quality Gate: FAILED")
    assert block[1] == "   • Strict mode: 1 issue found"


def test_unresolvable_policy_base_gate_says_could_not_decide(
    project, monkeypatch, capsys
):
    exit_code, out, err = _scan(
        monkeypatch, capsys, "--gate", "--diff-base", "no-such-ref", "--format", "json"
    )

    assert exit_code == 2
    assert out == ""
    assert "skylos: error: Could not resolve PR policy base: no-such-ref" in err
    block = _verdict_block(err, INCOMPLETE_VERDICT)
    assert block[1] == "   • Could not resolve PR policy base: no-such-ref"
    assert "fetch it" in block[2]


def test_failed_diff_gate_says_could_not_decide(project, monkeypatch, capsys):
    from contextlib import nullcontext
    from unittest.mock import Mock

    # The base policy resolves, but Git cannot diff against the base.
    monkeypatch.setattr(
        "skylos.cicd.policy.base_policy_context", lambda *_args: nullcontext()
    )
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *_args, **_kwargs: Mock(returncode=128, stdout="", stderr="bad ref"),
    )

    exit_code, out, err = _scan(
        monkeypatch, capsys, "--gate", "--diff-base", "origin/main", "--format", "json"
    )

    assert exit_code == 2
    assert out == ""
    block = _verdict_block(err, INCOMPLETE_VERDICT)
    assert block[1].startswith("   • Skylos diff unavailable: Git diff failed")
    assert "--diff-base" in block[2]


def test_analysis_crash_gate_says_could_not_decide(project, monkeypatch, capsys):
    def crash(*args, **kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(cli, "run_analyze", crash)

    exit_code, out, _err = _scan(monkeypatch, capsys, "--gate")

    assert exit_code == 1
    block = _verdict_block(out, "Quality Gate: ERROR")
    assert block[0] == "Quality Gate: ERROR — could not decide (exit 1)"
    assert block[1] == "   • Error during analysis: engine exploded"


# `skylos cicd gate` ----------------------------------------------------------


def test_cicd_gate_input_with_incomplete_scan_explains_itself(
    project, monkeypatch, capsys
):
    report = project / "report.json"
    report.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        json.dumps(
            _sca_result(
                unresolved_lockfile_dependency_count=1,
                lockfile_issues=[
                    {
                        "file": "pnpm-lock.yaml",
                        "line": 6,
                        "dependency": "left-pad",
                        "reason": "missing_locked_dependency",
                    }
                ],
            )
        ),
        encoding="utf-8",
    )

    exit_code, out, _err = _run(
        monkeypatch, capsys, "cicd", "gate", "--input", str(report), "--advisory"
    )

    assert exit_code == 2
    block = _verdict_block(out, INCOMPLETE_VERDICT)
    assert block[2] == f"   • {LOCKFILE_REASON}"
    assert block[3] == "       pnpm-lock.yaml:6  missing locked dependency: left-pad"


def test_cicd_gate_unreadable_input_says_could_not_decide(project, monkeypatch, capsys):
    exit_code, out, _err = _run(
        monkeypatch, capsys, "cicd", "gate", "--input", "missing.json"
    )

    assert exit_code == 1
    block = _verdict_block(out, "Quality Gate: ERROR")
    assert block[1].startswith("   • Error reading missing.json:")
