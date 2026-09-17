"""Real CLI GitLab reports, with OSV HTTP mocked and no target execution.

Malformed-location and category-forwarding cases wrap the real analyzer result
to exercise defensive output contracts that normal detectors must not produce.
"""

import json
import re

import pytest

import skylos.cli as cli
from skylos.core.baseline import save_baseline
from skylos.core.cli_shared import sanitize_addopts
from test.test_cli_sca_baseline import (
    _git,
    local_baseline_environment as local_baseline_environment,
)
from test.test_cli_sca_sarif import (
    RULE_ID,
    _write_lockfile,
    osv as osv,
    project as project,
)


_CATEGORY_IDS = {
    "unused_functions": "SKY-U001",
    "unused_imports": "SKY-U002",
    "unused_variables": "SKY-U003",
    "unused_classes": "SKY-U004",
    "unused_parameters": "SKY-U006",
    "unused_files": "SKY-E002",
    "unused_fixtures": "SKY-U000",
    "unused_exports": "SKY-E003",
    "forgotten": "SKY-U001",
    "danger": "SKY-D201",
    "reliability": "SKY-R001",
    "ai_defects": "SKY-L012",
    "quality": "SKY-Q301",
    "secrets": "SKY-S001",
    "custom_rules": "CUSTOM-GITLAB-FIXTURE",
    "circular_dependencies": "SKY-CIRC",
    "dependency_vulnerabilities": RULE_ID,
}


@pytest.fixture(autouse=True)
def _machine_output_safety(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    def no_progress(*args, **kwargs):
        pytest.fail("machine-readable GitLab output must not start progress rendering")

    monkeypatch.setattr(cli, "Progress", no_progress)


def _source(project, text, *, name="app.py"):
    path = project / name
    path.write_text(  # skylos: ignore[SKY-D324] all callers pass fresh pytest project directories
        text, encoding="utf-8"
    )
    return path


def _invoke(
    project,
    monkeypatch,
    capsys,
    *args,
    output=None,
    target=None,
    format_option="gitlab",
):
    command = [
        "skylos",
        str(project if target is None else target),
        "--no-provenance",
        "--no-grep-verify",
    ]
    if format_option is not None:
        command.extend(["--format", format_option])
    if output is not None:
        command.extend(["--output", str(output)])
    command.extend(args)
    monkeypatch.setattr(cli.sys, "argv", command)
    capsys.readouterr()
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _report(project, monkeypatch, capsys, *args, **kwargs):
    exit_code, stdout, stderr = _invoke(project, monkeypatch, capsys, *args, **kwargs)
    report = json.loads(stdout)
    assert isinstance(report, list)
    assert "\x1b" not in stdout
    for finding in report:
        assert isinstance(finding["description"], str) and finding["description"]
        assert isinstance(finding["check_name"], str) and finding["check_name"]
        assert re.fullmatch(r"[0-9a-f]{32,64}", finding["fingerprint"])
        assert finding["severity"] in {"info", "minor", "major", "critical", "blocker"}
        location = finding["location"]
        assert not location["path"].startswith(("/", "./"))
        assert ".." not in location["path"].split("/")
        assert type(location["lines"]["begin"]) is int
        assert location["lines"]["begin"] > 0
    return exit_code, report, stderr


def _mutate_analyzer_result(monkeypatch, change):
    run_analyze = cli.run_analyze

    def analyze_with_changed_result(*args, **kwargs):
        result = json.loads(run_analyze(*args, **kwargs))
        change(result)
        return json.dumps(result)

    monkeypatch.setattr(cli, "run_analyze", analyze_with_changed_result)


def _assert_incomplete(stderr):
    assert stderr.strip()
    assert "incomplete" in stderr.lower()


def test_gitlab_empty_scan_prints_only_a_json_array(project, monkeypatch, capsys):
    _source(project, 'raise AssertionError("static scanning must not execute this")\n')

    exit_code, report, stderr = _report(project, monkeypatch, capsys)

    assert exit_code == 0
    assert report == []
    assert not stderr.strip()


@pytest.mark.parametrize("addopts", [["--format", "gitlab"], ["--format=gitlab"]])
def test_gitlab_safe_addopts_preserve_the_format_without_allowing_side_effects(addopts):
    assert (
        sanitize_addopts(
            [*addopts, "--upload", "--output", "/not-a-test-output", "--trace"]
        )
        == addopts
    )


@pytest.mark.parametrize(
    "addopts", [["--format", "gitlab"], "--format=gitlab"], ids=["list", "string"]
)
def test_gitlab_format_from_project_addopts_reaches_the_real_cli(
    project, monkeypatch, capsys, addopts
):
    _source(project, 'eval("1 + 1")\n')
    _source(
        project,
        f"[tool.skylos]\naddopts = {json.dumps(addopts)}\n",
        name="pyproject.toml",
    )

    exit_code, report, stderr = _report(
        project, monkeypatch, capsys, "--danger", format_option=None
    )

    assert exit_code == 0
    assert [item["check_name"] for item in report] == ["SKY-D201"]
    assert not stderr.strip()


def test_explicit_json_format_overrides_gitlab_project_addopts(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')
    _source(
        project,
        '[tool.skylos]\naddopts = ["--format", "gitlab"]\n',
        name="pyproject.toml",
    )

    exit_code, stdout, _ = _invoke(
        project, monkeypatch, capsys, "--danger", format_option="json"
    )

    result = json.loads(stdout)
    assert exit_code == 0
    assert isinstance(result, dict)
    assert [item["rule_id"] for item in result["danger"]] == ["SKY-D201"]


def test_gitlab_output_file_is_an_array_and_stdout_is_empty(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')
    output = project.parent / "gl-code-quality-report.json"

    exit_code, stdout, stderr = _invoke(
        project, monkeypatch, capsys, "--danger", output=output
    )

    assert exit_code == 0
    assert stdout == ""
    assert not stderr.strip()
    report = json.loads(
        output.read_text(  # skylos: ignore[SKY-D325] bounded scanner report at a fresh pytest-owned path
            encoding="utf-8"
        )
    )
    assert [item["check_name"] for item in report] == ["SKY-D201"]
    assert report[0]["location"] == {"path": "app.py", "lines": {"begin": 1}}


def test_gitlab_real_dead_code_and_security_findings_are_exported(
    project, monkeypatch, capsys
):
    _source(project, 'def unused_helper():\n    return 1\n\neval("1 + 1")\n')

    exit_code, report, _ = _report(project, monkeypatch, capsys, "--danger")

    assert exit_code == 0
    ids = {item["check_name"] for item in report}
    assert {"SKY-U001", "SKY-D201"} <= ids
    assert {item["location"]["path"] for item in report} == {"app.py"}


@pytest.mark.parametrize(
    "flags,expected",
    [
        ([], 0),
        (["--gate"], 1),
        (["--strict"], 1),
        (["--gate", "--force"], 0),
        (["--strict", "--force"], 0),
    ],
)
def test_gitlab_preserves_gate_and_force_exit_codes(
    project, monkeypatch, capsys, flags, expected
):
    _source(project, 'eval("1 + 1")\n')
    _source(project, "[tool.skylos.gate]\nmax_high = 0\n", name="pyproject.toml")

    exit_code, report, _ = _report(project, monkeypatch, capsys, "--danger", *flags)

    assert exit_code == expected
    assert [item["check_name"] for item in report] == ["SKY-D201"]


def test_gitlab_has_no_automatic_upload_even_with_a_token(project, monkeypatch, capsys):
    monkeypatch.setenv("SKYLOS_TOKEN", "fixture-token-not-a-real-secret")
    _source(project, 'eval("1 + 1")\n')

    exit_code, report, _ = _report(project, monkeypatch, capsys, "--danger")

    # The imported project fixture fails immediately if upload_report is called.
    assert exit_code == 0
    assert report


@pytest.mark.parametrize("rule", ["SKY-U001", "SKY-D201", "SKY-D207"])
def test_gitlab_rule_selection_enables_and_filters_real_analyzers(
    project, monkeypatch, capsys, rule
):
    _source(
        project,
        "import hashlib\n\ndef unused_helper():\n    return 1\n"
        '\neval("1 + 1")\nhashlib.md5(b"fixture")\n',
    )

    exit_code, report, _ = _report(project, monkeypatch, capsys, "--select", rule)

    assert exit_code == 0
    assert report
    assert {item["check_name"] for item in report} == {rule}


def test_gitlab_rule_selection_with_no_matches_is_a_clean_array(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--select", "SKY-D207", "--strict"
    )

    assert exit_code == 0
    assert report == []


def test_gitlab_forwards_every_result_category_through_the_real_cli(
    project, monkeypatch, capsys
):
    source = _source(project, "pass\n" * len(_CATEGORY_IDS))

    def all_categories(result):
        for line, (category, rule_id) in enumerate(_CATEGORY_IDS.items(), 1):
            result[category] = [
                {
                    "rule_id": rule_id,
                    "file": str(source),
                    "line": line,
                    "name": f"fixture_{category}",
                    "message": f"Fixture category {category}",
                    "severity": "HIGH",
                }
            ]
        result["analysis_summary"]["sca_coverage"] = {
            "complete": True,
            "status": "complete",
        }

    _mutate_analyzer_result(monkeypatch, all_categories)

    exit_code, report, _ = _report(project, monkeypatch, capsys)

    assert exit_code == 0
    assert {item["location"]["lines"]["begin"] for item in report} == set(
        range(1, len(_CATEGORY_IDS) + 1)
    )
    assert {item["check_name"] for item in report} == set(_CATEGORY_IDS.values())


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_gitlab_sca_and_optional_sarif_keep_the_same_advisory(
    project, monkeypatch, capsys, osv, kind
):
    lockfile, *_ = _write_lockfile(project, kind)
    sarif_path = project.parent / "gitlab-companion.sarif"

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--sca", "--gate", "--sarif", str(sarif_path)
    )

    assert exit_code == 1
    assert [item["check_name"] for item in report] == [RULE_ID]
    assert report[0]["location"]["path"] == lockfile.name
    sarif = json.loads(
        sarif_path.read_text(  # skylos: ignore[SKY-D325] bounded scanner report at a fresh pytest-owned path
            encoding="utf-8"
        )
    )
    exported = sarif["runs"][0]["results"]
    assert [item["ruleId"] for item in exported] == [RULE_ID]
    physical = exported[0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == report[0]["location"]["path"]
    assert physical["region"]["startLine"] == report[0]["location"]["lines"]["begin"]


@pytest.mark.parametrize("force", [False, True])
def test_gitlab_sca_detail_failure_retains_findings_and_exits_two(
    project, monkeypatch, capsys, osv, force
):
    _write_lockfile(project, "npm")
    osv.fail_details = True

    exit_code, report, stderr = _report(
        project,
        monkeypatch,
        capsys,
        "--sca",
        "--gate",
        *(("--force",) if force else ()),
    )

    assert exit_code == 2
    assert [item["check_name"] for item in report] == [RULE_ID]
    _assert_incomplete(stderr)


def test_gitlab_sca_clean_response_preserves_exit_zero(
    project, monkeypatch, capsys, osv
):
    _write_lockfile(project, "npm")
    osv.vulnerable = False

    exit_code, report, stderr = _report(project, monkeypatch, capsys, "--sca", "--gate")

    assert exit_code == 0
    assert report == []
    assert not stderr.strip()


@pytest.mark.parametrize("force", [False, True])
def test_gitlab_syntax_error_is_incomplete_and_keeps_valid_findings(
    project, monkeypatch, capsys, force
):
    _source(project, 'eval("1 + 1")\n')
    _source(project, "def broken(:\n", name="broken.py")

    exit_code, report, stderr = _report(
        project, monkeypatch, capsys, "--danger", *(("--force",) if force else ())
    )

    assert exit_code == 2
    assert "SKY-D201" in {item["check_name"] for item in report}
    _assert_incomplete(stderr)


def test_gitlab_rule_selection_cannot_hide_incomplete_analysis(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')
    _source(project, "def broken(:\n", name="broken.py")

    exit_code, report, stderr = _report(
        project, monkeypatch, capsys, "--select", "SKY-D207", "--force"
    )

    assert exit_code == 2
    assert report == []
    _assert_incomplete(stderr)


@pytest.mark.parametrize(
    "bad_location", ["outside", "missing_file", "missing_line", "zero_line"]
)
@pytest.mark.parametrize("force", [False, True])
def test_gitlab_invalid_locations_fail_closed_without_dropping_valid_findings(
    project, monkeypatch, capsys, bad_location, force
):
    source = _source(project, 'eval("1 + 1")\n')

    def invalid_location(result):
        invalid = {
            "rule_id": "SKY-D202",
            "file": str(source),
            "line": 1,
            "message": "Fixture with invalid source location",
            "severity": "HIGH",
        }
        if bad_location == "outside":
            invalid["file"] = str(project.parent / "outside.py")
        elif bad_location == "zero_line":
            invalid["line"] = 0
        else:
            invalid.pop("file" if bad_location == "missing_file" else "line")
        result["danger"].append(invalid)

    _mutate_analyzer_result(monkeypatch, invalid_location)

    exit_code, report, stderr = _report(
        project, monkeypatch, capsys, "--danger", *(("--force",) if force else ())
    )

    assert exit_code == 2
    assert [item["check_name"] for item in report] == ["SKY-D201"]
    _assert_incomplete(stderr)


def test_gitlab_only_unrepresentable_findings_cannot_look_like_a_successful_clean_scan(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')

    def remove_locations(result):
        for item in result["danger"]:
            item.pop("file", None)
            item.pop("line", None)

    _mutate_analyzer_result(monkeypatch, remove_locations)

    exit_code, report, stderr = _report(project, monkeypatch, capsys, "--danger")

    assert exit_code == 2
    assert report == []
    _assert_incomplete(stderr)


@pytest.mark.parametrize("output_kind", ["gitlab", "sarif"])
def test_gitlab_rejects_symlink_outputs_without_modifying_the_target(
    project, monkeypatch, capsys, output_kind
):
    _source(project, 'eval("1 + 1")\n')
    victim = _source(project.parent, "KEEP", name="existing-report.json")
    linked_output = project.parent / "linked-output.json"
    try:
        linked_output.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    args = ["--danger"]
    kwargs = {}
    if output_kind == "gitlab":
        kwargs["output"] = linked_output
    else:
        args.extend(["--sarif", str(linked_output)])
    exit_code, _, _ = _invoke(project, monkeypatch, capsys, *args, **kwargs)

    assert exit_code != 0
    assert linked_output.is_symlink()
    assert (
        victim.read_text(  # skylos: ignore[SKY-D325] fixed pytest-owned KEEP file, not the symlink
            encoding="utf-8"
        )
        == "KEEP"
    )


def test_gitlab_fingerprints_are_stable_across_checkout_roots(
    project, monkeypatch, capsys
):
    text = 'def unused_helper():\n    return 1\n\neval("1 + 1")\n'
    _source(project, text)
    copy = project.parent / "relocated-checkout"
    copy.mkdir()
    _source(copy, text)
    _, first, _ = _report(project, monkeypatch, capsys, "--danger")
    monkeypatch.chdir(copy)

    _, second, _ = _report(copy, monkeypatch, capsys, "--danger")

    assert first
    assert {item["fingerprint"] for item in first} == {
        item["fingerprint"] for item in second
    }


def test_gitlab_fingerprints_are_stable_when_analyzer_findings_are_reordered(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\nexec("pass")\n')
    _, first, _ = _report(project, monkeypatch, capsys, "--danger")

    def reverse_findings(result):
        result["danger"].reverse()

    _mutate_analyzer_result(monkeypatch, reverse_findings)

    _, second, _ = _report(project, monkeypatch, capsys, "--danger")

    assert len(first) == 2
    assert {item["fingerprint"] for item in first} == {
        item["fingerprint"] for item in second
    }


def test_gitlab_sca_baseline_filters_known_findings_but_not_incomplete_scans(
    project, monkeypatch, capsys, osv
):
    _write_lockfile(project, "npm")
    from skylos.analyzer import analyze

    baseline = json.loads(analyze(str(project), enable_sca=True, grep_verify=False))
    save_baseline(project, baseline)
    capsys.readouterr()

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--sca", "--gate", "--baseline"
    )

    assert exit_code == 0
    assert report == []
    osv.fail_details = True
    exit_code, report, stderr = _report(
        project, monkeypatch, capsys, "--sca", "--gate", "--baseline", "--force"
    )
    assert exit_code == 2
    assert [item["check_name"] for item in report] == [RULE_ID]
    _assert_incomplete(stderr)


def test_gitlab_security_baseline_keeps_only_new_findings(project, monkeypatch, capsys):
    _source(project, 'eval("1 + 1")\n')
    _source(project, "[tool.skylos.gate]\nmax_high = 0\n", name="pyproject.toml")
    from skylos.analyzer import analyze

    baseline = json.loads(analyze(str(project), enable_danger=True, grep_verify=False))
    save_baseline(project, baseline)
    _source(project, 'eval("1 + 1")\nexec("pass")\n')

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--danger", "--gate", "--baseline"
    )

    assert exit_code == 1
    assert [item["check_name"] for item in report] == ["SKY-D202"]


def test_gitlab_diff_uses_actual_git_changes_without_changing_report_paths(
    project, monkeypatch, capsys
):
    _git(project, "init", "-q")
    _source(project, 'eval("1 + 1")\n')
    _git(project, "add", "app.py")
    _git(project, "commit", "-qm", "base fixture")
    base = _git(project, "rev-parse", "HEAD")
    _source(project, 'eval("1 + 1")\nexec("pass")\n')
    _git(project, "add", "app.py")
    _git(project, "commit", "-qm", "changed fixture")

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--danger", "--diff", base
    )

    assert exit_code == 0
    assert [item["check_name"] for item in report] == ["SKY-D202"]
    assert report[0]["location"] == {"path": "app.py", "lines": {"begin": 2}}


def test_gitlab_single_file_target_reports_repository_relative_path(
    project, monkeypatch, capsys
):
    _git(project, "init", "-q")
    package = project / "package"
    package.mkdir()
    source = _source(package, 'eval("1 + 1")\n')

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--danger", target=source
    )

    assert exit_code == 0
    assert [item["location"]["path"] for item in report] == ["package/app.py"]


def test_existing_json_format_still_emits_the_analyzer_object(
    project, monkeypatch, capsys
):
    _source(project, 'eval("1 + 1")\n')

    exit_code, stdout, _ = _invoke(
        project, monkeypatch, capsys, "--danger", "--format", "json"
    )

    result = json.loads(stdout)
    assert exit_code == 0
    assert isinstance(result, dict)
    assert [item["rule_id"] for item in result["danger"]] == ["SKY-D201"]


@pytest.mark.parametrize("legacy_flag", ["--json", "--llm", "--github"])
def test_gitlab_rejects_conflicting_legacy_output_flags_before_analysis(
    project, monkeypatch, capsys, legacy_flag
):
    _source(project, 'eval("1 + 1")\n')

    def no_analysis(*args, **kwargs):
        pytest.fail("conflicting report formats must be rejected before analysis")

    monkeypatch.setattr(cli, "run_analyze", no_analysis)

    exit_code, stdout, stderr = _invoke(project, monkeypatch, capsys, legacy_flag)

    assert exit_code == 2
    assert stdout == ""
    assert stderr.strip()


@pytest.mark.parametrize(
    "display_args",
    [
        ("--category", "dependency"),
        ("--severity", "critical"),
        ("--file-filter", "not-a-source"),
    ],
)
def test_gitlab_display_filters_do_not_bypass_the_original_gate(
    project, monkeypatch, capsys, display_args
):
    _source(project, 'eval("1 + 1")\n')
    _source(project, "[tool.skylos.gate]\nmax_high = 0\n", name="pyproject.toml")

    exit_code, report, _ = _report(
        project, monkeypatch, capsys, "--danger", "--gate", *display_args
    )

    assert exit_code == 1
    assert report == []
