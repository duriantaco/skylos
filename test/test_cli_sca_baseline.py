"""Exercise dependency baselines through the real CLI with mocked OSV HTTP."""

import json
import os
import subprocess

import pytest

import skylos.cli as cli
from skylos.core.baseline import save_baseline
from skylos.core.git_safety import read_only_git_environment
from skylos.rules.sca import vulnerability_scanner as sca
from test.test_cli_sca_sarif import (
    ADVISORY_ID,
    RULE_ID,
    _OSVTransport,
    _Response,
    _run_cli,
    _write_lockfile,
    project as project,
)


class _BaselineOSVTransport(_OSVTransport):
    def __init__(self):
        super().__init__()
        self.advisory_ids = [ADVISORY_ID]
        self.vulnerable_packages = None

    def post(self, url, *, json, **kwargs):
        assert url == sca.OSV_BATCH_URL
        self.queries.extend(json["queries"])
        self.latest_queries = json["queries"]
        return _Response(
            {
                "results": [
                    {"vulns": [{"id": item} for item in self.advisory_ids]}
                    if self.vulnerable_packages is None
                    or query["package"]["name"] in self.vulnerable_packages
                    else {}
                    for query in json["queries"]
                ]
            }
        )

    def get(self, url, **kwargs):
        advisory_id = url.rsplit("/", 1)[-1]
        assert url == f"https://api.osv.dev/v1/vulns/{advisory_id}"
        assert advisory_id in self.advisory_ids
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        self.advisory_requests.append(url)
        if self.fail_details:
            raise ConnectionError("test advisory detail service unavailable")
        return _Response(
            {
                "id": advisory_id,
                "summary": "Test dependency advisory",
                "database_specific": {"severity": self.severity_label},
                "affected": [
                    {
                        "package": query["package"],
                        "ranges": [
                            {
                                "type": "SEMVER"
                                if query["package"]["ecosystem"] == "npm"
                                else "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                            }
                        ],
                    }
                    for query in self.latest_queries
                ],
            }
        )


@pytest.fixture
def osv(monkeypatch):
    transport = _BaselineOSVTransport()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


@pytest.fixture(autouse=True)
def local_baseline_environment(monkeypatch):
    """Local cases stay local even when pytest itself runs on a CI worker."""
    for key in (
        "CI",
        "GITHUB_RUN_ID",
        "CI_PIPELINE_ID",
        "BUILD_BUILDID",
        "CIRCLE_WORKFLOW_ID",
        "BUILD_TAG",
    ):
        monkeypatch.delenv(key, raising=False)


def _git(project, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Skylos Test",
            "-c",
            "user.email=skylos-test@example.invalid",
            *args,
        ],
        cwd=project,
        env=read_only_git_environment(),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_baseline(project):
    _git(project, "init", "-q")
    _git(project, "add", ".skylos/baseline.json")
    _git(project, "commit", "-qm", "trusted dependency baseline")
    return _git(project, "rev-parse", "HEAD")


def _capture_baseline(project, monkeypatch):
    exit_code, result, sarif = _run_cli(project, monkeypatch)
    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    return save_baseline(project, result), result


def _run_baseline_command(project, monkeypatch, *extra_args):
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", "baseline", str(project), *extra_args]
    )
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


def _assert_clean_baseline(result, sarif):
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["dependency_vulnerabilities_count"] == 0
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert [
        item["rule_id"] for item in result["baseline_dependency_vulnerabilities"]
    ] == [RULE_ID]
    receipt = result["analysis_summary"]["dependency_baseline"]
    assert receipt["status"] == "applied"
    assert receipt["existing_count"] == 1
    assert receipt["new_count"] == 0


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_baseline_filters_known_dependency_from_json_sarif_and_gate(
    project, monkeypatch, osv, kind
):
    _write_lockfile(project, kind)
    _, original = _capture_baseline(project, monkeypatch)

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 0
    _assert_clean_baseline(result, sarif)
    assert (
        result["analysis_summary"]["sca_coverage"]
        == original["analysis_summary"]["sca_coverage"]
    )


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_baseline_command_sca_roundtrip(project, monkeypatch, osv, kind):
    _write_lockfile(project, kind)
    exit_code = _run_baseline_command(project, monkeypatch, "--sca")

    assert exit_code == 0
    assert osv.queries
    baseline = json.loads((project / ".skylos" / "baseline.json").read_text())
    assert baseline["counts"]["dependency_vulnerabilities"] == 1

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")
    assert exit_code == 0
    _assert_clean_baseline(result, sarif)


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_baseline_command_requires_sca_opt_in(project, monkeypatch, osv, kind):
    _write_lockfile(project, kind)

    assert _run_baseline_command(project, monkeypatch) == 0
    assert osv.queries == []
    assert osv.advisory_requests == []

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")
    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


@pytest.mark.parametrize("failure", ["details", "malformed_lock"])
def test_cli_baseline_command_refuses_to_overwrite_after_incomplete_scan(
    project, monkeypatch, osv, failure
):
    lockfile, *_ = _write_lockfile(project, "npm")
    baseline_path, _ = _capture_baseline(project, monkeypatch)
    original_baseline = baseline_path.read_bytes()
    if failure == "details":
        osv.fail_details = True
    else:
        lockfile.write_text("{invalid", encoding="utf-8")

    assert _run_baseline_command(project, monkeypatch, "--sca") == 2
    assert baseline_path.read_bytes() == original_baseline


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_ignores_line_shifts(project, monkeypatch, osv, kind):
    lockfile, *_ = _write_lockfile(project, kind)
    _, original = _capture_baseline(project, monkeypatch)
    original_line = original["dependency_vulnerabilities"][0]["line"]
    lockfile.write_text(
        "\n\n\n" + lockfile.read_text(encoding="utf-8"), encoding="utf-8"
    )

    unfiltered_exit, unfiltered, _ = _run_cli(project, monkeypatch)
    assert unfiltered_exit == 1
    assert unfiltered["dependency_vulnerabilities"][0]["line"] == original_line + 3

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")
    assert exit_code == 0
    _assert_clean_baseline(result, sarif)


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_survives_checkout_relocation(
    project, monkeypatch, osv, kind
):
    lockfile, *_ = _write_lockfile(project, kind)
    baseline_path, _ = _capture_baseline(project, monkeypatch)
    checkout = project.parent / "another-checkout"
    checkout.mkdir()
    (  # skylos: ignore[SKY-D324] fresh checkout under pytest tmp_path
        checkout / lockfile.name
    ).write_bytes(lockfile.read_bytes())
    (checkout / ".skylos").mkdir()
    (  # skylos: ignore[SKY-D324] fresh directory under pytest tmp_path
        checkout / ".skylos" / "baseline.json"
    ).write_bytes(baseline_path.read_bytes())
    monkeypatch.chdir(checkout)

    exit_code, result, sarif = _run_cli(checkout, monkeypatch, "--baseline")

    assert exit_code == 0
    _assert_clean_baseline(result, sarif)
    assert osv.queries[-1] == osv.queries[0]


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_keeps_new_advisory(project, monkeypatch, osv, kind):
    _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    new_advisory = "GHSA-xxxx-yyyy-zzzz"
    osv.advisory_ids.append(new_advisory)

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    expected_rule = f"SKY-SCA-{new_advisory}"
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        expected_rule
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [expected_rule]
    assert result["analysis_summary"]["dependency_vulnerabilities_count"] == 1


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_keeps_different_package_version(
    project, monkeypatch, osv, kind
):
    lockfile, _, old_version, _ = _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    new_version = "4.17.19" if kind == "npm" else "1.26.3"
    lockfile.write_text(
        lockfile.read_text(encoding="utf-8").replace(old_version, new_version),
        encoding="utf-8",
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert len(result["dependency_vulnerabilities"]) == 1
    assert result["dependency_vulnerabilities"][0]["metadata"]["package_version"] == (
        new_version
    )
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


def test_cli_dependency_baseline_keeps_changed_advisory_severity(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    osv.severity_label = "CRITICAL"

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert len(result["dependency_vulnerabilities"]) == 1
    assert result["dependency_vulnerabilities"][0]["severity"] == "CRITICAL"
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


def test_cli_dependency_baseline_keeps_package_json_dev_promoted_to_runtime(
    project, monkeypatch, osv
):
    manifest = project / "package.json"
    payload = {
        "name": "local-app",
        "version": "1.0.0",
        "devDependencies": {"lodash": "4.17.20"},
    }
    manifest.write_text(  # skylos: ignore[SKY-D324] pytest-owned package.json; no symlink creation
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    _, original = _capture_baseline(project, monkeypatch)
    assert (
        original["dependency_vulnerabilities"][0]["metadata"]["dependency_section"]
        == "devDependencies"
    )
    unchanged_exit, unchanged, unchanged_sarif = _run_cli(
        project, monkeypatch, "--baseline"
    )
    assert unchanged_exit == 0
    _assert_clean_baseline(unchanged, unchanged_sarif)

    payload["dependencies"] = payload.pop("devDependencies")
    manifest.write_text(  # skylos: ignore[SKY-D324] same pytest-owned regular file created above
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert (
        result["dependency_vulnerabilities"][0]["metadata"]["dependency_section"]
        == "dependencies"
    )
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_dependency_baseline_keeps_new_transitive_npm_install_path(
    project, monkeypatch, osv
):
    lockfile = project / "package-lock.json"
    original_path = "node_modules/parent-a/node_modules/lodash"
    additional_path = "node_modules/parent-b/node_modules/lodash"
    payload = {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "local-app",
                "dependencies": {"parent-a": "1.0.0", "parent-b": "1.0.0"},
            },
            "node_modules/parent-a": {
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"},
            },
            "node_modules/parent-b": {"version": "1.0.0"},
            original_path: {"version": "4.17.20"},
        },
    }
    osv.vulnerable_packages = {"lodash"}
    lockfile.write_text(  # skylos: ignore[SKY-D324] pytest-owned package-lock.json under tmp_path
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    _, original = _capture_baseline(project, monkeypatch)
    original_metadata = original["dependency_vulnerabilities"][0]["metadata"]
    assert original_metadata["package_path"] == original_path
    assert original_metadata["dependency_kind"] == "transitive"
    assert not original_metadata.get("dependency_roots")
    unchanged_exit, unchanged, unchanged_sarif = _run_cli(
        project, monkeypatch, "--baseline"
    )
    assert unchanged_exit == 0
    _assert_clean_baseline(unchanged, unchanged_sarif)

    payload["packages"]["node_modules/parent-b"]["dependencies"] = {"lodash": "4.17.20"}
    payload["packages"][additional_path] = {"version": "4.17.20"}
    lockfile.write_text(  # skylos: ignore[SKY-D324] same pytest-owned regular lockfile created above
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    occurrences = result["dependency_vulnerabilities"][0]["metadata"][
        "dependency_occurrences"
    ]
    assert {item["package_path"] for item in occurrences} == {
        original_path,
        additional_path,
    }
    assert all(not item.get("dependency_roots") for item in occurrences)
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["baseline_dependency_vulnerabilities"] == []


@pytest.mark.parametrize(
    "field,original_value,expanded_value,metadata_key",
    [
        ("requires-python", ">=3.11", ">=3.10", "requires_python"),
        (
            "resolution-markers",
            ["python_full_version >= '3.11'"],
            ["python_full_version >= '3.10'"],
            "lockfile_resolution_markers",
        ),
        (
            "supported-markers",
            ["sys_platform == 'linux'"],
            ["sys_platform == 'linux'", "sys_platform == 'darwin'"],
            "lockfile_supported_markers",
        ),
        (
            "required-markers",
            ["sys_platform == 'linux'"],
            ["sys_platform == 'linux'", "sys_platform == 'darwin'"],
            "lockfile_required_markers",
        ),
    ],
)
def test_cli_uv_dependency_baseline_keeps_expanded_global_environment(
    project, monkeypatch, osv, field, original_value, expanded_value, metadata_key
):
    lockfile, *_ = _write_lockfile(project, "uv")
    original_declaration = f"{field} = {json.dumps(original_value)}\n"
    text = lockfile.read_text(encoding="utf-8").replace(
        "[[package]]", original_declaration + "[[package]]", 1
    )
    lockfile.write_text(text, encoding="utf-8")
    _, original = _capture_baseline(project, monkeypatch)
    assert original["dependency_vulnerabilities"][0]["metadata"][metadata_key] == (
        original_value
    )
    unchanged_exit, unchanged, unchanged_sarif = _run_cli(
        project, monkeypatch, "--baseline"
    )
    assert unchanged_exit == 0
    _assert_clean_baseline(unchanged, unchanged_sarif)

    lockfile.write_text(
        text.replace(
            original_declaration, f"{field} = {json.dumps(expanded_value)}\n", 1
        ),
        encoding="utf-8",
    )
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert result["dependency_vulnerabilities"][0]["metadata"][metadata_key] == (
        expanded_value
    )
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_dependency_baseline_keeps_new_package_with_same_advisory(
    project, monkeypatch, osv
):
    lockfile, *_ = _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    payload = json.loads(lockfile.read_text(encoding="utf-8"))
    payload["packages"][""]["dependencies"]["minimist"] = "0.0.8"
    payload["packages"]["node_modules/minimist"] = {"version": "0.0.8"}
    lockfile.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert len(result["dependency_vulnerabilities"]) == 1
    assert result["dependency_vulnerabilities"][0]["metadata"]["package_name"] == (
        "minimist"
    )
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_keeps_new_manifest_occurrence(
    project, monkeypatch, osv, kind
):
    lockfile, *_ = _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    child = project / "another-app"
    child.mkdir()
    additional_lockfile = child / lockfile.name
    additional_lockfile.write_bytes(  # skylos: ignore[SKY-D324] fresh child directory under pytest tmp_path
        lockfile.read_bytes()
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert len(result["dependency_vulnerabilities"]) == 1
    occurrences = result["dependency_vulnerabilities"][0]["metadata"][
        "dependency_occurrences"
    ]
    assert {item["file"] for item in occurrences} == {
        str(lockfile),
        str(additional_lockfile),
    }
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_dependency_baseline_keeps_new_workspace_consumer(
    project, monkeypatch, osv, kind
):
    lockfile, name, version, _ = _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    if kind == "npm":
        payload = json.loads(lockfile.read_text(encoding="utf-8"))
        payload["packages"][""]["workspaces"] = ["packages/*"]
        payload["packages"]["packages/worker"] = {
            "name": "worker",
            "version": "1.0.0",
            "dependencies": {name: version},
        }
        payload["packages"]["node_modules/worker"] = {
            "resolved": "packages/worker",
            "link": True,
        }
        lockfile.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        expected_root = "packages/worker"
    else:
        text = lockfile.read_text(encoding="utf-8").replace(
            "[[package]]",
            '[manifest]\nmembers = ["local-app", "worker"]\n[[package]]',
            1,
        )
        lockfile.write_text(
            text
            + '[[package]]\nname = "worker"\nversion = "1.0.0"\n'
            + 'source = { editable = "packages/worker" }\n'
            + f'dependencies = [{{ name = "{name}" }}]\n',
            encoding="utf-8",
        )
        expected_root = "worker"

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert len(result["dependency_vulnerabilities"]) == 1
    assert (
        expected_root
        in result["dependency_vulnerabilities"][0]["metadata"]["dependency_roots"]
    )
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


def test_cli_uv_baseline_ignores_package_table_order(project, monkeypatch, osv):
    lockfile, *_ = _write_lockfile(project, "uv")
    _, original = _capture_baseline(project, monkeypatch)
    header, root_package, dependency = lockfile.read_text(encoding="utf-8").split(
        "[[package]]"
    )
    lockfile.write_text(
        header + "[[package]]" + dependency + "[[package]]" + root_package,
        encoding="utf-8",
    )
    unfiltered_exit, unfiltered, _ = _run_cli(project, monkeypatch)
    assert unfiltered_exit == 1
    assert (
        unfiltered["dependency_vulnerabilities"][0]["metadata"]["package_path"]
        != (original["dependency_vulnerabilities"][0]["metadata"]["package_path"])
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 0
    _assert_clean_baseline(result, sarif)


def test_cli_legacy_baseline_fingerprints_cannot_hide_dependency_findings(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    baseline_path, original = _capture_baseline(project, monkeypatch)
    finding = original["dependency_vulnerabilities"][0]
    baseline_path.write_text(
        json.dumps(
            {
                "counts": {"dependency_vulnerabilities": 1},
                "fingerprints": [
                    f"{finding['rule_id']}:{finding['file']}:{finding['line']}"
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


@pytest.mark.parametrize("kind", ["npm", "uv"])
@pytest.mark.parametrize("extra_args", [(), ("--force",)])
def test_cli_incomplete_advisory_lookup_preserves_known_finding_and_fails(
    project, monkeypatch, osv, kind, extra_args
):
    _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    osv.fail_details = True

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", *extra_args)

    assert exit_code == 2
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    metadata = result["dependency_vulnerabilities"][0]["metadata"]
    assert metadata["advisory_status"] == "unavailable"
    assert metadata["advisory_error"] == "advisory_transport_error"
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert result["analysis_summary"]["dependency_vulnerabilities_count"] == 1
    assert (
        result["analysis_summary"]["dependency_baseline"]["status"] == "scan_incomplete"
    )
    assert result["baseline_dependency_vulnerabilities"] == []


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_malformed_lockfile_cannot_pass_via_baseline_or_force(
    project, monkeypatch, osv, kind
):
    lockfile, *_ = _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    lockfile.write_text("{invalid" if kind == "npm" else "version = 999\n")
    osv.queries.clear()
    osv.advisory_requests.clear()

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", "--force")

    assert exit_code == 2
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert osv.queries == []
    assert osv.advisory_requests == []


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_one_broken_lockfile_preserves_other_known_dependency_findings(
    project, monkeypatch, osv, kind
):
    _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)
    broken_app = project / "broken-app"
    broken_app.mkdir()
    (  # skylos: ignore[SKY-D324] fresh child directory under pytest tmp_path
        broken_app / "package-lock.json"
    ).write_text("{invalid", encoding="utf-8")

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", "--force")

    assert exit_code == 2
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


@pytest.mark.parametrize("kind", ["npm", "uv"])
def test_cli_without_baseline_flag_keeps_known_findings(
    project, monkeypatch, osv, kind
):
    _write_lockfile(project, kind)
    _capture_baseline(project, monkeypatch)

    exit_code, result, sarif = _run_cli(project, monkeypatch)

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]


def test_cli_ci_baseline_without_ref_does_not_trust_worktree(project, monkeypatch, osv):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    monkeypatch.setenv("CI", "1")

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["analysis_summary"]["dependency_baseline"]["status"] == (
        "ci_ref_required"
    )
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_ci_baseline_reads_selected_commit_not_modified_worktree(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    base_commit = _commit_baseline(project)
    new_advisory = "GHSA-xxxx-yyyy-zzzz"
    osv.advisory_ids.append(new_advisory)
    current_exit, current, _ = _run_cli(project, monkeypatch)
    assert current_exit == 1
    assert len(current["dependency_vulnerabilities"]) == 2
    save_baseline(project, current)
    monkeypatch.setenv("CI", "1")

    exit_code, result, sarif = _run_cli(
        project, monkeypatch, "--baseline-ref", base_commit
    )

    assert exit_code == 1
    expected_rule = f"SKY-SCA-{new_advisory}"
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        expected_rule
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [expected_rule]
    receipt = result["analysis_summary"]["dependency_baseline"]
    assert receipt["status"] == "applied"
    assert receipt["existing_count"] == 1
    assert receipt["new_count"] == 1
    assert receipt["source"]["source"] == "git_ref"
    assert receipt["source"]["commit"] == base_commit


@pytest.mark.parametrize("ref", ["refs/heads/missing-baseline", "--invalid-ref"])
def test_cli_ci_baseline_ref_failure_never_falls_back_to_worktree(
    project, monkeypatch, osv, ref
):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    _commit_baseline(project)
    monkeypatch.setenv("CI", "1")

    exit_code, result, sarif = _run_cli(project, monkeypatch, f"--baseline-ref={ref}")

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    receipt = result["analysis_summary"]["dependency_baseline"]
    assert receipt["status"] == "unavailable"
    assert receipt["source"]["source"] == "git_ref"
    assert receipt["source"]["status"] == "unavailable"
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_strict_keeps_known_dependency_findings(project, monkeypatch, osv):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", "--strict")

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["analysis_summary"]["dependency_baseline"]["status"] == (
        "strict_requires_full_findings"
    )
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_explicit_upload_receives_all_dependency_findings(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    uploads = []

    def capture_upload(result, **kwargs):
        uploads.append(json.loads(json.dumps(result)))
        return {"success": True, "quality_gate_passed": True}

    monkeypatch.setattr(cli, "upload_report", capture_upload)
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline", "--upload")

    assert exit_code == 1
    assert len(uploads) == 1
    assert [item["rule_id"] for item in uploads[0]["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["analysis_summary"]["dependency_baseline"]["status"] == (
        "upload_requires_full_findings"
    )
    assert result["baseline_dependency_vulnerabilities"] == []


def test_cli_synced_policy_cannot_be_weakened_by_repo_baseline_or_config(
    project, monkeypatch, osv
):
    from skylos.config import dependency_baseline_policy_locked, load_config

    _write_lockfile(project, "npm")
    _capture_baseline(project, monkeypatch)
    (  # skylos: ignore[SKY-D324] fixture-owned .skylos directory under tmp_path
        project / ".skylos" / "config.yaml"
    ).write_text(
        "gate:\n"
        "  enabled: true\n"
        "  mode: enforce\n"
        "  max_dependency_vulnerabilities: 0\n",
        encoding="utf-8",
    )
    (  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        project / "pyproject.toml"
    ).write_text(
        "[tool.skylos]\n"
        "dependency_baseline_locked = false\n"
        "_dependency_baseline_locked = false\n"
        "[tool.skylos.gate]\n"
        "enabled = false\n"
        'mode = "advisory"\n'
        "max_dependency_vulnerabilities = 999\n",
        encoding="utf-8",
    )
    config = load_config(project)
    assert dependency_baseline_policy_locked(config) is True
    assert config["gate"]["max_dependency_vulnerabilities"] == 0
    assert config["gate"]["enabled"] is True

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--baseline")

    assert exit_code == 1
    assert [item["rule_id"] for item in result["dependency_vulnerabilities"]] == [
        RULE_ID
    ]
    assert [item["ruleId"] for item in sarif["runs"][0]["results"]] == [RULE_ID]
    assert result["analysis_summary"]["dependency_baseline"]["status"] == (
        "synced_policy_requires_full_findings"
    )
    assert result["baseline_dependency_vulnerabilities"] == []
