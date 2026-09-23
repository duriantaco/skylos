"""Exercise SCA through the real CLI/analyzer, with only OSV HTTP replaced."""

import json

import pytest

import skylos.cli as cli
from skylos.core.safe_cache_io import read_text_no_symlink, write_text_no_symlink
from skylos.rules.sca import vulnerability_scanner as sca


ADVISORY_ID = "GHSA-29mw-wpgm-hmr9"
RULE_ID = f"SKY-SCA-{ADVISORY_ID}"


class _Response:
    status_code = 200
    headers = {"Content-Type": "application/json"}

    def __init__(self, payload):
        self.payload = payload
        self.content = json.dumps(payload).encode("utf-8")

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload

    def iter_content(self, chunk_size=8192):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self):
        pass


class _OSVTransport:
    def __init__(self):
        self.queries = []
        self.advisory_requests = []
        self.fail_details = False
        self.vulnerable = True
        self.severity_label = "HIGH"
        self.numeric_score = None

    def post(self, url, *, json, **kwargs):
        assert url == sca.OSV_BATCH_URL
        self.queries.extend(json["queries"])
        return _Response(
            {
                "results": [
                    {"vulns": [{"id": ADVISORY_ID}]} if self.vulnerable else {}
                    for _ in json["queries"]
                ]
            }
        )

    def get(self, url, **kwargs):
        assert url == f"https://api.osv.dev/v1/vulns/{ADVISORY_ID}"
        self.advisory_requests.append(url)
        if self.fail_details:
            raise ConnectionError("test advisory detail service unavailable")
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        return _Response(
            {
                "id": ADVISORY_ID,
                "summary": "Test dependency advisory",
                "aliases": ["CVE-2020-28500"],
                "database_specific": {
                    **(
                        {"severity": self.severity_label} if self.severity_label else {}
                    ),
                    **(
                        {"cvss_score": self.numeric_score}
                        if self.numeric_score is not None
                        else {}
                    ),
                },
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
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
                    for query in self.queries
                ],
                "references": [
                    {
                        "type": "ADVISORY",
                        "url": f"https://osv.dev/vulnerability/{ADVISORY_ID}",
                    }
                ],
            }
        )


@pytest.fixture
def project(tmp_path, monkeypatch):
    path = tmp_path / "project"
    path.mkdir()
    monkeypatch.chdir(path)
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)

    def no_upload(*args, **kwargs):
        pytest.fail("CLI regression test must not upload anything")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    return path


@pytest.fixture
def osv(monkeypatch):
    transport = _OSVTransport()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


def _write_lockfile(project, kind):
    if kind in {"npm", "shrinkwrap"}:
        path = project / (
            "npm-shrinkwrap.json" if kind == "shrinkwrap" else "package-lock.json"
        )
        path.write_text(  # skylos: ignore[SKY-D324] all callers use the pytest project fixture
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "local-app",
                            "dependencies": {"lodash": "^4.17.20"},
                        },
                        "node_modules/lodash": {"version": "4.17.20"},
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return path, "lodash", "4.17.20", "npm"

    path = project / "uv.lock"
    path.write_text(  # skylos: ignore[SKY-D324] all callers use the pytest project fixture
        "version = 1\nrevision = 3\n"
        '[[package]]\nname = "local-app"\nversion = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = [{ name = "urllib3" }]\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    return path, "urllib3", "1.26.4", "PyPI"


def _run_cli(project, monkeypatch, *extra_args, gate=True):
    json_path = project.parent / "report.json"
    sarif_path = project.parent / "report.sarif"
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(project),
            "--sca",
            *(("--gate",) if gate else ()),
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--output",
            str(json_path),
            "--sarif",
            str(sarif_path),
            *extra_args,
        ],
    )
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    json_report = read_text_no_symlink(json_path, max_bytes=5_000_000)
    sarif_report = read_text_no_symlink(sarif_path, max_bytes=5_000_000)
    assert json_report is not None
    assert sarif_report is not None
    return (
        exit_code,
        json.loads(json_report),
        json.loads(sarif_report),
    )


def _assert_matching_dependency_reports(result, sarif, lockfile):
    json_findings = result["dependency_vulnerabilities"]
    sarif_findings = sarif["runs"][0]["results"]
    assert (
        [item["ruleId"] for item in sarif_findings]
        == [item["rule_id"] for item in json_findings]
        == [RULE_ID]
    )
    finding = json_findings[0]
    exported = sarif_findings[0]
    assert finding["file"] == str(lockfile)
    location = exported["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == lockfile.name
    assert location["region"]["startLine"] == finding["line"] > 1
    assert exported["properties"]["category"] == "DEPENDENCY"
    metadata = exported["properties"]["skylos_metadata"]
    for key in (
        "vuln_id",
        "package_name",
        "package_version",
        "ecosystem",
        "lockfile_version",
        "dependency_kind",
    ):
        assert metadata[key] == finding["metadata"][key]
    assert metadata["dependency_occurrences"][0]["file"] == str(lockfile)
    assert metadata["dependency_occurrences"][0]["line"] == finding["line"]


@pytest.mark.parametrize("kind", ["npm", "shrinkwrap", "uv"])
@pytest.mark.parametrize("with_source", [False, True])
def test_cli_lockfile_advisories_reach_json_sarif_and_gate(
    project, monkeypatch, osv, kind, with_source
):
    lockfile, name, version, ecosystem = _write_lockfile(project, kind)
    if with_source:
        source = project / "app.py"
        source.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
            'raise AssertionError("static analyzer must not execute this module")\n',
            encoding="utf-8",
        )
    exit_code, result, sarif = _run_cli(project, monkeypatch)
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert exit_code == 1
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    finding = result["dependency_vulnerabilities"][0]
    metadata = finding["metadata"]
    exported = sarif["runs"][0]["results"][0]
    assert finding["severity"] == "HIGH"
    assert exported["level"] == "error"
    assert metadata["advisory_status"] == "complete"
    assert metadata["fixed_version"] == "9.9.9"
    assert metadata["fixed_versions"] == ["9.9.9"]
    assert "Test dependency advisory" in finding["message"]
    assert "Upgrade to 9.9.9." in finding["message"]
    for key in (
        "fixed_version",
        "fixed_versions",
        "severity_vectors",
        "advisory_status",
    ):
        assert exported["properties"]["skylos_metadata"][key] == metadata[key]
    assert osv.advisory_requests == [f"https://api.osv.dev/v1/vulns/{ADVISORY_ID}"]
    assert osv.queries == [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    ]


@pytest.mark.parametrize("kind", ["npm", "shrinkwrap", "uv"])
def test_cli_keeps_partial_advisories_in_both_reports_on_detail_failure(
    project, monkeypatch, osv, kind
):
    lockfile, *_ = _write_lockfile(project, kind)
    osv.fail_details = True
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--force")
    _assert_matching_dependency_reports(result, sarif, lockfile)
    assert exit_code == 2
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    metadata = result["dependency_vulnerabilities"][0]["metadata"]
    assert metadata["advisory_status"] == "unavailable"
    assert metadata["advisory_error"] == "advisory_transport_error"
    assert metadata["fixed_version"] is None
    assert osv.advisory_requests


@pytest.mark.parametrize(
    "display_args,expected_count",
    [
        (("--category", "dependency"), 1),
        (("--category", "security"), 0),
        (("--file-filter", "package-lock.json"), 1),
        (("--file-filter", "not-in-this-project"), 0),
        (("--severity", "high"), 1),
        (("--severity", "critical"), 0),
    ],
)
def test_cli_sarif_dependency_display_filters_match_json_without_bypassing_gate(
    project, monkeypatch, osv, display_args, expected_count
):
    _write_lockfile(project, "npm")
    exit_code, result, sarif = _run_cli(project, monkeypatch, *display_args)
    assert exit_code == 1
    assert len(result["dependency_vulnerabilities"]) == expected_count
    assert len(sarif["runs"][0]["results"]) == expected_count


@pytest.mark.parametrize("kind", ["npm", "shrinkwrap"])
def test_cli_clean_lockfile_has_no_json_or_sarif_findings(
    project, monkeypatch, osv, kind
):
    _write_lockfile(project, kind)
    osv.vulnerable = False
    exit_code, result, sarif = _run_cli(project, monkeypatch)
    assert exit_code == 0
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["sca_coverage"]["complete"] is True
    assert osv.advisory_requests == []


def test_cli_preserves_vector_without_inventing_numeric_severity(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    osv.severity_label = None
    exit_code, result, sarif = _run_cli(project, monkeypatch)
    assert exit_code == 1
    finding = result["dependency_vulnerabilities"][0]
    assert finding["severity"] == "UNKNOWN"
    assert finding["metadata"]["cvss_score"] is None
    assert finding["metadata"]["advisory_status"] == "complete"
    assert finding["metadata"]["severity_vectors"] == [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]
    assert (
        sarif["runs"][0]["results"][0]["properties"]["skylos_metadata"][
            "severity_vectors"
        ]
        == finding["metadata"]["severity_vectors"]
    )


def test_cli_preserves_published_numeric_severity_in_both_reports(
    project, monkeypatch, osv
):
    _write_lockfile(project, "npm")
    osv.numeric_score = 9.8
    osv.severity_label = "CRITICAL"
    exit_code, result, sarif = _run_cli(project, monkeypatch)
    assert exit_code == 1
    finding = result["dependency_vulnerabilities"][0]
    exported = sarif["runs"][0]["results"][0]
    assert finding["severity"] == "CRITICAL"
    assert finding["metadata"]["cvss_score"] == 9.8
    assert exported["level"] == "error"
    assert exported["properties"]["skylos_metadata"]["cvss_score"] == 9.8


def test_cli_malformed_lockfile_still_writes_both_reports(project, monkeypatch, osv):
    lockfile = project / "package-lock.json"
    lockfile.write_text(  # skylos: ignore[SKY-D324] pytest project fixture under tmp_path
        "{invalid", encoding="utf-8"
    )
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--force")
    assert exit_code == 2
    assert result["dependency_vulnerabilities"] == []
    assert sarif["runs"][0]["results"] == []
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    assert osv.queries == []


def test_cli_shrinkwrap_precedence_keeps_occurrences_but_deduplicates_osv(
    project, monkeypatch, osv
):
    shrinkwrap, *_ = _write_lockfile(project, "shrinkwrap")
    assert write_text_no_symlink(
        project / "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/lodash": {"version": "4.17.21"}},
            }
        ),
    )
    assert write_text_no_symlink(
        project / "package.json", '{"dependencies":{"lodash":"4.17.20"}}'
    )
    nested = project / "nested"
    nested.mkdir()
    nested_shrinkwrap, *_ = _write_lockfile(nested, "shrinkwrap")

    exit_code, result, sarif = _run_cli(project, monkeypatch)

    _assert_matching_dependency_reports(result, sarif, shrinkwrap)
    assert exit_code == 1
    receipt = result["analysis_summary"]["sca_coverage"]
    assert receipt["complete"] is True
    assert receipt["ignored_lockfile_count"] == 1
    assert receipt["ignored_lockfiles"] == [
        {
            "file": str(project / "package-lock.json"),
            "selected_file": str(shrinkwrap),
            "reason": "npm_shrinkwrap_precedence",
        }
    ]
    metadata = result["dependency_vulnerabilities"][0]["metadata"]
    assert {item["file"] for item in metadata["dependency_occurrences"]} == {
        str(shrinkwrap),
        str(nested_shrinkwrap),
        str(project / "package.json"),
    }
    assert osv.queries == [
        {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}
    ]
    assert osv.advisory_requests == [f"https://api.osv.dev/v1/vulns/{ADVISORY_ID}"]


@pytest.mark.parametrize("failure", ["malformed", "symlink"])
def test_cli_failed_shrinkwrap_keeps_other_findings_without_package_lock_fallback(
    project, monkeypatch, osv, failure
):
    _write_lockfile(project, "npm")
    other_lockfile, *_ = _write_lockfile(project, "uv")
    shrinkwrap = project / "npm-shrinkwrap.json"
    if failure == "symlink":
        shrinkwrap.symlink_to(project / "package-lock.json")
    else:
        assert write_text_no_symlink(shrinkwrap, "{invalid")

    exit_code, result, sarif = _run_cli(project, monkeypatch, "--force")

    _assert_matching_dependency_reports(result, sarif, other_lockfile)
    assert exit_code == 2
    receipt = result["analysis_summary"]["sca_coverage"]
    assert receipt["complete"] is False
    assert receipt["parse_error_count"] == 1
    assert receipt["ignored_lockfile_count"] == 1
    assert osv.queries == [
        {"package": {"name": "urllib3", "ecosystem": "PyPI"}, "version": "1.26.4"}
    ]
