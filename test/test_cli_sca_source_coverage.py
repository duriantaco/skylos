"""Exercise source coverage through the real CLI with only OSV HTTP replaced."""

import json
import os
import subprocess
import sys

import pytest

from skylos import cli
from skylos.api._scan_coverage import _dependency_coverage_complete
from skylos.core.git_safety import read_only_git_environment
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.core.sca_baseline import dependency_scan_complete
from skylos.rules.sca import vulnerability_scanner as sca
from test.test_cli_sca_sarif import RULE_ID, _OSVTransport


MODES = {
    "rich": [],
    "llm": ["--llm"],
    "concise": ["--format", "concise"],
    "github": ["--github"],
    "json": ["--format", "json"],
}
GIT_SOURCE = (
    '{ git = "https://token:fixture-private-password@example.invalid/library.git'
    '#0123456789012345678901234567890123456789" }'
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


@pytest.fixture
def project(tmp_path, monkeypatch):
    # These are local scans, independent of the CI runner's PR base and policy.
    for name in tuple(os.environ):
        if name.startswith(("GIT_", "GITHUB_", "GITLAB_", "SKYLOS_", "BITBUCKET_")):
            monkeypatch.delenv(name)
    for name in ("CI", "TF_BUILD", "SYSTEM_PULLREQUEST_TARGETBRANCH", "SYSTEM_PULLREQUEST_PULLREQUESTID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setattr("skylos.cloud.sync.get_token", lambda: None)
    monkeypatch.setattr(cli, "upload_report", lambda *_args, **_kwargs: pytest.fail("Must not upload"))
    path = tmp_path.resolve() / "project"
    path.mkdir()
    subprocess.run(
        ["git", "-c", f"core.hooksPath={os.devnull}", "init", "-q", "-b", "main", str(path)],
        env=read_only_git_environment(), check=True, capture_output=True,
    )
    monkeypatch.chdir(path)
    _write(path / "src/app.py", 'def main():\n    return "ready"\n\nif __name__ == "__main__":\n    main()\n')
    return path


def _sources(project, *, source=GIT_SOURCE, public=True, public_version="1.26.4"):
    _write(
        project / "pyproject.toml",
        '[project]\nname = "project"\nversion = "0.1.0"\n'
        'dependencies = ["private-helper==0.1.0"' + (', "urllib3==1.26.4"' if public else '') + ']\n'
        '[tool.uv.sources]\nprivate-helper = { git = "https://example.invalid/library.git" }\n'
        '[tool.skylos.gate]\nmax_dependency_vulnerabilities = 0\n',
    )
    text = (
        'version = 1\nrevision = 3\n[[package]]\nname = "project"\n'
        'version = "0.1.0"\nsource = { virtual = "." }\n'
        'dependencies = [{ name = "private-helper" }'
        + (', { name = "urllib3" }' if public else '') + ']\n'
        '[[package]]\nname = "private-helper"\nversion = "0.1.0"\nsource = ' + source + '\n'
    )
    if public:
        text += (
            '[[package]]\nname = "urllib3"\nversion = ' + json.dumps(public_version) + '\n'
            'source = { registry = "https://pypi.org/simple" }\n'
        )
    _write(project / "uv.lock", text)


def _run(monkeypatch, capsys, mode, *extra):
    monkeypatch.setattr(sys, "argv", [
        "skylos", "src", "--sca", "--no-upload", "--no-provenance",
        "--no-grep-verify", *MODES[mode], *extra,
    ])
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    assert "fixture-private-password" not in captured.out + captured.err
    return code, captured.out, json.loads(captured.out) if mode == "json" else None


@pytest.fixture
def osv(monkeypatch):
    transport = _OSVTransport()
    transport.vulnerable = False
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("gated", [False, True])
def test_cli_git_source_is_a_visible_coverage_limit_not_an_operational_error(
    project, monkeypatch, capsys, osv, mode, gated
):
    _sources(project)
    code, output, payload = _run(monkeypatch, capsys, mode, *(('--gate', '--strict') if gated else ()))
    assert code == 0
    assert {query["package"]["name"] for query in osv.queries} == {"urllib3"}
    if payload is None:
        assert "not checked" in output.lower()
    else:
        receipt = payload["analysis_summary"]["sca_coverage"]
        assert receipt["status"] == "complete_with_non_registry_sources"
        assert receipt["query"]["complete"] is True
        assert receipt["non_registry_lockfile_dependency_count"] == 1
        assert receipt["unresolved_lockfile_dependency_count"] == 0
        assert receipt["complete"] is receipt["category_complete"] is False
        assert not dependency_scan_complete(payload)
        assert not _dependency_coverage_complete(payload["analysis_summary"])
        assert payload["dependency_vulnerabilities"] == []


@pytest.mark.parametrize("mode", MODES)
def test_cli_registry_cve_still_blocks_when_git_dependency_is_not_checked(
    project, monkeypatch, capsys, osv, mode
):
    _sources(project)
    osv.vulnerable = True
    code, output, payload = _run(monkeypatch, capsys, mode, "--gate", "--strict")
    assert code == 1
    assert {query["package"]["name"] for query in osv.queries} == {"urllib3"}
    if payload is not None:
        assert [finding["rule_id"] for finding in payload["dependency_vulnerabilities"]] == [RULE_ID]
        assert payload["analysis_summary"]["sca_coverage"]["status"] == "complete_with_non_registry_sources"
    else:
        assert "not checked" in output.lower()


@pytest.mark.parametrize("failure", ["source-shape", "public-version", "osv-outage"])
def test_cli_real_sca_failures_remain_operational_errors(
    project, monkeypatch, capsys, osv, failure
):
    _sources(
        project,
        source='{ git = "https://example.invalid/a.git#0123456789012345678901234567890123456789", registry = "https://pypi.org/simple" }' if failure == "source-shape" else GIT_SOURCE,
        public_version="not-a-version" if failure == "public-version" else "1.26.4",
    )
    if failure == "osv-outage":
        def unavailable(*_args, **_kwargs):
            raise ConnectionError("Offline test service unavailable")
        monkeypatch.setattr(osv, "post", unavailable)
    else:
        osv.vulnerable = True
    code, _, payload = _run(monkeypatch, capsys, "json", "--gate", "--strict")
    assert code == 2
    assert payload["analysis_summary"]["sca_coverage"]["status"] == "incomplete"
    if failure == "source-shape":
        assert [finding["rule_id"] for finding in payload["dependency_vulnerabilities"]] == [RULE_ID]


@pytest.mark.parametrize("mode", ["rich", "json"])
def test_cli_git_only_inventory_is_explicitly_unchecked_and_never_queries_osv(
    project, monkeypatch, capsys, osv, mode
):
    _sources(project, public=False)
    code, output, payload = _run(monkeypatch, capsys, mode, "--gate", "--strict")
    assert code == 0
    assert osv.queries == []
    if payload is not None:
        receipt = payload["analysis_summary"]["sca_coverage"]
        assert receipt["status"] == "complete_with_non_registry_sources"
        assert receipt["queried_dependency_count"] == 0
        assert receipt["complete"] is False
    else:
        assert "not checked" in output.lower()
