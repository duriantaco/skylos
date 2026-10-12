"""Unavailable package metadata is not evidence that an API is missing."""

import json

import pytest

from skylos.core import python_api_surface
from skylos.core.api_symbol_truth import (
    SURFACE_KIND_PYTHON_MODULE,
    cache_api_symbol_surface,
)
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect.api_signature_hallucination import (
    DEFAULT_API_SIGNATURE_ALLOWLIST,
    RULE_ID_API_SIGNATURE,
    scan_python_api_signature_hallucinations,
)


PANDAS_SOURCE = (
    "import pandas as pd\n\n"
    'df = pd.read_csv("data.csv")\n'
    'df["timestamp"] = pd.to_datetime(df["time"], unit="s", utc=True)\n'
)


def _write(path, source):
    assert write_text_no_symlink(path, source, encoding="utf-8")
    return path


def _pandas_surface(*, truncated=False):
    return {
        "module": "pandas",
        "members": {
            "read_csv": {
                "kind": "function",
                "parameters": [
                    {"name": "filepath_or_buffer", "kind": "POSITIONAL_OR_KEYWORD"},
                ],
            },
            "to_datetime": {
                "kind": "function",
                "parameters": [
                    {"name": "arg", "kind": "POSITIONAL_OR_KEYWORD"},
                    {"name": "unit", "kind": "POSITIONAL_OR_KEYWORD"},
                    {"name": "utc", "kind": "POSITIONAL_OR_KEYWORD"},
                ],
            },
        },
        "members_truncated": truncated,
    }


@pytest.mark.parametrize("module_name", DEFAULT_API_SIGNATURE_ALLOWLIST)
@pytest.mark.parametrize(
    "source_template",
    [
        "import {module}\n{module}.read_csv('data.csv')\n",
        "import {module} as api\napi.read_csv('data.csv')\n",
        "from {module} import read_csv as read\nread('data.csv')\n",
        "import {module}.io as api\napi.read_csv('data.csv')\n",
    ],
    ids=["direct", "alias", "from-import", "submodule"],
)
def test_unavailable_surface_does_not_claim_missing_api(
    tmp_path, module_name, source_template
):
    source = _write(tmp_path / "app.py", source_template.format(module=module_name))

    findings = scan_python_api_signature_hallucinations(
        tmp_path, [source], surface_loader=lambda *_: None
    )

    assert findings == []
    assert findings.check["outcome"] == "incomplete"
    assert findings.check["skipped_references"] >= 1
    assert findings.check["reasons"] == [
        {"code": "installed_api_metadata_unavailable", "count": findings.check["skipped_references"]}
    ]


@pytest.mark.parametrize("surface", [None, {}, {"members": None}, {"members": []}])
def test_pandas_issue_requires_available_member_metadata(tmp_path, surface):
    source = _write(tmp_path / "app.py", PANDAS_SOURCE)
    loaded = []

    def loader(_root, module_name):
        loaded.append(module_name)
        return surface

    findings = scan_python_api_signature_hallucinations(
        tmp_path, [source], surface_loader=loader
    )

    assert findings == []
    assert loaded == ["pandas"]


@pytest.mark.parametrize(
    "error_type",
    [ModuleNotFoundError, ImportError, AttributeError, TypeError, ValueError],
)
def test_failed_package_inspection_does_not_claim_missing_api(
    tmp_path, monkeypatch, error_type
):
    source = _write(tmp_path / "app.py", PANDAS_SOURCE)
    imported = []

    def importer(module_name):
        imported.append(module_name)
        raise error_type("package metadata unavailable")

    monkeypatch.setattr(python_api_surface, "_importer", lambda _: importer)

    findings = scan_python_api_signature_hallucinations(tmp_path, [source])

    assert findings == []
    assert imported == ["pandas"]
    assert not python_api_surface.load_python_api_surface_cache(tmp_path)["modules"]


@pytest.mark.parametrize("truncated", [False, True])
def test_pandas_known_calls_pass_and_invalid_keywords_remain_reported(
    tmp_path, truncated
):
    source = _write(
        tmp_path / "app.py",
        PANDAS_SOURCE + "pd.to_datetime(df['time'], imaginary=True)\n",
    )

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [source],
        surface_loader=lambda *_: _pandas_surface(truncated=truncated),
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == RULE_ID_API_SIGNATURE
    assert findings[0]["line"] == 5
    assert "argument 'imaginary'" in findings[0]["message"]


@pytest.mark.parametrize("members", [{}, _pandas_surface()["members"]])
def test_complete_surface_still_reports_missing_api(tmp_path, members):
    source = _write(tmp_path / "app.py", "import pandas as pd\npd.not_an_api()\n")

    findings = scan_python_api_signature_hallucinations(
        tmp_path,
        [source],
        surface_loader=lambda *_: {"members": members, "members_truncated": False},
    )

    assert [finding["symbol"] for finding in findings] == ["pandas.not_an_api"]


def test_unavailable_package_does_not_hide_other_package_findings(tmp_path):
    source = _write(
        tmp_path / "app.py",
        PANDAS_SOURCE + "import requests\nrequests.not_an_api()\n",
    )
    loaded = []

    def loader(_root, module_name):
        loaded.append(module_name)
        return None if module_name == "pandas" else {"members": {}}

    findings = scan_python_api_signature_hallucinations(
        tmp_path, [source], surface_loader=loader
    )

    assert [finding["symbol"] for finding in findings] == ["requests.not_an_api"]
    assert loaded == ["pandas", "requests"]


@pytest.mark.parametrize("cached", [False, True])
def test_unavailable_surface_is_retried_on_later_scans(tmp_path, monkeypatch, cached):
    source = _write(tmp_path / "app.py", PANDAS_SOURCE)
    calls = []

    def builder(module_name):
        calls.append(module_name)
        return None if len(calls) == 1 else _pandas_surface()

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", builder)
    if cached:
        assert cache_api_symbol_surface(
            tmp_path,
            {
                "kind": SURFACE_KIND_PYTHON_MODULE,
                "name": "pandas",
                "environment_key": "stale",
                "members": {},
            },
        )

    first = scan_python_api_signature_hallucinations(tmp_path, [source])
    second = scan_python_api_signature_hallucinations(tmp_path, [source])
    third = scan_python_api_signature_hallucinations(tmp_path, [source])

    assert first == second == third == []
    assert calls == ["pandas", "pandas"]


def test_analyzer_skips_unavailable_pandas_but_keeps_known_api_errors(
    tmp_path, monkeypatch
):
    from skylos.analyzer import analyze
    from skylos.rules.ai_defect import dependency_hallucination as dependency
    from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest

    _write(
        tmp_path / "app.py",
        PANDAS_SOURCE + "import requests\nrequests.not_an_api()\n",
    )
    loaded = []

    def builder(module_name):
        loaded.append(module_name)
        return None if module_name == "pandas" else {"members": {}}

    monkeypatch.setattr(python_api_surface, "build_python_api_surface", builder)
    monkeypatch.setattr(
        dependency, "scan_python_dependency_hallucinations", lambda *a, **k: []
    )
    monkeypatch.setattr(
        manifest, "scan_manifest_dependency_hallucinations", lambda *a, **k: []
    )
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    result = json.loads(
        analyze(str(tmp_path), enable_ai_defects=True, grep_verify=False)
    )

    findings = [
        finding
        for finding in result.get("ai_defects", [])
        if finding["rule_id"] == RULE_ID_API_SIGNATURE
    ]
    assert [finding["symbol"] for finding in findings] == ["requests.not_an_api"]
    assert loaded == ["pandas", "requests"]
    assert result.get("analysis_errors", []) == []


def test_unavailable_metadata_changes_real_verifier_and_cli_verdict(tmp_path, monkeypatch, capsys):
    from skylos.commands.verify_cmd import run_verify_command
    from skylos.rules.ai_defect import dependency_hallucination as dependency
    from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest
    from skylos.verify_change import verify_change_path

    _write(tmp_path / "app.py", "import requests\nrequests.not_an_api()\n")
    monkeypatch.setattr(python_api_surface, "build_python_api_surface", lambda *_: None)
    monkeypatch.setattr(dependency, "scan_python_dependency_hallucinations", lambda *a, **k: [])
    monkeypatch.setattr(manifest, "scan_manifest_dependency_hallucinations", lambda *a, **k: [])
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    payload = verify_change_path(tmp_path, behavior_comparison=False)

    assert payload["status"] == "incomplete"
    assert payload["findings"] == []
    check = next(c for c in payload["coverage"]["checks"] if c["id"] == "python_installed_api_signature")
    assert check["outcome"] == "incomplete"
    assert check["unchecked_modules"] == [
        {"module": "requests", "file": str(tmp_path / "app.py"), "reason": "installed_api_metadata_unavailable"}
    ]
    exit_code = run_verify_command([str(tmp_path), "--no-behavior", "--format", "json"])
    assert exit_code == 2
    assert json.loads(capsys.readouterr().out)["status"] == "incomplete"


def test_complete_installed_metadata_still_passes_verification(tmp_path, monkeypatch):
    from skylos.rules.ai_defect import dependency_hallucination as dependency
    from skylos.rules.ai_defect import manifest_dependency_hallucination as manifest
    from skylos.verify_change import verify_change_path

    _write(tmp_path / "app.py", "import pandas as pd\npd.to_datetime('2026-01-01', utc=True)\n")
    monkeypatch.setattr(python_api_surface, "build_python_api_surface", lambda *_: _pandas_surface())
    monkeypatch.setattr(dependency, "scan_python_dependency_hallucinations", lambda *a, **k: [])
    monkeypatch.setattr(manifest, "scan_manifest_dependency_hallucinations", lambda *a, **k: [])
    monkeypatch.setenv("SKYLOS_JOBS", "1")

    payload = verify_change_path(tmp_path, behavior_comparison=False)

    assert payload["status"] == "pass"
    check = next(c for c in payload["coverage"]["checks"] if c["id"] == "python_installed_api_signature")
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1
    assert check["skipped_references"] == 0


def test_truncated_metadata_keeps_verified_findings_and_incomplete_coverage(tmp_path):
    source = _write(tmp_path / "app.py", "import pandas as pd\npd.to_datetime('now', imaginary=True)\n")
    result = scan_python_api_signature_hallucinations(
        tmp_path, [source], surface_loader=lambda *_: _pandas_surface(truncated=True)
    )

    assert [finding["symbol"] for finding in result] == ["pandas.to_datetime"]
    assert result.check["outcome"] == "fail"
    assert result.check["skipped_references"] == 1
    assert result.check["reasons"] == [{"code": "installed_api_metadata_truncated", "count": 1}]


def test_missing_callable_signature_is_incomplete_without_inventing_finding(tmp_path):
    source = _write(tmp_path / "app.py", "import requests\nrequests.get('https://example.test', invented=True)\n")
    result = scan_python_api_signature_hallucinations(
        tmp_path, [source],
        surface_loader=lambda *_: {"members": {"get": {"kind": "function", "signature": "", "parameters": []}}},
    )

    assert result == []
    assert result.check["outcome"] == "incomplete"
    assert result.check["skipped_references"] == 1
    assert result.check["unchecked_calls"][0]["symbol"] == "requests.get"
    assert result.check["reasons"] == [{"code": "installed_api_signature_unavailable", "count": 1}]
