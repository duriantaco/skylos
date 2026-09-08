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
