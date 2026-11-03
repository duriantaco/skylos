"""Main's path sanitizer must retain the precision branch's provider proof."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger import scan_file_with_tree
from test.fixture_paths import write_fixture


def _project(tmp_path, monkeypatch, provider):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="uploads"\n')
    prefix = "from fastapi import Request\nfrom werkzeug.utils import secure_filename\n"
    if provider == "project":
        write_fixture(tmp_path, "werkzeug/__init__.py", "")
        write_fixture(
            tmp_path,
            "werkzeug/utils.py",
            "def secure_filename(name):\n    return name\n",
        )
    elif provider == "patched":
        prefix = (
            "import werkzeug.utils\n"
            "werkzeug.utils.secure_filename = lambda name: name\n" + prefix
        )
    source = (
        prefix
        + "import os\n"
        + "def store(request: Request):\n"
        + '    name = secure_filename(request.query_params["filename"])\n'
        + '    with open(os.path.join("/srv/uploads", name), "wb") as output:\n'
        + '        output.write(b"content")\n'
    )
    path = write_fixture(tmp_path, "app.py", source)
    return path, source


def _path_findings(findings):
    return [
        finding
        for finding in findings
        if finding["rule_id"] in {"SKY-D215", "SKY-D324"}
    ]


def _expected(source, provider):
    if provider == "native":
        return set()
    line = next(
        number
        for number, text in enumerate(source.splitlines(), 1)
        if "with open(" in text
    )
    return {("SKY-D215", line), ("SKY-D324", line)}


@pytest.mark.parametrize("provider", ["native", "project", "patched"])
def test_secure_filename_raw_provider_identity(tmp_path, monkeypatch, provider):
    path, source = _project(tmp_path, monkeypatch, provider)
    findings = []
    scan_file_with_tree(
        ast.parse(source),
        path,
        findings,
        source=source,
        project_root=tmp_path,
    )
    assert {
        (finding["rule_id"], finding["line"]) for finding in _path_findings(findings)
    } == _expected(source, provider)


@pytest.mark.parametrize("provider", ["native", "project"])
def test_secure_filename_provider_default_output(tmp_path, monkeypatch, provider):
    _, source = _project(tmp_path, monkeypatch, provider)
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_sca=False,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    findings = _path_findings(result.get("danger", []))
    assert {(finding["rule_id"], finding["line"]) for finding in findings} == _expected(
        source, provider
    )
    assert all(finding["listing"]["listed"] for finding in findings)
    assert check_gate({"danger": findings}, {"gate": {"max_security": 0}})[0] == (
        provider == "native"
    )
