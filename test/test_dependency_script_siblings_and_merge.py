"""Executable scripts' sibling imports, and one finding per missing package."""

import json
from pathlib import Path

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.analyzer import analyze
from test.fixture_paths import make_fixture_directory, write_fixture


def _stub(monkeypatch, statuses=None):
    statuses = statuses or {}
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys", "json"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: {})
    monkeypatch.setattr(
        dep, "_check_pypi_status", lambda name, _cache: statuses.get(name, "missing")
    )


SCRIPT = "#!/usr/bin/env python3\nfrom flight_common import run\n\nrun()\n"


def _plan(tmp_path, script=SCRIPT, extra=None):
    repo = make_fixture_directory(tmp_path, "repo")
    write_fixture(repo, "pyproject.toml", '[project]\nname="drone"\ndependencies=[]\n')
    write_fixture(repo, "fly/__init__.py", "")
    write_fixture(repo, "fly/plan/__init__.py", "")
    write_fixture(repo, "fly/plan/flight_common.py", "def run():\n    pass\n")
    source = write_fixture(repo, "fly/plan/flight_test_10.py", script)
    for name, text in (extra or {}).items():
        write_fixture(repo, name, text)
    return repo, source


def _symbols(findings):
    return [(row["rule_id"], row["symbol"]) for row in findings]


def test_executable_script_imports_its_sibling_inside_a_package(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo, source = _plan(tmp_path)

    assert _symbols(dep.scan_python_dependency_hallucinations(repo, [source])) == []


@pytest.mark.parametrize(
    "case",
    [
        "main-guard-only",
        "imported-by-project",
        "run-with-dash-m",
        "relative-import",
        "submodule-required",
        "shadowing-directory",
    ],
)
def test_script_sibling_needs_script_only_execution(monkeypatch, tmp_path, case):
    _stub(monkeypatch)
    script = SCRIPT
    extra = {}
    if case == "main-guard-only":
        script = "from flight_common import run\n\nif __name__ == '__main__':\n    run()\n"
    elif case == "imported-by-project":
        extra = {"fly/launcher.py": "from fly.plan import flight_test_10\n"}
    elif case == "run-with-dash-m":
        extra = {"run.sh": "python -m fly.plan.flight_test_10\n"}
    elif case == "relative-import":
        script = SCRIPT + "from . import flight_common as again\n"
    elif case == "submodule-required":
        script = "#!/usr/bin/env python3\nimport flight_common.extra\n"
    elif case == "shadowing-directory":
        extra = {"fly/plan/flight_common/__init__.py": "def run():\n    pass\n"}
        script = "#!/usr/bin/env python3\nimport flight_common\n"
    repo, source = _plan(tmp_path, script=script, extra=extra)

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    if case == "shadowing-directory":
        # A package directory beside the file is not this rule's case; it
        # keeps the existing package-context decision.
        assert all(symbol == "flight_common" for _rule, symbol in _symbols(findings))
    else:
        assert [symbol for _rule, symbol in _symbols(findings)] == ["flight_common"]


def _analyze(tmp_path, files):
    for name, text in files.items():
        write_fixture(tmp_path, name, text)
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, enable_ai_defects=True)
    )
    return [
        row
        for row in result.get("ai_defects", [])
        if row["rule_id"] in {dep.RULE_ID_UNDECLARED, dep.RULE_ID_HALLUCINATION}
    ]


def test_same_missing_package_is_one_finding_listing_every_site(tmp_path):
    rows = _analyze(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["requests"]\n',
            "app/__init__.py": "",
            "app/a.py": "import cv2\nimport requests\n",
            "app/b.py": "import cv2\n",
            "app/c.py": "import cv2\n",
        },
    )
    cv2 = [row for row in rows if row["symbol"] == "cv2"]
    assert len(cv2) == 1
    assert cv2[0]["metadata"]["import_site_count"] == 3
    assert sorted(site["file"] for site in cv2[0]["metadata"]["other_import_sites"]) == [
        "app/b.py",
        "app/c.py",
    ]
    assert "Also imported in 2 other files" in cv2[0]["message"]
    assert not any("_dependency_scope" in row for row in rows)


def test_separate_manifests_keep_separate_findings(tmp_path):
    manifest = '[project]\nname="app"\nversion="1"\ndependencies=["requests"]\n'
    rows = _analyze(
        tmp_path,
        {
            "svc_a/pyproject.toml": manifest,
            "svc_a/main.py": "import cv2\n",
            "svc_b/pyproject.toml": manifest,
            "svc_b/main.py": "import cv2\n",
        },
    )
    assert sorted(Path(row["file"]).parent.name for row in rows if row["symbol"] == "cv2") == [
        "svc_a",
        "svc_b",
    ]


def test_inline_ignore_on_one_site_does_not_hide_the_others(tmp_path):
    rows = _analyze(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["requests"]\n',
            "app/__init__.py": "",
            "app/a.py": "import cv2  # skylos: ignore[SKY-D223]\n",
            "app/b.py": "import cv2\n",
        },
    )
    cv2 = [row for row in rows if row["symbol"] == "cv2"]
    assert [Path(row["file"]).name for row in cv2] == ["b.py"]
