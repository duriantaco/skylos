"""setup.cfg and setup.py dependency declarations (httpie shape).

httpie/cli declares everything in ``setup.cfg`` (``[options] install_requires``
and ``[options.extras_require]``) next to a bare ``setup()``. None of it was
read, so the first ``-a`` run reported 85 false SKY-D223 "undeclared
dependency" findings. Both files are read statically; setup.py is never run.
"""

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.core.python_requirements import (
    parse_setup_cfg_text,
    parse_setup_py_text,
    read_setup_cfg,
)
from skylos.rules.quality.unused_deps import scan_unused_dependencies
from skylos.rules.sca import vulnerability_scanner as sca
from test.test_cli_sca_sarif import osv as osv
from test.test_dependency_providers import _findings, _stub_registry, _write

HTTPIE_SETUP_CFG = """\
# Please keep all characters in this file in ASCII
[tool:pytest]
testpaths = httpie tests

[metadata]
name = httpie
version = attr: httpie.__version__

[options]
packages = find:
install_requires =
    pip
    charset_normalizer>=2.0.0
    defusedxml>=0.6.0
    requests[socks] >=2.22.0
    Pygments>=2.5.2
    requests-toolbelt>=0.9.1
    multidict>=4.7.0
    setuptools
    importlib-metadata>=1.4.0; python_version<"3.8"
    rich>=9.10.0
    colorama>=0.2.4; sys_platform=="win32"
python_requires = >=3.7

[options.entry_points]
console_scripts =
    http = httpie.__main__:main

[options.extras_require]
dev =
    pytest
    pytest-httpbin>=0.0.6
    responses
    werkzeug<2.1.0
    pyopenssl
    pyyaml
    Jinja2
test =
    pytest
    responses
"""

HTTPIE_IMPORTS = {
    "httpie/core.py": (
        "import requests\nimport charset_normalizer\nimport defusedxml\n"
        "import pygments\nimport requests_toolbelt\nimport multidict\n"
        "import rich\nimport colorama\nimport importlib_metadata\n"
    ),
    "tests/test_x.py": (
        "import pytest\nimport responses\nimport werkzeug\nimport pytest_httpbin\n"
    ),
    "docs/generate.py": "import yaml\nimport jinja2\nimport OpenSSL\n",
}

# module -> installed distributions (the environment the scan runs in)
INSTALLED = {
    "requests": {"requests"},
    "charset_normalizer": {"charset-normalizer"},
    "defusedxml": {"defusedxml"},
    "pygments": {"pygments"},
    "requests_toolbelt": {"requests-toolbelt"},
    "multidict": {"multidict"},
    "rich": {"rich"},
    "colorama": {"colorama"},
    "importlib_metadata": {"importlib-metadata"},
    "pytest": {"pytest"},
    "responses": {"responses"},
    "werkzeug": {"werkzeug"},
    "pytest_httpbin": {"pytest-httpbin"},
    "yaml": {"pyyaml"},
    "jinja2": {"jinja2"},
    "OpenSSL": {"pyopenssl"},
}


def _httpie(tmp_path):
    repo = tmp_path / "httpie"
    _write(repo / "setup.cfg", HTTPIE_SETUP_CFG)
    _write(repo / "setup.py", "from setuptools import setup\n\nsetup()\n")
    files = [_write(repo / path, text) for path, text in HTTPIE_IMPORTS.items()]
    return repo, files


# --- setup.cfg ---------------------------------------------------------------


def test_setup_cfg_install_requires_and_extras_are_read_like_pyproject(tmp_path):
    parsed = parse_setup_cfg_text(HTTPIE_SETUP_CFG, tmp_path / "setup.cfg")
    assert parsed.name == "httpie"
    assert parsed.dynamic is False
    assert parsed.names(runtime_only=True) == {
        "pip",
        "charset-normalizer",
        "defusedxml",
        "requests",
        "pygments",
        "requests-toolbelt",
        "multidict",
        "setuptools",
        "importlib-metadata",
        "rich",
        "colorama",
    }
    assert parsed.names() - parsed.names(runtime_only=True) == {
        "pytest",
        "pytest-httpbin",
        "responses",
        "werkzeug",
        "pyopenssl",
        "pyyaml",
        "jinja2",
    }
    lines = dict(parsed.install)
    assert lines["requests[socks] >=2.22.0"] == 15
    assert lines['importlib-metadata>=1.4.0; python_version<"3.8"'] == 20
    assert sorted(parsed.extras) == ["dev", "test"]


def test_setup_cfg_single_line_lists_and_markers(tmp_path):
    parsed = parse_setup_cfg_text(
        "[options]\n"
        'install_requires = requests>=2; idna; python_version<"3.8"\n'
        "setup_requires = setuptools_scm\n"
        "tests_require = pytest\n",
        tmp_path / "setup.cfg",
    )
    # setuptools splits a one-line value on ";"; a marker chunk is not a name.
    assert parsed.names(runtime_only=True) == {"requests", "idna"}
    assert parsed.names() == {"requests", "idna", "setuptools-scm", "pytest"}


def test_setup_cfg_file_directive_reads_contained_requirements_only(tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "requirements" / "base.txt", "requests==2.32.0\nflask\n")
    _write(tmp_path / "outside.txt", "evil==1.0\n")
    cfg = _write(
        repo / "setup.cfg",
        "[options]\ninstall_requires = file: requirements/base.txt\n"
        "[options.extras_require]\nx = file: ../outside.txt\n",
    )
    parsed = read_setup_cfg(cfg, root=repo)
    assert parsed.names() == {"requests", "flask"}
    assert parsed.dynamic is True  # the outside include was refused


@pytest.mark.parametrize(
    "text",
    [
        "[options]\ninstall_requires = attr: pkg.REQUIRES\n",
        "[options\ninstall_requires = requests\n",
    ],
)
def test_setup_cfg_unreadable_values_are_open_ended(tmp_path, text):
    parsed = parse_setup_cfg_text(text, tmp_path / "setup.cfg")
    assert parsed.dynamic is True
    assert parsed.names() == set()


# --- setup.py ----------------------------------------------------------------


def test_setup_py_literal_keywords_names_and_concatenation(tmp_path):
    parsed = parse_setup_py_text(
        "from setuptools import setup\n"
        "BASE = ['requests>=2', 'click']\n"
        "EXTRAS = {'yaml': ['PyYAML'], 'dev': BASE + ['pytest']}\n"
        "setup(\n"
        "    name='tool',\n"
        "    install_requires=BASE + ['rich; python_version>\"3\"'],\n"
        "    extras_require=EXTRAS,\n"
        "    setup_requires=['setuptools_scm'],\n"
        "    tests_require=('responses',),\n"
        ")\n",
        tmp_path / "setup.py",
    )
    assert parsed.name == "tool"
    assert parsed.dynamic is False
    assert parsed.names(runtime_only=True) == {"requests", "click", "rich"}
    assert parsed.names() == {
        "requests",
        "click",
        "rich",
        "pyyaml",
        "pytest",
        "setuptools-scm",
        "responses",
    }
    assert dict(parsed.install)["click"] == 2


@pytest.mark.parametrize(
    "source",
    [
        "from setuptools import setup\nsetup(**META)\n",
        "from setuptools import setup\n"
        "setup(install_requires=open('requirements.txt').read().splitlines())\n",
        "from setuptools import setup\nR = ['a']\nR = ['b']\nsetup(install_requires=R)\n",
        "import setuptools\nsetuptools.setup(extras_require=make_extras())\n",
    ],
)
def test_setup_py_non_literal_declarations_are_open_ended(tmp_path, source):
    parsed = parse_setup_py_text(source, tmp_path / "setup.py")
    assert parsed.dynamic is True
    assert parsed.names() == set()


def test_setup_py_is_parsed_never_executed(tmp_path):
    marker = tmp_path / "executed"
    source = (
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
        "from setuptools import setup\n"
        "setup(install_requires=['requests'])\n"
    )
    parsed = parse_setup_py_text(source, tmp_path / "setup.py")
    assert parsed.names() == {"requests"}
    assert not marker.exists()
    # Python 2 syntax is not parsed (callers fall back to a literal scan).
    assert parse_setup_py_text("print 'x'\nsetup()\n", tmp_path / "setup.py") is None


def test_python2_setup_py_falls_back_to_literal_install_requires(tmp_path):
    setup_py = _write(
        tmp_path / "setup.py",
        "print 'legacy'\nsetup(name='old', install_requires=['requests'])\n",
    )
    assert dep._parse_setup_py(setup_py) == ({"requests"}, "old")


# --- SKY-D222 / SKY-D223 -----------------------------------------------------


def test_httpie_setup_cfg_declarations_are_not_undeclared_imports(
    monkeypatch, tmp_path
):
    repo, files = _httpie(tmp_path)
    _stub_registry(monkeypatch, installed=INSTALLED)

    findings = dep.scan_python_dependency_hallucinations(repo, files)

    assert _findings(findings) == []


def test_undeclared_import_next_to_setup_cfg_is_still_reported(monkeypatch, tmp_path):
    repo, files = _httpie(tmp_path)
    files.append(_write(repo / "extras" / "hook.py", "import PyInstaller\n"))
    _stub_registry(monkeypatch, installed={**INSTALLED, "PyInstaller": {"pyinstaller"}})

    findings = dep.scan_python_dependency_hallucinations(repo, files)

    assert _findings(findings) == [
        (dep.RULE_ID_UNDECLARED, dep.SEV_MEDIUM, "PyInstaller")
    ]
    assert findings[0]["message"] == (
        "Undeclared import 'PyInstaller' (provided by: pyinstaller). Add to "
        "requirements.txt, pyproject.toml, setup.cfg or setup.py."
    )


@pytest.mark.parametrize(
    "pypi,expected",
    [
        (
            {"leftpadx": "exists"},
            "Undeclared import 'leftpadx'. Not found in "
            "requirements.txt, pyproject.toml, setup.cfg or setup.py.",
        ),
        (
            {},
            "Undeclared import 'leftpadx'. Not found in "
            "requirements.txt, pyproject.toml, setup.cfg or setup.py "
            "(possible import/dist name mismatch).",
        ),
    ],
)
def test_undeclared_import_messages_name_every_declaration_file(
    monkeypatch, tmp_path, pypi, expected
):
    repo = tmp_path / "repo"
    _write(repo / "setup.cfg", "[options]\ninstall_requires =\n    requests\n")
    source = _write(repo / "app.py", "import requests\nimport leftpadx\n")
    _stub_registry(monkeypatch, pypi=pypi, installed={"requests": {"requests"}})
    monkeypatch.setattr(dep, "_is_confident_hallucination_candidate", lambda _n: False)

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert [finding["message"] for finding in findings] == [expected]


def test_made_up_import_is_critical_with_setup_cfg_declarations(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(
        repo / "setup.cfg",
        "[options]\ninstall_requires =\n    requests>=2\n"
        "[options.extras_require]\nyaml =\n    PyYAML\n",
    )
    source = _write(
        repo / "app.py", "import requests\nimport yaml\nimport fastjsonx_turbo\n"
    )
    _stub_registry(
        monkeypatch,
        pypi={"requests": "exists", "pyyaml": "exists"},
        wheels={
            "requests": {"modules": ["requests"]},
            "pyyaml": {"modules": ["yaml", "_yaml"]},
        },
    )

    findings = dep.scan_python_dependency_hallucinations(repo, [source])

    assert _findings(findings) == [
        (dep.RULE_ID_HALLUCINATION, dep.SEV_CRITICAL, "fastjsonx_turbo")
    ]


def test_nested_setup_cfg_scopes_its_own_declarations(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "root"\ndependencies = []\n')
    _write(
        repo / "plugins" / "auth" / "setup.cfg",
        "[options]\ninstall_requires =\n    pyjwt\n",
    )
    inside = _write(repo / "plugins" / "auth" / "auth.py", "import jwt\n")
    outside = _write(repo / "app.py", "import jwt\n")
    _stub_registry(monkeypatch, installed={"jwt": {"pyjwt"}})

    findings = dep.scan_python_dependency_hallucinations(repo, [inside, outside])

    assert [(f["file"], f["symbol"]) for f in findings] == [(str(outside), "jwt")]


def test_setup_py_extras_and_tests_require_declare_imports(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write(
        repo / "setup.py",
        "from setuptools import setup\n"
        "setup(name='x', install_requires=['requests'],\n"
        "      extras_require={'yaml': ['PyYAML']}, tests_require=['responses'])\n",
    )
    source = _write(
        repo / "tests" / "test_x.py",
        "import requests\nimport yaml\nimport responses\n",
    )
    _stub_registry(
        monkeypatch,
        installed={
            "requests": {"requests"},
            "yaml": {"pyyaml"},
            "responses": {"responses"},
        },
    )

    assert dep.scan_python_dependency_hallucinations(repo, [source]) == []


# --- SKY-U005 ----------------------------------------------------------------


def _unused(findings):
    return sorted(finding["name"] for finding in findings)


def test_unused_setup_cfg_runtime_dependency_points_at_its_line(tmp_path):
    repo = tmp_path / "repo"
    cfg = _write(
        repo / "setup.cfg",
        "[metadata]\nname = tool\n\n[options]\ninstall_requires =\n"
        "    requests\n    pyserial\n"
        "setup_requires =\n    setuptools_scm\n"
        "[options.extras_require]\ndocs =\n    sphinx-rtd-theme\n",
    )
    source = _write(repo / "tool" / "core.py", "import requests\n")

    findings = scan_unused_dependencies(repo, [source], location_root=repo)

    # Extras and build requirements are not run-time imports.
    assert _unused(findings) == ["pyserial"]
    assert findings[0]["file"] == str(cfg)
    assert findings[0]["line"] == 7


def test_setup_py_build_requirements_are_not_reported_unused(tmp_path):
    repo = tmp_path / "repo"
    setup_py = _write(
        repo / "setup.py",
        "from setuptools import setup\n"
        "setup(\n"
        "    name='tool',\n"
        "    install_requires=['requests', 'pyserial'],\n"
        "    setup_requires=['setuptools_scm', 'cython'],\n"
        ")\n",
    )
    source = _write(repo / "tool.py", "import requests\n")

    findings = scan_unused_dependencies(repo, [source], location_root=repo)

    assert _unused(findings) == ["pyserial"]
    assert findings[0]["file"] == str(setup_py)
    assert findings[0]["line"] == 4


# --- SCA (OSV) ---------------------------------------------------------------


def _queried(osv):
    return {(query["package"]["name"], query["version"]) for query in osv.queries}


def test_sca_reads_exact_setup_cfg_install_requires_pins(tmp_path, osv):
    cfg = _write(
        tmp_path / "setup.cfg",
        "[flake8]\nignore = E501\n\n[options]\ninstall_requires =\n"
        "    requests==2.32.3\n    click>=8\n"
        "    vendored @ https://example.invalid/vendored-1.0.tar.gz\n"
        "[options.extras_require]\ndev =\n    pytest==8.0.0\n",
    )

    result = sca.scan_dependencies(tmp_path)

    assert _queried(osv) == {("requests", "2.32.3")}
    receipt = result.receipt
    assert receipt["supported_manifest_count"] == 1
    assert receipt["unresolved_dependency_count"] == 2
    assert receipt["status"] == "complete_with_unresolved_versions"
    finding = result[0]
    assert finding["file"] == str(cfg)
    assert finding["line"] == 6


def test_sca_reads_literal_setup_py_pins_without_running_it(tmp_path, osv):
    marker = tmp_path / "executed"
    setup_py = _write(
        tmp_path / "setup.py",
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
        "from setuptools import setup\n"
        "REQUIRES = ['urllib3==1.26.4']\n"
        "setup(name='x', install_requires=REQUIRES, tests_require=['pytest==8.0.0'])\n",
    )

    result = sca.scan_dependencies(tmp_path)

    assert not marker.exists()
    assert _queried(osv) == {("urllib3", "1.26.4")}
    assert result[0]["file"] == str(setup_py)
    assert result[0]["line"] == 4


@pytest.mark.parametrize(
    "name,text",
    [
        ("setup.cfg", "[flake8]\nmax-line-length = 100\n"),
        ("setup.py", "from setuptools import setup\nsetup()\n"),
        ("setup.py", "from setuptools import setup\nsetup(**META)\n"),
    ],
)
def test_setuptools_files_without_install_requires_are_not_manifests(
    tmp_path, osv, name, text
):
    _write(tmp_path / name, text)

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "no_supported_manifests"
    assert osv.queries == []
