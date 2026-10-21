"""SKY-D223 false positives: distributions the project's own environment
definitions install, although no manifest names them directly.

* microsoft/agent-lightning@ee707b6 ``examples/search_r1/agents/
  search_r1_agent.py`` imports ``openai``. pyproject declares the extra
  ``autogen-ext[openai]`` and ``uv.lock`` resolves ``openai``.
* the same commit's ``examples/search_r1/retrieval_server.py`` imports
  ``faiss``; the example's own ``data_process.sh`` runs
  ``conda install ... faiss-gpu=1.8.0``, but only inside
  ``if [[ ${SEARCH_R1_SKIP_RETRIEVER_INSTALL} != 1 ]]`` (no else), so it is
  not an install that always runs and ``faiss`` is still reported.

A lockfile alone declares nothing: a locked package counts only through an
unconditional edge from a declared distribution (section c). An environment
file (environment.yml, Pipfile ``[packages]``), a straight-line install in a
setup script, or the final stage of the one Dockerfile that copies the code
provides a
distribution for the directory it sits in and everything below it (see
test_undeclared_import_env_round4.py and _round5.py for what does not
count). An import nothing in that chain declares or installs is still
reported.
"""

import os

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.core.safe_cache_io import write_text_no_symlink


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding="utf-8")
    return path


def _stub(monkeypatch, installed=None, statuses=None):
    statuses = statuses or {}
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "_build_installed_module_mapping", lambda: installed or {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(
        dep, "_check_pypi_status", lambda name, _cache: statuses.get(name, "exists")
    )


def _rules(findings):
    return sorted(
        (f["rule_id"], f["symbol"], os.path.basename(os.path.dirname(f["file"])))
        for f in findings
    )


PYPROJECT = (
    '[project]\nname = "agl-lite"\ndependencies = ["httpx>=0.28"]\n'
    '[project.optional-dependencies]\nverl = ["autogen-ext[openai]"]\n'
)

UV_LOCK = """version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "agl-lite"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "autogen-ext"
version = "0.7.5"
source = { registry = "https://pypi.org/simple" }

[package.optional-dependencies]
openai = [
    { name = "openai" },
]

[[package]]
name = "openai"
version = "2.8.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pillow"
version = "11.0.0"
source = { registry = "https://pypi.org/simple" }
"""

DATA_PROCESS_SH = """#!/usr/bin/env bash
set -euo pipefail
PYTORCH_CUDA="${SEARCH_R1_PYTORCH_CUDA:-12.1}"
if [[ "${SEARCH_R1_SKIP_RETRIEVER_INSTALL:-0}" != "1" ]]; then
    conda install -y \\
        "pytorch==2.4.0" \\
        "pytorch-cuda=$PYTORCH_CUDA" \\
        -c pytorch -c nvidia
    conda install -y -c pytorch -c nvidia "faiss-gpu=1.8.0"
    python -m pip install -U "transformers==4.57.1" datasets pyserini tqdm
fi
"""

DATA_PROCESS_UNCONDITIONAL_SH = """#!/usr/bin/env bash
set -euo pipefail
PYTORCH_CUDA="${SEARCH_R1_PYTORCH_CUDA:-12.1}"
conda install -y \\
    "pytorch==2.4.0" \\
    "pytorch-cuda=$PYTORCH_CUDA" \\
    -c pytorch -c nvidia
conda install -y -c pytorch -c nvidia "faiss-gpu=1.8.0"
python -m pip install -U "transformers==4.57.1" datasets pyserini tqdm
"""

STRAIGHT_LINE_SH = """#!/usr/bin/env bash
set -euo pipefail
python -m pip install -U "transformers==4.57.1" datasets pyserini tqdm
"""


# -- (a) lockfiles do not declare imports ----------------------------------------


def test_uv_lock_transitive_import_is_still_undeclared(monkeypatch, tmp_path):
    """A locked package no edge from a declared distribution reaches is not
    provided. UV_LOCK's project entry records no ``autogen-ext[openai]`` edge,
    so nothing requests the extra that brings openai."""
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(repo / "uv.lock", UV_LOCK)
    agent = _write(
        repo / "examples" / "search_r1" / "agents" / "search_r1_agent.py",
        "import httpx\n\n\ndef run():\n    from openai import AsyncOpenAI\n"
        "    import PIL.Image\n    import left_pad_py\n    return AsyncOpenAI\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [agent])
    assert sorted(symbol for _, symbol, _ in _rules(findings)) == [
        "PIL",
        "left_pad_py",
        "openai",
    ]


@pytest.mark.parametrize(
    "filename, text",
    [
        (
            "poetry.lock",
            '[[package]]\nname = "rich"\nversion = "13.7.1"\n'
            'description = "x"\noptional = false\npython-versions = ">=3.8"\n'
            'files = []\n\n[metadata]\nlock-version = "2.0"\n',
        ),
        (
            "pdm.lock",
            '[metadata]\ngroups = ["default"]\n\n[[package]]\nname = "rich"\n'
            'version = "13.7.1"\nrequires_python = ">=3.8"\n',
        ),
        (
            "Pipfile.lock",
            '{"_meta": {"hash": {"sha256": "x"}}, "default": {"rich": '
            '{"version": "==13.7.1"}}, "develop": {}}',
        ),
        (
            "pylock.toml",
            'lock-version = "1.0"\ncreated-by = "uv"\n\n[[packages]]\n'
            'name = "rich"\nversion = "13.7.1"\n',
        ),
        (
            "conda-lock.yml",
            "version: 1\nmetadata:\n  platforms: [linux-64]\npackage:\n"
            "- name: rich\n  version: 13.7.1\n  manager: pip\n  platform: linux-64\n",
        ),
        ("Pipfile", '[packages]\nrich = "*"\n\n[dev-packages]\npytest = "*"\n'),
    ],
)
def test_lockfiles_do_not_provide_distributions(monkeypatch, tmp_path, filename, text):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(repo / filename, text)
    app = _write(repo / "app" / "cli.py", "import rich\nimport unlocked_pkg\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    expected = ["unlocked_pkg"] if filename == "Pipfile" else ["rich", "unlocked_pkg"]
    assert sorted(symbol for _, symbol, _ in _rules(findings)) == expected


def test_setup_script_only_covers_its_own_subtree(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "mono"\ndependencies = []\n')
    _write(repo / "services" / "a" / "setup.sh", "pip install redis\n")
    a = _write(repo / "services" / "a" / "app.py", "import redis\n")
    b = _write(repo / "services" / "b" / "worker.py", "import redis\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [a, b])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "redis", "b")]


def test_installed_name_lookalike_does_not_provide_import(monkeypatch, tmp_path):
    # docker-pycreds ships ``dockerpycreds``, not ``docker``: a shared name
    # token is not evidence that an installed distribution provides an import.
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(repo / "setup.sh", "pip install docker-pycreds\n")
    app = _write(repo / "app" / "build.py", "import docker\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "docker", "app")]


def test_variant_distribution_does_not_provide_a_base_import(monkeypatch, tmp_path):
    # faiss-cpu and onnxruntime-gpu do ship ``faiss``/``onnxruntime``, but a
    # name rule cannot tell those apart from dask-cuda, which ships only
    # ``dask_cuda`` (round 5). Without known metadata, nothing is assumed.
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(repo / "app" / "setup.sh", "pip install faiss-cpu onnxruntime-gpu\n")
    app = _write(
        repo / "app" / "index.py", "import faiss\nimport onnxruntime\nimport annoy\n"
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert [symbol for _rule, symbol, _dir in _rules(findings)] == [
        "annoy",
        "faiss",
        "onnxruntime",
    ]


# -- (b) install commands and environment files --------------------------------


def test_setup_script_reading_stops_at_the_first_assignment(monkeypatch, tmp_path):
    # ``PYTORCH_CUDA=...`` could redirect what follows (PIP_TARGET, PATH);
    # a strict reading stops there, and ``conda`` installs never count.
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(
        repo / "examples" / "search_r1" / "data_process.sh",
        DATA_PROCESS_UNCONDITIONAL_SH,
    )
    server = _write(
        repo / "examples" / "search_r1" / "retrieval_server.py",
        "import faiss\nimport pyserini\nimport torch\nimport made_up_retriever\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [server])
    assert [symbol for _rule, symbol, _dir in _rules(findings)] == [
        "faiss",
        "made_up_retriever",
        "pyserini",
        "torch",
    ]


def test_example_setup_script_installs_its_imports(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(repo / "examples" / "search_r1" / "data_process.sh", STRAIGHT_LINE_SH)
    server = _write(
        repo / "examples" / "search_r1" / "retrieval_server.py",
        "import pyserini\nimport datasets\nimport made_up_retriever\n",
    )
    other = _write(repo / "examples" / "other" / "index.py", "import pyserini\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [server, other])
    # The script installs for its own directory only; a sibling example and
    # an uninstalled import still count.
    assert _rules(findings) == [
        (dep.RULE_ID_UNDECLARED, "made_up_retriever", "search_r1"),
        (dep.RULE_ID_UNDECLARED, "pyserini", "other"),
    ]


def test_conditional_example_install_does_not_declare_imports(monkeypatch, tmp_path):
    # The real agent-lightning script installs only when
    # SEARCH_R1_SKIP_RETRIEVER_INSTALL is not 1; nothing guarantees the
    # retriever's packages are there, so its imports stay undeclared.
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(repo / "examples" / "search_r1" / "data_process.sh", DATA_PROCESS_SH)
    server = _write(
        repo / "examples" / "search_r1" / "retrieval_server.py",
        "import faiss\nimport pyserini\nimport torch\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [server])
    assert [symbol for _rule, symbol, _dir in _rules(findings)] == [
        "faiss",
        "pyserini",
        "torch",
    ]


def test_ancestor_setup_script_covers_nested_directories(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(
        repo / "examples" / "setup.sh",
        "#!/bin/sh\npip install scienceworld 'swebench>=2'\n",
    )
    agent = _write(
        repo / "examples" / "science_world" / "agents" / "agent.py",
        "import scienceworld\nimport swebench\n",
    )
    lib = _write(repo / "app" / "core.py", "import scienceworld\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [agent, lib])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "scienceworld", "app")]


def test_dockerfile_run_pip_install_provides_imports(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(
        repo / "demo" / "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n"
        "RUN --mount=type=cache,target=/root/.cache pip install --no-cache-dir \\\n"
        '    gradio==4.0 \\\n    && pip install "uvicorn[standard]"\n'
        'CMD ["python", "app.py"]\n',
    )
    app = _write(
        repo / "demo" / "app.py", "import gradio\nimport uvicorn\nimport chromadb\n"
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "chromadb", "demo")]


def test_conda_environment_file_provides_conda_and_pip_dependencies(
    monkeypatch, tmp_path
):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(
        repo / "notebooks" / "environment.yml",
        "name: rag\nchannels:\n  - pytorch\n  - conda-forge\ndependencies:\n"
        "  - python=3.10\n  - pytorch::pytorch>=2.1\n  - faiss-cpu=1.8.0\n"
        "  - pip\n  - pip:\n    - sentence-transformers==2.2.2\n    - -e .\n",
    )
    nb = _write(
        repo / "notebooks" / "embed.py",
        "import torch\nimport faiss\nimport sentence_transformers\nimport chromadb\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [nb])
    # faiss-cpu is a variant name nothing maps to ``faiss`` (round 5).
    assert _rules(findings) == [
        (dep.RULE_ID_UNDECLARED, "chromadb", "notebooks"),
        (dep.RULE_ID_UNDECLARED, "faiss", "notebooks"),
    ]


def test_commands_that_do_not_install_into_the_environment_do_not_count(
    monkeypatch, tmp_path
):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(
        repo / "tools" / "bootstrap.sh",
        "#!/bin/sh\n# pip install commented\n"
        'echo "pip install quoted"\n'
        "pip uninstall -y gone\npip download dl\n"
        "pipx install black\nuvx ruff\nuv tool install mypy\n"
        "conda remove -y removed\nconda search searched\n"
        "pip install $PKG\n",
    )
    script = _write(
        repo / "tools" / "lint.py",
        "import commented\nimport quoted\nimport gone\nimport dl\n"
        "import black\nimport ruff\nimport mypy\nimport removed\nimport searched\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [script])
    assert [symbol for _rule, symbol, _dir in _rules(findings)] == [
        "black",
        "commented",
        "dl",
        "gone",
        "mypy",
        "quoted",
        "removed",
        "ruff",
        "searched",
    ]


def test_symlinked_setup_script_is_not_read(monkeypatch, tmp_path):
    _stub(monkeypatch)
    outside = _write(tmp_path / "outside" / "install.sh", "pip install faiss-cpu\n")
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    (repo / "app").mkdir(parents=True)
    try:
        os.symlink(outside, repo / "app" / "install.sh")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    app = _write(repo / "app" / "index.py", "import faiss\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _rules(findings) == [(dep.RULE_ID_UNDECLARED, "faiss", "app")]


def test_environment_definitions_never_create_findings_without_manifests(
    monkeypatch, tmp_path
):
    # Install scripts only suppress; they do not turn a manifest-less
    # repository into one where every other import is reported.
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "install.sh", "pip install requests\n")
    app = _write(repo / "app" / "main.py", "import requests\nimport flask\n")
    assert dep.scan_python_dependency_hallucinations(repo, [app]) == []


def test_hallucination_rule_is_unchanged_by_environment_definitions(
    monkeypatch, tmp_path
):
    _stub(monkeypatch, statuses={"reqeusts_magic": "missing"})
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "app"\ndependencies = []\n')
    _write(
        repo / "uv.lock",
        'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.0"\n',
    )
    _write(repo / "app" / "setup.sh", "pip install requests\n")
    app = _write(repo / "app" / "main.py", "import reqeusts_magic\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _rules(findings) == [(dep.RULE_ID_HALLUCINATION, "reqeusts_magic", "app")]


def test_diff_scan_uses_the_same_environment_scope(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(repo / "uv.lock", UV_LOCK)
    _write(repo / "examples" / "search_r1" / "data_process.sh", STRAIGHT_LINE_SH)
    _write(
        repo / "examples" / "search_r1" / "retrieval_server.py",
        "import pyserini\nimport made_up_retriever\n",
    )
    _write(
        repo / "examples" / "search_r1" / "agents" / "agent.py",
        "def run():\n    from openai import AsyncOpenAI\n    return AsyncOpenAI\n",
    )
    findings, _unreachable = dep.scan_diff_added_imports(
        repo,
        [
            ("examples/search_r1/retrieval_server.py", 1, "pyserini"),
            ("examples/search_r1/retrieval_server.py", 2, "made_up_retriever"),
            ("examples/search_r1/agents/agent.py", 2, "openai"),
        ],
    )
    # pyserini is installed by the example's setup script; openai only
    # arrives through a locked extra and stays undeclared.
    assert sorted(f["symbol"] for f in findings) == ["made_up_retriever", "openai"]


JINJA_PYPROJECT = '[project]\nname = "site"\ndependencies = ["jinja2>=3.1"]\n'

JINJA_UV_LOCK = """version = 1
revision = 3

[[package]]
name = "site"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "jinja2" },
]

[[package]]
name = "jinja2"
version = "3.1.6"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "markupsafe" },
    { name = "colorama", marker = "sys_platform == 'win32'" },
]

[package.optional-dependencies]
i18n = [
    { name = "babel" },
]

[[package]]
name = "markupsafe"
version = "3.0.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "babel"
version = "2.16.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "colorama"
version = "0.4.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "rich"
version = "13.9.4"
source = { registry = "https://pypi.org/simple" }
"""

JINJA_IMPORTS = (
    "import jinja2\nimport markupsafe\nimport babel\nimport colorama\n"
    "import rich\nimport left_pad_py\n"
)
STILL_UNDECLARED = ["babel", "colorama", "left_pad_py", "rich"]


def _symbols(findings):
    return sorted(symbol for _rule, symbol, _dir in _rules(findings))


def _kinds(findings):
    """SKY-D222, or SKY-D223 "Possible hallucinated import" while declared
    providers are uninspected, are both hallucination reports."""
    kinds = []
    for finding in findings:
        kind = "undeclared"
        if finding["rule_id"] == dep.RULE_ID_HALLUCINATION or (
            "hallucinated" in finding["message"]
        ):
            kind = "hallucinated"
        kinds.append(
            (kind, finding["symbol"], os.path.basename(os.path.dirname(finding["file"])))
        )
    return sorted(kinds)


def test_uv_lock_edge_from_a_declared_package_provides_its_dependency(
    monkeypatch, tmp_path
):
    """A lockfile or installed metadata that records an unconditional edge
    from a declared distribution provides the dependency's imports
    (awesome-python: jinja2 -> markupsafe in uv.lock; TrendRadar: boto3 ->
    botocore). Locked packages no edge reaches, marker edges and extras
    nobody requests do not."""
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", JINJA_PYPROJECT)
    _write(repo / "uv.lock", JINJA_UV_LOCK)
    app = _write(repo / "site" / "render.py", JINJA_IMPORTS)
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _symbols(findings) == STILL_UNDECLARED


def test_poetry_and_pdm_lock_edges_provide_dependencies(monkeypatch, tmp_path):
    _stub(monkeypatch)
    locks = {
        "poetry.lock": (
            '[[package]]\nname = "Jinja2"\nversion = "3.1.6"\noptional = false\n'
            'python-versions = ">=3.7"\nfiles = []\n\n'
            '[package.dependencies]\nMarkupSafe = ">=2.0"\n'
            'Babel = {version = ">=2.7", optional = true}\n'
            'colorama = {version = "*", markers = "sys_platform == \\"win32\\""}\n\n'
            '[package.extras]\ni18n = ["Babel (>=2.7)"]\n\n'
            '[[package]]\nname = "markupsafe"\nversion = "3.0.2"\noptional = false\n'
            'python-versions = ">=3.9"\nfiles = []\n\n'
            '[[package]]\nname = "rich"\nversion = "13.9.4"\noptional = false\n'
            'python-versions = ">=3.8"\nfiles = []\n\n'
            '[metadata]\nlock-version = "2.0"\n'
        ),
        "pdm.lock": (
            '[metadata]\ngroups = ["default"]\n\n'
            '[[package]]\nname = "jinja2"\nversion = "3.1.6"\n'
            'dependencies = ["MarkupSafe>=2.0", "colorama; sys_platform == \'win32\'"]\n\n'
            '[[package]]\nname = "jinja2"\nversion = "3.1.6"\nextras = ["i18n"]\n'
            'dependencies = ["babel>=2.7", "jinja2==3.1.6"]\n\n'
            '[[package]]\nname = "markupsafe"\nversion = "3.0.2"\n\n'
            '[[package]]\nname = "rich"\nversion = "13.9.4"\n'
        ),
    }
    for filename, text in locks.items():
        repo = tmp_path / filename.replace(".", "_")
        _write(repo / "pyproject.toml", JINJA_PYPROJECT)
        _write(repo / filename, text)
        app = _write(repo / "site" / "render.py", JINJA_IMPORTS)
        findings = dep.scan_python_dependency_hallucinations(repo, [app])
        assert _symbols(findings) == STILL_UNDECLARED, filename


def test_extra_requested_by_the_locked_project_entry_is_followed(
    monkeypatch, tmp_path
):
    """The real agent-lightning uv.lock records the project's own
    ``verl = [{ name = "autogen-ext", extra = ["openai"] }]`` edge, so the
    extra's openai is brought along; another extra of autogen-ext is not."""
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", PYPROJECT)
    _write(
        repo / "uv.lock",
        UV_LOCK.replace(
            'source = { editable = "." }\n',
            'source = { editable = "." }\n\n[package.optional-dependencies]\n'
            'verl = [\n    { name = "autogen-ext", extra = ["openai"] },\n]\n',
            1,
        ).replace(
            'openai = [\n    { name = "openai" },\n]\n',
            'openai = [\n    { name = "openai" },\n]\n'
            'pillow = [\n    { name = "pillow" },\n]\n',
        ),
    )
    agent = _write(
        repo / "examples" / "agent.py",
        "from openai import AsyncOpenAI\nimport PIL.Image\n",
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [agent])
    assert _symbols(findings) == ["PIL"]


@pytest.mark.parametrize(
    "case",
    [
        "undeclared_root",
        "marker_root",
        "incompatible_locked_version",
        "forked_entries",
        "nearest_lock",
        "symlinked_lock",
        "hallucination",
    ],
)
def test_lock_evidence_that_must_not_provide_an_import(monkeypatch, tmp_path, case):
    """``undeclared_root``: a stale project entry still lists jinja2, the
    manifest does not. ``marker_root``: jinja2 is declared only for Python 2.
    ``incompatible_locked_version``: the lock's jinja2 3.1.6 is outside the
    declared ``<3``. ``forked_entries``: one locked jinja2 lacks the edge.
    ``nearest_lock``: a nested project's own lock lacks it."""
    statuses = {}
    if case == "hallucination":
        statuses = {"markupsafe": "missing"}
    _stub(monkeypatch, statuses=statuses)
    repo = tmp_path / "repo"
    pyproject = JINJA_PYPROJECT
    lock = JINJA_UV_LOCK
    app_dir = repo / "site"
    if case == "undeclared_root":
        pyproject = '[project]\nname = "site"\ndependencies = []\n'
    if case == "marker_root":
        pyproject = (
            '[project]\nname = "site"\n'
            "dependencies = [\"jinja2; python_version < '3.0'\"]\n"
        )
    if case == "incompatible_locked_version":
        pyproject = '[project]\nname = "site"\ndependencies = ["jinja2<3"]\n'
    if case == "forked_entries":
        lock = lock.replace(
            '[[package]]\nname = "markupsafe"',
            '[[package]]\nname = "jinja2"\nversion = "2.11.3"\n'
            'source = { registry = "https://pypi.org/simple" }\n\n'
            '[[package]]\nname = "markupsafe"',
        )
    if case == "nearest_lock":
        app_dir = repo / "services" / "api"
        _write(app_dir / "pyproject.toml", JINJA_PYPROJECT)
        _write(
            app_dir / "uv.lock",
            'version = 1\n\n[[package]]\nname = "jinja2"\nversion = "3.1.6"\n'
            'source = { registry = "https://pypi.org/simple" }\n',
        )
    _write(repo / "pyproject.toml", pyproject)
    if case == "symlinked_lock":
        outside = _write(tmp_path / "outside" / "uv.lock", lock)
        try:
            os.symlink(outside, repo / "uv.lock")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
    else:
        _write(repo / "uv.lock", lock)
    app = _write(app_dir / "render.py", "import markupsafe\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    expected_kind = "undeclared"
    if case == "hallucination":
        expected_kind = "hallucinated"
    assert [(kind, symbol) for kind, symbol, _dir in _kinds(findings)] == [
        (expected_kind, "markupsafe")
    ]


PYDANTIC_REQUIREMENTS = {
    "pydantic": (
        "2.13.4",
        (
            "typing-extensions>=4.14.1",
            "annotated-types>=0.6.0",
            "colorama; sys_platform == 'win32'",
            "email-validator>=2.0.0; extra == 'email'",
        ),
    ),
    "typing-extensions": ("4.16.0", ()),
    "annotated-types": ("0.5.0", ()),
    "colorama": ("0.4.6", ()),
    "email-validator": ("2.2.0", ()),
}
PYDANTIC_INSTALLED = {
    "pydantic": {"pydantic"},
    "typing_extensions": {"typing-extensions"},
    "annotated_types": {"annotated-types"},
    "colorama": {"colorama"},
    "email_validator": {"email-validator"},
}
PYDANTIC_IMPORTS = (
    "import pydantic\nfrom typing_extensions import Self\nimport annotated_types\n"
    "import colorama\nimport email_validator\n"
)


@pytest.mark.parametrize(
    "declared, installed, expected",
    [
        (
            "pydantic>=2.0",
            PYDANTIC_INSTALLED,
            ["annotated_types", "colorama", "email_validator"],
        ),
        (
            "pydantic>=3",
            PYDANTIC_INSTALLED,
            ["annotated_types", "colorama", "email_validator", "typing_extensions"],
        ),
        (
            "pydantic>=2.0",
            {k: v for k, v in PYDANTIC_INSTALLED.items() if k != "pydantic"},
            ["annotated_types", "colorama", "email_validator", "typing_extensions"],
        ),
    ],
    ids=["satisfied", "declared_version_not_installed", "not_in_module_snapshot"],
)
def test_installed_requires_dist_of_a_declared_distribution(
    monkeypatch, tmp_path, declared, installed, expected
):
    _stub(monkeypatch, installed=installed)
    monkeypatch.setattr(
        dep, "_build_installed_requirements", lambda: dict(PYDANTIC_REQUIREMENTS)
    )
    repo = tmp_path / "repo"
    _write(
        repo / "pyproject.toml",
        f'[project]\nname = "svc"\ndependencies = ["{declared}"]\n',
    )
    app = _write(repo / "svc" / "models.py", PYDANTIC_IMPORTS)
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _symbols(findings) == expected


def test_installed_requirements_read_metadata_headers_only(tmp_path):
    metadata = (
        "Metadata-Version: 2.1\nName: Pydantic\nVersion: 2.13.4\n"
        "Requires-Dist: typing-extensions>=4.14.1\n\n"
        "Requires-Dist: not-a-header\n"
    )
    fields = dep._metadata_requirements(metadata)
    assert fields == {
        "Name": "Pydantic",
        "Version": "2.13.4",
        "Requires-Dist": ["typing-extensions>=4.14.1"],
    }


SHIPPED_ONLY_PYPROJECT = (
    '[build-system]\nrequires = ["setuptools>=68"]\n'
    'build-backend = "setuptools.build_meta"\n\n'
    '[project]\nname = "svc"\ndependencies = ["httpx"]\n\n'
    '[tool.setuptools.packages.find]\ninclude = ["svc*"]\n'
)
BENCH_IMPORTS = "import matplotlib\nimport made_up_plotter\n"


def _layout(repo, pyproject, extra_files=()):
    _write(repo / "pyproject.toml", pyproject)
    for relative, text in extra_files:
        _write(repo / relative, text)
    return [
        _write(repo / "benchmarks" / "frames" / "plot.py", BENCH_IMPORTS),
        _write(repo / "tests" / "test_plot.py", "import matplotlib\n"),
        _write(repo / "svc" / "core.py", "import matplotlib\n"),
        _write(repo / "app.py", "import matplotlib\n"),
    ]


def test_unshipped_benchmark_and_test_code_has_no_dependency_scope(
    monkeypatch, tmp_path
):
    """serviette's pyproject packages only ``serviette*``; its benchmarks/
    scripts import matplotlib, pandas, huggingface_hub that their README
    installs by hand. The shipped package and a root-level app script keep
    the manifest's scope; the hallucinated benchmark import is still
    reported."""
    _stub(monkeypatch, statuses={"made_up_plotter": "missing"})
    repo = tmp_path / "repo"
    files = _layout(repo, SHIPPED_ONLY_PYPROJECT)
    findings = dep.scan_python_dependency_hallucinations(repo, files)
    assert _kinds(findings) == [
        ("hallucinated", "made_up_plotter", "frames"),
        ("undeclared", "matplotlib", "repo"),
        ("undeclared", "matplotlib", "svc"),
    ]
    diff_findings, _unreachable = dep.scan_diff_added_imports(
        repo,
        [
            ("benchmarks/frames/plot.py", 1, "matplotlib"),
            ("benchmarks/frames/plot.py", 2, "made_up_plotter"),
            ("svc/core.py", 1, "matplotlib"),
        ],
    )
    assert _kinds(diff_findings) == [
        ("hallucinated", "made_up_plotter", "frames"),
        ("undeclared", "matplotlib", "svc"),
    ]


@pytest.mark.parametrize(
    "selection",
    [
        '[tool.hatch.build.targets.wheel]\npackages = ["svc"]\n',
        '[tool.hatch.build.targets.wheel]\nonly-include = ["svc", "app.py"]\n',
        '[tool.poetry]\npackages = [{ include = "svc" }]\n',
        '[tool.setuptools]\npackages = ["svc"]\npy-modules = ["app"]\n',
    ],
    ids=["hatch_packages", "hatch_only_include", "poetry_packages", "setuptools_list"],
)
def test_other_backends_name_their_shipped_packages(monkeypatch, tmp_path, selection):
    _stub(monkeypatch)
    backend = "setuptools.build_meta"
    if "hatch" in selection:
        backend = "hatchling.build"
    if "poetry" in selection:
        backend = "poetry.core.masonry.api"
    pyproject = (
        f'[build-system]\nrequires = []\nbuild-backend = "{backend}"\n\n'
        '[project]\nname = "svc"\ndependencies = []\n\n' + selection
    )
    repo = tmp_path / "repo"
    files = _layout(repo, pyproject)
    findings = dep.scan_python_dependency_hallucinations(repo, files)
    assert _rules(findings) == [
        (dep.RULE_ID_UNDECLARED, "matplotlib", "repo"),
        (dep.RULE_ID_UNDECLARED, "matplotlib", "svc"),
    ]


@pytest.mark.parametrize(
    "pyproject, extra_files",
    [
        (
            SHIPPED_ONLY_PYPROJECT.replace('include = ["svc*"]', 'where = ["."]'),
            (),
        ),
        (
            SHIPPED_ONLY_PYPROJECT.replace('include = ["svc*"]', 'include = ["svc*", "bench*"]'),
            (),
        ),
        (SHIPPED_ONLY_PYPROJECT, (("requirements.txt", "httpx\n"),)),
        (SHIPPED_ONLY_PYPROJECT, (("benchmarks/requirements-bench.txt", "pandas\n"),)),
        (SHIPPED_ONLY_PYPROJECT, (("setup.py", "from setuptools import setup\nsetup()\n"),)),
        (SHIPPED_ONLY_PYPROJECT, (("benchmarks/frames/setup.sh", "pip install pandas\n"),)),
        (
            SHIPPED_ONLY_PYPROJECT.replace("setuptools.build_meta", "hatchling.build"),
            (),
        ),
        (
            '[build-system]\nrequires = []\nbuild-backend = "hatchling.build"\n\n'
            '[project]\nname = "svc"\ndependencies = []\n\n'
            '[tool.hatch.build.targets.wheel]\npackages = ["svc"]\n'
            'include = ["benchmarks/**/*.py"]\n',
            (),
        ),
        (
            '[build-system]\nrequires = []\nbuild-backend = "poetry.core.masonry.api"\n\n'
            '[tool.poetry]\nname = "svc"\npackages = [{ include = "*" }]\n',
            (),
        ),
        (
            '[project]\nname = "svc"\ndependencies = []\n',
            (),
        ),
    ],
    ids=[
        "find_everything",
        "include_matches_benchmarks",
        "root_requirements",
        "nested_requirements",
        "setup_py",
        "environment_script",
        "config_of_another_backend",
        "hatch_include_glob",
        "poetry_glob",
        "automatic_discovery",
    ],
)
def test_benchmark_imports_stay_undeclared_without_an_exact_selection(
    monkeypatch, tmp_path, pyproject, extra_files
):
    _stub(monkeypatch, statuses={"made_up_plotter": "missing"})
    repo = tmp_path / "repo"
    bench = _layout(repo, pyproject, extra_files)[0]
    findings = dep.scan_python_dependency_hallucinations(repo, [bench])
    assert _kinds(findings) == [
        ("hallucinated", "made_up_plotter", "frames"),
        ("undeclared", "matplotlib", "frames"),
    ]
