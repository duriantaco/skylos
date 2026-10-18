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

Lockfiles do not declare imports. An environment file (environment.yml,
Pipfile ``[packages]``), a straight-line install in a setup script, or the
final stage of the one Dockerfile that copies the code provides a
distribution for the directory it sits in and everything below it (see
test_undeclared_import_env_round4.py and _round5.py for what does not
count). An import nothing in that chain declares or installs is still
reported.
"""

import os

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        text, encoding="utf-8"
    )
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
# A lockfile adds transitive distributions; code that imports one it only gets
# through another dependency still has an undeclared import.


def test_uv_lock_transitive_import_is_still_undeclared(monkeypatch, tmp_path):
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
