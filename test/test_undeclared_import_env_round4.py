"""SKY-D223 environment evidence must describe the environment the code runs in.

Hidden real defects found by an adversarial review (fnhunt3 t01-t14):

* an install that only runs under a condition (``if [ -n "$WITH_YAML" ]``,
  ``[ ... ] && pip install``), inside a shell function nobody calls, inside a
  loop or ``case``;
* an install into another environment: ``--target``/``--prefix``/``--root``,
  a pip or python by path (``.lint/bin/pip``), after activating another
  environment, ``conda create``/``conda install -n``, ``uv run --with``;
* Pipfile ``[dev-packages]``;
* a Dockerfile whose final stage never copies the importing code, or an
  earlier build stage;
* (round 5, see test_undeclared_import_env_round5.py) anything a strict
  straight-line reading cannot prove: control flow, functions, ``exit``,
  assignments, activation, ``conda``, and options other than a small
  allowlist known to target the running interpreter;
* a CI or tooling script beside (or above) the manifest that declares the
  code's environment;
* a "Possible hallucinated import" that a setup script also "installs".
"""

from pathlib import Path

import pytest

import skylos.rules.ai_defect.dependency_hallucination as dep
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.ai_defect.environment_dependencies import shell_install_names


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


def _symbols(findings):
    return sorted(f["symbol"] for f in findings)


def _names(script, tmp_path):
    return set(shell_install_names(script, tmp_path, tmp_path))


# -- shell scripts: only installs that always run --------------------------------


@pytest.mark.parametrize(
    "script, expected",
    [
        ("pip install alpha\n", {"alpha"}),
        ('if [ -n "$WITH_YAML" ]; then\n  pip install pyyaml\nfi\n', set()),
        # Control flow, functions and and-or lists stop the reading (round 5:
        # following them hid installs after ``exit``/``return``).
        (
            "if nvidia-smi; then pip install faiss-gpu; else pip install faiss-cpu; fi\n",
            set(),
        ),
        (
            "if a; then pip install x\nelif b; then pip install x\nfi\n",
            set(),
        ),
        (
            "if a; then pip install x y\nelif b; then pip install x\n"
            "else pip install x z\nfi\n",
            set(),
        ),
        ("install_extras() {\n  pip install httpx\n}\npip install -e .\n", set()),
        ("install_extras() {\n  pip install httpx\n}\ninstall_extras\n", set()),
        ("function extras { pip install httpx; }\nextras\n", set()),
        (
            'extras() { pip install httpx; }\nif [ -n "$X" ]; then extras; fi\n',
            set(),
        ),
        ('[ -n "$X" ] && pip install alpha\n', set()),
        ('[ -n "$X" ] &&\n  pip install alpha\n', set()),
        ('[ -n "$X" ] && \\\n  pip install alpha\n', set()),
        ("pip freeze |\n  grep -q alpha || pip install alpha\n", set()),
        ("cd sub &&\n  pip install alpha\n", set()),
        ("apt-get remove -y x || true && pip install alpha\n", set()),
        ('[ -n "$X" ] || pip install alpha && pip install beta\n', set()),
        ("command -v uv && uv pip install alpha || pip install alpha\n", set()),
        ("N=${N:-$((GPUS / 2))}\nM=${M:-a b}\npip install alpha\n", set()),
        (
            'if [[ "$C" =~ (^|[[:space:]])rg && -n "$D" ]]; then pip install beta; fi\n'
            "pip install alpha\n",
            set(),
        ),
        ("command -v uv >/dev/null && uv pip install alpha\n", set()),
        ("cd sub && pip install alpha\n", set()),
        ("pip install alpha || pip install beta\n", set()),
        ("pip install alpha || true\n", set()),
        ("for p in a b; do pip install alpha; done\n", set()),
        ("while read p; do pip install alpha; done < list\n", set()),
        (
            "case $1 in\n  gpu) pip install alpha;;\n  *) pip install beta;;\nesac\n",
            set(),
        ),
        ('[ -n "$X" ] && { pip install alpha; }\n', set()),
        ("{ pip install alpha; }\n( pip install beta )\n", set()),
        ("pip install alpha > /dev/null 2>&1\n", {"alpha"}),
        ('if [ -n "$X" ]; then\n  pip install alpha\n', set()),  # unterminated
        ("fi\npip install alpha\n", set()),  # unbalanced
    ],
)
def test_shell_installs_count_only_when_they_always_run(tmp_path, script, expected):
    assert _names(script, tmp_path) == expected


@pytest.mark.parametrize(
    "script",
    [
        "pip install --target ./layer/python requests\n",
        "pip install -t layer requests\n",
        "pip install --prefix=/opt/tool requests\n",
        "pip install --root /chroot requests\n",
        "uv pip install --target build requests\n",
        "python -m venv .lint\n.lint/bin/pip install requests ruff\n",
        "/opt/other/bin/python -m pip install requests\n",
        "python -m venv .lint\n. .lint/bin/activate\npip install requests\n",
        "source venv/bin/activate && pip install requests\n",
        "conda create -y -n docs-env python=3.12 sphinx requests\n",
        "conda install -y -n other requests\n",
        "mamba install -p /envs/x requests\n",
        "conda activate retriever\nconda install -y requests\n",
        "uv run --with requests python scripts/smoke.py\n",
        "pipx install requests\n",
        "bash -c 'pip install requests'\n",
    ],
)
def test_installs_into_another_environment_do_not_count(tmp_path, script):
    assert _names(script, tmp_path) == set()


def test_case_statement_stops_the_reading(tmp_path):
    script = (
        'case "$TOOL" in\n'
        "  Bash)\n"
        '    if [[ "$CMD" =~ (^|[[:space:]])rg[[:space:]] ]]; then\n'
        "      P=1\n"
        "    fi\n"
        "    ;;\n"
        "esac\n"
        "pip install alpha\n"
    )
    assert _names(script, tmp_path) == set()


def test_long_script_is_read_until_the_first_non_straight_line_command(tmp_path):
    filler = "".join(f'echo "line {i} of a long setup script"\n' for i in range(600))
    script = "pip install alpha\n" + filler + "pip install beta\n"
    assert len(script) > 16384
    assert _names(script, tmp_path) == {"alpha", "beta"}
    stopped = 'pip install alpha\nif [ -n "$X" ]; then\n' + filler + "fi\npip install beta\n"
    assert _names(stopped, tmp_path) == {"alpha"}


def test_installs_into_the_running_environment_count(tmp_path):
    # Only pip/pip3/python -m pip/python3 -m pip/uv pip with options known to
    # target the running interpreter count; ``conda`` stops the reading.
    script = (
        "pip3 install alpha\npython -m pip install beta\n"
        "python3.12 -m pip install gamma\nuv pip install delta\n"
        "sudo pip install epsilon\npip install --user eta\n"
        "pip install theta\nconda install -y zeta\npip install iota\n"
    )
    assert _names(script, tmp_path) == {"alpha", "beta", "delta", "theta"}


def test_agent_lightning_retriever_install_is_conditional(tmp_path):
    # microsoft/agent-lightning@ee707b6 examples/search_r1/data_process.sh:
    # every install sits inside ``if [[ ${SKIP_RETRIEVER_INSTALL} != 1 ]]``
    # without an else, after ``conda activate "$ENV_NAME"``.
    script = (
        'if ! conda env list | grep -qx "$ENV_NAME"; then\n'
        '    conda create -n "$ENV_NAME" "python=$PYTHON_VERSION" -y\nfi\n'
        'conda activate "$ENV_NAME"\n'
        'if [[ "${SEARCH_R1_SKIP_RETRIEVER_INSTALL:-0}" != "1" ]]; then\n'
        '    conda install -y -c pytorch -c nvidia "faiss-gpu=1.8.0"\n'
        '    python -m pip install -U "transformers==4.57.1" datasets pyserini\n'
        "fi\n"
    )
    assert _names(script, tmp_path) == set()


# -- Dockerfiles: the final stage, and only for code it copies ---------------------


def _docker_scan(monkeypatch, tmp_path, dockerfile, directory="app"):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", '[project]\nname = "svc"\ndependencies = []\n')
    _write(tmp_path / "Dockerfile", dockerfile)
    code = _write(tmp_path / directory / "main.py", "import alpha\nimport beta\n")
    return _symbols(dep.scan_python_dependency_hallucinations(tmp_path, [code]))


def test_dockerfile_final_stage_only(monkeypatch, tmp_path):
    assert _docker_scan(
        monkeypatch,
        tmp_path,
        "FROM python:3.12 AS build\nRUN pip install alpha\n"
        "FROM python:3.12-slim\nCOPY . /app\nRUN pip install beta\n",
    ) == ["alpha"]


def test_dockerfile_stage_inherits_its_base_stage(monkeypatch, tmp_path):
    dockerfile = (
        "FROM python:3.12 AS base\nRUN pip install alpha\n"
        "FROM base AS app\nCOPY src/ /srv/src\nRUN pip install beta\n"
    )
    assert _docker_scan(monkeypatch, tmp_path, dockerfile, "src/pkg") == []


def test_dockerfile_does_not_cover_code_it_does_not_copy(monkeypatch, tmp_path):
    dockerfile = (
        "FROM python:3.12 AS base\nRUN pip install alpha\n"
        "FROM base AS app\nCOPY src/ /srv/src\nRUN pip install beta\n"
    )
    assert _docker_scan(monkeypatch, tmp_path, dockerfile, "tools") == ["alpha", "beta"]


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM python:3.12\nRUN pip install alpha beta\nCMD celery -A worker worker\n",
        "FROM python:3.12 AS b\nCOPY . .\nFROM python:3.12\n"
        "COPY --from=b /app /app\nRUN pip install alpha beta\n",
        "FROM python:3.12\nCOPY worker/ /worker\nRUN pip install alpha beta\n",
        "FROM python:3.12\nCOPY requirements.txt .\nRUN pip install alpha beta\n",
        "FROM python:3.12\nCOPY *.py ./\nRUN pip install alpha beta\n",
    ],
)
def test_dockerfile_that_does_not_copy_the_code_does_not_count(
    monkeypatch, tmp_path, dockerfile
):
    assert _docker_scan(monkeypatch, tmp_path, dockerfile) == ["alpha", "beta"]


def test_dockerfile_heredoc_body_is_not_instructions(monkeypatch, tmp_path):
    # verl docker/Dockerfile.stable.trtllm: a Python heredoc line
    # ``from pathlib import Path`` is not a FROM instruction, and a heredoc
    # RUN is not a plain install.
    dockerfile = (
        "FROM python:3.12\nCOPY . /app\nRUN pip install alpha\n"
        "RUN python3 - <<'PY'\nfrom pathlib import Path\nrun = 1\nPY\n"
        "RUN <<-EOF\n\tpip install beta\n\tEOF\n"
    )
    assert _docker_scan(monkeypatch, tmp_path, dockerfile) == ["beta"]


def test_dockerfile_glob_copy_covers_only_its_own_directory(monkeypatch, tmp_path):
    dockerfile = "FROM python:3.12\nCOPY *.py ./\nRUN pip install alpha\n"
    assert _docker_scan(monkeypatch, tmp_path, dockerfile, ".") == ["beta"]
    assert _docker_scan(monkeypatch, tmp_path, dockerfile) == ["alpha", "beta"]


# -- which definitions describe the importing file's environment ------------------


def test_ci_script_beside_the_manifest_does_not_declare_imports(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(
        repo / "pyproject.toml", '[project]\nname = "svc"\ndependencies = ["flask"]\n'
    )
    _write(
        repo / "ci.sh", "#!/bin/sh\nset -e\npip install pytest requests\npytest -q\n"
    )
    app = _write(repo / "app" / "main.py", "import flask\nimport requests\n")
    tool = _write(repo / "tools" / "run.py", "import requests\n")
    _write(repo / "tools" / "ci.sh", "pip install pytest requests\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app, tool])
    # tools/ has no manifest: its own script is its only environment definition.
    assert [(f["symbol"], Path(f["file"]).parent.name) for f in findings] == [
        ("requests", "app")
    ]


def test_manifest_nearer_than_the_script_wins(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "mono"\ndependencies = []\n')
    _write(repo / "services" / "setup.sh", "pip install redis\n")
    _write(repo / "services" / "a" / "requirements.txt", "flask\n")
    a = _write(repo / "services" / "a" / "app.py", "import flask\nimport redis\n")
    b = _write(repo / "services" / "b" / "worker.py", "import redis\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [a, b])
    assert [(f["symbol"], Path(f["file"]).parent.name) for f in findings] == [
        ("redis", "a")
    ]


def test_dockerfile_that_copies_the_code_counts_beside_the_manifest(
    monkeypatch, tmp_path
):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "svc"\ndependencies = []\n')
    _write(
        repo / "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /srv\nCOPY . .\n"
        "RUN apt-get update && pip install --no-cache-dir gunicorn uvicorn\n",
    )
    _write(repo / "Dockerfile.worker", "FROM python:3.12\nRUN pip install httpx\n")
    app = _write(
        repo / "app" / "main.py", "import uvicorn\nimport httpx\nimport gunicorn\n"
    )
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _symbols(findings) == ["httpx"]


def test_pipfile_dev_packages_do_not_declare_runtime_imports(monkeypatch, tmp_path):
    _stub(monkeypatch)
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "svc"\ndependencies = []\n')
    _write(
        repo / "Pipfile",
        '[packages]\nflask = "*"\n\n[dev-packages]\nrequests = "*"\npytest = "*"\n',
    )
    app = _write(repo / "app" / "main.py", "import flask\nimport requests\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _symbols(findings) == ["requests"]


def test_installed_lookalike_of_a_possible_hallucination_still_reports(
    monkeypatch, tmp_path
):
    # The declared distribution cannot be inspected, so the hallucination is
    # downgraded to "Possible hallucinated import"; a setup script that runs
    # ``pip install fastjson-turbo`` is no evidence the package exists.
    _stub(
        monkeypatch,
        statuses={"fastjson_turbo": "missing", "fastjson-turbo": "missing"},
    )
    monkeypatch.setattr(dep, "_lookup_dist_modules", lambda batch, ctx: None)
    repo = tmp_path / "repo"
    _write(
        repo / "pyproject.toml", '[project]\nname = "svc"\ndependencies = ["flask"]\n'
    )
    _write(repo / "app" / "setup.sh", "pip install fastjson-turbo\n")
    app = _write(repo / "app" / "main.py", "import fastjson_turbo\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        (dep.RULE_ID_UNDECLARED, "fastjson_turbo")
    ]
    assert findings[0]["message"].startswith("Possible hallucinated import")


def test_name_mismatch_on_a_missing_project_is_not_silenced(monkeypatch, tmp_path):
    # PyPI has no project by the import's name and nothing maps it, so the
    # finding is "possible import/dist name mismatch"; an install line of the
    # same name proves nothing either.
    _stub(monkeypatch, statuses={"zz": "missing"})
    repo = tmp_path / "repo"
    _write(repo / "pyproject.toml", '[project]\nname = "svc"\ndependencies = []\n')
    _write(repo / "app" / "setup.sh", "pip install zz\n")
    app = _write(repo / "app" / "main.py", "import zz\n")
    findings = dep.scan_python_dependency_hallucinations(repo, [app])
    assert _symbols(findings) == ["zz"]
