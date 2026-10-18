"""SKY-D223 environment evidence counts only in shapes that can be proven.

Rounds 4 and 5 of adversarial review found environment evidence hiding
imports that nothing provides: installs after ``exit``/``return``, after
``export PIP_TARGET=...``/``PATH=venv``, with ``--python`` or ``--user``,
inside a Dockerfile stage that is not the image (a test stage last, a second
``Dockerfile.test``), behind a ``.dockerignore``, a docs-only conda file, a
root conda file above a service manifest, Pipfile markers, a ``-cuda``
variant name, and a namespace sibling (``google.cloud.bigquery`` from
``google-cloud-storage``). Following shell and Docker semantics in general
kept failing, so evidence now counts only in straight-line shapes, and
anything else is reported as before.
"""

import time
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


def _scan(repo, *files):
    findings = dep.scan_python_dependency_hallucinations(
        repo, [repo / relative for relative in files]
    )
    return sorted(
        (str(Path(f["file"]).relative_to(repo)), f["symbol"]) for f in findings
    )


PYPROJECT = '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["flask"]\n'


# -- shell scripts: straight-line commands only -------------------------------


@pytest.mark.parametrize(
    "script, expected",
    [
        ("#!/bin/sh\nset -euo pipefail\npip install alpha\n", {"alpha"}),
        ("pip3 install -U --no-cache-dir alpha 'beta[extra]>=2'\n", {"alpha", "beta"}),
        ("python -m pip install -q alpha\npython3 -m pip install beta\n", {"alpha", "beta"}),
        ("uv pip install --upgrade-strategy eager alpha\n", {"alpha"}),
        ("pip install --progress-bar off --pre alpha\n", {"alpha"}),
        ("apt-get update\nmkdir -p out\npip install alpha > /dev/null 2>&1\n", {"alpha"}),
        ("pip install -r requirements.txt alpha\n", {"alpha"}),
        ("pip install -e . alpha\n", {"alpha"}),
        ("pip install alpha\r\npip install beta\r\n", {"alpha", "beta"}),
        ("pip install \\\n  alpha \\\n  beta\n", {"alpha", "beta"}),
        # stop at the first command that is not straight-line
        ("exit 0\npip install alpha\n", set()),
        ("pip install alpha\nexit 0\npip install beta\n", {"alpha"}),
        ("deps() { return 0; pip install alpha; }\ndeps\n", set()),
        ("export PIP_TARGET=/tmp/isolated\npip install alpha\n", set()),
        ("PIP_TARGET=./layer pip install alpha\n", set()),
        ('export PATH="$PWD/.venv/bin:$PATH"\npip install alpha\n', set()),
        ("VERSION=1\npip install alpha\n", set()),
        ('[ "$CI" = true ] || exit 0\npip install alpha\n', set()),
        ('if [ -z "$X" ]; then\n  exit 0\nfi\npip install alpha\n', set()),
        ("source .venv/bin/activate\npip install alpha\n", set()),
        (". .venv/bin/activate\npip install alpha\n", set()),
        ("conda install -y alpha\npip install beta\n", set()),
        ("cd sub\npip install alpha\n", set()),
        ("pip install alpha; pip install beta\n", set()),
        ("pip install alpha && pip install beta\n", set()),
        ("{ pip install alpha; }\n", set()),
        ("cat <<EOF > x\npip install alpha\nEOF\npip install beta\n", set()),
        ("echo 'unclosed\npip install alpha\n", set()),
        # installs into another environment, or not plainly by name
        ("pip install --target ./layer alpha\n", set()),
        ("pip install --user alpha\n", set()),
        ("uv pip install --python .docs-venv/bin/python alpha\n", set()),
        ("pip --python .docs-venv/bin/python install alpha\n", set()),
        ("sudo -H pip3 install alpha\n", set()),
        (".venv/bin/pip install alpha\n", set()),
        ("python3.12 -m pip install alpha\n", set()),
        ("pip install $PKG alpha\n", set()),
        ("pip install 'alpha; python_version < \"3.0\"' beta\n", {"beta"}),
        ("pip install https://example.com/alpha.whl beta\n", {"beta"}),
        # a ``#`` inside a word is not a comment
        ("pip install alpha#notcomment beta # comment gamma\n", {"beta"}),
    ],
)
def test_only_straight_line_installs_count(tmp_path, script, expected):
    assert set(shell_install_names(script, tmp_path, tmp_path)) == expected


def test_crafted_test_brackets_stay_linear(tmp_path):
    # ``[[ a && a && ... ]]`` once rescanned every word per operator.
    script = "[[ " + " && ".join(["a"] * 6000) + " ]]\npip install alpha\n"
    started = time.perf_counter()
    assert set(shell_install_names(script, tmp_path, tmp_path)) == set()
    assert time.perf_counter() - started < 1.0


def test_long_straight_line_script_is_read_to_the_end(tmp_path):
    filler = "".join(f'echo "line {i} of a long setup script"\n' for i in range(3000))
    script = "pip install alpha\n" + filler + "pip install beta\n"
    started = time.perf_counter()
    assert set(shell_install_names(script, tmp_path, tmp_path)) == {"alpha", "beta"}
    assert time.perf_counter() - started < 1.0


# -- which scripts and environment files describe the code's environment --------


def test_script_beside_a_pipfile_is_a_tooling_script(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "app" / "Pipfile", '[packages]\nrequests = "*"\n')
    _write(tmp_path / "app" / "setup.sh", "pip install rich\n")
    _write(tmp_path / "app" / "main.py", "import rich\nimport requests\n")
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "rich")]


def test_script_beside_a_requirements_directory_is_a_tooling_script(
    monkeypatch, tmp_path
):
    _stub(monkeypatch)
    _write(tmp_path / "requirements" / "base.txt", "flask\n")
    _write(
        tmp_path / "ci.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\npip install coverage requests\n",
    )
    _write(tmp_path / "app" / "main.py", "import flask\nimport requests\n")
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "requests")]


def test_pipfile_entry_with_markers_is_not_counted(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(
        tmp_path / "Pipfile",
        '[packages]\nrich = {version = "*", markers = "python_version < \'3.0\'"}\n'
        'httpx = {version = "==0.27"}\nflask = "*"\n',
    )
    _write(tmp_path / "app" / "main.py", "import rich\nimport httpx\nimport flask\n")
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "rich")]


def test_only_a_file_named_environment_yml_counts(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(
        tmp_path / "docs" / "environment-docs.yml",
        "dependencies:\n  - pip\n  - pip:\n      - requests\n",
    )
    _write(tmp_path / "docs" / "build.py", "import requests\n")
    _write(
        tmp_path / "nb" / "environment.yml",
        "dependencies:\n  - pip\n  - pip:\n      - requests\n",
    )
    _write(tmp_path / "nb" / "run.py", "import requests\n")
    assert _scan(tmp_path, "docs/build.py", "nb/run.py") == [
        ("docs/build.py", "requests")
    ]


def test_root_conda_file_does_not_cover_a_service_with_its_own_manifest(
    monkeypatch, tmp_path
):
    _stub(monkeypatch)
    _write(
        tmp_path / "environment.yml",
        "name: mono-dev\ndependencies:\n  - pip\n  - pip:\n      - flask\n      - requests\n",
    )
    _write(tmp_path / "services" / "b" / "requirements.txt", "flask\n")
    _write(tmp_path / "services" / "b" / "main.py", "import flask\nimport requests\n")
    assert _scan(tmp_path, "services/b/main.py") == [("services/b/main.py", "requests")]


def test_conda_file_beside_another_manifest_does_not_count(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(
        tmp_path / "environment.yml",
        "dependencies:\n  - pip\n  - pip:\n      - requests\n",
    )
    _write(tmp_path / "app" / "main.py", "import flask\nimport requests\n")
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "requests")]


# -- Dockerfiles: one image, its final stage, nothing ignored ---------------------


DOCKERFILE = (
    "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n"
    "RUN apt-get update && pip install --no-cache-dir requests\n"
)


def _docker_repo(tmp_path, files):
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "app" / "main.py", "import flask\nimport requests\n")
    for relative, text in files.items():
        _write(tmp_path / relative, text)


def test_single_dockerfile_that_copies_the_code_counts(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _docker_repo(tmp_path, {"Dockerfile": DOCKERFILE})
    assert _scan(tmp_path, "app/main.py") == []


@pytest.mark.parametrize(
    "files",
    [
        # the image's code is in the base stage; only the test stage installs
        {
            "Dockerfile": "FROM python:3.12-slim AS base\nWORKDIR /app\nCOPY . .\n"
            "FROM base AS test\nRUN pip install pytest requests\n"
        },
        # the stage that copies and installs is not the image: the final
        # stage takes only the files (``--from``), not the site-packages
        {
            "Dockerfile": "FROM python:3.12 AS dev\nCOPY . .\nRUN pip install requests\n"
            "FROM python:3.12-slim\nCOPY --from=dev /app /app\n"
        },
        # two images copy the code: which one runs it is unknown
        {"Dockerfile": DOCKERFILE, "Dockerfile.test": DOCKERFILE},
        # two stages copy the code
        {
            "Dockerfile": "FROM python:3.12 AS build\nCOPY . .\n"
            "FROM python:3.12-slim\nCOPY . .\nRUN pip install requests\n"
        },
        # the build context may leave the code out
        {"Dockerfile": DOCKERFILE, ".dockerignore": "app/\n"},
        {"Dockerfile": DOCKERFILE, "Dockerfile.dockerignore": "app/\n"},
        # installs after the environment is redirected
        {
            "Dockerfile": "FROM python:3.12\nCOPY . .\nENV PIP_TARGET=/layer\n"
            "RUN pip install requests\n"
        },
        {
            "Dockerfile": "FROM python:3.12\nCOPY . .\nENV PATH=/opt/venv/bin:$PATH\n"
            "RUN pip install requests\n"
        },
        {
            "Dockerfile": "FROM python:3.12\nARG UV_PROJECT_ENVIRONMENT=/x\nCOPY . .\n"
            "RUN pip install requests\n"
        },
        # a RUN that is not a plain chain of installs and harmless commands
        {"Dockerfile": "FROM python:3.12\nCOPY . .\nRUN [ -n \"$X\" ] || pip install requests\n"},
        {"Dockerfile": "FROM python:3.12\nCOPY . .\nRUN cd /tmp && pip install requests\n"},
        {"Dockerfile": "FROM python:3.12\nCOPY . .\nRUN pip install --user requests\n"},
        {"Dockerfile": "FROM python:3.12\nCOPY . .\nRUN <<EOF\npip install requests\nEOF\n"},
    ],
)
def test_dockerfile_evidence_needs_one_unambiguous_image(monkeypatch, tmp_path, files):
    _stub(monkeypatch)
    _docker_repo(tmp_path, files)
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "requests")]


def test_dockerfile_installs_with_requirement_files_still_count(monkeypatch, tmp_path):
    # ``-r``/``-e .``/``.`` pick what to install, not where: the plain names
    # in the same command still land in the image's interpreter.
    _stub(monkeypatch)
    _docker_repo(
        tmp_path,
        {
            "Dockerfile": "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n"
            "RUN pip install -r requirements.txt && pip install --no-cache-dir . requests\n"
        },
    )
    assert _scan(tmp_path, "app/main.py") == []


def test_service_dockerfile_covers_only_its_service(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "services" / "a" / "requirements.txt", "flask\n")
    _write(tmp_path / "services" / "b" / "requirements.txt", "flask\n")
    _write(
        tmp_path / "services" / "a" / "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n"
        "RUN pip install -r requirements.txt && pip install requests\n",
    )
    _write(
        tmp_path / "services" / "b" / "Dockerfile",
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n"
        "RUN pip install -r requirements.txt httpx\n",
    )
    _write(tmp_path / "services" / "a" / "main.py", "import flask\nimport requests\n")
    _write(
        tmp_path / "services" / "b" / "main.py",
        "import flask\nimport requests\nimport httpx\n",
    )
    assert _scan(tmp_path, "services/a/main.py", "services/b/main.py") == [
        ("services/b/main.py", "requests")
    ]


# -- what an installed distribution provides ------------------------------------


def test_known_import_names_win_over_the_distribution_name(monkeypatch, tmp_path):
    # PyYAML installs ``yaml``; ``import pyyaml`` fails at run time.
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "app" / "setup.sh", "pip install PyYAML\n")
    _write(tmp_path / "app" / "loader.py", "import flask\nimport pyyaml\nimport yaml\n")
    assert _scan(tmp_path, "app/loader.py") == [("app/loader.py", "pyyaml")]


def test_variant_distribution_does_not_provide_its_base_name(monkeypatch, tmp_path):
    # dask-cuda ships ``dask_cuda``; ``dask`` is only its dependency.
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "app" / "setup.sh", "pip install dask-cuda\n")
    _write(tmp_path / "app" / "main.py", "import flask\nimport dask\nimport dask_cuda\n")
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "dask")]


def test_namespace_sibling_is_not_provided(monkeypatch, tmp_path):
    _stub(monkeypatch)
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "app" / "setup.sh", "pip install google-cloud-storage\n")
    _write(
        tmp_path / "app" / "bq.py",
        "import flask\nfrom google.cloud import bigquery\n",
    )
    _write(
        tmp_path / "app" / "gcs.py",
        "import flask\nfrom google.cloud import storage\n",
    )
    found = _scan(tmp_path, "app/bq.py", "app/gcs.py")
    assert [path for path, _symbol in found] == ["app/bq.py"]


def test_dockerignore_inside_the_code_folder_is_not_a_build_ignore(monkeypatch, tmp_path):
    # Docker reads ``.dockerignore`` at the build-context root only.
    _stub(monkeypatch)
    _docker_repo(tmp_path, {"Dockerfile": DOCKERFILE, "app/.dockerignore": "*.pyc\n"})
    assert _scan(tmp_path, "app/main.py") == []


def test_repository_dockerignore_counts_for_a_nested_dockerfile(monkeypatch, tmp_path):
    # ``docker build -f app/Dockerfile .`` reads the root .dockerignore.
    _stub(monkeypatch)
    _docker_repo(tmp_path, {"app/Dockerfile": DOCKERFILE, ".dockerignore": "app/\n"})
    assert _scan(tmp_path, "app/main.py") == [("app/main.py", "requests")]
