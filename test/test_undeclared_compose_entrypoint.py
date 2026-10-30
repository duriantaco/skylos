"""Exact Compose command environments count only for that file's D223.

All fixture files are parsed as data. No Docker build, install, or app executes.
"""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from skylos.rules.ai_defect import dependency_hallucination as dep
from skylos.rules.ai_defect.compose_environment import (
    _UniqueLoader,
    compose_entrypoint_distributions,
)


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _fixture(root):
    _write(root, "pyproject.toml", '[project]\nname="fixture"\ndependencies=[]\n')
    entry = _write(root, "sim/app.py", "import fastapi\nimport uvicorn\n")
    _write(root, "sim/sibling.py", "import fastapi\n")
    _write(root, "backend/api.py", "import fastapi\n")
    _write(
        root, "sim/versions.env", "FASTAPI_VERSION=0.141.1\nUVICORN_VERSION=0.52.4\n"
    )
    dockerfile = (
        "FROM python:3.11-slim-bookworm AS telemetry\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\n"
        "WORKDIR /workspace/backend\n"
        "COPY sim/versions.env /tmp/versions.env\n"
        'RUN set -eux; . /tmp/versions.env; python -m pip install --no-cache-dir "fastapi==${FASTAPI_VERSION}" "uvicorn[standard]==${UVICORN_VERSION}"; rm /tmp/versions.env\n'
        "FROM ubuntu:22.04 AS other\n"
        "RUN python3 -m pip install unrelated\n"
    )
    _write(root, "sim/Dockerfile", dockerfile)
    data = {
        "name": "fixture",
        "services": {
            "api": {
                "build": {
                    "context": ".",
                    "dockerfile": "sim/Dockerfile",
                    "target": "telemetry",
                },
                "working_dir": "/workspace/backend",
                "command": ["python", "/workspace/sim/app.py"],
                "volumes": [".:/workspace:ro"],
            },
        },
    }
    _write(root, "compose.yaml", yaml.safe_dump(data))
    return entry, data, dockerfile


def _stub(monkeypatch, *, missing=()):
    monkeypatch.setattr(dep, "_get_stdlib_modules", lambda: {"os", "sys"})
    monkeypatch.setattr(dep, "_load_private_allowlist", lambda: set())
    monkeypatch.setattr(dep, "installed_module_mapping", lambda builder: {})
    monkeypatch.setattr(dep, "_load_import_to_dist_mapping", lambda: {})
    monkeypatch.setattr(
        dep,
        "_check_pypi_status",
        lambda name, cache: "missing" if name in missing else "exists",
    )
    monkeypatch.setattr(dep, "_fetch_dist_modules", lambda *args, **kwargs: None)


def test_bound_command_file_clears_only_its_declaration_findings(tmp_path, monkeypatch):
    entry, _, _ = _fixture(tmp_path)
    _stub(monkeypatch)
    files = [entry, tmp_path / "sim/sibling.py", tmp_path / "backend/api.py"]
    findings = dep.scan_python_dependency_hallucinations(tmp_path, files)
    assert sorted(
        (f["rule_id"], Path(f["file"]).relative_to(tmp_path).as_posix(), f["symbol"])
        for f in findings
    ) == [
        ("SKY-D223", "backend/api.py", "fastapi"),
        ("SKY-D223", "sim/sibling.py", "fastapi"),
    ]


def test_same_directory_cache_cannot_leak_entrypoint_declarations(tmp_path):
    entry, _, _ = _fixture(tmp_path)
    cache = {}
    assert dep._environment_scope_for_file(tmp_path, entry, cache) == {
        "fastapi",
        "uvicorn",
    }
    assert not dep._environment_scope_for_file(
        tmp_path, tmp_path / "sim/sibling.py", cache
    )
    assert not dep._environment_scope_for_file(
        tmp_path, tmp_path / "backend/api.py", cache
    )


def test_diff_mode_uses_exact_entry_file_without_sibling_cache_leak(
    tmp_path, monkeypatch
):
    _fixture(tmp_path)
    _stub(monkeypatch)
    findings, unreachable = dep.scan_diff_added_imports(
        tmp_path,
        [
            ("sim/app.py", 1, "fastapi"),
            ("sim/app.py", 2, "uvicorn"),
            ("sim/sibling.py", 1, "fastapi"),
            ("backend/api.py", 1, "fastapi"),
        ],
    )
    assert not unreachable
    assert sorted((f["rule_id"], f["file"], f["symbol"]) for f in findings) == [
        ("SKY-D223", "backend/api.py", "fastapi"),
        ("SKY-D223", "sim/sibling.py", "fastapi"),
    ]


@pytest.mark.parametrize(
    "case",
    [
        "shell_command",
        "command_interpolation",
        "different_interpreter",
        "entrypoint",
        "custom_startup",
        "environment_path",
        "environment_pythonpath",
        "environment_pip_target",
        "env_file",
        "custom_image",
        "build_argument",
        "build_context",
        "build_target",
        "dockerfile_traversal",
        "read_write_mount",
        "extra_mount",
        "duplicate_service",
        "alternate_read_write_service",
        "override_file",
        "yaml_alias",
        "yaml_duplicate_key",
        "custom_base",
        "image_entrypoint",
        "stage_shell",
        "stage_user",
        "stage_path",
        "unknown_run",
        "pip_target",
        "missing_version",
        "version_shell_code",
        "version_unknown_variable",
        "single_quoted_version",
        "version_excluded",
        "unknown_ignore_pattern",
        "symlink_versions",
        "symlink_compose",
        "copy_other_stage",
        "wrong_working_dir",
    ],
)
def test_unknown_or_alternative_context_keeps_findings(tmp_path, case):
    entry, data, dockerfile = _fixture(tmp_path)
    service = data["services"]["api"]
    if case == "shell_command":
        service["command"] = "python /workspace/sim/app.py"
    elif case == "command_interpolation":
        service["command"][1] = "${SCRIPT}"
    elif case == "different_interpreter":
        service["command"][0] = "python3"
    elif case == "entrypoint":
        service["entrypoint"] = ["wrapper"]
    elif case == "custom_startup":
        service["post_start"] = [{"command": "custom"}]
    elif case == "environment_path":
        service["environment"] = {"PATH": "/other/bin"}
    elif case == "environment_pythonpath":
        service["environment"] = {"PYTHONPATH": "/other"}
    elif case == "environment_pip_target":
        service["environment"] = {"PIP_TARGET": "/other"}
    elif case == "env_file":
        service["env_file"] = ["custom.env"]
    elif case == "custom_image":
        service["image"] = "custom:latest"
    elif case == "build_argument":
        service["build"]["args"] = {"VERSION": "other"}
    elif case == "build_context":
        service["build"]["context"] = "${CONTEXT}"
    elif case == "build_target":
        service["build"]["target"] = "other"
    elif case == "dockerfile_traversal":
        service["build"]["dockerfile"] = "../Dockerfile"
    elif case == "read_write_mount":
        service["volumes"] = [".:/workspace:rw"]
    elif case == "extra_mount":
        service["volumes"].append("./other:/workspace/sim:ro")
    elif case in {"duplicate_service", "alternate_read_write_service"}:
        other = deepcopy(service)
        if case == "alternate_read_write_service":
            other["volumes"] = [".:/workspace:rw"]
        data["services"]["alternate"] = other
    elif case == "override_file":
        _write(
            tmp_path,
            "compose.override.yaml",
            "services:\n  api:\n    environment:\n      PYTHONPATH: /other\n",
        )
    elif case == "custom_base":
        dockerfile = dockerfile.replace("python:3.11-slim-bookworm", "custom:latest")
    elif case == "image_entrypoint":
        dockerfile = dockerfile.replace("WORKDIR", 'ENTRYPOINT ["wrapper"]\nWORKDIR', 1)
    elif case == "stage_shell":
        dockerfile = dockerfile.replace("WORKDIR", 'SHELL ["bash", "-c"]\nWORKDIR', 1)
    elif case == "stage_user":
        dockerfile = dockerfile.replace("WORKDIR", "USER other\nWORKDIR", 1)
    elif case == "stage_path":
        dockerfile = dockerfile.replace("WORKDIR", "ENV PATH=/other/bin\nWORKDIR", 1)
    elif case == "unknown_run":
        dockerfile = dockerfile.replace("RUN set", "RUN custom\nRUN set", 1)
    elif case == "pip_target":
        dockerfile = dockerfile.replace("--no-cache-dir", "--target /other")
    elif case == "missing_version":
        (tmp_path / "sim/versions.env").unlink()
    elif case == "version_shell_code":
        _write(
            tmp_path,
            "sim/versions.env",
            "FASTAPI_VERSION=$(curl remote)\nUVICORN_VERSION=0.52.4\n",
        )
    elif case == "version_unknown_variable":
        dockerfile = dockerfile.replace("FASTAPI_VERSION", "MISSING_VERSION")
    elif case == "single_quoted_version":
        dockerfile = dockerfile.replace(
            '"fastapi==${FASTAPI_VERSION}"', "'fastapi==${FASTAPI_VERSION}'"
        )
    elif case == "version_excluded":
        _write(tmp_path, ".dockerignore", "sim/versions.env\n")
    elif case == "unknown_ignore_pattern":
        _write(tmp_path, ".dockerignore", "[sv]im/**\n")
    elif case == "symlink_versions":
        original = tmp_path / "sim/versions.env"
        original.rename(tmp_path / "actual.env")
        original.symlink_to(tmp_path / "actual.env")
    elif case == "copy_other_stage":
        dockerfile = dockerfile.replace(
            "COPY sim/versions.env", "COPY --from=other sim/versions.env"
        )
    elif case == "wrong_working_dir":
        service["working_dir"] = "/different"
    _write(tmp_path, "compose.yaml", yaml.safe_dump(data))
    _write(tmp_path, "sim/Dockerfile", dockerfile)
    if case == "yaml_alias":
        _write(
            tmp_path,
            "compose.yaml",
            (tmp_path / "compose.yaml").read_text()
            + "extra: &config {}\nother: *config\n",
        )
    elif case == "yaml_duplicate_key":
        _write(
            tmp_path,
            "compose.yaml",
            (tmp_path / "compose.yaml").read_text() + "services: {}\n",
        )
    elif case == "symlink_compose":
        original = tmp_path / "compose.yaml"
        original.rename(tmp_path / "actual.yaml")
        original.symlink_to(tmp_path / "actual.yaml")
    assert not compose_entrypoint_distributions(tmp_path, entry)


def test_literal_ignored_tree_can_explicitly_include_the_version_file(tmp_path):
    entry, _, _ = _fixture(tmp_path)
    _write(
        tmp_path,
        ".dockerignore",
        "**\n!.dockerignore\n!sim/\n!sim/**\nsim/**/__pycache__/\nsim/**/*.pyc\n",
    )
    assert compose_entrypoint_distributions(tmp_path, entry) == {"fastapi", "uvicorn"}


def test_nonexistent_distribution_stays_d222(tmp_path, monkeypatch):
    entry, _, dockerfile = _fixture(tmp_path)
    _write(tmp_path, "sim/app.py", "import totally_missing_dist\n")
    _write(
        tmp_path,
        "sim/Dockerfile",
        dockerfile.replace(
            "fastapi==${FASTAPI_VERSION}", "totally_missing_dist==${FASTAPI_VERSION}"
        ),
    )
    _stub(monkeypatch, missing={"totally_missing_dist"})
    findings = dep.scan_python_dependency_hallucinations(tmp_path, [entry])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [
        ("SKY-D222", "totally_missing_dist")
    ]


@pytest.mark.parametrize(
    "key",
    [
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PIP_TARGET",
        "UV_PROJECT_ENVIRONMENT",
        "CONDA_PREFIX",
        "VIRTUAL_ENV",
        "ENV",
        "BASH_ENV",
        "IFS",
        "LD_PRELOAD",
    ],
)
def test_sourced_version_file_cannot_redirect_interpreter_or_install(tmp_path, key):
    entry, _, _ = _fixture(tmp_path)
    with (tmp_path / "sim/versions.env").open("a") as stream:
        stream.write(f"{key}=other\n")
    assert not compose_entrypoint_distributions(tmp_path, entry)


@pytest.mark.parametrize("ifs", [None, "a"])
def test_shell_field_splitting_cannot_invent_package_declarations(
    tmp_path, monkeypatch, ifs
):
    entry, _, dockerfile = _fixture(tmp_path)
    with (tmp_path / "sim/versions.env").open("a") as stream:
        stream.write("PACKAGE=fastapi\n")
        if ifs is not None:
            stream.write(f"IFS={ifs}\n")
    _write(
        tmp_path,
        "sim/Dockerfile",
        dockerfile.replace('"fastapi==${FASTAPI_VERSION}"', "${PACKAGE}"),
    )
    _stub(monkeypatch)
    findings = dep.scan_python_dependency_hallucinations(tmp_path, [entry])
    assert [(row["rule_id"], row["symbol"]) for row in findings] == (
        [] if ifs is None else [("SKY-D223", "fastapi"), ("SKY-D223", "uvicorn")]
    )


@pytest.mark.parametrize(
    "case",
    ["partial_directory", "single_file", "shell_wrapper", "entrypoint", "no_mount"],
)
def test_alternate_unmodeled_launcher_keeps_entrypoint_findings(
    tmp_path, monkeypatch, case
):
    entry, data, _ = _fixture(tmp_path)
    alternate = deepcopy(data["services"]["api"])
    alternate["build"]["target"] = "other"
    alternate["volumes"] = ["./sim:/workspace/sim:ro"]
    if case == "single_file":
        alternate["volumes"] = ["./sim/app.py:/workspace/sim/app.py:ro"]
    elif case == "shell_wrapper":
        alternate["command"] = ["sh", "-c", "python /workspace/sim/app.py"]
    elif case == "entrypoint":
        alternate["entrypoint"] = alternate.pop("command")
    elif case == "no_mount":
        alternate["volumes"] = []
    data["services"]["alternate"] = alternate
    _write(tmp_path, "compose.yaml", yaml.safe_dump(data))
    _stub(monkeypatch)
    findings = dep.scan_python_dependency_hallucinations(tmp_path, [entry])
    assert [(row["rule_id"], row["symbol"]) for row in findings] == [
        ("SKY-D223", "fastapi"),
        ("SKY-D223", "uvicorn"),
    ]


@pytest.mark.parametrize("spec", ['"fastapi"evil', '"fastapi""evil"'])
def test_shell_word_concatenation_does_not_invent_fastapi_declaration(
    tmp_path, monkeypatch, spec
):
    entry, _, dockerfile = _fixture(tmp_path)
    _write(
        tmp_path,
        "sim/Dockerfile",
        dockerfile.replace('"fastapi==${FASTAPI_VERSION}"', spec),
    )
    assert "fastapi" not in compose_entrypoint_distributions(tmp_path, entry)
    _stub(monkeypatch)
    findings = dep.scan_python_dependency_hallucinations(tmp_path, [entry])
    assert [(f["rule_id"], f["symbol"]) for f in findings] == [("SKY-D223", "fastapi")]


def test_shell_word_concatenation_retains_real_single_word(tmp_path):
    entry, _, dockerfile = _fixture(tmp_path)
    _write(
        tmp_path,
        "sim/Dockerfile",
        dockerfile.replace(
            '"fastapi==${FASTAPI_VERSION}"', '"fast"api==${FASTAPI_VERSION}'
        ),
    )
    assert compose_entrypoint_distributions(tmp_path, entry) == {"fastapi", "uvicorn"}


@pytest.mark.parametrize(
    "case",
    [
        "pip_module_copy",
        "removed_source",
        "custom_frontend",
        "dotenv_selector",
        "bom_ignore",
        "bom_source",
        "duplicate_stage_case",
        "tmpfs",
        "volumes_from",
        "configs",
        "secrets",
    ],
)
def test_additional_unknown_build_or_runtime_context(tmp_path, case):
    entry, data, dockerfile = _fixture(tmp_path)
    if case == "pip_module_copy":
        dockerfile = dockerfile.replace("/tmp/versions.env", "/tmp/pip.py")
    elif case == "removed_source":
        dockerfile = dockerfile.replace(
            "FROM ubuntu",
            "RUN . /tmp/versions.env; python -m pip install fastapi\nFROM ubuntu",
        )
    elif case == "custom_frontend":
        dockerfile = "#syntax=custom/frontend:1\n" + dockerfile
    elif case == "dotenv_selector":
        _write(tmp_path, ".env", "COMPOSE_FILE=other.yaml\n")
    elif case == "bom_ignore":
        _write(tmp_path, ".dockerignore", "\ufeffsim/versions.env\n")
    elif case == "bom_source":
        _write(
            tmp_path,
            "sim/versions.env",
            "\ufeffFASTAPI_VERSION=0.141.1\nUVICORN_VERSION=0.52.4\n",
        )
    elif case == "duplicate_stage_case":
        dockerfile = dockerfile.replace("AS other", "AS Telemetry")
    elif case in {"tmpfs", "volumes_from", "configs", "secrets"}:
        data["services"]["api"][case] = ["/usr/local/lib/python3.11/site-packages"]
    _write(tmp_path, "sim/Dockerfile", dockerfile)
    _write(tmp_path, "compose.yaml", yaml.safe_dump(data))
    assert not compose_entrypoint_distributions(tmp_path, entry)


def test_copy_glob_is_not_a_literal_source_even_when_starred_file_exists(tmp_path):
    entry, _, dockerfile = _fixture(tmp_path)
    _write(tmp_path, "sim/versions*.env", (tmp_path / "sim/versions.env").read_text())
    _write(
        tmp_path,
        "sim/versions-other.env",
        "FASTAPI_VERSION=9.9.9\nUVICORN_VERSION=9.9.9\n",
    )
    _write(
        tmp_path,
        "sim/Dockerfile",
        dockerfile.replace("COPY sim/versions.env", "COPY sim/versions*.env"),
    )
    assert not compose_entrypoint_distributions(tmp_path, entry)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate",
        "alias",
        "merge",
        "python_name",
        "python_tuple",
        "python_apply",
        "multiple_documents",
    ],
)
def test_otherwise_valid_yaml_cannot_bypass_strict_safe_loading(tmp_path, case):
    entry, _, _ = _fixture(tmp_path)
    text = (tmp_path / "compose.yaml").read_text()
    if case == "duplicate":
        text += "name: otherwise-valid\n"
    elif case == "alias":
        text = text.replace(
            "name: fixture\n", "name: &project fixture\nversion: *project\n"
        )
    elif case == "merge":
        text += "<<: {name: otherwise-valid}\n"
    elif case == "multiple_documents":
        text += "---\n" + text
    else:
        tags = {
            "python_name": "!!python/name:builtins.str ''",
            "python_tuple": "!!python/tuple [1, 2]",
            "python_apply": "!!python/object/apply:builtins.str [fixture]",
        }
        text = text.replace("name: fixture\n", f"name: {tags[case]}\n")
    _write(tmp_path, "compose.yaml", text)
    assert not compose_entrypoint_distributions(tmp_path, entry)


@pytest.mark.parametrize("invalid", [False, True])
def test_yaml_loader_is_disposed_after_success_or_rejection(
    tmp_path, monkeypatch, invalid
):
    entry, _, _ = _fixture(tmp_path)
    if invalid:
        with (tmp_path / "compose.yaml").open("a") as stream:
            stream.write("name: duplicate\n")
    disposed = []
    original_dispose = _UniqueLoader.dispose

    def dispose(loader):
        disposed.append(loader)
        original_dispose(loader)

    monkeypatch.setattr(_UniqueLoader, "dispose", dispose)
    names = compose_entrypoint_distributions(tmp_path, entry)
    assert names == (frozenset() if invalid else {"fastapi", "uvicorn"})
    assert len(disposed) == 1


def test_compose_parser_passes_yaml_security_self_scan():
    from skylos.rules.danger.danger import scan_ctx

    root = Path(__file__).resolve().parents[1]
    source = root / "skylos/rules/ai_defect/compose_environment.py"
    findings = scan_ctx(root, [source])
    assert not [row for row in findings if row["rule_id"] == "SKY-D206"]
