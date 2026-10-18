"""Project mypy policy and test scope for T101/T102 applicability."""

import ast
import os
import textwrap
from pathlib import Path

import pytest

from skylos.analysis.file_processing import collect_python_raw_imports
from skylos.analysis.typing_policy import annotation_requirement
from skylos.analysis.typing_scope import scope_typing_findings
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality._typing import is_typing_test_path


def _project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("fixture path leaves project")
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(
            path, textwrap.dedent(text).lstrip("\n"), encoding="utf-8"
        )
    return root


def _requirement(root: Path, relative: str):
    return annotation_requirement(root / relative, root, "")


SCRAPY_SHAPE = {
    "pyproject.toml": """
        [tool.mypy]
        strict = true

        [[tool.mypy.overrides]]
        module = "tests.*"
        allow_untyped_defs = true
        allow_incomplete_defs = true
    """,
    "tox.ini": """
        [testenv]
        commands =
            pytest {posargs:pkg tests}

        [testenv:default-reactor]
        commands = {[testenv]commands} --reactor=default

        [testenv:mypy]
        commands =
            mypy {posargs:pkg tests}
    """,
    "pkg/__init__.py": "",
    "pkg/core.py": "",
    "tests/__init__.py": "",
    "tests/test_core.py": "",
    "scripts/tool.py": "",
}


def test_tox_posargs_default_and_section_references_are_resolved(tmp_path):
    root = _project(tmp_path, SCRAPY_SHAPE)

    assert _requirement(root, "pkg/core.py") is True
    assert _requirement(root, "tests/test_core.py") is False
    assert _requirement(root, "scripts/tool.py") is None


def test_bare_posargs_uses_configured_files(tmp_path):
    root = _project(
        tmp_path,
        {
            "setup.cfg": "[mypy]\ndisallow_untyped_defs = True\nfiles = pkg\n",
            "tox.ini": "[testenv:mypy]\ncommands = mypy {posargs}\n",
            "pkg/a.py": "",
            "other/b.py": "",
        },
    )

    assert _requirement(root, "pkg/a.py") is True
    assert _requirement(root, "other/b.py") is None


@pytest.mark.parametrize(
    "command, expected",
    [
        (
            "mypy --strict --show-error-codes --pretty --no-error-summary"
            " --junit-xml build/mypy.xml --cache-dir=.cache --install-types"
            " --non-interactive src",
            True,
        ),
        ("mypy --strict --allow-untyped-defs --allow-incomplete-defs src", False),
        ("mypy --allow-incomplete-defs --strict src", True),
        ("mypy --strict --exclude legacy src", None),
        ("mypy --junit-xml", None),
    ],
)
def test_output_only_flags_are_neutral_and_strict_is_strict(tmp_path, command, expected):
    root = _project(
        tmp_path,
        {
            "setup.cfg": "[mypy]\nignore_missing_imports = True\n",
            "Makefile": f"typecheck:\n\t{command}\n",
            "src/app/core.py": "",
        },
    )

    assert _requirement(root, "src/app/core.py") is expected


@pytest.mark.parametrize(
    "files, expected",
    [
        ({}, None),
        ({"Makefile": "lint:\n\tmypy\n"}, None),
        ({"Makefile": "lint:\n\tmypy pkg\n"}, True),
    ],
)
def test_requirement_without_selection_is_unknown_scope(tmp_path, files, expected):
    root = _project(
        tmp_path,
        {"pyproject.toml": "[tool.mypy]\ndisallow_untyped_defs = true\n", "pkg/a.py": "", **files},
    )

    assert _requirement(root, "pkg/a.py") is expected


@pytest.mark.parametrize(
    "config, expected",
    [
        ("allow_incomplete_defs = True\n", False),
        ("allow_incomplete_defs = True\ndisallow_untyped_defs = True\nfiles = pkg\n", True),
        ("ignore_missing_imports = True\n", None),
        ("strict = False\n", None),
    ],
)
def test_only_explicit_partial_signature_acceptance_opts_out(tmp_path, config, expected):
    root = _project(tmp_path, {"setup.cfg": "[mypy]\n" + config, "pkg/a.py": ""})

    assert _requirement(root, "pkg/a.py") is expected


def test_project_policy_cache_tracks_consulted_files(tmp_path):
    root = _project(tmp_path, SCRAPY_SHAPE)
    assert _requirement(root, "scripts/tool.py") is None

    tox = root / "tox.ini"
    original = tox.read_text(encoding="utf-8")
    assert write_text_no_symlink(
        tox,
        original.replace("{posargs:pkg tests}", "{posargs:pkg scripts tests}"),
        encoding="utf-8",
    )
    assert _requirement(root, "scripts/tool.py") is True

    assert write_text_no_symlink(tox, original, encoding="utf-8")
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    assert write_text_no_symlink(
        workflow, "jobs:\n  t:\n    steps:\n      - run: mypy scripts\n", encoding="utf-8"
    )
    assert _requirement(root, "scripts/tool.py") is True

    workflow.unlink()
    assert _requirement(root, "scripts/tool.py") is None


@pytest.mark.parametrize(
    "relative, expected",
    [
        ("webfw/test/client.py", False),  # django.test-style shipped API
        ("webfw/corpus/samples.py", False),
        ("webfw/tests/helpers.py", True),
        ("tests/support/helpers.py", True),
        ("test/helpers.py", True),
        ("src/webfw/tests/helpers.py", True),
        ("webfw/conftest.py", True),
        ("webfw/test_client.py", True),
    ],
)
def test_typing_test_paths_follow_project_test_layout(tmp_path, relative, expected):
    assert is_typing_test_path(tmp_path / relative, tmp_path) is expected


def _scoped_files(root: Path, files: dict[str, str]) -> set[str]:
    _project(root, files)
    modmap, raw_imports, findings = {}, {}, []
    for relative in files:
        if not relative.endswith(".py"):
            continue
        path = root / relative
        parts = list(Path(relative).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        modmap[str(path)] = module
        tree = ast.parse(path.read_text(encoding="utf-8"))
        raw_imports[str(path)] = collect_python_raw_imports(tree, str(path), module)
        findings.append({"rule_id": "SKY-T101", "file": str(path)})
    kept = scope_typing_findings(findings, modmap, raw_imports, root)
    return {os.path.relpath(f["file"], root) for f in kept}


def test_package_conftest_does_not_make_the_library_test_only(tmp_path):
    kept = _scoped_files(
        tmp_path,
        {
            "lib/__init__.py": "from lib.core import load\nfrom lib import util\n",
            "lib/conftest.py": "import lib\n",
            "lib/core.py": "",
            "lib/util.py": "",
            "t/__init__.py": "",
            "t/conftest.py": "from t.helpers import make\n",
            "t/helpers.py": "",
            "t/test_x.py": "from t.helpers import make\n",
        },
    )

    assert {"lib/core.py", "lib/util.py"} <= kept
    assert "t/helpers.py" not in kept
