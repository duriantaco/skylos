"""Annotation coverage is enforced only by an applicable source policy."""

from pathlib import Path

import pytest

from test.fixture_paths import write_fixture

from skylos.analysis.typing_policy import (
    AnnotationPolicy,
    annotation_policy,
    annotation_requirement,
)


def _write(root, relative, text):
    write_fixture(root, relative, text, overwrite=True)


def _policy(root, relative="pkg/core.py", source=""):
    return annotation_policy(root / relative, root, source)


@pytest.mark.parametrize(
    "settings, expected",
    [
        ("", AnnotationPolicy()),
        ("check_untyped_defs = true\n", AnnotationPolicy()),
        ("ignore_missing_imports = true\n", AnnotationPolicy()),
        ("strict = false\n", AnnotationPolicy()),
        ("disallow_incomplete_defs = true\n", AnnotationPolicy(None, True)),
        ("disallow_untyped_defs = true\n", AnnotationPolicy(True, True)),
        ("strict = true\n", AnnotationPolicy(True, True)),
        (
            "strict = true\ndisallow_untyped_defs = false\n",
            AnnotationPolicy(False, True),
        ),
        (
            "strict = true\ndisallow_incomplete_defs = false\n",
            AnnotationPolicy(True, True),
        ),
        (
            "strict = true\ndisallow_untyped_defs = false\n"
            "disallow_incomplete_defs = false\n",
            AnnotationPolicy(False, False),
        ),
        ("ignore_errors = true\nstrict = true\n", AnnotationPolicy(False, False)),
    ],
)
def test_selected_policy_distinguishes_complete_and_partial(tmp_path, settings, expected):
    _write(tmp_path, "pyproject.toml", '[tool.mypy]\nfiles = ["pkg"]\n' + settings)
    assert _policy(tmp_path) == expected


@pytest.mark.parametrize(
    "settings",
    ["strict = true\n", "disallow_incomplete_defs = true\n"],
)
@pytest.mark.parametrize(
    "selection",
    [
        'files = ["other"]\n',
        "",
        'files = ["pkg"]\nexclude = "legacy"\n',
        'files = ["$WORKSPACE/pkg"]\n',
    ],
)
def test_unknown_or_unselected_scope_does_not_enforce(tmp_path, settings, selection):
    _write(tmp_path, "pyproject.toml", "[tool.mypy]\n" + settings + selection)
    assert _policy(tmp_path) == AnnotationPolicy()


def test_module_override_applies_to_both_requirement_kinds(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/legacy/__init__.py", "")
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.mypy]\nstrict = true\nfiles = ["pkg"]\n'
        '[[tool.mypy.overrides]]\nmodule = "pkg.legacy.*"\n'
        "disallow_untyped_defs = false\n"
        '[[tool.mypy.overrides]]\nmodule = "pkg.legacy.unchecked"\n'
        "disallow_incomplete_defs = false\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)
    assert _policy(tmp_path, "pkg/legacy/partial.py") == AnnotationPolicy(False, True)
    assert _policy(tmp_path, "pkg/legacy/unchecked.py") == AnnotationPolicy(False, False)


@pytest.mark.parametrize(
    "source, expected, legacy",
    [
        ("# mypy: disallow-untyped-defs\n", AnnotationPolicy(True, True), True),
        ("# mypy: disallow-incomplete-defs\n", AnnotationPolicy(None, True), None),
        (
            "# mypy: allow-untyped-defs, allow-incomplete-defs\n",
            AnnotationPolicy(False, False),
            False,
        ),
        ("# mypy: ignore-errors\n", AnnotationPolicy(False, False), False),
        ('text = "# mypy: disallow-untyped-defs"\n', AnnotationPolicy(), None),
    ],
)
def test_inline_policy_is_real_comment_evidence(tmp_path, source, expected, legacy):
    filename = tmp_path / "pkg/core.py"
    assert annotation_policy(filename, None, source) == expected
    assert annotation_requirement(filename, None, source) is legacy


def test_inline_flags_override_module_and_global_requirements(tmp_path):
    _write(tmp_path, "pyproject.toml", '[tool.mypy]\nstrict = true\nfiles = ["pkg"]\n')
    assert _policy(tmp_path, source="# mypy: allow-untyped-defs\n") == AnnotationPolicy(False, True)


@pytest.mark.parametrize(
    "command, expected",
    [
        ("mypy --strict pkg", AnnotationPolicy(True, True)),
        ("mypy --disallow-incomplete-defs pkg", AnnotationPolicy(None, True)),
        ("mypy --check-untyped-defs pkg", AnnotationPolicy()),
        (
            "mypy --disallow-untyped-defs --check-untyped-defs pkg",
            AnnotationPolicy(True, True),
        ),
        ("mypy --strict other", AnnotationPolicy()),
        ("mypy --strict --exclude legacy pkg", AnnotationPolicy()),
        ("mypy --strict --config-file missing.ini pkg", AnnotationPolicy()),
        ("mypy --strict --config-file=missing.ini pkg", AnnotationPolicy()),
        (
            "mypy --strict --allow-untyped-defs pkg",
            AnnotationPolicy(False, True),
        ),
    ],
)
def test_checked_in_commands_can_declare_policy_without_config(tmp_path, command, expected):
    _write(tmp_path, "Makefile", f"typing:\n\t{command}\n")
    assert _policy(tmp_path) == expected


def test_separate_invocations_contribute_separate_requirement_kinds(tmp_path):
    _write(tmp_path, "pyproject.toml", "[tool.mypy]\n")
    _write(
        tmp_path,
        "Makefile",
        "typing:\n\tmypy --disallow-incomplete-defs pkg\n"
        "\tmypy --strict other\n\tmypy --unrecognised-option pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(None, True)
    assert _policy(tmp_path, "other/core.py") == AnnotationPolicy(True, True)


def test_scoped_module_flags_override_invocation_flags(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.mypy]\n[[tool.mypy.overrides]]\nmodule = "pkg.*"\n'
        "disallow_untyped_defs = false\ndisallow_incomplete_defs = true\n",
    )
    _write(tmp_path, "Makefile", "typing:\n\tmypy --strict pkg\n")
    assert _policy(tmp_path) == AnnotationPolicy(False, True)


@pytest.mark.parametrize(
    "config",
    [
        "[tool.mypy]\nstrict = 'maybe'\nfiles = ['pkg']\n",
        "[tool.mypy\nstrict = true\n",
        "[tool.mypy]\nstrict = true\nfiles = ['pkg']\n"
        "[[tool.mypy.overrides]]\nmodule = 'pkg.*.core'\n",
    ],
)
def test_unsupported_policy_is_unknown(tmp_path, config):
    _write(tmp_path, "pyproject.toml", config)
    assert _policy(tmp_path) == AnnotationPolicy()


def test_partial_only_requirement_remains_legacy_unknown(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.mypy]\nfiles = ["pkg"]\ndisallow_incomplete_defs = true\n',
    )
    assert _policy(tmp_path) == AnnotationPolicy(None, True)
    assert annotation_requirement(tmp_path / "pkg/core.py", tmp_path) is None


def test_no_policy_is_not_partial_signature_requirement(tmp_path):
    source = "def public(value: int):\n    return value\n"
    assert _policy(tmp_path, source=source) == AnnotationPolicy()


def test_historical_reader_without_workflow_inventory_cannot_prove_scope(tmp_path):
    def reader(relative: Path):
        if str(relative) == "pyproject.toml":
            return '[tool.mypy]\nstrict = true\nfiles = ["pkg"]\n'
        raise FileNotFoundError(relative)

    assert annotation_policy(tmp_path / "pkg/core.py", tmp_path, reader=reader) == AnnotationPolicy()


@pytest.mark.parametrize("level", ["workflow", "job", "step"])
@pytest.mark.parametrize("directory", ["subdir", "${{ matrix.directory }}", "/workspace"])
def test_workflow_nonroot_directory_cannot_enforce_root_paths(tmp_path, level, directory):
    import yaml

    step = {"run": "mypy --strict pkg"}
    job = {"steps": [step]}
    workflow = {"jobs": {"typing": job}}
    if level == "step":
        step["working-directory"] = directory
    else:
        owner = workflow if level == "workflow" else job
        owner["defaults"] = {"run": {"working-directory": directory}}
    _write(tmp_path, ".github/workflows/typing.yml", yaml.safe_dump(workflow))

    assert _policy(tmp_path) == AnnotationPolicy()


@pytest.mark.parametrize("directory", [".", "./", "./."])
@pytest.mark.parametrize("override", ["job", "step"])
def test_workflow_root_directory_overrides_inherited_subdirectory(tmp_path, directory, override):
    import yaml

    step = {"run": "mypy --disallow-incomplete-defs pkg"}
    job = {"steps": [step]}
    workflow = {
        "defaults": {"run": {"working-directory": "subdir"}},
        "jobs": {"typing": job},
    }
    if override == "step":
        job["defaults"] = {"run": {"working-directory": "other"}}
        step["working-directory"] = directory
    else:
        job["defaults"] = {"run": {"working-directory": directory}}
    _write(tmp_path, ".github/workflows/typing.yml", yaml.safe_dump(workflow))

    assert _policy(tmp_path) == AnnotationPolicy(None, True)


def test_nonroot_workflow_does_not_fall_back_to_root_config_selection(tmp_path):
    _write(tmp_path, "pyproject.toml", '[tool.mypy]\nstrict = true\nfiles = ["pkg"]\n')
    _write(
        tmp_path,
        ".github/workflows/typing.yml",
        "jobs:\n  typing:\n    steps:\n      - run: mypy\n"
        "        working-directory: subdir\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy()


def test_root_workflow_can_prove_requirement_alongside_unknown_invocation(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/typing.yml",
        "jobs:\n  typing:\n    steps:\n      - run: mypy --strict pkg\n"
        "        working-directory: subdir\n      - run: mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)


@pytest.mark.parametrize(
    "change",
    ["cd subdir", "pushd subdir", "popd", "builtin cd subdir", "command cd subdir"],
)
def test_multiline_workflow_directory_changes_make_later_targets_unknown(tmp_path, change):
    _write(
        tmp_path,
        ".github/workflows/typing.yml",
        "jobs:\n  typing:\n    steps:\n      - run: |\n"
        f"          {change}\n          mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy()


def test_workflow_multiline_root_command_still_proves_policy(tmp_path):
    _write(
        tmp_path,
        ".github/workflows/typing.yml",
        "jobs:\n  typing:\n    steps:\n      - run: |\n"
        "          echo 'checking types'\n          mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)


@pytest.mark.parametrize("option", ["changedir", "change_dir"])
@pytest.mark.parametrize(
    "directory", ["subdir", "{toxinidir}/subdir", "{env:TYPECHECK_ROOT}"]
)
def test_tox_nonroot_directory_cannot_enforce_root_paths(tmp_path, option, directory):
    _write(tmp_path, "mypy.ini", "[mypy]\ndisallow_untyped_defs=True\nfiles=pkg\n")
    _write(
        tmp_path,
        "tox.ini",
        f"[testenv:typing]\n{option}={directory}\ncommands=mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy()


@pytest.mark.parametrize("directory", [".", "./", "{toxinidir}", "{tox_root}"])
def test_tox_proved_root_directory_preserves_requirements(tmp_path, directory):
    _write(
        tmp_path,
        "tox.ini",
        f"[testenv:typing]\nchangedir={directory}\ncommands=mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)


def test_tox_inherited_changedir_is_respected(tmp_path):
    _write(
        tmp_path,
        "tox.ini",
        "[testenv]\nchangedir=subdir\ncommands=pytest\n"
        "[testenv:typing]\ncommands=mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy()


def test_tox_changedir_root_override_and_section_reference_are_respected(tmp_path):
    _write(
        tmp_path,
        "tox.ini",
        "[paths]\nroot={toxinidir}\n[testenv]\nchangedir=subdir\ncommands=pytest\n"
        "[testenv:typing]\nchangedir={[paths]root}\ncommands=mypy --strict pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)


@pytest.mark.parametrize("inline_flag", ["disallow-untyped-defs", "disallow-incomplete-defs"])
def test_inline_requirements_do_not_override_global_ignore_errors(tmp_path, inline_flag):
    _write(
        tmp_path,
        "mypy.ini",
        "[mypy]\ndisallow_untyped_defs=True\nfiles=pkg\nignore_errors=True\n",
    )
    assert _policy(tmp_path, source=f"# mypy: {inline_flag}\n") == AnnotationPolicy(False, False)


def test_inline_requirement_still_preserves_legacy_wrapper_answer(tmp_path):
    _write(tmp_path, "mypy.ini", "[mypy]\nfiles=pkg\nignore_errors=True\n")
    source = "# mypy: disallow-untyped-defs\n"
    assert _policy(tmp_path, source=source) == AnnotationPolicy(False, False)
    assert annotation_requirement(tmp_path / "pkg/core.py", tmp_path, source) is True


def test_inline_ignore_errors_false_overrides_project_opt_out(tmp_path):
    _write(tmp_path, "mypy.ini", "[mypy]\nfiles=pkg\nignore_errors=True\n")
    source = "# mypy: disallow-untyped-defs, ignore-errors=false\n"
    assert _policy(tmp_path, source=source) == AnnotationPolicy(True, True)


def test_inline_requirement_respects_module_specific_ignore_errors(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "mypy.ini",
        "[mypy]\nfiles=pkg\n[mypy-pkg.ignored]\nignore_errors=True\n",
    )
    source = "# mypy: disallow-untyped-defs\n"
    assert _policy(tmp_path, "pkg/core.py", source) == AnnotationPolicy(True, True)
    assert _policy(tmp_path, "pkg/ignored.py", source) == AnnotationPolicy(False, False)


def test_unknown_command_cannot_bypass_known_ignore_errors(tmp_path):
    _write(tmp_path, "mypy.ini", "[mypy]\nfiles=pkg\nignore_errors=True\n")
    _write(tmp_path, "Makefile", "typing:\n\tmypy --unsupported pkg\n")
    assert _policy(tmp_path, source="# mypy: disallow-untyped-defs\n") == AnnotationPolicy(False, False)


@pytest.mark.parametrize(
    "flags",
    [
        "--platform linux", "--platform=win32", "--python-version 3.11",
        "--python-version=3.13", "--platform darwin --python-version 3.10",
    ],
)
def test_literal_checker_context_preserves_selected_strict_policy(tmp_path, flags):
    _write(tmp_path, "mypy.ini", "[mypy]\nstrict=True\nfiles=pkg\n")
    _write(tmp_path, "tox.ini", f"[testenv:typing]\ncommands=mypy {flags}\n")
    assert _policy(tmp_path) == AnnotationPolicy(True, True)
    assert _policy(tmp_path, "other/core.py") == AnnotationPolicy()


def test_literal_checker_context_preserves_explicit_invocation_targets(tmp_path):
    _write(tmp_path, "mypy.ini", "[mypy]\nstrict=True\nfiles=other\n")
    _write(
        tmp_path,
        "tox.ini",
        "[testenv:typing]\ncommands=mypy --platform linux --python-version=3.11 pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy(True, True)
    assert _policy(tmp_path, "other/core.py") == AnnotationPolicy()


@pytest.mark.parametrize(
    "flags",
    [
        "--platform", "--platform=", "--python-version", "--python-version=",
        "--platform $PLATFORM", "--platform={env:PLATFORM}",
        "--python-version ${PYTHON_VERSION}", "--python-version 3.x",
        "--platform --strict", "--python-version --strict",
    ],
)
def test_unknown_or_missing_checker_context_does_not_prove_policy(tmp_path, flags):
    _write(tmp_path, "mypy.ini", "[mypy]\nstrict=True\nfiles=pkg\n")
    _write(tmp_path, "tox.ini", f"[testenv:typing]\ncommands=mypy {flags}\n")
    assert _policy(tmp_path) == AnnotationPolicy()


def test_checker_context_cannot_override_nonroot_invocation_scope(tmp_path):
    _write(tmp_path, "mypy.ini", "[mypy]\nstrict=True\nfiles=pkg\n")
    _write(
        tmp_path,
        "tox.ini",
        "[testenv:typing]\nchangedir=subdir\ncommands=mypy --platform linux pkg\n",
    )
    assert _policy(tmp_path) == AnnotationPolicy()


@pytest.mark.parametrize(
    "command, expected",
    [
        ("mypy --platform linux pkg", AnnotationPolicy()),
        ("mypy --strict --python-version=3.10 pkg", AnnotationPolicy(True, True)),
        (
            "mypy --platform=darwin --disallow-incomplete-defs pkg",
            AnnotationPolicy(None, True),
        ),
    ],
)
def test_checker_context_does_not_create_or_weaken_a_requirement(tmp_path, command, expected):
    _write(tmp_path, "Makefile", f"typing:\n\t{command}\n")
    assert _policy(tmp_path) == expected
