"""Data-only regression cases for mirrored dependency version transitions."""

import json

import pytest

from skylos.cicd.review import filter_findings_to_diff
from skylos.rules.ai_defect.dependency_version_bump import (
    MAX_MANIFEST_BYTES,
    detect_mirrored_dependency_bumps,
    is_supported_path,
)


def project(version, dependencies=(), name="example-app"):
    return (
        "[project]\n"
        f'name = "{name}"\n'
        f'version = "{version}"\n'
        f"dependencies = {json.dumps(list(dependencies))}\n"
    )


def snapshots(
    old_dependency="flask>=1.2.3",
    new_dependency="flask>=1.2.4",
    path="requirements.txt",
):
    return (
        {"pyproject.toml": project("1.2.3"), path: old_dependency + "\n"},
        {"pyproject.toml": project("1.2.4"), path: new_dependency + "\n"},
    )


def lock_package(
    name, version, source='source = { registry = "https://pypi.org/simple" }'
):
    return f'[[package]]\nname = "{name}"\nversion = "{version}"\n{source}\n'


def test_pyproject_dependency_has_exact_after_location_and_advisory_metadata():
    old = project("1.2.3", ["flask>=1.2.3"])
    new = """# flask>=1.2.4 is only a comment
[project]
name = "example-app"
version = "1.2.4"
dependencies = [
    "flask>=1.2.4", # actual dependency
]
"""
    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": old}, {"pyproject.toml": new}
    )
    assert len(findings) == 1
    finding = findings[0]
    assert (finding["rule_id"], finding["severity"], finding["category"]) == (
        "SKY-A106",
        "LOW",
        "ai_defect",
    )
    assert finding["kind"] == finding["defect_type"] == "mirrored_dependency_bump"
    assert finding["file"] == "pyproject.toml"
    assert finding["line"] == 6
    assert finding["metadata"] == {
        "signal_only": True,
        "blocking_recommended": False,
        "project": "example-app",
        "project_old_version": "1.2.3",
        "project_new_version": "1.2.4",
        "project_file": "pyproject.toml",
        "project_line": 4,
        "dependency": "flask",
        "dependency_old_version": "1.2.3",
        "dependency_new_version": "1.2.4",
        "dependency_operator": ">=",
        "evidence_path": "pyproject.toml",
    }
    assert "do not prove a defect" in finding["message"]


@pytest.mark.parametrize("operator", ["==", "===", "!=", ">=", "<=", ">", "<", "~="])
def test_all_pep_requirement_operators_match_exact_transition(operator):
    findings = detect_mirrored_dependency_bumps(
        *snapshots(f"flask{operator}1.2.3", f"flask{operator}1.2.4")
    )
    assert len(findings) == 1
    assert findings[0]["metadata"]["dependency_operator"] == operator


@pytest.mark.parametrize(
    "path",
    [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements/development.txt",
        "requirements/nested/tests.txt",
    ],
)
def test_requirements_paths(path):
    findings = detect_mirrored_dependency_bumps(*snapshots(path=path))
    assert len(findings) == 1
    assert findings[0]["file"] == path


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "package.json",
        "setup.cfg",
        "data.txt",
        "../requirements.txt",
        "/requirements.txt",
        "a/../requirements.txt",
        "a\\requirements.txt",
    ],
)
def test_unsupported_paths_are_not_scanned(path):
    assert not is_supported_path(path)
    assert detect_mirrored_dependency_bumps(*snapshots(path=path)) == []


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("flask>=1.2.2", "flask>=1.2.4"),
        ("flask>=1.2.3", "flask>=1.2.5"),
        ("flask>=1.2.3", "flask==1.2.4"),
        ("flask>=1.2.3", "other>=1.2.4"),
        ("flask>=1.2.3", "flask>=1.2.3"),
        ("", "flask>=1.2.4"),
        ("flask>=1.2.3", ""),
        ("flask>=2; python_version == '1.2.3'", "flask>=2; python_version == '1.2.4'"),
        ("# flask>=1.2.3", "# flask>=1.2.4"),
        ("flask>=2 # 1.2.3", "flask>=2 # 1.2.4"),
        (
            "https://example.test/flask-1.2.3.whl",
            "https://example.test/flask-1.2.4.whl",
        ),
        (
            "flask @ https://example.test/flask-1.2.3.whl",
            "flask @ https://example.test/flask-1.2.4.whl",
        ),
        ("-r requirements-1.2.3.txt", "-r requirements-1.2.4.txt"),
        ("flask==1.2.3.*", "flask==1.2.4.*"),
        ("flask>=1.2.3 --hash=sha256:abc", "flask>=1.2.4 --hash=sha256:def"),
    ],
)
def test_no_unrelated_or_unsupported_requirement_transition(before, after):
    assert detect_mirrored_dependency_bumps(*snapshots(before, after)) == []


def test_requirement_formatting_extras_markers_and_reordering():
    before, after = snapshots(
        'Flask_Plugin [b,a] (>=1.2.3,!=9.0); python_version < "4"\nother==8',
        'other==8\nflask-plugin[a,b]>=1.2.4, !=9.0; python_version < "4" # note',
    )
    findings = detect_mirrored_dependency_bumps(before, after)
    assert len(findings) == 1
    assert findings[0]["name"] == "flask-plugin"
    assert findings[0]["line"] == 2


@pytest.mark.parametrize(
    "section", ["[project.optional-dependencies]\ntests", "[dependency-groups]\ntests"]
)
def test_pyproject_dependency_groups(section):
    before = project("1.2.3") + section + ' = ["flask>=1.2.3"]\n'
    after = project("1.2.4") + section + ' = ["flask>=1.2.4"]\n'
    assert (
        len(
            detect_mirrored_dependency_bumps(
                {"pyproject.toml": before}, {"pyproject.toml": after}
            )
        )
        == 1
    )


def test_dependency_moving_groups_is_not_a_version_edit():
    before = project("1.2.3", ["flask>=1.2.3"])
    after = (
        project("1.2.4") + '[project.optional-dependencies]\ntests = ["flask>=1.2.4"]\n'
    )
    assert (
        detect_mirrored_dependency_bumps(
            {"pyproject.toml": before}, {"pyproject.toml": after}
        )
        == []
    )


def test_build_system_requires_is_a_dependency_declaration():
    before = project("1.2.3") + '[build-system]\nrequires = ["setuptools>=1.2.3"]\n'
    after = before.replace("1.2.3", "1.2.4")
    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": before}, {"pyproject.toml": after}
    )
    assert len(findings) == 1
    assert (findings[0]["name"], findings[0]["line"]) == ("setuptools", 6)


@pytest.mark.parametrize("keyword", ["setup_requires", "tests_require"])
def test_static_setup_additional_dependency_lists(keyword):
    before = f'from setuptools import setup\nsetup(name="example", version="1.2.3", {keyword}=["flask>=1.2.3"])\n'
    after = before.replace("1.2.3", "1.2.4")
    assert (
        len(detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after}))
        == 1
    )


@pytest.mark.parametrize("prefix", ["^", "~", "==", "", "!="])
def test_poetry_metadata_and_dependency_constraints(prefix):
    def poetry(version):
        return f'[tool.poetry]\nname = "example"\nversion = "{version}"\n[tool.poetry.dependencies]\nflask = "{prefix}{version}"\n'

    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": poetry("1.2.3")}, {"pyproject.toml": poetry("1.2.4")}
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 5


def test_poetry_dependency_inline_table_and_group():
    def poetry(version):
        return (
            project(version)
            + f'[tool.poetry.group.test.dependencies]\nflask = {{ version = "^{version}", optional = true }}\n'
        )

    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": poetry("1.2.3")}, {"pyproject.toml": poetry("1.2.4")}
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 6


@pytest.mark.parametrize(
    "source",
    [
        "{ workspace = true }",
        '{ path = "../member" }',
        '{ git = "https://example.test/member" }',
        '{ url = "https://example.test/member.whl" }',
        "[{ workspace = true, marker = \"sys_platform == 'linux'\" }]",
    ],
)
def test_uv_source_overrides_are_not_registry_dependencies(source):
    before = (
        project("1.2.3", ["member>=1.2.3"]) + f"[tool.uv.sources]\nmember = {source}\n"
    )
    after = (
        project("1.2.4", ["member>=1.2.4"]) + f"[tool.uv.sources]\nmember = {source}\n"
    )
    assert (
        detect_mirrored_dependency_bumps(
            {"pyproject.toml": before}, {"pyproject.toml": after}
        )
        == []
    )


def test_poetry_path_dependency_is_not_a_registry_dependency():
    before = (
        project("1.2.3")
        + '[tool.poetry.dependencies]\nmember = { version = "1.2.3", path = "../member" }\n'
    )
    after = before.replace("1.2.3", "1.2.4")
    assert (
        detect_mirrored_dependency_bumps(
            {"pyproject.toml": before}, {"pyproject.toml": after}
        )
        == []
    )


@pytest.mark.parametrize("call", ["setup", "setuptools.setup", "build_package"])
def test_static_setup_metadata_and_dependencies(call):
    def setup(version):
        return (
            "import setuptools\nfrom setuptools import setup, setup as build_package\n"
            f'{call}(\n    name="example", version="{version}",\n'
            f'    install_requires=["flask>={version}"],\n'
            f'    extras_require={{"test": ["pytest!={version}"]}},\n)\n'
        )

    findings = detect_mirrored_dependency_bumps(
        {"setup.py": setup("1.2.3")}, {"setup.py": setup("1.2.4")}
    )
    assert [(item["name"], item["line"]) for item in findings] == [
        ("flask", 5),
        ("pytest", 6),
    ]


@pytest.mark.parametrize(
    "prefix",
    [
        "def setup(**kwargs): pass\n",
        "setup = custom\n",
        "from custom import setup\n",
        "def outer(setup): pass\n",
    ],
)
def test_shadowed_setup_is_not_project_metadata(prefix):
    before = (
        prefix
        + 'setup(name="example", version="1.2.3", install_requires=["flask>=1.2.3"])\n'
    )
    after = before.replace("1.2.3", "1.2.4")
    assert (
        detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after})
        == []
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "from unrelated import setup\n",
        "from setuptools import setup\ndef unused():\n    ",
    ],
)
def test_unbound_or_unexecuted_setup_calls_are_not_metadata(prefix):
    before = (
        prefix
        + 'setup(name="example", version="1.2.3", install_requires=["flask>=1.2.3"])\n'
    )
    after = before.replace("1.2.3", "1.2.4")
    assert (
        detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after})
        == []
    )


def test_static_setup_call_in_main_guard_is_supported():
    before = 'from setuptools import setup\nif __name__ == "__main__":\n    setup(name="example", version="1.2.3", install_requires=["flask>=1.2.3"])\n'
    after = before.replace("1.2.3", "1.2.4")
    assert (
        len(detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after}))
        == 1
    )


@pytest.mark.parametrize(
    "content",
    [
        'setup(name="example", version=VERSION, install_requires=["flask>=VERSION"])',
        'setup(name="example", version="VERSION", install_requires=requirements)',
        'setup(name="example", version="VERSION", **extra)',
        'setup(name="example", version="VERSION")\nsetup(name="other", version="VERSION")',
    ],
)
def test_dynamic_or_ambiguous_setup_is_skipped(content):
    before = "from setuptools import setup\n" + content.replace("VERSION", "1.2.3")
    after = "from setuptools import setup\n" + content.replace("VERSION", "1.2.4")
    assert (
        detect_mirrored_dependency_bumps({"setup.py": before}, {"setup.py": after})
        == []
    )


@pytest.mark.parametrize("filename", ["uv.lock", "poetry.lock"])
def test_lock_records_use_the_changed_version_line(filename):
    source = (
        'source = { registry = "https://pypi.org/simple" }'
        if filename == "uv.lock"
        else ""
    )
    before, after = snapshots(path=filename)
    before[filename] = lock_package("flask", "1.2.3", source)
    after[filename] = '# version = "1.2.4" is just text\n' + lock_package(
        "flask", "1.2.4", source
    )
    findings = detect_mirrored_dependency_bumps(before, after)
    assert len(findings) == 1
    assert findings[0]["line"] == 4


def test_unchanged_duplicate_lock_version_does_not_hide_the_changed_record():
    before, after = snapshots(path="uv.lock")
    before["uv.lock"] = lock_package("markdown-it-py", "1.2.3") + lock_package(
        "markdown-it-py", "4.0.0"
    )
    after["uv.lock"] = lock_package("markdown-it-py", "4.0.0") + lock_package(
        "markdown-it-py", "1.2.4"
    )
    findings = detect_mirrored_dependency_bumps(before, after)
    assert len(findings) == 1
    assert findings[0]["line"] == 7


def test_multiple_changed_lock_records_in_same_slot_are_ambiguous():
    before, after = snapshots(path="uv.lock")
    before["uv.lock"] = lock_package("flask", "1.2.3") + lock_package("flask", "2.0.0")
    after["uv.lock"] = lock_package("flask", "1.2.4") + lock_package("flask", "2.0.1")
    assert detect_mirrored_dependency_bumps(before, after) == []


@pytest.mark.parametrize(
    "source",
    [
        'source = { editable = "." }',
        'source = { virtual = "member" }',
        'source = { path = "member" }',
        'source = { git = "https://example.test/repo" }',
        'source = { url = "https://example.test/member.whl" }',
    ],
)
def test_local_lock_records_are_not_registry_dependencies(source):
    before, after = snapshots(path="uv.lock")
    before["uv.lock"] = lock_package("member", "1.2.3", source)
    after["uv.lock"] = lock_package("member", "1.2.4", source)
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_lock_nested_dependency_metadata_hashes_and_urls_are_not_pins():
    before, after = snapshots(path="uv.lock")
    before["uv.lock"] = (
        lock_package("flask", "9.0.0")
        + 'dependencies = [{ name = "other", version = "1.2.3" }]\nsdist = { url = "https://example.test/flask-1.2.3.tar.gz", hash = "sha256:1.2.3" }\n'
    )
    after["uv.lock"] = before["uv.lock"].replace("1.2.3", "1.2.4")
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_lock_table_source_subsections_are_scoped_to_their_package():
    before, after = snapshots(path="uv.lock")
    before["uv.lock"] = (
        '[[package]]\nname = "flask"\nversion = "1.2.3"\n[package.source]\nregistry = "https://pypi.org/simple"\n'
    )
    after["uv.lock"] = before["uv.lock"].replace("1.2.3", "1.2.4")
    assert len(detect_mirrored_dependency_bumps(before, after)) == 1


def test_self_references_are_excluded_with_normalized_names():
    before = project("1.2.3", ["EXAMPLE_app>=1.2.3"])
    after = project("1.2.4", ["example.app>=1.2.4"])
    assert (
        detect_mirrored_dependency_bumps(
            {"pyproject.toml": before}, {"pyproject.toml": after}
        )
        == []
    )


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        project("1.2.3"),
        '[project]\nname="example"\nversion="1.2.4"\ndynamic=["version"]\n',
    ],
)
def test_requires_an_actual_static_project_version_change(metadata):
    before, after = snapshots()
    if metadata is None:
        before.pop("pyproject.toml")
        after.pop("pyproject.toml")
    else:
        after["pyproject.toml"] = metadata
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_project_name_change_is_not_a_known_project_transition():
    before, after = snapshots()
    after["pyproject.toml"] = project("1.2.4", name="different-project")
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_conflicting_project_metadata_is_skipped():
    before, after = snapshots()
    before["setup.py"] = (
        'from setuptools import setup\nsetup(name="example-app", version="9.0.0")'
    )
    after["setup.py"] = (
        'from setuptools import setup\nsetup(name="example-app", version="9.0.1")'
    )
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_agreeing_project_manifests_do_not_duplicate_findings():
    before, after = snapshots()
    before["setup.py"] = (
        'from setuptools import setup\nsetup(name="example-app", version="1.2.3")'
    )
    after["setup.py"] = (
        'from setuptools import setup\nsetup(name="example-app", version="1.2.4")'
    )
    assert len(detect_mirrored_dependency_bumps(before, after)) == 1


@pytest.mark.parametrize(
    "nested_manifest",
    [project("9.0.0", name="nested"), "[broken", "[tool.ruff]\nline-length = 88\n"],
)
def test_nested_project_boundary_blocks_ancestor_version_evidence(nested_manifest):
    before, after = snapshots(path="nested/requirements.txt")
    before["nested/pyproject.toml"] = nested_manifest
    after["nested/pyproject.toml"] = nested_manifest
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_independent_projects_use_only_their_own_version_transition():
    before, after = snapshots(path="nested/requirements.txt")
    before["nested/pyproject.toml"] = project("2.0.0", name="nested")
    after["nested/pyproject.toml"] = project("2.0.1", name="nested")
    before["nested/requirements.txt"] += "pytest>=2.0.0\n"
    after["nested/requirements.txt"] += "pytest>=2.0.1\n"
    findings = detect_mirrored_dependency_bumps(before, after)
    assert [item["name"] for item in findings] == ["pytest"]
    assert findings[0]["metadata"]["project"] == "nested"


@pytest.mark.parametrize(
    "broken",
    [
        "[invalid",
        'x = "unterminated',
        '[project]\nname="example"\nname="duplicate"',
        "[" * 1000,
        "x" * (MAX_MANIFEST_BYTES + 1),
    ],
)
def test_invalid_and_oversized_metadata_is_safely_skipped(broken):
    before, after = snapshots()
    after["pyproject.toml"] = broken
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_bad_file_does_not_prevent_other_project_findings():
    before, after = snapshots()
    before["broken/pyproject.toml"] = after["broken/pyproject.toml"] = "[broken"
    assert len(detect_mirrored_dependency_bumps(before, after)) == 1


def test_dotted_and_quoted_toml_keys_and_literal_string_arrays():
    def content(version):
        return f"""project.name = 'example'
project.version = '{version}'
project."dependencies" = [
    'Flask>={version}',
]
"""

    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": content("1.2.3")}, {"pyproject.toml": content("1.2.4")}
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 4


def test_multiline_toml_text_cannot_supply_project_or_dependency_metadata():
    before, after = snapshots()
    for files, version in ((before, "1.2.3"), (after, "1.2.4")):
        files["pyproject.toml"] = (
            f'description = """\n[project]\nname = "fake"\nversion = "{version}"\ndependencies=["flask>={version}"]\n"""\n'
        )
    assert detect_mirrored_dependency_bumps(before, after) == []


def test_result_order_is_stable_and_distinct_declarations_are_preserved():
    before, after = snapshots()
    before["requirements-dev.txt"] = "pytest>=1.2.3\n"
    after["requirements-dev.txt"] = "pytest>=1.2.4\n"
    first = detect_mirrored_dependency_bumps(before, after)
    second = detect_mirrored_dependency_bumps(
        dict(reversed(list(before.items()))), dict(reversed(list(after.items())))
    )
    assert first == second
    assert [item["file"] for item in first] == [
        "requirements-dev.txt",
        "requirements.txt",
    ]


@pytest.mark.parametrize("provider", ["uv", "poetry", "uv-lock", "poetry-lock"])
def test_sibling_local_sources_do_not_hide_an_independent_registry_bump(provider):
    path = "service-a/pyproject.toml"
    before = {path: project("1.2.3", ["flask>=1.2.3"], name="service-a")}
    after = {path: project("1.2.4", ["flask>=1.2.4"], name="service-a")}
    sibling_path = "service-b/pyproject.toml"
    sibling = project("9.0.0", name="service-b")
    if provider == "uv":
        sibling += '[tool.uv.sources]\nflask = { path = "vendor/flask" }\n'
    elif provider == "poetry":
        sibling += (
            "[tool.poetry.dependencies]\n"
            'flask = { version = "9.0.0", path = "vendor/flask" }\n'
        )
    else:
        filename = "uv.lock" if provider == "uv-lock" else "poetry.lock"
        source = (
            'source = { editable = "vendor/flask" }'
            if provider == "uv-lock"
            else 'source = { type = "directory", url = "vendor/flask" }'
        )
        lock = lock_package("flask", "9.0.0", source)
        before[f"service-b/{filename}"] = lock
        after[f"service-b/{filename}"] = lock + "# Unrelated metadata note.\n"
    before[sibling_path] = sibling
    after[sibling_path] = sibling + "# Unrelated metadata note.\n"

    findings = detect_mirrored_dependency_bumps(before, after)
    assert len(findings) == 1
    assert findings[0]["file"] == path
    assert findings[0]["metadata"]["project"] == "service-a"


def test_known_internal_packages_stay_excluded_when_using_registry_releases():
    before = {
        "pyproject.toml": project("1.2.3", ["internal-package>=1.2.3"]),
        "packages/internal/pyproject.toml": project("1.2.3", name="internal-package"),
    }
    after = {
        "pyproject.toml": project("1.2.4", ["internal-package>=1.2.4"]),
        "packages/internal/pyproject.toml": project("1.2.4", name="internal-package"),
    }
    assert detect_mirrored_dependency_bumps(before, after) == []


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("closing_quote_count", [4, 5])
@pytest.mark.parametrize(
    "description", ["A quoted description", "First line\nLast line"]
)
def test_valid_multiline_toml_quote_endings_keep_dependency_locations(
    quote, closing_quote_count, description
):
    def content(version):
        return (
            "[project]\n"
            'name = "example"\n'
            f'version = "{version}"\n'
            f"description = {quote * 3}{description}{quote * closing_quote_count}\n"
            f'dependencies = ["flask>={version}"]\n'
        )

    findings = detect_mirrored_dependency_bumps(
        {"pyproject.toml": content("1.2.3")},
        {"pyproject.toml": content("1.2.4")},
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 5 + description.count("\n")


@pytest.mark.parametrize(
    ("literal", "expected_line", "changed_line"),
    [
        ('"flask>="\n        "VERSION"', 7, 7),
        ('r"flask>="\n        r"VERSION"', 7, 7),
        ('""\n        "flask>=VERSION"', 7, 7),
        ('"  flask ( "\n        ">=VERSION"\n        ", !=9)"', 7, 7),
        ('"flask>=9,"\n        "!=VERSION"', 7, 7),
        ('"flask>=1.2."\n        "PATCH"', 6, 7),
        ('"""flask>=\\\nVERSION"""', 7, 7),
    ],
)
def test_split_setup_literals_keep_version_lines_and_survive_diff_filter(
    literal, expected_line, changed_line
):
    def content(version):
        dependency = literal.replace("VERSION", version).replace("PATCH", version[-1])
        return (
            "from setuptools import setup\n"
            "setup(\n"
            '    name="example",\n'
            f'    version="{version}",\n'
            "    install_requires=[\n"
            f"        {dependency},\n"
            "    ],\n"
            ")\n"
        )

    findings = detect_mirrored_dependency_bumps(
        {"setup.py": content("1.2.3")}, {"setup.py": content("1.2.4")}
    )
    assert len(findings) == 1
    assert findings[0]["line"] == expected_line
    assert (
        filter_findings_to_diff(
            findings,
            [
                {"file": "setup.py", "start": 4, "end": 4},
                {"file": "setup.py", "start": changed_line, "end": changed_line},
            ],
        )
        == findings
    )


def test_split_setup_literal_span_does_not_include_unrelated_lines():
    before = (
        'from setuptools import setup\nsetup(name="example", version="1.2.3",\n'
        '    install_requires=["flask>="\n                      "1.2.3"])\n'
    )
    after = before.replace("1.2.3", "1.2.4")
    findings = detect_mirrored_dependency_bumps(
        {"setup.py": before}, {"setup.py": after}
    )
    assert findings[0]["related_locations"] == [
        {"file": "setup.py", "start_line": 3, "end_line": 4}
    ]
    assert (
        filter_findings_to_diff(findings, [{"file": "setup.py", "start": 2, "end": 2}])
        == []
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_split_setup_locations_handle_utf8_columns_and_line_endings(newline):
    before = (
        'from setuptools import setup\nsetup(name="example", version="1.2.3",\n'
        '    description="caf\u00e9", install_requires=["flask>="\n'
        '                                            "1.2.3"])\n'
    ).replace("\n", newline)
    after = before.replace("1.2.3", "1.2.4")
    findings = detect_mirrored_dependency_bumps(
        {"setup.py": before}, {"setup.py": after}
    )
    assert len(findings) == 1
    assert findings[0]["line"] == 4
